/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2017-2018 Solarflare Communications Inc.
 * All rights reserved.
 *
 * This software was jointly developed between OKTET Labs (under contract
 * for Solarflare) and Solarflare Communications, Inc.
 */

/* EF10 packed stream native datapath implementation */

#include <stdbool.h>

#include <rte_byteorder.h>
#include <rte_mbuf_ptype.h>
#include <rte_mbuf.h>
#include <rte_io.h>

#include "efx.h"
#include "efx_types.h"
#include "efx_regs.h"
#include "efx_regs_ef10.h"

#include "sfc_tweak.h"
#include "sfc_dp_rx.h"
#include "sfc_kvargs.h"
#include "sfc_ef10.h"

#define sfc_ef10_ps_rx_err(dpq, ...) \
	SFC_DP_LOG(SFC_KVARG_DATAPATH_EF10_PACKED, ERR, dpq, __VA_ARGS__)

#if 1
#define	EFX_RX_PACKED_STREAM_ALIGNMENT 64
#define	EFX_RX_PACKED_STREAM_RX_PREFIX_SIZE 8
#endif

#define SFC_EF10_PACKED_STREAM_BUFSIZE (64 * 1024)


struct sfc_ef10_ps_hugebuf {
	struct rte_mbuf_ext_shared_info	shinfo;
	void				*buf_addr;
	rte_iova_t			buf_iova;
	struct rte_mempool		*mp;
};

struct sfc_ef10_ps_rx_sw_desc {
	struct sfc_ef10_ps_hugebuf	*hbuf;
};

struct sfc_ef10_ps_rxq {
	/* Used on data path */
	unsigned int			flags;
#define SFC_EF10_PS_RXQ_STARTED		0x1
#define SFC_EF10_PS_RXQ_NOT_RUNNING	0x2
#define SFC_EF10_PS_RXQ_EXCEPTION	0x4
	unsigned int			rxq_ptr_mask;
	unsigned int			completed;
	unsigned int			pending_pkts;
	uint8_t				*next_pkt;
	unsigned int			packets;
	unsigned int			evq_read_ptr;
	unsigned int			evq_ptr_mask;
	efx_qword_t			*evq_hw_ring;
	struct sfc_ef10_ps_rx_sw_desc	*sw_ring;
	struct rte_mempool		*indirect_mp;
	uint8_t				credits;
	uint16_t			port_id;

	/* Used on refill */
	unsigned int			added;
	unsigned int			max_fill_level;
	unsigned int			refill_threshold;
	struct rte_mempool		*refill_mp;
	efx_qword_t			*rxq_hw_ring;
	volatile void			*doorbell;

	/* Datapath receive queue anchor */
	struct sfc_dp_rxq		dp;
};

static inline struct sfc_ef10_ps_rxq *
sfc_ef10_ps_rxq_by_dp_rxq(struct sfc_dp_rxq *dp_rxq)
{
	return container_of(dp_rxq, struct sfc_ef10_ps_rxq, dp);
}

static void
sfc_ef10_ps_rx_qpush(struct sfc_ef10_ps_rxq *rxq)
{
	efx_dword_t dword;

	/* Hardware has alignment restriction for WPTR */
	RTE_BUILD_BUG_ON(SFC_RX_REFILL_BULK % SFC_EF10_RX_WPTR_ALIGN != 0);
	SFC_ASSERT(RTE_ALIGN(rxq->added, SFC_EF10_RX_WPTR_ALIGN) == rxq->added);

	EFX_POPULATE_DWORD_1(dword, ERF_DZ_RX_DESC_WPTR,
			     rxq->added & rxq->rxq_ptr_mask);

	/* DMA sync to device is not required */

	/*
	 * rte_write32() has rte_io_wmb() which guarantees that the STORE
	 * operations (i.e. Rx and event descriptor updates) that precede
	 * the rte_io_wmb() call are visible to NIC before the STORE
	 * operations that follow it (i.e. doorbell write).
	 */
	rte_write32(dword.ed_u32[0], rxq->doorbell);
}

static void
sfc_ef10_ps_rx_update_credits(struct sfc_ef10_ps_rxq *rxq)
{
	efx_dword_t dword;

	if (rxq->credits == 0)
		return;

	EFX_POPULATE_DWORD_3(dword,
			     ERF_DZ_RX_DESC_MAGIC_DOORBELL, 1,
			     ERF_DZ_RX_DESC_MAGIC_CMD,
			     ERE_DZ_RX_DESC_MAGIC_CMD_PS_CREDITS,
			     ERF_DZ_RX_DESC_MAGIC_DATA, rxq->credits);

	/* DMA sync to device is not required */

	/*
	 * rte_write32() has rte_io_wmb() which guarantees that the STORE
	 * operations (i.e. Rx and event descriptor updates) that precede
	 * the rte_io_wmb() call are visible to NIC before the STORE
	 * operations that follow it (i.e. doorbell write).
	 */
	rte_write32(dword.ed_u32[0], rxq->doorbell);

	rxq->credits = 0;
}

static void
sfc_ef10_ps_rx_qrefill(struct sfc_ef10_ps_rxq *rxq)
{
	const unsigned int rxq_ptr_mask = rxq->rxq_ptr_mask;
	unsigned int free_space;
	unsigned int bulks;
	void *objs[SFC_RX_REFILL_BULK];
	unsigned int added = rxq->added;

	free_space = rxq->max_fill_level - (added - rxq->completed);

	if (free_space < rxq->refill_threshold)
		return;

	bulks = free_space / RTE_DIM(objs);

	while (bulks-- > 0) {
		unsigned int id;
		unsigned int i;

		if (unlikely(rte_mempool_get_bulk(rxq->refill_mp, objs,
						  RTE_DIM(objs)) < 0)) {
			struct rte_eth_dev_data *dev_data =
				rte_eth_devices[rxq->port_id].data;

			/*
			 * It is hardly a safe way to increment counter
			 * from different contexts, but all PMDs do it.
			 */
			dev_data->rx_mbuf_alloc_failed += RTE_DIM(objs);
			break;
		}

		for (i = 0, id = added & rxq_ptr_mask;
		     i < RTE_DIM(objs);
		     ++i, ++id) {
			struct sfc_ef10_ps_rx_sw_desc *rxd;

			SFC_ASSERT((id & ~rxq_ptr_mask) == 0);
			rxd = &rxq->sw_ring[id];
			rxd->hbuf = objs[i];

			EFX_POPULATE_QWORD_2(rxq->rxq_hw_ring[id],
			    ESF_DZ_RX_KER_BYTE_CNT, 32 /* FIXME */,
			    ESF_DZ_RX_KER_BUF_ADDR, rxd->hbuf->buf_iova);
		}

		added += RTE_DIM(objs);
	}

	/* Push doorbell if something is posted */
	if (likely(rxq->added != added)) {
		rxq->added = added;
		sfc_ef10_ps_rx_qpush(rxq);
	}
}

static uint16_t
sfc_ef10_ps_rx_get_pending(struct sfc_ef10_ps_rxq *rxq,
			   struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	uint16_t n_rx_pkts = RTE_MIN(nb_pkts, rxq->pending_pkts);
	struct sfc_ef10_ps_hugebuf *hbuf;
	uint8_t *next_pkt;
	unsigned int i;

	if (n_rx_pkts == 0)
		return 0;

	rxq->pending_pkts -= n_rx_pkts;

	if (rte_mempool_get_bulk(rxq->indirect_mp, (void **)rx_pkts,
				 n_rx_pkts) < 0)
		return 0;

	hbuf = rxq->sw_ring[rxq->completed & rxq->rxq_ptr_mask].hbuf;

	/* Increment extbuf reference counter for all packets at once */
	rte_mbuf_ext_refcnt_update(&hbuf->shinfo, n_rx_pkts);

	next_pkt = rxq->next_pkt;
	for (i = 0; i < n_rx_pkts; ++i) {
		struct rte_mbuf *m = *rx_pkts++;
		const efx_qword_t *qwordp;
		uint16_t pkt_space;
		uint16_t cap_len;

		/* Parse pseudo-header */
		qwordp = (const efx_qword_t *)next_pkt;
		/* Original packet length is not used */
		cap_len = EFX_QWORD_FIELD(*qwordp, ES_DZ_PS_RX_PREFIX_CAP_LEN);

		pkt_space =
			SFC_P2_ROUND_UP(EFX_RX_PACKED_STREAM_RX_PREFIX_SIZE +
					cap_len,
					EFX_RX_PACKED_STREAM_ALIGNMENT) +
			EFX_RX_PACKED_STREAM_ALIGNMENT;

		rte_pktmbuf_attach_extbuf(m, next_pkt,
			hbuf->buf_iova + RTE_PTR_DIFF(next_pkt, hbuf->buf_addr),
			pkt_space, &hbuf->shinfo);

		/* Move to the next packet and prefetch it */
		next_pkt += pkt_space;
		rte_prefetch0(next_pkt);

		m->data_off = EFX_RX_PACKED_STREAM_RX_PREFIX_SIZE;
		m->port = rxq->port_id;
		m->packet_type = RTE_PTYPE_L2_ETHER;
		rte_pktmbuf_pkt_len(m) = cap_len;
		rte_pktmbuf_data_len(m) = cap_len;
	}

	rxq->next_pkt = next_pkt;

	return n_rx_pkts;
}

static void
sfc_ef10_ps_rx_discard_pending(struct sfc_ef10_ps_rxq *rxq)
{
	uint8_t *next_pkt;
	unsigned int i;

	next_pkt = rxq->next_pkt;

	for (i = 0; i < rxq->pending_pkts; ++i) {
		const efx_qword_t *qwordp;
		uint16_t buf_len;

		qwordp = (const efx_qword_t *)next_pkt;
		buf_len = EFX_QWORD_FIELD(*qwordp, ES_DZ_PS_RX_PREFIX_CAP_LEN);
		buf_len = SFC_P2_ROUND_UP(buf_len +
					  EFX_RX_PACKED_STREAM_RX_PREFIX_SIZE,
					  EFX_RX_PACKED_STREAM_ALIGNMENT);
		next_pkt += buf_len + EFX_RX_PACKED_STREAM_ALIGNMENT;
	}

	rxq->next_pkt = next_pkt;
	rxq->pending_pkts = 0;
}

static inline void
sfc_ef10_ps_free_huge_buf(struct sfc_ef10_ps_hugebuf *hbuf)
{
	if (rte_mbuf_ext_refcnt_read(&hbuf->shinfo) == 1)
		rte_mempool_put(hbuf->mp, hbuf->shinfo.fcb_opaque);
	else if (rte_mbuf_ext_refcnt_update(&hbuf->shinfo, -1) == 0)
		hbuf->shinfo.free_cb(hbuf->buf_addr, hbuf->shinfo.fcb_opaque);
}

static void
sfc_ef10_ps_rx_process_ev(struct sfc_ef10_ps_rxq *rxq, efx_qword_t rx_ev)
{
	unsigned int ready;

	SFC_ASSERT(rxq->pending_pkts == 0);

	ready = (EFX_QWORD_FIELD(rx_ev, ESF_DZ_RX_DSC_PTR_LBITS) -
		 rxq->packets) &
		EFX_MASK32(ESF_DZ_RX_DSC_PTR_LBITS);

	rxq->packets += ready;
	rxq->pending_pkts = ready;

	if (EFX_TEST_QWORD_BIT(rx_ev, ESF_DZ_RX_EV_ROTATE_LBN)) {
		struct sfc_ef10_ps_rx_sw_desc *rxd;

		/* Credit is spent by firmware */
		rxq->credits++;

		/* Drop our reference to huge buffer */
		rxd = &rxq->sw_ring[rxq->completed & rxq->rxq_ptr_mask];
		sfc_ef10_ps_free_huge_buf(rxd->hbuf);

		/* Switch to the next huge buffer */
		rxq->completed++;
		rxd = &rxq->sw_ring[rxq->completed & rxq->rxq_ptr_mask];
		rxq->next_pkt = rxd->hbuf->buf_addr;
	}

	if (rx_ev.eq_u64[0] &
	    rte_cpu_to_le_64((1ull << ESF_DZ_RX_ECC_ERR_LBN) |
			     (1ull << ESF_DZ_RX_ECRC_ERR_LBN)))
		sfc_ef10_ps_rx_discard_pending(rxq);
}

static bool
sfc_ef10_ps_rx_event_get(struct sfc_ef10_ps_rxq *rxq, efx_qword_t *rx_ev)
{
	*rx_ev = rxq->evq_hw_ring[rxq->evq_read_ptr & rxq->evq_ptr_mask];

	if (!sfc_ef10_ev_present(*rx_ev))
		return false;

	if (unlikely(EFX_QWORD_FIELD(*rx_ev, FSF_AZ_EV_CODE) !=
		     FSE_AZ_EV_CODE_RX_EV)) {
		/*
		 * Do not move read_ptr to keep the event for exception
		 * handling
		 */
		rxq->flags |= SFC_EF10_PS_RXQ_EXCEPTION;
		sfc_ef10_ps_rx_err(&rxq->dp.dpq,
				   "RxQ exception at EvQ read ptr %#x",
				   rxq->evq_read_ptr);
		return false;
	}

	rxq->evq_read_ptr++;
	return true;
}

static uint16_t
sfc_ef10_ps_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
		      uint16_t nb_pkts)
{
	struct sfc_ef10_ps_rxq *rxq = sfc_ef10_ps_rxq_by_dp_rxq(rx_queue);
	const unsigned int evq_old_read_ptr = rxq->evq_read_ptr;
	uint16_t n_rx_pkts;
	efx_qword_t rx_ev;

	if (unlikely(rxq->flags &
		     (SFC_EF10_PS_RXQ_NOT_RUNNING | SFC_EF10_PS_RXQ_EXCEPTION)))
		return 0;

	n_rx_pkts = sfc_ef10_ps_rx_get_pending(rxq, rx_pkts, nb_pkts);

	while (n_rx_pkts != nb_pkts && sfc_ef10_ps_rx_event_get(rxq, &rx_ev)) {
		if (EFX_TEST_QWORD_BIT(rx_ev, ESF_DZ_RX_DROP_EVENT_LBN))
			continue;

		sfc_ef10_ps_rx_process_ev(rxq, rx_ev);
		n_rx_pkts += sfc_ef10_ps_rx_get_pending(rxq,
							rx_pkts + n_rx_pkts,
							nb_pkts - n_rx_pkts);
	}

	sfc_ef10_ev_qclear(rxq->evq_hw_ring, rxq->evq_ptr_mask,
			   evq_old_read_ptr, rxq->evq_read_ptr);

	/* It is not a problem if we refill in the case of exception */
	sfc_ef10_ps_rx_update_credits(rxq);
	sfc_ef10_ps_rx_qrefill(rxq);

	return n_rx_pkts;
}

static const uint32_t *
sfc_ef10_ps_supported_ptypes_get(__rte_unused uint32_t tunnel_encaps)
{
	static const uint32_t ef10_packed_ptypes[] = {
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_UNKNOWN
	};

	return ef10_packed_ptypes;
}

static sfc_dp_rx_qdesc_npending_t sfc_ef10_ps_rx_qdesc_npending;
static unsigned int
sfc_ef10_ps_rx_qdesc_npending(__rte_unused struct sfc_dp_rxq *dp_rxq)
{
	/*
	 * Correct implementation requires EvQ polling and events
	 * processing.
	 */
	return -ENOTSUP;
}

static sfc_dp_rx_qdesc_status_t sfc_ef10_ps_rx_qdesc_status;
static int
sfc_ef10_ps_rx_qdesc_status(__rte_unused struct sfc_dp_rxq *dp_rxq,
			    __rte_unused uint16_t offset)
{
	return -ENOTSUP;
}

static sfc_dp_rx_get_dev_info_t sfc_ef10_ps_rx_get_dev_info;
static void
sfc_ef10_ps_rx_get_dev_info(struct rte_eth_dev_info *dev_info)
{
	/*
	 * Number of descriptors just defines maximum number of pushed
	 * descriptors (fill level).
	 */
	dev_info->rx_desc_lim.nb_min = SFC_RX_REFILL_BULK;
	dev_info->rx_desc_lim.nb_align = SFC_RX_REFILL_BULK;
}

static sfc_dp_rx_qsize_up_rings_t sfc_ef10_ps_rx_qsize_up_rings;
static int
sfc_ef10_ps_rx_qsize_up_rings(uint16_t nb_rx_desc,
			      struct sfc_dp_rx_hw_limits *limits,
			      __rte_unused struct rte_mempool *mb_pool,
			      unsigned int *rxq_entries,
			      unsigned int *evq_entries,
			      unsigned int *rxq_max_fill_level)
{
	/*
	 * rte_ethdev API guarantees that the number meets min, max and
	 * alignment requirements.
	 */
	if (nb_rx_desc <= limits->rxq_min_entries)
		*rxq_entries = limits->rxq_min_entries;
	else
		*rxq_entries = rte_align32pow2(nb_rx_desc);

	*evq_entries = *rxq_entries;

	*rxq_max_fill_level = RTE_MIN(nb_rx_desc, EFX_RXQ_LIMIT(*evq_entries));
	return 0;
}

static void
sfc_ef10_ps_hugebuf_free(__rte_unused void *addr, void *opaque)
{
	void *obj = opaque;
	struct sfc_ef10_ps_hugebuf *hbuf = obj;

	rte_mbuf_ext_refcnt_set(&hbuf->shinfo, 1);
	rte_mempool_put(hbuf->mp, obj);
}

static void
sfc_ef10_ps_hugebuf_init(struct rte_mempool *mp, __rte_unused void *opaque_arg,
			 void *obj, __rte_unused unsigned int obj_idx)
{
	struct sfc_ef10_ps_hugebuf *hbuf = obj;
	size_t off;

	hbuf->shinfo.free_cb = sfc_ef10_ps_hugebuf_free;
	hbuf->shinfo.fcb_opaque = obj;
	rte_mbuf_ext_refcnt_set(&hbuf->shinfo, 1);

	hbuf->buf_addr =
		RTE_PTR_ALIGN_CEIL(hbuf + 1, SFC_EF10_PACKED_STREAM_BUFSIZE);

	off = RTE_PTR_DIFF(hbuf->buf_addr, obj);
	hbuf->buf_iova = rte_mempool_virt2iova(obj) + off;
	hbuf->mp = mp;

	SFC_ASSERT(off + SFC_EF10_PACKED_STREAM_BUFSIZE <= mp->elt_size);
}

static struct rte_mempool *
sfc_ef10_ps_rx_hugebuf_pool_create(struct sfc_ef10_ps_rxq *rxq, int socket_id)
{
	unsigned int elt_size;
	char hb_pool_name[64];

	/* Twice size to guarantee possibility to align */
	elt_size = RTE_ALIGN_FLOOR(sizeof(struct sfc_ef10_ps_hugebuf) +
		SFC_EF10_PACKED_STREAM_BUFSIZE * 2, RTE_MEMPOOL_ALIGN);

	snprintf(hb_pool_name, sizeof(hb_pool_name),
		 "sfc-hugebuf%u.%u", rxq->port_id, rxq->dp.dpq.queue_id);

	/* ptr_mask is the number of entres in the queue minus 1,
	 * which happens to be the optimal size for rte_mempool_create
	 */
	return rte_mempool_create(hb_pool_name, rxq->rxq_ptr_mask, elt_size,
				  1, sizeof(struct rte_pktmbuf_pool_private),
				  NULL, NULL, sfc_ef10_ps_hugebuf_init, NULL,
				  socket_id,
				  MEMPOOL_F_NO_SPREAD | MEMPOOL_F_SC_GET);
}

static sfc_dp_rx_qcreate_t sfc_ef10_ps_rx_qcreate;
static int
sfc_ef10_ps_rx_qcreate(uint16_t port_id, uint16_t queue_id,
		       const struct rte_pci_addr *pci_addr, int socket_id,
		       const struct sfc_dp_rx_qcreate_info *info,
		       struct sfc_dp_rxq **dp_rxqp)
{
	struct sfc_ef10_ps_rxq *rxq;
	int rc;

	rc = ENOMEM;
	rxq = rte_zmalloc_socket("sfc-ef10-rxq", sizeof(*rxq),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq == NULL)
		goto fail_rxq_alloc;

	sfc_dp_queue_init(&rxq->dp.dpq, port_id, queue_id, pci_addr);

	rc = ENOMEM;
	rxq->sw_ring = rte_calloc_socket("sfc-ef10-rxq-sw_ring",
					 info->rxq_entries,
					 sizeof(*rxq->sw_ring),
					 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq->sw_ring == NULL)
		goto fail_desc_alloc;

	rxq->flags |= SFC_EF10_PS_RXQ_NOT_RUNNING;
	rxq->rxq_ptr_mask = info->rxq_entries - 1;
	rxq->evq_ptr_mask = info->evq_entries - 1;
	rxq->evq_hw_ring = info->evq_hw_ring;
	rxq->max_fill_level = info->max_fill_level;
	rxq->refill_threshold = info->refill_threshold;
	rxq->indirect_mp = info->refill_mb_pool;
	rxq->port_id = port_id;
	rxq->rxq_hw_ring = info->rxq_hw_ring;

	rc = ENOMEM;
	rxq->refill_mp = sfc_ef10_ps_rx_hugebuf_pool_create(rxq, socket_id);
	if (rxq->refill_mp == NULL)
		goto fail_huge_pktmbuf_pool_create;

	rxq->doorbell = (volatile uint8_t *)info->mem_bar +
			ER_DZ_RX_DESC_UPD_REG_OFST +
			(info->hw_index << info->vi_window_shift);

	*dp_rxqp = &rxq->dp;
	return 0;

fail_huge_pktmbuf_pool_create:
	rte_free(rxq->sw_ring);

fail_desc_alloc:
	rte_free(rxq);

fail_rxq_alloc:
	return rc;
}

static sfc_dp_rx_qdestroy_t sfc_ef10_ps_rx_qdestroy;
static void
sfc_ef10_ps_rx_qdestroy(struct sfc_dp_rxq *dp_rxq)
{
	struct sfc_ef10_ps_rxq *rxq = sfc_ef10_ps_rxq_by_dp_rxq(dp_rxq);

	rte_mempool_free(rxq->refill_mp);
	rte_free(rxq->sw_ring);
	rte_free(rxq);
}

static sfc_dp_rx_qstart_t sfc_ef10_ps_rx_qstart;
static int
sfc_ef10_ps_rx_qstart(struct sfc_dp_rxq *dp_rxq, unsigned int evq_read_ptr)
{
	struct sfc_ef10_ps_rxq *rxq = sfc_ef10_ps_rxq_by_dp_rxq(dp_rxq);
	struct sfc_ef10_ps_rx_sw_desc *rxd;
	void *obj;

	rxq->pending_pkts = 0;
	rxq->packets = UINT_MAX;
	rxq->evq_read_ptr = evq_read_ptr;

	rxq->completed = rxq->added = 0;

	sfc_ef10_ps_rx_qrefill(rxq);

	/*
	 * Step back to handle the first EV_ROTATE correctly.
	 * Allocate dummy mbuf to be freed on the first EV_ROTATE.
	 * It is not used, so do not bother to initialize it.
	 * Do it after refill to not account it in fill level.
	 */
	if (rte_mempool_get(rxq->refill_mp, &obj) != 0)
		return ENOMEM;
	rxq->completed--;
	rxd = &rxq->sw_ring[rxq->completed & rxq->rxq_ptr_mask];
	rxd->hbuf = obj;

	rxq->flags |= SFC_EF10_PS_RXQ_STARTED;
	rxq->flags &=
		~(SFC_EF10_PS_RXQ_NOT_RUNNING | SFC_EF10_PS_RXQ_EXCEPTION);

	/*
	 * Control path grants initial packed stream credits to firmware
	 * in accordance with event queue size. We simply track when
	 * credits are spent and refill.
	 */

	return 0;
}

static sfc_dp_rx_qstop_t sfc_ef10_ps_rx_qstop;
static void
sfc_ef10_ps_rx_qstop(struct sfc_dp_rxq *dp_rxq, unsigned int *evq_read_ptr)
{
	struct sfc_ef10_ps_rxq *rxq = sfc_ef10_ps_rxq_by_dp_rxq(dp_rxq);

	rxq->flags |= SFC_EF10_PS_RXQ_NOT_RUNNING;

	*evq_read_ptr = rxq->evq_read_ptr;
}

static sfc_dp_rx_qrx_ev_t sfc_ef10_ps_rx_qrx_ev;
static bool
sfc_ef10_ps_rx_qrx_ev(struct sfc_dp_rxq *dp_rxq, __rte_unused unsigned int id)
{
	__rte_unused struct sfc_ef10_ps_rxq *rxq;

	rxq = sfc_ef10_ps_rxq_by_dp_rxq(dp_rxq);
	SFC_ASSERT(rxq->flags & SFC_EF10_PS_RXQ_NOT_RUNNING);

	/*
	 * It is safe to ignore Rx event since we free all mbufs on
	 * queue purge anyway.
	 */

	return false;
}

static sfc_dp_rx_qpurge_t sfc_ef10_ps_rx_qpurge;
static void
sfc_ef10_ps_rx_qpurge(struct sfc_dp_rxq *dp_rxq)
{
	struct sfc_ef10_ps_rxq *rxq = sfc_ef10_ps_rxq_by_dp_rxq(dp_rxq);
	unsigned int i;
	struct sfc_ef10_ps_rx_sw_desc *rxd;

	for (i = rxq->completed; i != rxq->added; ++i) {
		rxd = &rxq->sw_ring[i & rxq->rxq_ptr_mask];
		sfc_ef10_ps_free_huge_buf(rxd->hbuf);
	}

	rxq->flags &= ~SFC_EF10_PS_RXQ_STARTED;
}

struct sfc_dp_rx sfc_ef10_ps_rx = {
	.dp = {
		.name		= SFC_KVARG_DATAPATH_EF10_PACKED,
		.type		= SFC_DP_RX,
		.hw_fw_caps	= SFC_DP_HW_FW_CAP_EF10 |
				  SFC_DP_HW_FW_CAP_RX_PACKED_STREAM_64K,
	},
	.features		= SFC_DP_RX_FEAT_MULTI_PROCESS,
	.dev_offload_capa	= 0,
	.queue_offload_capa	= DEV_RX_OFFLOAD_SCATTER,
	.get_dev_info		= sfc_ef10_ps_rx_get_dev_info,
	.qsize_up_rings		= sfc_ef10_ps_rx_qsize_up_rings,
	.qcreate		= sfc_ef10_ps_rx_qcreate,
	.qdestroy		= sfc_ef10_ps_rx_qdestroy,
	.qstart			= sfc_ef10_ps_rx_qstart,
	.qstop			= sfc_ef10_ps_rx_qstop,
	.qrx_ev			= sfc_ef10_ps_rx_qrx_ev,
	.qpurge			= sfc_ef10_ps_rx_qpurge,
	.supported_ptypes_get	= sfc_ef10_ps_supported_ptypes_get,
	.qdesc_npending		= sfc_ef10_ps_rx_qdesc_npending,
	.qdesc_status		= sfc_ef10_ps_rx_qdesc_status,
	.pkt_burst		= sfc_ef10_ps_recv_pkts,
};
