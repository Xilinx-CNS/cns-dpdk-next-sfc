/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cn10k_worker.h"
#include "cnxk_eventdev.h"
#include "cnxk_worker.h"

static uint32_t
cn10k_sso_gw_mode_wdata(struct cnxk_sso_evdev *dev)
{
	uint32_t wdata = BIT(16) | 1;

	switch (dev->gw_mode) {
	case CN10K_GW_MODE_NONE:
	default:
		break;
	case CN10K_GW_MODE_PREF:
		wdata |= BIT(19);
		break;
	case CN10K_GW_MODE_PREF_WFE:
		wdata |= BIT(20) | BIT(19);
		break;
	}

	return wdata;
}

static void *
cn10k_sso_init_hws_mem(void *arg, uint8_t port_id)
{
	struct cnxk_sso_evdev *dev = arg;
	struct cn10k_sso_hws *ws;

	/* Allocate event port memory */
	ws = rte_zmalloc("cn10k_ws",
			 sizeof(struct cn10k_sso_hws) + RTE_CACHE_LINE_SIZE,
			 RTE_CACHE_LINE_SIZE);
	if (ws == NULL) {
		plt_err("Failed to alloc memory for port=%d", port_id);
		return NULL;
	}

	/* First cache line is reserved for cookie */
	ws = (struct cn10k_sso_hws *)((uint8_t *)ws + RTE_CACHE_LINE_SIZE);
	ws->base = roc_sso_hws_base_get(&dev->sso, port_id);
	ws->tx_base = ws->base;
	ws->hws_id = port_id;
	ws->swtag_req = 0;
	ws->gw_wdata = cn10k_sso_gw_mode_wdata(dev);
	ws->lmt_base = dev->sso.lmt_base;

	return ws;
}

static int
cn10k_sso_hws_link(void *arg, void *port, uint16_t *map, uint16_t nb_link)
{
	struct cnxk_sso_evdev *dev = arg;
	struct cn10k_sso_hws *ws = port;

	return roc_sso_hws_link(&dev->sso, ws->hws_id, map, nb_link);
}

static int
cn10k_sso_hws_unlink(void *arg, void *port, uint16_t *map, uint16_t nb_link)
{
	struct cnxk_sso_evdev *dev = arg;
	struct cn10k_sso_hws *ws = port;

	return roc_sso_hws_unlink(&dev->sso, ws->hws_id, map, nb_link);
}

static void
cn10k_sso_hws_setup(void *arg, void *hws, uintptr_t *grps_base)
{
	struct cnxk_sso_evdev *dev = arg;
	struct cn10k_sso_hws *ws = hws;
	uint64_t val;

	rte_memcpy(ws->grps_base, grps_base,
		   sizeof(uintptr_t) * CNXK_SSO_MAX_HWGRP);
	ws->fc_mem = dev->fc_mem;
	ws->xaq_lmt = dev->xaq_lmt;

	/* Set get_work timeout for HWS */
	val = NSEC2USEC(dev->deq_tmo_ns) - 1;
	plt_write64(val, ws->base + SSOW_LF_GWS_NW_TIM);
}

static void
cn10k_sso_hws_release(void *arg, void *hws)
{
	struct cnxk_sso_evdev *dev = arg;
	struct cn10k_sso_hws *ws = hws;
	int i;

	for (i = 0; i < dev->nb_event_queues; i++)
		roc_sso_hws_unlink(&dev->sso, ws->hws_id, (uint16_t *)&i, 1);
	memset(ws, 0, sizeof(*ws));
}

static void
cn10k_sso_hws_flush_events(void *hws, uint8_t queue_id, uintptr_t base,
			   cnxk_handle_event_t fn, void *arg)
{
	struct cn10k_sso_hws *ws = hws;
	uint64_t cq_ds_cnt = 1;
	uint64_t aq_cnt = 1;
	uint64_t ds_cnt = 1;
	struct rte_event ev;
	uint64_t val, req;

	plt_write64(0, base + SSO_LF_GGRP_QCTL);

	req = queue_id;	    /* GGRP ID */
	req |= BIT_ULL(18); /* Grouped */
	req |= BIT_ULL(16); /* WAIT */

	aq_cnt = plt_read64(base + SSO_LF_GGRP_AQ_CNT);
	ds_cnt = plt_read64(base + SSO_LF_GGRP_MISC_CNT);
	cq_ds_cnt = plt_read64(base + SSO_LF_GGRP_INT_CNT);
	cq_ds_cnt &= 0x3FFF3FFF0000;

	while (aq_cnt || cq_ds_cnt || ds_cnt) {
		plt_write64(req, ws->base + SSOW_LF_GWS_OP_GET_WORK0);
		cn10k_sso_hws_get_work_empty(ws, &ev);
		if (fn != NULL && ev.u64 != 0)
			fn(arg, ev);
		if (ev.sched_type != SSO_TT_EMPTY)
			cnxk_sso_hws_swtag_flush(
				ws->base + SSOW_LF_GWS_WQE0,
				ws->base + SSOW_LF_GWS_OP_SWTAG_FLUSH);
		do {
			val = plt_read64(ws->base + SSOW_LF_GWS_PENDSTATE);
		} while (val & BIT_ULL(56));
		aq_cnt = plt_read64(base + SSO_LF_GGRP_AQ_CNT);
		ds_cnt = plt_read64(base + SSO_LF_GGRP_MISC_CNT);
		cq_ds_cnt = plt_read64(base + SSO_LF_GGRP_INT_CNT);
		/* Extract cq and ds count */
		cq_ds_cnt &= 0x3FFF3FFF0000;
	}

	plt_write64(0, ws->base + SSOW_LF_GWS_OP_GWC_INVAL);
	rte_mb();
}

static void
cn10k_sso_hws_reset(void *arg, void *hws)
{
	struct cnxk_sso_evdev *dev = arg;
	struct cn10k_sso_hws *ws = hws;
	uintptr_t base = ws->base;
	uint64_t pend_state;
	union {
		__uint128_t wdata;
		uint64_t u64[2];
	} gw;
	uint8_t pend_tt;

	/* Wait till getwork/swtp/waitw/desched completes. */
	do {
		pend_state = plt_read64(base + SSOW_LF_GWS_PENDSTATE);
	} while (pend_state & (BIT_ULL(63) | BIT_ULL(62) | BIT_ULL(58) |
			       BIT_ULL(56) | BIT_ULL(54)));
	pend_tt = CNXK_TT_FROM_TAG(plt_read64(base + SSOW_LF_GWS_WQE0));
	if (pend_tt != SSO_TT_EMPTY) { /* Work was pending */
		if (pend_tt == SSO_TT_ATOMIC || pend_tt == SSO_TT_ORDERED)
			cnxk_sso_hws_swtag_untag(base +
						 SSOW_LF_GWS_OP_SWTAG_UNTAG);
		plt_write64(0, base + SSOW_LF_GWS_OP_DESCHED);
	}

	/* Wait for desched to complete. */
	do {
		pend_state = plt_read64(base + SSOW_LF_GWS_PENDSTATE);
	} while (pend_state & BIT_ULL(58));

	switch (dev->gw_mode) {
	case CN10K_GW_MODE_PREF:
		while (plt_read64(base + SSOW_LF_GWS_PRF_WQE0) & BIT_ULL(63))
			;
		break;
	case CN10K_GW_MODE_PREF_WFE:
		while (plt_read64(base + SSOW_LF_GWS_PRF_WQE0) &
		       SSOW_LF_GWS_TAG_PEND_GET_WORK_BIT)
			continue;
		plt_write64(0, base + SSOW_LF_GWS_OP_GWC_INVAL);
		break;
	case CN10K_GW_MODE_NONE:
	default:
		break;
	}

	if (CNXK_TT_FROM_TAG(plt_read64(base + SSOW_LF_GWS_PRF_WQE0)) !=
	    SSO_TT_EMPTY) {
		plt_write64(BIT_ULL(16) | 1,
			    ws->base + SSOW_LF_GWS_OP_GET_WORK0);
		do {
			roc_load_pair(gw.u64[0], gw.u64[1],
				      ws->base + SSOW_LF_GWS_WQE0);
		} while (gw.u64[0] & BIT_ULL(63));
		pend_tt = CNXK_TT_FROM_TAG(plt_read64(base + SSOW_LF_GWS_WQE0));
		if (pend_tt != SSO_TT_EMPTY) { /* Work was pending */
			if (pend_tt == SSO_TT_ATOMIC ||
			    pend_tt == SSO_TT_ORDERED)
				cnxk_sso_hws_swtag_untag(
					base + SSOW_LF_GWS_OP_SWTAG_UNTAG);
			plt_write64(0, base + SSOW_LF_GWS_OP_DESCHED);
		}
	}

	plt_write64(0, base + SSOW_LF_GWS_OP_GWC_INVAL);
	rte_mb();
}

static void
cn10k_sso_set_rsrc(void *arg)
{
	struct cnxk_sso_evdev *dev = arg;

	dev->max_event_ports = dev->sso.max_hws;
	dev->max_event_queues =
		dev->sso.max_hwgrp > RTE_EVENT_MAX_QUEUES_PER_DEV ?
			      RTE_EVENT_MAX_QUEUES_PER_DEV :
			      dev->sso.max_hwgrp;
}

static int
cn10k_sso_rsrc_init(void *arg, uint8_t hws, uint8_t hwgrp)
{
	struct cnxk_sso_evdev *dev = arg;

	return roc_sso_rsrc_init(&dev->sso, hws, hwgrp);
}

static int
cn10k_sso_updt_tx_adptr_data(const struct rte_eventdev *event_dev)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	int i;

	if (dev->tx_adptr_data == NULL)
		return 0;

	for (i = 0; i < dev->nb_event_ports; i++) {
		struct cn10k_sso_hws *ws = event_dev->data->ports[i];
		void *ws_cookie;

		ws_cookie = cnxk_sso_hws_get_cookie(ws);
		ws_cookie = rte_realloc_socket(
			ws_cookie,
			sizeof(struct cnxk_sso_hws_cookie) +
				sizeof(struct cn10k_sso_hws) +
				(sizeof(uint64_t) * (dev->max_port_id + 1) *
				 RTE_MAX_QUEUES_PER_PORT),
			RTE_CACHE_LINE_SIZE, SOCKET_ID_ANY);
		if (ws_cookie == NULL)
			return -ENOMEM;
		ws = RTE_PTR_ADD(ws_cookie, sizeof(struct cnxk_sso_hws_cookie));
		memcpy(&ws->tx_adptr_data, dev->tx_adptr_data,
		       sizeof(uint64_t) * (dev->max_port_id + 1) *
			       RTE_MAX_QUEUES_PER_PORT);
		event_dev->data->ports[i] = ws;
	}

	return 0;
}

static void
cn10k_sso_fp_fns_set(struct rte_eventdev *event_dev)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	const event_dequeue_t sso_hws_deq[2][2][2][2][2][2] = {
#define R(name, f5, f4, f3, f2, f1, f0, flags)                                 \
	[f5][f4][f3][f2][f1][f0] = cn10k_sso_hws_deq_##name,
		NIX_RX_FASTPATH_MODES
#undef R
	};

	const event_dequeue_burst_t sso_hws_deq_burst[2][2][2][2][2][2] = {
#define R(name, f5, f4, f3, f2, f1, f0, flags)                                 \
	[f5][f4][f3][f2][f1][f0] = cn10k_sso_hws_deq_burst_##name,
		NIX_RX_FASTPATH_MODES
#undef R
	};

	const event_dequeue_t sso_hws_tmo_deq[2][2][2][2][2][2] = {
#define R(name, f5, f4, f3, f2, f1, f0, flags)                                 \
	[f5][f4][f3][f2][f1][f0] = cn10k_sso_hws_deq_tmo_##name,
		NIX_RX_FASTPATH_MODES
#undef R
	};

	const event_dequeue_burst_t sso_hws_tmo_deq_burst[2][2][2][2][2][2] = {
#define R(name, f5, f4, f3, f2, f1, f0, flags)                                 \
	[f5][f4][f3][f2][f1][f0] = cn10k_sso_hws_deq_tmo_burst_##name,
		NIX_RX_FASTPATH_MODES
#undef R
	};

	const event_dequeue_t sso_hws_deq_seg[2][2][2][2][2][2] = {
#define R(name, f5, f4, f3, f2, f1, f0, flags)                                 \
	[f5][f4][f3][f2][f1][f0] = cn10k_sso_hws_deq_seg_##name,
		NIX_RX_FASTPATH_MODES
#undef R
	};

	const event_dequeue_burst_t sso_hws_deq_seg_burst[2][2][2][2][2][2] = {
#define R(name, f5, f4, f3, f2, f1, f0, flags)                                 \
	[f5][f4][f3][f2][f1][f0] = cn10k_sso_hws_deq_seg_burst_##name,
		NIX_RX_FASTPATH_MODES
#undef R
	};

	const event_dequeue_t sso_hws_tmo_deq_seg[2][2][2][2][2][2] = {
#define R(name, f5, f4, f3, f2, f1, f0, flags)                                 \
	[f5][f4][f3][f2][f1][f0] = cn10k_sso_hws_deq_tmo_seg_##name,
		NIX_RX_FASTPATH_MODES
#undef R
	};

	const event_dequeue_burst_t
		sso_hws_tmo_deq_seg_burst[2][2][2][2][2][2] = {
#define R(name, f5, f4, f3, f2, f1, f0, flags)                                 \
	[f5][f4][f3][f2][f1][f0] = cn10k_sso_hws_deq_tmo_seg_burst_##name,
			NIX_RX_FASTPATH_MODES
#undef R
		};

	/* Tx modes */
	const event_tx_adapter_enqueue
		sso_hws_tx_adptr_enq[2][2][2][2][2][2] = {
#define T(name, f5, f4, f3, f2, f1, f0, sz, flags)                             \
	[f5][f4][f3][f2][f1][f0] = cn10k_sso_hws_tx_adptr_enq_##name,
			NIX_TX_FASTPATH_MODES
#undef T
		};

	const event_tx_adapter_enqueue
		sso_hws_tx_adptr_enq_seg[2][2][2][2][2][2] = {
#define T(name, f5, f4, f3, f2, f1, f0, sz, flags)                             \
	[f5][f4][f3][f2][f1][f0] = cn10k_sso_hws_tx_adptr_enq_seg_##name,
			NIX_TX_FASTPATH_MODES
#undef T
		};

	event_dev->enqueue = cn10k_sso_hws_enq;
	event_dev->enqueue_burst = cn10k_sso_hws_enq_burst;
	event_dev->enqueue_new_burst = cn10k_sso_hws_enq_new_burst;
	event_dev->enqueue_forward_burst = cn10k_sso_hws_enq_fwd_burst;
	if (dev->rx_offloads & NIX_RX_MULTI_SEG_F) {
		event_dev->dequeue = sso_hws_deq_seg
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_VLAN_STRIP_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_TSTAMP_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_MARK_UPDATE_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_CHECKSUM_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_PTYPE_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_RSS_F)];
		event_dev->dequeue_burst = sso_hws_deq_seg_burst
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_VLAN_STRIP_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_TSTAMP_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_MARK_UPDATE_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_CHECKSUM_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_PTYPE_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_RSS_F)];
		if (dev->is_timeout_deq) {
			event_dev->dequeue = sso_hws_tmo_deq_seg
				[!!(dev->rx_offloads &
				    NIX_RX_OFFLOAD_VLAN_STRIP_F)]
				[!!(dev->rx_offloads & NIX_RX_OFFLOAD_TSTAMP_F)]
				[!!(dev->rx_offloads &
				    NIX_RX_OFFLOAD_MARK_UPDATE_F)]
				[!!(dev->rx_offloads &
				    NIX_RX_OFFLOAD_CHECKSUM_F)]
				[!!(dev->rx_offloads & NIX_RX_OFFLOAD_PTYPE_F)]
				[!!(dev->rx_offloads & NIX_RX_OFFLOAD_RSS_F)];
			event_dev->dequeue_burst = sso_hws_tmo_deq_seg_burst
				[!!(dev->rx_offloads &
				    NIX_RX_OFFLOAD_VLAN_STRIP_F)]
				[!!(dev->rx_offloads & NIX_RX_OFFLOAD_TSTAMP_F)]
				[!!(dev->rx_offloads &
				    NIX_RX_OFFLOAD_MARK_UPDATE_F)]
				[!!(dev->rx_offloads &
				    NIX_RX_OFFLOAD_CHECKSUM_F)]
				[!!(dev->rx_offloads & NIX_RX_OFFLOAD_PTYPE_F)]
				[!!(dev->rx_offloads & NIX_RX_OFFLOAD_RSS_F)];
		}
	} else {
		event_dev->dequeue = sso_hws_deq
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_VLAN_STRIP_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_TSTAMP_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_MARK_UPDATE_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_CHECKSUM_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_PTYPE_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_RSS_F)];
		event_dev->dequeue_burst = sso_hws_deq_burst
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_VLAN_STRIP_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_TSTAMP_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_MARK_UPDATE_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_CHECKSUM_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_PTYPE_F)]
			[!!(dev->rx_offloads & NIX_RX_OFFLOAD_RSS_F)];
		if (dev->is_timeout_deq) {
			event_dev->dequeue = sso_hws_tmo_deq
				[!!(dev->rx_offloads &
				    NIX_RX_OFFLOAD_VLAN_STRIP_F)]
				[!!(dev->rx_offloads & NIX_RX_OFFLOAD_TSTAMP_F)]
				[!!(dev->rx_offloads &
				    NIX_RX_OFFLOAD_MARK_UPDATE_F)]
				[!!(dev->rx_offloads &
				    NIX_RX_OFFLOAD_CHECKSUM_F)]
				[!!(dev->rx_offloads & NIX_RX_OFFLOAD_PTYPE_F)]
				[!!(dev->rx_offloads & NIX_RX_OFFLOAD_RSS_F)];
			event_dev->dequeue_burst = sso_hws_tmo_deq_burst
				[!!(dev->rx_offloads &
				    NIX_RX_OFFLOAD_VLAN_STRIP_F)]
				[!!(dev->rx_offloads & NIX_RX_OFFLOAD_TSTAMP_F)]
				[!!(dev->rx_offloads &
				    NIX_RX_OFFLOAD_MARK_UPDATE_F)]
				[!!(dev->rx_offloads &
				    NIX_RX_OFFLOAD_CHECKSUM_F)]
				[!!(dev->rx_offloads & NIX_RX_OFFLOAD_PTYPE_F)]
				[!!(dev->rx_offloads & NIX_RX_OFFLOAD_RSS_F)];
		}
	}

	if (dev->tx_offloads & NIX_TX_MULTI_SEG_F) {
		/* [SEC] [TSMP] [MBUF_NOFF] [VLAN] [OL3_L4_CSUM] [L3_L4_CSUM] */
		event_dev->txa_enqueue = sso_hws_tx_adptr_enq_seg
			[!!(dev->tx_offloads & NIX_TX_OFFLOAD_TSTAMP_F)]
			[!!(dev->tx_offloads & NIX_TX_OFFLOAD_TSO_F)]
			[!!(dev->tx_offloads & NIX_TX_OFFLOAD_MBUF_NOFF_F)]
			[!!(dev->tx_offloads & NIX_TX_OFFLOAD_VLAN_QINQ_F)]
			[!!(dev->tx_offloads & NIX_TX_OFFLOAD_OL3_OL4_CSUM_F)]
			[!!(dev->tx_offloads & NIX_TX_OFFLOAD_L3_L4_CSUM_F)];
	} else {
		event_dev->txa_enqueue = sso_hws_tx_adptr_enq
			[!!(dev->tx_offloads & NIX_TX_OFFLOAD_TSTAMP_F)]
			[!!(dev->tx_offloads & NIX_TX_OFFLOAD_TSO_F)]
			[!!(dev->tx_offloads & NIX_TX_OFFLOAD_MBUF_NOFF_F)]
			[!!(dev->tx_offloads & NIX_TX_OFFLOAD_VLAN_QINQ_F)]
			[!!(dev->tx_offloads & NIX_TX_OFFLOAD_OL3_OL4_CSUM_F)]
			[!!(dev->tx_offloads & NIX_TX_OFFLOAD_L3_L4_CSUM_F)];
	}

	event_dev->txa_enqueue_same_dest = event_dev->txa_enqueue;
}

static void
cn10k_sso_info_get(struct rte_eventdev *event_dev,
		   struct rte_event_dev_info *dev_info)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);

	dev_info->driver_name = RTE_STR(EVENTDEV_NAME_CN10K_PMD);
	cnxk_sso_info_get(dev, dev_info);
}

static int
cn10k_sso_dev_configure(const struct rte_eventdev *event_dev)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	int rc;

	rc = cnxk_sso_dev_validate(event_dev);
	if (rc < 0) {
		plt_err("Invalid event device configuration");
		return -EINVAL;
	}

	roc_sso_rsrc_fini(&dev->sso);

	rc = cn10k_sso_rsrc_init(dev, dev->nb_event_ports,
				 dev->nb_event_queues);
	if (rc < 0) {
		plt_err("Failed to initialize SSO resources");
		return -ENODEV;
	}

	rc = cnxk_sso_xaq_allocate(dev);
	if (rc < 0)
		goto cnxk_rsrc_fini;

	rc = cnxk_setup_event_ports(event_dev, cn10k_sso_init_hws_mem,
				    cn10k_sso_hws_setup);
	if (rc < 0)
		goto cnxk_rsrc_fini;

	/* Restore any prior port-queue mapping. */
	cnxk_sso_restore_links(event_dev, cn10k_sso_hws_link);

	dev->configured = 1;
	rte_mb();

	return 0;
cnxk_rsrc_fini:
	roc_sso_rsrc_fini(&dev->sso);
	dev->nb_event_ports = 0;
	return rc;
}

static int
cn10k_sso_port_setup(struct rte_eventdev *event_dev, uint8_t port_id,
		     const struct rte_event_port_conf *port_conf)
{

	RTE_SET_USED(port_conf);
	return cnxk_sso_port_setup(event_dev, port_id, cn10k_sso_hws_setup);
}

static void
cn10k_sso_port_release(void *port)
{
	struct cnxk_sso_hws_cookie *gws_cookie = cnxk_sso_hws_get_cookie(port);
	struct cnxk_sso_evdev *dev;

	if (port == NULL)
		return;

	dev = cnxk_sso_pmd_priv(gws_cookie->event_dev);
	if (!gws_cookie->configured)
		goto free;

	cn10k_sso_hws_release(dev, port);
	memset(gws_cookie, 0, sizeof(*gws_cookie));
free:
	rte_free(gws_cookie);
}

static int
cn10k_sso_port_link(struct rte_eventdev *event_dev, void *port,
		    const uint8_t queues[], const uint8_t priorities[],
		    uint16_t nb_links)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	uint16_t hwgrp_ids[nb_links];
	uint16_t link;

	RTE_SET_USED(priorities);
	for (link = 0; link < nb_links; link++)
		hwgrp_ids[link] = queues[link];
	nb_links = cn10k_sso_hws_link(dev, port, hwgrp_ids, nb_links);

	return (int)nb_links;
}

static int
cn10k_sso_port_unlink(struct rte_eventdev *event_dev, void *port,
		      uint8_t queues[], uint16_t nb_unlinks)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	uint16_t hwgrp_ids[nb_unlinks];
	uint16_t unlink;

	for (unlink = 0; unlink < nb_unlinks; unlink++)
		hwgrp_ids[unlink] = queues[unlink];
	nb_unlinks = cn10k_sso_hws_unlink(dev, port, hwgrp_ids, nb_unlinks);

	return (int)nb_unlinks;
}

static int
cn10k_sso_start(struct rte_eventdev *event_dev)
{
	int rc;

	rc = cn10k_sso_updt_tx_adptr_data(event_dev);
	if (rc < 0)
		return rc;

	rc = cnxk_sso_start(event_dev, cn10k_sso_hws_reset,
			    cn10k_sso_hws_flush_events);
	if (rc < 0)
		return rc;
	cn10k_sso_fp_fns_set(event_dev);

	return rc;
}

static void
cn10k_sso_stop(struct rte_eventdev *event_dev)
{
	cnxk_sso_stop(event_dev, cn10k_sso_hws_reset,
		      cn10k_sso_hws_flush_events);
}

static int
cn10k_sso_close(struct rte_eventdev *event_dev)
{
	return cnxk_sso_close(event_dev, cn10k_sso_hws_unlink);
}

static int
cn10k_sso_selftest(void)
{
	return cnxk_sso_selftest(RTE_STR(event_cn10k));
}

static int
cn10k_sso_rx_adapter_caps_get(const struct rte_eventdev *event_dev,
			      const struct rte_eth_dev *eth_dev, uint32_t *caps)
{
	int rc;

	RTE_SET_USED(event_dev);
	rc = strncmp(eth_dev->device->driver->name, "net_cn10k", 9);
	if (rc)
		*caps = RTE_EVENT_ETH_RX_ADAPTER_SW_CAP;
	else
		*caps = RTE_EVENT_ETH_RX_ADAPTER_CAP_INTERNAL_PORT |
			RTE_EVENT_ETH_RX_ADAPTER_CAP_MULTI_EVENTQ |
			RTE_EVENT_ETH_RX_ADAPTER_CAP_OVERRIDE_FLOW_ID |
			RTE_EVENT_ETH_RX_ADAPTER_CAP_EVENT_VECTOR;

	return 0;
}

static void
cn10k_sso_set_priv_mem(const struct rte_eventdev *event_dev, void *lookup_mem,
		       void *tstmp_info)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	int i;

	for (i = 0; i < dev->nb_event_ports; i++) {
		struct cn10k_sso_hws *ws = event_dev->data->ports[i];
		ws->lookup_mem = lookup_mem;
		ws->tstamp = tstmp_info;
	}
}

static int
cn10k_sso_rx_adapter_queue_add(
	const struct rte_eventdev *event_dev, const struct rte_eth_dev *eth_dev,
	int32_t rx_queue_id,
	const struct rte_event_eth_rx_adapter_queue_conf *queue_conf)
{
	struct cn10k_eth_rxq *rxq;
	void *lookup_mem;
	void *tstmp_info;
	int rc;

	rc = strncmp(eth_dev->device->driver->name, "net_cn10k", 8);
	if (rc)
		return -EINVAL;

	rc = cnxk_sso_rx_adapter_queue_add(event_dev, eth_dev, rx_queue_id,
					   queue_conf);
	if (rc)
		return -EINVAL;
	rxq = eth_dev->data->rx_queues[0];
	lookup_mem = rxq->lookup_mem;
	tstmp_info = rxq->tstamp;
	cn10k_sso_set_priv_mem(event_dev, lookup_mem, tstmp_info);
	cn10k_sso_fp_fns_set((struct rte_eventdev *)(uintptr_t)event_dev);

	return 0;
}

static int
cn10k_sso_rx_adapter_queue_del(const struct rte_eventdev *event_dev,
			       const struct rte_eth_dev *eth_dev,
			       int32_t rx_queue_id)
{
	int rc;

	rc = strncmp(eth_dev->device->driver->name, "net_cn10k", 8);
	if (rc)
		return -EINVAL;

	return cnxk_sso_rx_adapter_queue_del(event_dev, eth_dev, rx_queue_id);
}

static int
cn10k_sso_rx_adapter_vector_limits(
	const struct rte_eventdev *dev, const struct rte_eth_dev *eth_dev,
	struct rte_event_eth_rx_adapter_vector_limits *limits)
{
	struct cnxk_eth_dev *cnxk_eth_dev;
	int ret;

	RTE_SET_USED(dev);
	ret = strncmp(eth_dev->device->driver->name, "net_cn10k", 8);
	if (ret)
		return -ENOTSUP;

	cnxk_eth_dev = cnxk_eth_pmd_priv(eth_dev);
	limits->log2_sz = true;
	limits->min_sz = 1 << ROC_NIX_VWQE_MIN_SIZE_LOG2;
	limits->max_sz = 1 << ROC_NIX_VWQE_MAX_SIZE_LOG2;
	limits->min_timeout_ns =
		(roc_nix_get_vwqe_interval(&cnxk_eth_dev->nix) + 1) * 100;
	limits->max_timeout_ns = BITMASK_ULL(8, 0) * limits->min_timeout_ns;

	return 0;
}

static int
cnxk_sso_rx_adapter_vwqe_enable(struct cnxk_eth_dev *cnxk_eth_dev,
				uint16_t port_id, uint16_t rq_id, uint16_t sz,
				uint64_t tmo_ns, struct rte_mempool *vmp)
{
	struct roc_nix_rq *rq;

	rq = &cnxk_eth_dev->rqs[rq_id];

	if (!rq->sso_ena)
		return -EINVAL;
	if (rq->flow_tag_width == 0)
		return -EINVAL;

	rq->vwqe_ena = 1;
	rq->vwqe_first_skip = 0;
	rq->vwqe_aura_handle = roc_npa_aura_handle_to_aura(vmp->pool_id);
	rq->vwqe_max_sz_exp = rte_log2_u32(sz);
	rq->vwqe_wait_tmo =
		tmo_ns /
		((roc_nix_get_vwqe_interval(&cnxk_eth_dev->nix) + 1) * 100);
	rq->tag_mask = (port_id & 0xF) << 20;
	rq->tag_mask |=
		(((port_id >> 4) & 0xF) | (RTE_EVENT_TYPE_ETHDEV_VECTOR << 4))
		<< 24;

	return roc_nix_rq_modify(&cnxk_eth_dev->nix, rq, 0);
}

static int
cn10k_sso_rx_adapter_vector_config(
	const struct rte_eventdev *event_dev, const struct rte_eth_dev *eth_dev,
	int32_t rx_queue_id,
	const struct rte_event_eth_rx_adapter_event_vector_config *config)
{
	struct cnxk_eth_dev *cnxk_eth_dev;
	struct cnxk_sso_evdev *dev;
	int i, rc;

	rc = strncmp(eth_dev->device->driver->name, "net_cn10k", 8);
	if (rc)
		return -EINVAL;

	dev = cnxk_sso_pmd_priv(event_dev);
	cnxk_eth_dev = cnxk_eth_pmd_priv(eth_dev);
	if (rx_queue_id < 0) {
		for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
			cnxk_sso_updt_xae_cnt(dev, config->vector_mp,
					      RTE_EVENT_TYPE_ETHDEV_VECTOR);
			rc = cnxk_sso_xae_reconfigure(
				(struct rte_eventdev *)(uintptr_t)event_dev);
			rc = cnxk_sso_rx_adapter_vwqe_enable(
				cnxk_eth_dev, eth_dev->data->port_id, i,
				config->vector_sz, config->vector_timeout_ns,
				config->vector_mp);
			if (rc)
				return -EINVAL;
		}
	} else {

		cnxk_sso_updt_xae_cnt(dev, config->vector_mp,
				      RTE_EVENT_TYPE_ETHDEV_VECTOR);
		rc = cnxk_sso_xae_reconfigure(
			(struct rte_eventdev *)(uintptr_t)event_dev);
		rc = cnxk_sso_rx_adapter_vwqe_enable(
			cnxk_eth_dev, eth_dev->data->port_id, rx_queue_id,
			config->vector_sz, config->vector_timeout_ns,
			config->vector_mp);
		if (rc)
			return -EINVAL;
	}

	return 0;
}

static int
cn10k_sso_tx_adapter_caps_get(const struct rte_eventdev *dev,
			      const struct rte_eth_dev *eth_dev, uint32_t *caps)
{
	int ret;

	RTE_SET_USED(dev);
	ret = strncmp(eth_dev->device->driver->name, "net_cn10k", 8);
	if (ret)
		*caps = 0;
	else
		*caps = RTE_EVENT_ETH_TX_ADAPTER_CAP_INTERNAL_PORT |
			RTE_EVENT_ETH_TX_ADAPTER_CAP_EVENT_VECTOR;

	return 0;
}

static int
cn10k_sso_tx_adapter_queue_add(uint8_t id, const struct rte_eventdev *event_dev,
			       const struct rte_eth_dev *eth_dev,
			       int32_t tx_queue_id)
{
	int rc;

	RTE_SET_USED(id);
	rc = cnxk_sso_tx_adapter_queue_add(event_dev, eth_dev, tx_queue_id);
	if (rc < 0)
		return rc;
	rc = cn10k_sso_updt_tx_adptr_data(event_dev);
	if (rc < 0)
		return rc;
	cn10k_sso_fp_fns_set((struct rte_eventdev *)(uintptr_t)event_dev);

	return 0;
}

static int
cn10k_sso_tx_adapter_queue_del(uint8_t id, const struct rte_eventdev *event_dev,
			       const struct rte_eth_dev *eth_dev,
			       int32_t tx_queue_id)
{
	int rc;

	RTE_SET_USED(id);
	rc = cnxk_sso_tx_adapter_queue_del(event_dev, eth_dev, tx_queue_id);
	if (rc < 0)
		return rc;
	return cn10k_sso_updt_tx_adptr_data(event_dev);
}

static struct rte_eventdev_ops cn10k_sso_dev_ops = {
	.dev_infos_get = cn10k_sso_info_get,
	.dev_configure = cn10k_sso_dev_configure,
	.queue_def_conf = cnxk_sso_queue_def_conf,
	.queue_setup = cnxk_sso_queue_setup,
	.queue_release = cnxk_sso_queue_release,
	.port_def_conf = cnxk_sso_port_def_conf,
	.port_setup = cn10k_sso_port_setup,
	.port_release = cn10k_sso_port_release,
	.port_link = cn10k_sso_port_link,
	.port_unlink = cn10k_sso_port_unlink,
	.timeout_ticks = cnxk_sso_timeout_ticks,

	.eth_rx_adapter_caps_get = cn10k_sso_rx_adapter_caps_get,
	.eth_rx_adapter_queue_add = cn10k_sso_rx_adapter_queue_add,
	.eth_rx_adapter_queue_del = cn10k_sso_rx_adapter_queue_del,
	.eth_rx_adapter_start = cnxk_sso_rx_adapter_start,
	.eth_rx_adapter_stop = cnxk_sso_rx_adapter_stop,

	.eth_rx_adapter_vector_limits_get = cn10k_sso_rx_adapter_vector_limits,
	.eth_rx_adapter_event_vector_config =
		cn10k_sso_rx_adapter_vector_config,

	.eth_tx_adapter_caps_get = cn10k_sso_tx_adapter_caps_get,
	.eth_tx_adapter_queue_add = cn10k_sso_tx_adapter_queue_add,
	.eth_tx_adapter_queue_del = cn10k_sso_tx_adapter_queue_del,

	.timer_adapter_caps_get = cnxk_tim_caps_get,

	.dump = cnxk_sso_dump,
	.dev_start = cn10k_sso_start,
	.dev_stop = cn10k_sso_stop,
	.dev_close = cn10k_sso_close,
	.dev_selftest = cn10k_sso_selftest,
};

static int
cn10k_sso_init(struct rte_eventdev *event_dev)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	int rc;

	if (RTE_CACHE_LINE_SIZE != 64) {
		plt_err("Driver not compiled for CN9K");
		return -EFAULT;
	}

	rc = roc_plt_init();
	if (rc < 0) {
		plt_err("Failed to initialize platform model");
		return rc;
	}

	event_dev->dev_ops = &cn10k_sso_dev_ops;
	/* For secondary processes, the primary has done all the work */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		cn10k_sso_fp_fns_set(event_dev);
		return 0;
	}

	rc = cnxk_sso_init(event_dev);
	if (rc < 0)
		return rc;

	cn10k_sso_set_rsrc(cnxk_sso_pmd_priv(event_dev));
	if (!dev->max_event_ports || !dev->max_event_queues) {
		plt_err("Not enough eventdev resource queues=%d ports=%d",
			dev->max_event_queues, dev->max_event_ports);
		cnxk_sso_fini(event_dev);
		return -ENODEV;
	}

	plt_sso_dbg("Initializing %s max_queues=%d max_ports=%d",
		    event_dev->data->name, dev->max_event_queues,
		    dev->max_event_ports);

	return 0;
}

static int
cn10k_sso_probe(struct rte_pci_driver *pci_drv, struct rte_pci_device *pci_dev)
{
	return rte_event_pmd_pci_probe(pci_drv, pci_dev,
				       sizeof(struct cnxk_sso_evdev),
				       cn10k_sso_init);
}

static const struct rte_pci_id cn10k_pci_sso_map[] = {
	CNXK_PCI_ID(PCI_SUBSYSTEM_DEVID_CN10KA, PCI_DEVID_CNXK_RVU_SSO_TIM_PF),
	CNXK_PCI_ID(PCI_SUBSYSTEM_DEVID_CN10KAS, PCI_DEVID_CNXK_RVU_SSO_TIM_PF),
	CNXK_PCI_ID(PCI_SUBSYSTEM_DEVID_CN10KA, PCI_DEVID_CNXK_RVU_SSO_TIM_VF),
	CNXK_PCI_ID(PCI_SUBSYSTEM_DEVID_CN10KAS, PCI_DEVID_CNXK_RVU_SSO_TIM_VF),
	{
		.vendor_id = 0,
	},
};

static struct rte_pci_driver cn10k_pci_sso = {
	.id_table = cn10k_pci_sso_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_NEED_IOVA_AS_VA,
	.probe = cn10k_sso_probe,
	.remove = cnxk_sso_remove,
};

RTE_PMD_REGISTER_PCI(event_cn10k, cn10k_pci_sso);
RTE_PMD_REGISTER_PCI_TABLE(event_cn10k, cn10k_pci_sso_map);
RTE_PMD_REGISTER_KMOD_DEP(event_cn10k, "vfio-pci");
RTE_PMD_REGISTER_PARAM_STRING(event_cn10k, CNXK_SSO_XAE_CNT "=<int>"
			      CNXK_SSO_GGRP_QOS "=<string>"
			      CNXK_SSO_FORCE_BP "=1"
			      CN10K_SSO_GW_MODE "=<int>"
			      CNXK_TIM_DISABLE_NPA "=1"
			      CNXK_TIM_CHNK_SLOTS "=<int>"
			      CNXK_TIM_RINGS_LMT "=<int>"
			      CNXK_TIM_STATS_ENA "=1");
