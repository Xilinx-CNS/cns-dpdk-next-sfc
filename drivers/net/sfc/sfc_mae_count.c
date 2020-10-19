/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2020 Xilinx, Inc.
 */

#include <rte_common.h>
#include <rte_spinlock.h>
#include <rte_service_component.h>

#include "efx.h"

#include "sfc_ev.h"
#include "sfc.h"
#include "sfc_rx.h"
#include "sfc_mae_count.h"
#include "sfc_rx.h"
#include "sfc_service.h"

int
sfc_mae_counter_add(struct sfc_adapter *sa,
		    struct sfc_mae_counter_id *counterp)
{
	struct sfc_mae_counter_registry *reg = &sa->mae.counter_registry;
	struct sfc_mae_counters *counters = &reg->counters;
	struct sfc_mae_counter *p;
	efx_counter_t mae_counter;
	int rc;

	rc = efx_mae_counters_alloc(sa->nic, 1, &mae_counter, NULL);
	if (rc != 0)
		goto fail_mae_counter_alloc;

	if (mae_counter.id >= counters->n_mae_counters) {
		/*
		 * ID of a counter is expected to be within the range
		 * between 0 and the maximum count of counters to always
		 * fit into a pre-allocated array size of maximum counter ID.
		 */
		sfc_err(sa, "MAE counter ID is out of expected range");
		rc = EFAULT;
		goto fail_counter_id_range;
	}

	counterp->mae_id = mae_counter;

	p = &counters->mae_counters[mae_counter.id];
	rte_spinlock_lock(&counters->lock);

	p->hits = 0;
	p->bytes = 0;

	rte_spinlock_unlock(&counters->lock);

	return 0;

fail_counter_id_range:
	(void)efx_mae_counters_free(sa->nic, 1, &mae_counter, NULL);

fail_mae_counter_alloc:
	return rc;
}

int
sfc_mae_counter_del(struct sfc_adapter *sa,
		    const struct sfc_mae_counter_id *counter)
{
	if (counter->mae_id.id == EFX_MAE_RSRC_ID_INVALID)
		return 0;

	return efx_mae_counters_free(sa->nic, 1, &counter->mae_id, NULL);
}

static void
sfc_mae_counter_increment(struct sfc_mae_counters *counters,
			  uint32_t mae_counter_id, uint64_t hits,
			  uint64_t bytes)
{
	struct sfc_mae_counter *p = &counters->mae_counters[mae_counter_id];

	rte_spinlock_lock(&counters->lock);

	p->hits += hits;
	p->bytes += bytes;

	rte_spinlock_unlock(&counters->lock);
}

/*
 * FIXME, ticket CT-8024: use layout defined by a generated header when
 * available.
 * All fields are in little endian.
 */
struct counter_packet_header {
	uint8_t version;
	uint8_t identifier;
	uint8_t header_offset;
	uint8_t payload_offset;
} __rte_packed;

/*
 * FIXME, ticket CT-8024: use layout defined by a generated header when
 * available.
 * All fields are in little endian.
 */
struct counter_packet_header_data {
	uint16_t sequence_index;
	uint16_t counter_count;
	uint32_t reserved[3];
} __rte_packed;

/*
 * FIXME, ticket CT-8024: use layout defined by a generated header when
 * available.
 * All fields are in little endian.
 */
struct counter_packet_entry {
	uint32_t counter_index;
	uint8_t packet_count[6];
	uint8_t byte_count[6];
} __rte_packed;

static uint64_t
sfc_mae_counter_entry_get_packets(const uint8_t *ptr)
{
	uint64_t val_le = 0;

	rte_memcpy(&val_le,
		   ptr + offsetof(struct counter_packet_entry, packet_count),
		   RTE_SIZEOF_FIELD(struct counter_packet_entry, packet_count));

	return rte_le_to_cpu_64(val_le);
}

static uint64_t
sfc_mae_counter_entry_get_bytes(const uint8_t *ptr)
{
	uint64_t val_le = 0;

	rte_memcpy(&val_le,
		   ptr + offsetof(struct counter_packet_entry, byte_count),
		   RTE_SIZEOF_FIELD(struct counter_packet_entry, byte_count));

	return rte_le_to_cpu_64(val_le);
}

static uint32_t
sfc_mae_counter_entry_get_index(const uint8_t *ptr)
{
	/*
	 * Index is properly aligned since entry size, header and
	 * the start of the packet is cacheline aligned.
	 */
	return rte_le_to_cpu_32(*(const uint32_t *)ptr);
}

static void
sfc_mae_update_counter(struct sfc_mae_counter_registry *counter_registry,
		       const uint8_t *entry)
{
	sfc_mae_counter_increment(&counter_registry->counters,
				  sfc_mae_counter_entry_get_index(entry),
				  sfc_mae_counter_entry_get_packets(entry),
				  sfc_mae_counter_entry_get_bytes(entry));
}

static void
sfc_mae_parse_counter_packet(struct sfc_mae_counter_registry *counter_registry,
			     const struct rte_mbuf *m)
{
	struct counter_packet_header *hdr;
	struct counter_packet_header_data hdr_data;
	unsigned int entry_idx;
	unsigned int offset;

#if 1
	if (rte_log_get_level(sfc_logtype_driver) == RTE_LOG_DEBUG)
		rte_pktmbuf_dump(stderr, m, 1000);
#endif

	if (unlikely(m->nb_segs != 1 || m->data_len < sizeof(*hdr))) {
		SFC_GENERIC_LOG(DEBUG, "Invalid counter");
		return;
	}

	hdr = rte_pktmbuf_mtod(m, struct counter_packet_header *);

	rte_memcpy(&hdr_data,
		   rte_pktmbuf_mtod(m, uint8_t *) + hdr->header_offset,
		   sizeof(hdr_data));

	for (offset = hdr->payload_offset, entry_idx = 0;
	     m->data_len - offset >= sizeof(struct counter_packet_entry) &&
	     entry_idx < rte_le_to_cpu_16(hdr_data.counter_count);
	     offset += sizeof(struct counter_packet_entry), entry_idx++) {
		sfc_mae_update_counter(counter_registry,
				       rte_pktmbuf_mtod(m, uint8_t *) + offset);
	}
}

static int32_t
sfc_mae_counter_routine(void *arg)
{
	struct sfc_adapter *sa = arg;
	struct sfc_mae_counter_registry *counter_registry =
		&sa->mae.counter_registry;
	struct rte_mbuf *mbufs[SFC_MAE_COUNT_RX_BURST];
	unsigned int pushed_diff;
	unsigned int pushed;
	unsigned int i;
	uint16_t n;
	int rc;

	n = counter_registry->rx_pkt_burst(counter_registry->rx_dp, mbufs,
					   SFC_MAE_COUNT_RX_BURST);
	for (i = 0; i < n; i++) {
		sfc_mae_parse_counter_packet(counter_registry, mbufs[i]);
		rte_pktmbuf_free(mbufs[i]);
	}

	if (!counter_registry->use_credits)
		return 0;

	pushed = sfc_rx_get_pushed(sa, counter_registry->rx_dp);
	pushed_diff = pushed - counter_registry->pushed_buffers;

	if (pushed_diff >= SFC_CNT_RXQ_REFILL_LEVEL) {
		rc = efx_mae_counters_stream_give_credits(sa->nic, pushed_diff);
		if (rc == 0)
			counter_registry->pushed_buffers = pushed;
		else
			SFC_GENERIC_LOG(DEBUG, "Give credits failed %d", rc);
	}

	return 0;
}

static void
sfc_mae_counter_service_unregister(struct sfc_adapter *sa)
{
	struct sfc_mae_counter_registry *registry =
		&sa->mae.counter_registry;
	const unsigned int wait_ms = 10000;
	unsigned int i;

	rte_service_runstate_set(registry->service_id, 0);
	rte_service_component_runstate_set(registry->service_id, 0);

	/*
	 * Wait for the counter routine to finish the last iteration.
	 * Give up on timeout.
	 */
	for (i = 0; i < wait_ms; i++) {
		if (rte_service_may_be_active(registry->service_id) == 0)
			break;

		rte_delay_ms(1);
	}

	rte_service_map_lcore_set(registry->service_id,
				  registry->service_core_id, 0);

	rte_service_component_unregister(registry->service_id);
}

static struct sfc_rxq_info *
sfc_cnt_rxq_info_get(struct sfc_adapter *sa)
{
	return &sfc_sa2shared(sa)->rxq_info[sa->cnt_rxq.rxq_index];
}

static int
sfc_mae_counter_service_register(struct sfc_adapter *sa,
				 uint32_t counter_stream_flags)
{
	struct rte_service_spec service;
	char counter_service_name[sizeof(service.name)] = "counter_sevice";
	struct sfc_mae_counter_registry *counter_registry =
		&sa->mae.counter_registry;
	const char *ser = "MAE counter service";
	uint32_t cid;
	uint32_t sid;
	int rc;

	/* Prepare service info */
	memset(&service, 0, sizeof(service));
	strlcpy(service.name, counter_service_name, sizeof(service.name));
	service.socket_id = sa->socket_id;
	service.callback = sfc_mae_counter_routine;
	service.callback_userdata = sa;
	counter_registry->rx_pkt_burst = sa->eth_dev->rx_pkt_burst;
	counter_registry->rx_dp = sfc_cnt_rxq_info_get(sa)->dp;
	counter_registry->pushed_buffers = 0;
	counter_registry->use_credits = counter_stream_flags &
		EFX_MAE_COUNTERS_STREAM_OUT_USES_CREDITS;

	cid = sfc_get_service_lcore(sa->socket_id);
	if (cid == RTE_MAX_LCORE && sa->socket_id != SOCKET_ID_ANY) {
		/* Warn and try to allocate on any NUMA node */
		sfc_warn(sa,
			"Failed to get service lcore for %s at socket %d",
			ser, sa->socket_id);

		cid = sfc_get_service_lcore(SOCKET_ID_ANY);
	}
	if (cid == RTE_MAX_LCORE) {
		rc = ENOTSUP;
		sfc_err(sa, "Failed to get service lcore for %s", ser);
		goto fail_get_service_lcore;
	}

	/* Service core may be in "stopped" state, start it */
	rc = rte_service_lcore_start(cid);
	if (rc != 0 && rc != -EALREADY) {
		rc = ENOTSUP;
		sfc_err(sa, "Failed to start service core for %s", ser);
		goto fail_start_core;
	}

	/* Register counter service */
	rc = rte_service_component_register(&service, &sid);
	if (rc != 0) {
		rc = ENOEXEC;
		sfc_err(sa, "Failed to register %s component", ser);
		goto fail_register;
	}

	/* Map the service with the service core */
	rc = rte_service_map_lcore_set(sid, cid, 1);
	if (rc != 0) {
		rc = -rc;
		sfc_err(sa, "Failed to map lcore for %s", ser);
		goto fail_map_lcore;
	}

	/* Run the service */
	rc = rte_service_component_runstate_set(sid, 1);
	if (rc < 0) {
		rc = -rc;
		sfc_err(sa, "Failed to run %s component", ser);
		goto fail_component_runstate_set;
	}
	rc = rte_service_runstate_set(sid, 1);
	if (rc < 0) {
		rc = -rc;
		sfc_err(sa, "Failed to run %s", ser);
		goto fail_runstate_set;
	}

	counter_registry->service_core_id = cid;
	counter_registry->service_id = sid;

	return 0;

fail_runstate_set:
	rte_service_component_runstate_set(sid, 0);

fail_component_runstate_set:
	rte_service_map_lcore_set(sid, cid, 0);

fail_map_lcore:
	rte_service_component_unregister(sid);

fail_register:
fail_start_core:
fail_get_service_lcore:
	sfc_log_init(sa, "failed %d", rc);

	return rc;
}

int
sfc_mae_counters_init(struct sfc_mae_counters *counters,
		      uint32_t nb_counters_max)
{
	rte_spinlock_init(&counters->lock);

	counters->mae_counters = rte_zmalloc("sfc_mae_counters",
		sizeof(*counters->mae_counters) * nb_counters_max, 0);
	if (counters->mae_counters == NULL)
		return ENOMEM;

	counters->n_mae_counters = nb_counters_max;

	return 0;
}

void
sfc_mae_counters_fini(struct sfc_mae_counters *counters)
{
	rte_free(counters->mae_counters);
}

int
sfc_mae_count_rxq_attach(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;
	unsigned int n_elements;
	unsigned int cache_size;
	/* The mempool is internal and private area is not required */
	const uint16_t priv_size = 0;
	const uint16_t data_room_size = RTE_PKTMBUF_HEADROOM +
		SFC_MAE_COUNT_STREAM_PACKET_SIZE;
	int rc;

	sfc_log_init(sa, "entry");

	if (!sas->cnt_rxq_supported)
		return 0;

	/*
	 * At least one element in the ring is always unused to distinguish
	 * between empty and full ring cases.
	 */
	n_elements = SFC_CNT_RXQ_RX_DESC_COUNT - 1;

	/*
	 * The cache must have sufficient space to put received buckets
	 * before they're reused on refill.
	 */
	cache_size = rte_align32pow2(SFC_CNT_RXQ_REFILL_LEVEL +
				     SFC_MAE_COUNT_RX_BURST - 1);

	if (snprintf(name, sizeof(name), "cnt_rxq-pool-%u", sas->port_id) >=
	    (int)sizeof(name))
		return ENAMETOOLONG;

	/*
	 * It could be single-producer single-consumer ring mempool which
	 * requires minimal barriers. However, cache size and refill/burst
	 * policy are aligned, therefore it does not matter which
	 * mempool backend is chosen since backend is unused in fact.
	 */
	mp = rte_pktmbuf_pool_create(name, n_elements, cache_size,
				     priv_size, data_room_size, sa->socket_id);
	if (mp == NULL) {
		rc = rte_errno;
		goto fail_mp_create;
	}

	sa->cnt_rxq.rxq_index = sfc_cnt_rxq_sw_index(sas);
	sa->cnt_rxq.mp = mp;
	sa->cnt_rxq.state |= SFC_CNT_RXQ_ATTACHED;

	return 0;

fail_mp_create:
	sfc_log_init(sa, "failed %d", rc);

	return rc;
}

void
sfc_mae_count_rxq_detach(struct sfc_adapter *sa)
{
	sfc_log_init(sa, "entry");

	if ((sa->cnt_rxq.state & SFC_CNT_RXQ_ATTACHED) == 0)
		return;

	rte_mempool_free(sa->cnt_rxq.mp);
	sa->cnt_rxq.mp = NULL;
	sa->cnt_rxq.state &= ~SFC_CNT_RXQ_ATTACHED;
}

int
sfc_mae_count_rxq_init(struct sfc_adapter *sa)
{
	struct rte_eth_rxconf rxconf = {
		.rx_free_thresh = SFC_CNT_RXQ_REFILL_LEVEL,
		.rx_drop_en = 1,
	};
	uint16_t nb_rx_desc = SFC_CNT_RXQ_RX_DESC_COUNT;
	int rc;

	sfc_log_init(sa, "entry");

	if ((sa->cnt_rxq.state & SFC_CNT_RXQ_ATTACHED) == 0)
		return 0;

	nb_rx_desc = RTE_MIN(nb_rx_desc, sa->rxq_max_entries);
	nb_rx_desc = RTE_MAX(nb_rx_desc, sa->rxq_min_entries);

	rc = sfc_rx_qinit_info(sa, sa->cnt_rxq.rxq_index, 0);
	if (rc != 0)
		goto fail_cnt_rxq_init_info;

	rc = sfc_rx_qinit(sa, sa->cnt_rxq.rxq_index, nb_rx_desc,
			  sa->socket_id, &rxconf, sa->cnt_rxq.mp);
	if (rc != 0)
		goto fail_cnt_rxq_init;

	sa->cnt_rxq.state |= SFC_CNT_RXQ_INITIALIZED;

	return 0;

fail_cnt_rxq_init:
fail_cnt_rxq_init_info:
	sfc_log_init(sa, "failed %d", rc);

	return rc;
}

void
sfc_mae_count_rxq_fini(struct sfc_adapter *sa)
{
	sfc_log_init(sa, "entry");

	if ((sa->cnt_rxq.state & SFC_CNT_RXQ_INITIALIZED) == 0)
		return;

	sfc_rx_qfini(sa, sa->cnt_rxq.rxq_index);
}

void
sfc_mae_count_stop(struct sfc_adapter *sa)
{
	struct sfc_mae *mae = &sa->mae;

	sfc_log_init(sa, "entry");

	if (!mae->cnt_rxq_running)
		return;

	sfc_mae_counter_service_unregister(sa);
	efx_mae_counters_stream_stop(sa->nic, sa->cnt_rxq.rxq_index, NULL);

	mae->cnt_rxq_running = false;
}

int
sfc_mae_count_start(struct sfc_adapter *sa)
{
	struct sfc_mae *mae = &sa->mae;
	uint32_t flags;
	int rc;

	SFC_ASSERT(sa->cnt_rxq.state & SFC_CNT_RXQ_ATTACHED);

	if (mae->cnt_rxq_running)
		return 0;

	sfc_log_init(sa, "entry");

	rc = efx_mae_counters_stream_start(sa->nic, sa->cnt_rxq.rxq_index,
					   SFC_MAE_COUNT_STREAM_PACKET_SIZE,
					   0 /* No flags required */, &flags);
	if (rc != 0) {
		sfc_err(sa, "Failed to start MAE counters stream");
		goto fail_counter_stream;
	}

	sfc_log_init(sa, "Stream start flags: 0x%x", flags);

	rc = sfc_mae_counter_service_register(sa, flags);
	if (rc != 0)
		goto fail_service_register;

	mae->cnt_rxq_running = true;

	return 0;

fail_service_register:
	efx_mae_counters_stream_stop(sa->nic, sa->cnt_rxq.rxq_index, NULL /* FIXME */);

fail_counter_stream:
	sfc_log_init(sa, "failed %d", rc);

	return rc;
}

int
sfc_mae_counter_get(struct sfc_mae_counters *counters,
		    const struct sfc_mae_counter_id *counter,
		    struct rte_flow_query_count *data)
{
	struct sfc_mae_counter *p;

	p = &counters->mae_counters[counter->mae_id.id];

	rte_spinlock_lock(&counters->lock);

	data->hits_set = 1;
	data->bytes_set = 1;
	data->hits = p->hits;
	data->bytes = p->bytes;
	if (data->reset != 0) {
		p->hits = 0;
		p->bytes = 0;
	}

	rte_spinlock_unlock(&counters->lock);

	return 0;
}
