/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2020 Xilinx, Inc.
 */

#include <rte_common.h>
#include <rte_service_component.h>

#include "efx.h"

#include "sfc_ev.h"
#include "sfc.h"
#include "sfc_rx.h"
#include "sfc_mae_counter.h"
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
	uint32_t generation_count;
	uint32_t unused;
	int rc;

	/*
	 * The actual count of counters allocated is ignored since a failure
	 * to allocate a single counter is indicated by non-zero return code.
	 */
	rc = efx_mae_counters_alloc(sa->nic, 1, &unused, &mae_counter,
				    &generation_count);
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

	/*
	 * Ordering is relaxed since it is the only operation on counter value.
	 * And it does not depend on different stores/loads in other threads.
	 * Paired with relaxed ordering in counter increment.
	 */
	__atomic_store(&p->reset.pkts_bytes.int128,
		       &p->value.pkts_bytes.int128, __ATOMIC_RELAXED);
	p->generation_count = generation_count;

	/*
	 * The flag is set at the very end of add operation and reset
	 * at the beginning of delete operation. Release ordering is
	 * paired with acquire ordering on load in counter increment operation.
	 */
	__atomic_store_n(&p->inuse, true, __ATOMIC_RELEASE);

	return 0;

fail_counter_id_range:
	(void)efx_mae_counters_free(sa->nic, 1, &unused, &mae_counter, NULL);

fail_mae_counter_alloc:
	sfc_log_init(sa, "failed: %s", rte_strerror(rc));
	return rc;
}

int
sfc_mae_counter_del(struct sfc_adapter *sa,
		    const struct sfc_mae_counter_id *counter)
{
	struct sfc_mae_counter_registry *reg = &sa->mae.counter_registry;
	struct sfc_mae_counters *counters = &reg->counters;
	struct sfc_mae_counter *p;
	uint32_t unused;
	int rc;

	if (counter->mae_id.id == EFX_MAE_RSRC_ID_INVALID)
		return 0;

	SFC_ASSERT(counter->mae_id.id < counters->n_mae_counters);
	/*
	 * The flag is set at the very end of add operation and reset
	 * at the beginning of delete operation. Release ordering is
	 * paired with acquire ordering on load in counter increment operation.
	 */
	p = &counters->mae_counters[counter->mae_id.id];
	__atomic_store_n(&p->inuse, false, __ATOMIC_RELEASE);

	rc = efx_mae_counters_free(sa->nic, 1, &unused, &counter->mae_id, NULL);
	if (rc != 0)
		sfc_err(sa, "counters free failed: %s", rte_strerror(rc));

	return rc;
}

static void
sfc_mae_counter_increment(struct sfc_mae_counters *counters,
			  uint32_t mae_counter_id,
			  uint32_t generation_count,
			  uint64_t pkts, uint64_t bytes)
{
	struct sfc_mae_counter *p = &counters->mae_counters[mae_counter_id];
	struct sfc_mae_counters_xstats *xstats = &counters->xstats;
	union sfc_pkts_bytes cnt_val;
	bool inuse;

	/*
	 * Acquire ordering is paired with release ordering in counter add
	 * and delete operations.
	 */
	__atomic_load(&p->inuse, &inuse, __ATOMIC_ACQUIRE);
	if (!inuse) {
		/*
		 * Two possible cases include:
		 * 1) Counter is just allocated. Too early counter update
		 *    cannot be processed properly.
		 * 2) Stale update of freed and not reallocated counter.
		 *    There is no point in processing that update.
		 */
		xstats->not_inuse_update++;
		return;
	}

	if (unlikely(generation_count < p->generation_count)) {
		/*
		 * It is a stale update for the reallocated counter
		 * (i.e., freed and the same ID allocated again).
		 */
		xstats->realloc_update++;
		return;
	}

	cnt_val.pkts = p->value.pkts + pkts;
	cnt_val.bytes = p->value.bytes + bytes;

	/*
	 * Ordering is relaxed since it is the only operation on counter value.
	 * And it does not depend on different stores/loads in other threads.
	 * Paired with relaxed ordering on counter reset.
	 */
	__atomic_store(&p->value.pkts_bytes,
		       &cnt_val.pkts_bytes, __ATOMIC_RELAXED);
}

/*
 * FIXME, CT-8024: use layout defined by a generated header when
 * available.
 * All fields are in little endian.
 */
struct counter_packet_header {
	uint8_t version;
	uint8_t identifier;
	uint8_t header_offset;
	uint8_t payload_offset;
};

/*
 * FIXME, CT-8024: use layout defined by a generated header when
 * available.
 * All fields are in little endian.
 */
struct counter_packet_header_data {
	uint16_t sequence_index;
	uint16_t counter_count;
	uint32_t reserved[3];
};

/*
 * FIXME, CT-8024: use layout defined by a generated header when
 * available.
 * All fields are in little endian.
 */
struct counter_packet_entry {
	uint32_t counter_index;
	uint8_t packet_count[6];
	uint8_t byte_count[6];
};

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
		       uint32_t generation_count,
		       const uint8_t *entry)
{
	sfc_mae_counter_increment(&counter_registry->counters,
				  sfc_mae_counter_entry_get_index(entry),
				  generation_count,
				  sfc_mae_counter_entry_get_packets(entry),
				  sfc_mae_counter_entry_get_bytes(entry));
}

static void
sfc_mae_parse_counter_packet(struct sfc_mae_counter_registry *counter_registry,
			     const struct rte_mbuf *m)
{
	struct counter_packet_header *hdr;
	struct counter_packet_header_data hdr_data;
	unsigned int counter_count;
	unsigned int entry_idx;
	unsigned int offset;

	RTE_BUILD_BUG_ON(sizeof(struct counter_packet_header) != 4);
	RTE_BUILD_BUG_ON(sizeof(struct counter_packet_header_data) != 16);
	RTE_BUILD_BUG_ON(sizeof(struct counter_packet_entry) != 16);

	if (unlikely(m->nb_segs != 1 || m->data_len < sizeof(*hdr))) {
		SFC_GENERIC_LOG(DEBUG, "Invalid counter");
		return;
	}

	hdr = rte_pktmbuf_mtod(m, struct counter_packet_header *);

	rte_memcpy(&hdr_data,
		   rte_pktmbuf_mtod(m, uint8_t *) + hdr->header_offset,
		   sizeof(hdr_data));

	counter_count = rte_le_to_cpu_16(hdr_data.counter_count);
	for (offset = hdr->payload_offset, entry_idx = 0;
	     m->data_len - offset >= sizeof(struct counter_packet_entry) &&
	     entry_idx < counter_count;
	     offset += sizeof(struct counter_packet_entry), entry_idx++) {
		/*
		 * The generation count is located in the Rx prefix in the
		 * USER_MARK field which is written into hash.fdir.hi field
		 * of an mbuf.
		 * TODO: add reference to the documentation about USER_MARK
		 * field.
		 */
		sfc_mae_update_counter(counter_registry, m->hash.fdir.hi,
				       rte_pktmbuf_mtod(m, uint8_t *) + offset);
	}
}

static int32_t
sfc_mae_counter_routine(void *arg)
{
	struct sfc_adapter *sa = arg;
	struct sfc_mae_counter_registry *counter_registry =
		&sa->mae.counter_registry;
	struct rte_mbuf *mbufs[SFC_MAE_COUNTER_RX_BURST];
	unsigned int pushed_diff;
	unsigned int pushed;
	unsigned int i;
	uint16_t n;
	int rc;

	n = counter_registry->rx_pkt_burst(counter_registry->rx_dp, mbufs,
					   SFC_MAE_COUNTER_RX_BURST);
	for (i = 0; i < n; i++) {
		sfc_mae_parse_counter_packet(counter_registry, mbufs[i]);
		rte_pktmbuf_free(mbufs[i]);
	}

	if (!counter_registry->use_credits)
		return 0;

	pushed = sfc_rx_get_pushed(sa, counter_registry->rx_dp);
	pushed_diff = pushed - counter_registry->pushed_n_buffers;

	if (pushed_diff >= SFC_COUNTER_RXQ_REFILL_LEVEL) {
		rc = efx_mae_counters_stream_give_credits(sa->nic, pushed_diff);
		if (rc == 0) {
			counter_registry->pushed_n_buffers = pushed;
		} else {
			/*
			 * FIXME: counters might be important for the
			 * application. Handle the error in order to recover
			 * from the failure
			 */
			SFC_GENERIC_LOG(DEBUG, "Give credits failed: %s",
					rte_strerror(rc));
		}
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
	if (i == wait_ms)
		sfc_warn(sa, "failed to wait for counter service to stop");

	rte_service_map_lcore_set(registry->service_id,
				  registry->service_core_id, 0);

	rte_service_component_unregister(registry->service_id);
}

static struct sfc_rxq_info *
sfc_counter_rxq_info_get(struct sfc_adapter *sa)
{
	return &sfc_sa2shared(sa)->rxq_info[sa->counter_rxq.sw_index];
}

static int
sfc_mae_counter_service_register(struct sfc_adapter *sa,
				 uint32_t counter_stream_flags)
{
	struct rte_service_spec service;
	char counter_service_name[sizeof(service.name)] = "counter_sevice";
	struct sfc_mae_counter_registry *counter_registry =
		&sa->mae.counter_registry;
	uint32_t cid;
	uint32_t sid;
	int rc;

	sfc_log_init(sa, "entry");

	/* Prepare service info */
	memset(&service, 0, sizeof(service));
	strlcpy(service.name, counter_service_name, sizeof(service.name));
	service.socket_id = sa->socket_id;
	service.callback = sfc_mae_counter_routine;
	service.callback_userdata = sa;
	counter_registry->rx_pkt_burst = sa->eth_dev->rx_pkt_burst;
	counter_registry->rx_dp = sfc_counter_rxq_info_get(sa)->dp;
	counter_registry->pushed_n_buffers = 0;
	counter_registry->use_credits = counter_stream_flags &
		EFX_MAE_COUNTERS_STREAM_OUT_USES_CREDITS;

	cid = sfc_get_service_lcore(sa->socket_id);
	if (cid == RTE_MAX_LCORE && sa->socket_id != SOCKET_ID_ANY) {
		/* Warn and try to allocate on any NUMA node */
		sfc_warn(sa,
			"Failed to get service lcore for counter service at socket %d",
			sa->socket_id);

		cid = sfc_get_service_lcore(SOCKET_ID_ANY);
	}
	if (cid == RTE_MAX_LCORE) {
		rc = ENOTSUP;
		sfc_err(sa, "Failed to get service lcore for counter service");
		goto fail_get_service_lcore;
	}

	/* Service core may be in "stopped" state, start it */
	rc = rte_service_lcore_start(cid);
	if (rc != 0 && rc != -EALREADY) {
		rc = ENOTSUP;
		sfc_err(sa, "Failed to start service core for counter service");
		goto fail_start_core;
	}

	/* Register counter service */
	rc = rte_service_component_register(&service, &sid);
	if (rc != 0) {
		rc = ENOEXEC;
		sfc_err(sa, "Failed to register counter service component");
		goto fail_register;
	}

	/* Map the service with the service core */
	rc = rte_service_map_lcore_set(sid, cid, 1);
	if (rc != 0) {
		rc = -rc;
		sfc_err(sa, "Failed to map lcore for counter service");
		goto fail_map_lcore;
	}

	/* Run the service */
	rc = rte_service_component_runstate_set(sid, 1);
	if (rc < 0) {
		rc = -rc;
		sfc_err(sa, "Failed to run counter service component");
		goto fail_component_runstate_set;
	}
	rc = rte_service_runstate_set(sid, 1);
	if (rc < 0) {
		rc = -rc;
		sfc_err(sa, "Failed to run counter service");
		goto fail_runstate_set;
	}

	counter_registry->service_core_id = cid;
	counter_registry->service_id = sid;

	sfc_log_init(sa, "done");

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
	sfc_log_init(sa, "failed: %s", rte_strerror(rc));

	return rc;
}

int
sfc_mae_counters_init(struct sfc_mae_counters *counters,
		      uint32_t nb_counters_max)
{
	int rc;

	SFC_GENERIC_LOG(DEBUG, "%s: entry", __func__);

	counters->mae_counters = rte_zmalloc("sfc_mae_counters",
		sizeof(*counters->mae_counters) * nb_counters_max, 0);
	if (counters->mae_counters == NULL) {
		rc = ENOMEM;
		SFC_GENERIC_LOG(ERR, "%s: failed: %s", __func__,
				rte_strerror(rc));
		return rc;
	}

	counters->n_mae_counters = nb_counters_max;

	SFC_GENERIC_LOG(DEBUG, "%s: done", __func__);

	return 0;
}

void
sfc_mae_counters_fini(struct sfc_mae_counters *counters)
{
	rte_free(counters->mae_counters);
}

int
sfc_mae_counter_rxq_attach(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;
	unsigned int n_elements;
	unsigned int cache_size;
	/* The mempool is internal and private area is not required */
	const uint16_t priv_size = 0;
	const uint16_t data_room_size = RTE_PKTMBUF_HEADROOM +
		SFC_MAE_COUNTER_STREAM_PACKET_SIZE;
	int rc;

	sfc_log_init(sa, "entry");

	if (!sas->counters_rxq_allocated) {
		sfc_log_init(sa, "counter queue is not supported - skip");
		return 0;
	}

	/*
	 * At least one element in the ring is always unused to distinguish
	 * between empty and full ring cases.
	 */
	n_elements = SFC_COUNTER_RXQ_RX_DESC_COUNT - 1;

	/*
	 * The cache must have sufficient space to put received buckets
	 * before they're reused on refill.
	 */
	cache_size = rte_align32pow2(SFC_COUNTER_RXQ_REFILL_LEVEL +
				     SFC_MAE_COUNTER_RX_BURST - 1);

	if (snprintf(name, sizeof(name), "counter_rxq-pool-%u", sas->port_id) >=
	    (int)sizeof(name)) {
		sfc_err(sa, "failed: counter RxQ mempool name is too long");
		rc = ENAMETOOLONG;
		goto fail_long_name;
	}

	/*
	 * It could be single-producer single-consumer ring mempool which
	 * requires minimal barriers. However, cache size and refill/burst
	 * policy are aligned, therefore it does not matter which
	 * mempool backend is chosen since backend is unused.
	 */
	mp = rte_pktmbuf_pool_create(name, n_elements, cache_size,
				     priv_size, data_room_size, sa->socket_id);
	if (mp == NULL) {
		sfc_err(sa, "failed to create counter RxQ mempool");
		rc = rte_errno;
		goto fail_mp_create;
	}

	sa->counter_rxq.sw_index = sfc_counters_rxq_sw_index(sas);
	sa->counter_rxq.mp = mp;
	sa->counter_rxq.state |= SFC_COUNTER_RXQ_ATTACHED;

	sfc_log_init(sa, "done");

	return 0;

fail_mp_create:
fail_long_name:
	sfc_log_init(sa, "failed: %s", rte_strerror(rc));

	return rc;
}

void
sfc_mae_counter_rxq_detach(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);

	sfc_log_init(sa, "entry");

	if (!sas->counters_rxq_allocated) {
		sfc_log_init(sa, "counter queue is not supported - skip");
		return;
	}

	if ((sa->counter_rxq.state & SFC_COUNTER_RXQ_ATTACHED) == 0) {
		sfc_log_init(sa, "counter queue is not attached - skip");
		return;
	}

	rte_mempool_free(sa->counter_rxq.mp);
	sa->counter_rxq.mp = NULL;
	sa->counter_rxq.state &= ~SFC_COUNTER_RXQ_ATTACHED;

	sfc_log_init(sa, "done");
}

int
sfc_mae_counter_rxq_init(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	const struct rte_eth_rxconf rxconf = {
		.rx_free_thresh = SFC_COUNTER_RXQ_REFILL_LEVEL,
		.rx_drop_en = 1,
	};
	uint16_t nb_rx_desc = SFC_COUNTER_RXQ_RX_DESC_COUNT;
	int rc;

	sfc_log_init(sa, "entry");

	if (!sas->counters_rxq_allocated) {
		sfc_log_init(sa, "counter queue is not supported - skip");
		return 0;
	}

	if ((sa->counter_rxq.state & SFC_COUNTER_RXQ_ATTACHED) == 0) {
		sfc_log_init(sa, "counter queue is not attached - skip");
		return 0;
	}

	nb_rx_desc = RTE_MIN(nb_rx_desc, sa->rxq_max_entries);
	nb_rx_desc = RTE_MAX(nb_rx_desc, sa->rxq_min_entries);

	rc = sfc_rx_qinit_info(sa, sa->counter_rxq.sw_index,
			       EFX_RXQ_FLAG_USER_MARK);
	if (rc != 0)
		goto fail_counter_rxq_init_info;

	rc = sfc_rx_qinit(sa, sa->counter_rxq.sw_index, nb_rx_desc,
			  sa->socket_id, &rxconf, sa->counter_rxq.mp);
	if (rc != 0) {
		sfc_err(sa, "failed to init counter RxQ");
		goto fail_counter_rxq_init;
	}

	sa->counter_rxq.state |= SFC_COUNTER_RXQ_INITIALIZED;

	sfc_log_init(sa, "done");

	return 0;

fail_counter_rxq_init:
fail_counter_rxq_init_info:
	sfc_log_init(sa, "failed: %s", rte_strerror(rc));

	return rc;
}

void
sfc_mae_counter_rxq_fini(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);

	sfc_log_init(sa, "entry");

	if (!sas->counters_rxq_allocated) {
		sfc_log_init(sa, "counter queue is not supported - skip");
		return;
	}

	if ((sa->counter_rxq.state & SFC_COUNTER_RXQ_INITIALIZED) == 0) {
		sfc_log_init(sa, "counter queue is not initialized - skip");
		return;
	}

	sfc_rx_qfini(sa, sa->counter_rxq.sw_index);

	sfc_log_init(sa, "done");
}

void
sfc_mae_counter_stop(struct sfc_adapter *sa)
{
	struct sfc_mae *mae = &sa->mae;

	sfc_log_init(sa, "entry");

	if (!mae->counter_rxq_running) {
		sfc_log_init(sa, "counter queue is not running - skip");
		return;
	}

	sfc_mae_counter_service_unregister(sa);
	efx_mae_counters_stream_stop(sa->nic, sa->counter_rxq.sw_index, NULL);

	mae->counter_rxq_running = false;

	sfc_log_init(sa, "done");
}

int
sfc_mae_counter_start(struct sfc_adapter *sa)
{
	struct sfc_mae *mae = &sa->mae;
	uint32_t flags;
	int rc;

	SFC_ASSERT(sa->counter_rxq.state & SFC_COUNTER_RXQ_ATTACHED);

	if (mae->counter_rxq_running)
		return 0;

	sfc_log_init(sa, "entry");

	rc = efx_mae_counters_stream_start(sa->nic, sa->counter_rxq.sw_index,
					   SFC_MAE_COUNTER_STREAM_PACKET_SIZE,
					   0 /* No flags required */, &flags);
	if (rc != 0) {
		sfc_err(sa, "Failed to start MAE counters stream");
		goto fail_counter_stream;
	}

	sfc_log_init(sa, "stream start flags: 0x%x", flags);

	rc = sfc_mae_counter_service_register(sa, flags);
	if (rc != 0)
		goto fail_service_register;

	mae->counter_rxq_running = true;

	return 0;

fail_service_register:
	efx_mae_counters_stream_stop(sa->nic, sa->counter_rxq.sw_index, NULL);

fail_counter_stream:
	sfc_log_init(sa, "failed: %s", rte_strerror(rc));

	return rc;
}

int
sfc_mae_counter_get(struct sfc_mae_counters *counters,
		    const struct sfc_mae_counter_id *counter,
		    struct rte_flow_query_count *data)
{
	struct sfc_mae_counter *p;
	union sfc_pkts_bytes value;

	SFC_ASSERT(counter->mae_id.id < counters->n_mae_counters);
	p = &counters->mae_counters[counter->mae_id.id];

	/*
	 * Ordering is relaxed since it is the only operation on counter value.
	 * And it does not depend on different stores/loads in other threads.
	 * Paired with relaxed ordering in counter increment.
	 */
	value.pkts_bytes.int128 = __atomic_load_n(&p->value.pkts_bytes.int128,
						  __ATOMIC_RELAXED);

	data->hits_set = 1;
	data->bytes_set = 1;
	data->hits = value.pkts - p->reset.pkts;
	data->bytes = value.bytes - p->reset.bytes;

	if (data->reset != 0) {
		p->reset.pkts = value.pkts;
		p->reset.bytes = value.bytes;
	}

	return 0;
}
