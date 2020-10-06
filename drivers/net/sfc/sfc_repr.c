/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2019-2020 Xilinx, Inc.
 * Copyright(c) 2019 Solarflare Communications Inc.
 *
 * This software was jointly developed between OKTET Labs (under contract
 * for Solarflare) and Solarflare Communications, Inc.
 */

#include <stdint.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ethdev_driver.h>

#include "sfc.h"
#include "sfc_debug.h"
#include "sfc_repr.h"
#include "sfc_repr_proxy_api.h"
#include "sfc_dp_tx.h"
#include "sfc_switch.h"

/** Multi-process shared representor private data */
struct sfc_repr_shared {
	struct sfc_adapter	*pf_sa;
	uint16_t		repr_id;
	uint16_t		switch_domain_id;
	uint16_t		switch_port_id;
	struct rte_eth_stats	stats;
};

struct sfc_repr_rxq {
	/* Datapath members */
	struct rte_ring		*ring;

	/* Non-datapath members */
	struct sfc_repr_shared	*srs;
	uint16_t		queue_id;
};

struct sfc_repr_txq {
	/* Datapath members */
	struct rte_ring		*ring;
	efx_mport_id_t		egress_mport;

	/* Non-datapath members */
	struct sfc_repr_shared	*srs;
	uint16_t		queue_id;
};

/** Primary process representor private data */
struct sfc_repr {
	/**
	 * PMD setup and configuration is not thread safe. Since it is not
	 * performance sensitive, it is better to guarantee thread-safety
	 * and add device level lock. Adapter control operations which
	 * change its state should acquire the lock.
	 */
	rte_spinlock_t			lock;
	enum sfc_adapter_state		state;
};

#define sfcr_err(sr, ...) \
	do {								\
		const struct sfc_repr *_sr = (sr);			\
									\
		(void)_sr;						\
		SFC_GENERIC_LOG(ERR, __VA_ARGS__);			\
	} while (0)

#define sfcr_warn(sr, ...) \
	do {								\
		const struct sfc_repr *_sr = (sr);			\
									\
		(void)_sr;						\
		SFC_GENERIC_LOG(WARNING, __VA_ARGS__);			\
	} while (0)

#define sfcr_info(sr, ...) \
	do {								\
		const struct sfc_repr *_sr = (sr);			\
									\
		(void)_sr;						\
		SFC_GENERIC_LOG(INFO, __VA_ARGS__);			\
	} while (0)

static inline struct sfc_repr_shared *
sfc_repr_shared_by_eth_dev(struct rte_eth_dev *eth_dev)
{
	struct sfc_repr_shared *srs = eth_dev->data->dev_private;

	return srs;
}

static inline struct sfc_repr *
sfc_repr_by_eth_dev(struct rte_eth_dev *eth_dev)
{
	struct sfc_repr *sr = eth_dev->process_private;

	return sr;
}

/*
 * Add wrapper functions to acquire/release lock to be able to remove or
 * change the lock in one place.
 */

static inline void
sfc_repr_lock_init(struct sfc_repr *sr)
{
	rte_spinlock_init(&sr->lock);
}

static inline void
sfc_repr_lock(struct sfc_repr *sr)
{
	rte_spinlock_lock(&sr->lock);
}

static inline int
sfc_repr_trylock(struct sfc_repr *sr)
{
	return rte_spinlock_trylock(&sr->lock);
}

static inline void
sfc_repr_unlock(struct sfc_repr *sr)
{
	rte_spinlock_unlock(&sr->lock);
}

static inline void
sfc_repr_lock_fini(__rte_unused struct sfc_repr *sr)
{
	/* Just for symmetry of the API */
}

static uint16_t
sfc_repr_rx_burst(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct sfc_repr_rxq *rxq = rx_queue;
	void **objs = (void *)&rx_pkts[0];
	unsigned int n_bytes = 0;
	unsigned int n_rx;
	unsigned int i;

	/* mbufs port is already filled correctly by representors proxy */
	n_rx = rte_ring_sc_dequeue_burst(rxq->ring, objs, nb_pkts, NULL);

	for (i = 0; i < n_rx; i++)
		n_bytes += rx_pkts[i]->pkt_len;

	rxq->srs->stats.ipackets += n_rx;
	rxq->srs->stats.ibytes += n_bytes;

	return n_rx;
}

static uint16_t
sfc_repr_tx_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct sfc_repr_txq *txq = tx_queue;
	unsigned int n_bytes = 0;
	unsigned int n_tx;
	void **objs;
	uint16_t i;

	/*
	 * mbuf is likely cache-hot. Set flag and egress m-port here
	 * instead of doing it in representors proxy.
	 * Also it should help to avoid cache bounce.
	 * Moreoever, potentially, it allows to use one multi-producer
	 * single-consumer ring for all representors.
	 *
	 * The only potential problem is doing it many times if enqueue
	 * fails and sender retries.
	 */
	for (i = 0; i < nb_pkts; ++i) {
		struct rte_mbuf *m = tx_pkts[i];

		m->ol_flags |= sfc_dp_mport_override;
		*RTE_MBUF_DYNFIELD(m, sfc_dp_mport_offset,
				   typeof(&((efx_mport_id_t *)0)->id)) =
						txq->egress_mport.id;
		n_bytes += tx_pkts[i]->pkt_len;
	}

	objs = (void *)&tx_pkts[0];
	n_tx = rte_ring_sp_enqueue_burst(txq->ring, objs, nb_pkts, NULL);

	for (i = n_tx; i < nb_pkts; ++i)
		n_bytes -= tx_pkts[i]->pkt_len;

	txq->srs->stats.opackets += n_tx;
	txq->srs->stats.obytes += n_bytes;

	return n_tx;
}

static int
sfc_repr_start(struct rte_eth_dev *dev)
{
	struct sfc_repr *sr = sfc_repr_by_eth_dev(dev);
	struct sfc_repr_shared *srs;
	int rc;

	sfcr_info(sr, "%s() entry", __func__);

	switch (sr->state) {
	case SFC_ADAPTER_CONFIGURED:
		break;
	case SFC_ADAPTER_STARTED:
		sfcr_info(sr, "already started");
		return 0;
	default:
		rc = EINVAL;
		goto fail_bad_state;
	}

	sr->state = SFC_ADAPTER_STARTING;

	srs = sfc_repr_shared_by_eth_dev(dev);
	rc = sfc_repr_proxy_start_id(srs->pf_sa, srs->repr_id);

	if (rc == 0)
		sr->state = SFC_ADAPTER_STARTED;
	else
		sr->state = SFC_ADAPTER_CONFIGURED;

	sfcr_info(sr, "%s() done %d", __func__, rc);

fail_bad_state:
	return rc;
}

static int
sfc_repr_dev_start(struct rte_eth_dev *dev)
{
	struct sfc_repr *sr = sfc_repr_by_eth_dev(dev);
	int rc;

	sfcr_info(sr, "%s() entry", __func__);

	sfc_repr_lock(sr);
	rc = sfc_repr_start(dev);
	sfc_repr_unlock(sr);

	sfcr_info(sr, "%s() done %d", __func__, rc);
	SFC_ASSERT(rc >= 0);
	return -rc;
}

static void
sfc_repr_stop_no_lock(struct rte_eth_dev *dev)
{
	struct sfc_repr *sr = sfc_repr_by_eth_dev(dev);
	struct sfc_repr_shared *srs;

	sfcr_info(sr, "%s() entry", __func__);

	switch (sr->state) {
	case SFC_ADAPTER_STARTED:
		break;
	case SFC_ADAPTER_CONFIGURED:
		sfcr_info(sr, "already stopped");
		return;
	default:
		sfcr_err(sr, "stop in unexpected state %u", sr->state);
		SFC_ASSERT(B_FALSE);
		return;
	}

	srs = sfc_repr_shared_by_eth_dev(dev);
	sfc_repr_proxy_stop_id(srs->pf_sa, srs->repr_id);

	sr->state = SFC_ADAPTER_CONFIGURED;
	sfcr_info(sr, "%s() done", __func__);
}

static void
sfc_repr_dev_stop(struct rte_eth_dev *dev)
{
	struct sfc_repr *sr = sfc_repr_by_eth_dev(dev);

	sfcr_info(sr, "%s() entry", __func__);

	sfc_repr_lock(sr);
	sfc_repr_stop_no_lock(dev);
	sfc_repr_unlock(sr);

	sfcr_info(sr, "%s() done", __func__);
}

#if 0
static int
sfc_repr_check_conf(struct sfc_repr *sr, const struct rte_eth_conf *conf)
{
	int rc = 0;
	struct rte_eth_conf zero_conf = {0};

	if (conf->link_speeds != 0) {
		sfcr_err(sr, "Specific link speeds are not supported");
		rc = EINVAL;
	}

	if (memcmp(&conf->rxmode, &zero_conf.rxmode,
		   sizeof(conf->rxmode) != 0)) {
		sfcr_err(sr, "Rxmode not supported");
		rc = EINVAL;
	}

	if (memcmp(&conf->txmode, &zero_conf.txmode,
		   sizeof(conf->txmode) != 0)) {
		sfcr_err(sr, "Txmode not supported");
		rc = EINVAL;
	}

	if (conf->lpbk_mode != 0) {
		sfcr_err(sr, "Loopback not supported");
		rc = EINVAL;
	}

	if (memcmp(&conf->rx_adv_conf, &zero_conf.rx_adv_conf,
		   sizeof(conf->rx_adv_conf) != 0)) {
		sfcr_err(sr, "Rx advanced configuration not supported");
		rc = EINVAL;
	}

	if (conf->dcb_capability_en != 0) {
		sfcr_err(sr, "Priority-based flow control not supported");
		rc = EINVAL;
	}

	if (conf->fdir_conf.mode != RTE_FDIR_MODE_NONE) {
		sfcr_err(sr, "Flow Director not supported");
		rc = EINVAL;
	}

	if ((conf->intr_conf.lsc != 0) ) {
		sfcr_err(sr, "Link status change interrupt not supported");
		rc = EINVAL;
	}

	if (conf->intr_conf.rxq != 0) {
		sfcr_err(sr, "Receive queue interrupt not supported");
		rc = EINVAL;
	}

	if (conf->intr_conf.rmv != 0) {
		sfcr_err(sr, "Remove interrupt not supported");
		rc = EINVAL;
	}

	return rc;
}
#endif


static int
sfc_repr_configure(struct sfc_repr *sr, const struct rte_eth_conf *conf)
{
	int rc = 0;

	sfcr_info(sr, "%s() entry", __func__);
#if 0
	rc = sfc_repr_check_conf(sr, conf);
	if (rc != 0)
		goto fail_check_conf;
#endif

	sr->state = SFC_ADAPTER_CONFIGURED;

	sfcr_info(sr, "%s() done", __func__);
#if 0
fail_check_conf:
#endif
	return rc;
}

static int
sfc_repr_dev_configure(struct rte_eth_dev *dev)
{
	struct sfc_repr *sr = sfc_repr_by_eth_dev(dev);
	struct rte_eth_dev_data *dev_data = dev->data;
	int rc;

	sfcr_info(sr, "%s() entry n_rxq=%u n_txq=%u", __func__,
		  dev_data->nb_rx_queues, dev_data->nb_tx_queues);

	sfc_repr_lock(sr);
	switch (sr->state) {
	case SFC_ADAPTER_CONFIGURED:
		/* FALLTHROUGH */
	case SFC_ADAPTER_INITIALIZED:
		rc = sfc_repr_configure(sr, &dev_data->dev_conf);
		break;
	default:
		sfcr_err(sr, "unexpected adapter state %u to configure",
			 sr->state);
		rc = EINVAL;
		break;
	}
	sfc_repr_unlock(sr);

	sfcr_info(sr, "%s() done %d", __func__, rc);
	SFC_ASSERT(rc >= 0);
	return -rc;
}

static int
sfc_repr_dev_infos_get(struct rte_eth_dev *dev,
		       struct rte_eth_dev_info *dev_info)
{
	struct sfc_repr_shared *srs = sfc_repr_shared_by_eth_dev(dev);

	dev_info->device = dev->device;

	dev_info->max_rx_queues = SFC_REPR_RXQ_MAX;
	dev_info->max_tx_queues = SFC_REPR_TXQ_MAX;
	dev_info->default_rxconf.rx_drop_en = 1;
	dev_info->switch_info.domain_id = srs->switch_domain_id;
	dev_info->switch_info.port_id = srs->switch_port_id;

	return 0;
}

static int
sfc_repr_create_port(struct sfc_adapter *pf_sa, uint16_t repr_id,
		     uint16_t rte_port_id)
{
	return sfc_repr_proxy_add_port(pf_sa, repr_id, rte_port_id);
}

static int
sfc_repr_destroy_port(struct sfc_adapter *pf_sa, uint16_t repr_id)
{
	return sfc_repr_proxy_del_port(pf_sa, repr_id);
}

static int
sfc_repr_dev_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
	struct sfc_repr_shared *srs = sfc_repr_shared_by_eth_dev(dev);
	uint16_t pf_port_id = sfc_sa2shared(srs->pf_sa)->port_id;
	struct sfc_repr *sr = sfc_repr_by_eth_dev(dev);
	struct rte_eth_link link;

	if (sr->state != SFC_ADAPTER_STARTED)
		sfc_port_link_mode_to_info(EFX_LINK_UNKNOWN, &link);
	else if (wait_to_complete)
		rte_eth_link_get(pf_port_id, &link);
	else
		rte_eth_link_get_nowait(pf_port_id, &link);

	return rte_eth_linkstatus_set(dev, &link);
}

static int
sfc_repr_ring_create(struct sfc_adapter *pf_sa, uint16_t repr_id,
		     bool tx, uint16_t qid, uint16_t nb_desc,
		     unsigned int socket_id, struct rte_ring **ring)
{
	char ring_name[RTE_RING_NAMESIZE];
	int ret;

	ret = snprintf(ring_name, sizeof(ring_name), "sfc_%u_repr_%u_%cxq%u",
		       sfc_sa2shared(pf_sa)->port_id, repr_id, tx ? 't' : 'r',
		       qid);
	if (ret >= (int)sizeof(ring_name))
		return -ENAMETOOLONG;

	/*
	 * Single producer/consumer rings are used since the API for Tx/Rx
	 * packet burst for representors are guaranteed to be called from
	 * a single thread, and the user of the other end (representor proxy)
	 * is also single-threaded.
	 */
	*ring = rte_ring_create(ring_name, nb_desc, socket_id,
			       RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (*ring == NULL)
		return -rte_errno;

	return 0;
}

static int
sfc_repr_rx_qcheck_conf(struct sfc_repr *sr,
			const struct rte_eth_rxconf *rx_conf)
{
	int rc = 0;

	if (rx_conf->rx_thresh.pthresh != 0 ||
	    rx_conf->rx_thresh.hthresh != 0 ||
	    rx_conf->rx_thresh.wthresh != 0) {
		sfcr_warn(sr,
			"RxQ prefetch/host/writeback thresholds are not supported");
	}

	if (rx_conf->rx_free_thresh != 0) {
		sfcr_err(sr, "RxQ free threshold is not supported");
		rc = EINVAL;
	}

	if (rx_conf->rx_drop_en == 0) {
		sfcr_err(sr, "RxQ drop disable is not supported");
		rc = EINVAL;
	}

	if (rx_conf->rx_deferred_start) {
		sfcr_err(sr, "Deferred start is not supported");
		rc = EINVAL;
	}

	if (rx_conf->offloads != 0) {
		sfcr_err(sr, "Offloads are not supported");
		rc = EINVAL;
	}

	return rc;
}


static int
sfc_repr_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
			uint16_t nb_rx_desc, unsigned int socket_id,
			__rte_unused const struct rte_eth_rxconf *rx_conf,
			struct rte_mempool *mb_pool)
{
	struct sfc_repr_shared *srs = sfc_repr_shared_by_eth_dev(dev);
	struct sfc_repr *sr = sfc_repr_by_eth_dev(dev);
	struct sfc_repr_rxq *rxq;
	int ret;

	ret = -sfc_repr_rx_qcheck_conf(sr, rx_conf);
	if (ret != 0)
		goto fail_check_conf;

	ret = -ENOMEM;
	rxq = rte_zmalloc_socket("sfc-repr-rxq", sizeof(*rxq),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq == NULL)
		goto fail_rxq_alloc;

	rxq->srs = srs;
	rxq->queue_id = rx_queue_id;

	ret = sfc_repr_ring_create(srs->pf_sa, srs->repr_id,
				   false, rxq->queue_id, nb_rx_desc,
				   socket_id, &rxq->ring);
	if (ret != 0)
		goto fail_ring_create;

	ret = sfc_repr_proxy_add_rxq(srs->pf_sa, srs->repr_id,
				     rxq->queue_id, rxq->ring, mb_pool);
	if (ret != 0)
		goto fail_proxy_add_rxq;

	dev->data->rx_queues[rx_queue_id] = rxq;

	return 0;

fail_proxy_add_rxq:
	rte_ring_free(rxq->ring);

fail_ring_create:
	rte_free(rxq);

fail_rxq_alloc:
fail_check_conf:
	return ret;
}

static void
sfc_repr_rx_queue_release(void *queue)
{
	struct sfc_repr_rxq *rxq = queue;
	struct sfc_repr_shared *srs;

	if (rxq == NULL)
		return;

	srs = rxq->srs;
	sfc_repr_proxy_del_rxq(srs->pf_sa, srs->repr_id, rxq->queue_id);
	rte_ring_free(rxq->ring);
	rte_free(rxq);
}

static int
sfc_repr_tx_qcheck_conf(struct sfc_repr *sr,
			const struct rte_eth_txconf *tx_conf)
{
	int rc = 0;

	if (tx_conf->tx_rs_thresh != 0) {
		sfcr_err(sr, "RS bit in transmit descriptor is not supported");
		rc = EINVAL;
	}

	if (tx_conf->tx_free_thresh != 0) {
		sfcr_err(sr, "TxQ free threshold is not supported");
		rc = EINVAL;
	}

	if (tx_conf->tx_thresh.pthresh != 0 ||
	    tx_conf->tx_thresh.hthresh != 0 ||
	    tx_conf->tx_thresh.wthresh != 0) {
		sfcr_warn(sr,
			"prefetch/host/writeback thresholds are not supported");
	}

	if (tx_conf->tx_deferred_start) {
		sfcr_err(sr, "Deferred start is not supported");
		rc = EINVAL;
	}

	if (tx_conf->offloads != 0) {
		sfcr_err(sr, "Offloads are not supported");
		rc = EINVAL;
	}

	return rc;
}

static int
sfc_repr_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
			uint16_t nb_tx_desc, unsigned int socket_id,
			const struct rte_eth_txconf *tx_conf)
{
	struct sfc_repr_shared *srs = sfc_repr_shared_by_eth_dev(dev);
	struct sfc_repr *sr = sfc_repr_by_eth_dev(dev);
	struct sfc_repr_txq *txq;
	int ret;

	ret = -sfc_repr_tx_qcheck_conf(sr, tx_conf);
	if (ret != 0)
		goto fail_check_conf;

	ret = -ENOMEM;
	txq = rte_zmalloc_socket("sfc-repr-txq", sizeof(*txq),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (txq == NULL)
		goto fail_txq_alloc;

	txq->srs = srs;
	txq->queue_id = tx_queue_id;

	ret = sfc_repr_ring_create(srs->pf_sa, srs->repr_id,
				   true, txq->queue_id, nb_tx_desc,
				   socket_id, &txq->ring);
	if (ret != 0)
		goto fail_ring_create;

	ret = sfc_repr_proxy_add_txq(srs->pf_sa, srs->repr_id,
				     txq->queue_id, txq->ring,
				     &txq->egress_mport);
	if (ret != 0)
		goto fail_proxy_add_txq;

	dev->data->tx_queues[tx_queue_id] = txq;

	return 0;

fail_proxy_add_txq:
	rte_ring_free(txq->ring);

fail_ring_create:
	rte_free(txq);

fail_txq_alloc:
fail_check_conf:
	return ret;
}

static void
sfc_repr_tx_queue_release(void *queue)
{
	struct sfc_repr_txq *txq = queue;
	struct sfc_repr_shared *srs;

	if (txq == NULL)
		return;

	srs = txq->srs;
	sfc_repr_proxy_del_txq(srs->pf_sa, srs->repr_id, txq->queue_id);
	rte_ring_free(txq->ring);
	rte_free(txq);
}

static void
sfc_repr_close(struct sfc_repr *sr)
{
	SFC_ASSERT(sr->state == SFC_ADAPTER_CONFIGURED);
	sr->state = SFC_ADAPTER_CLOSING;

	/* Put representor close actions here */

	sr->state = SFC_ADAPTER_INITIALIZED;
}

static int
sfc_repr_dev_close(struct rte_eth_dev *dev)
{
	struct sfc_repr *sr = sfc_repr_by_eth_dev(dev);
	struct sfc_repr_shared *srs = sfc_repr_shared_by_eth_dev(dev);
	unsigned int i;

	sfcr_info(sr, "%s() entry", __func__);

	sfc_repr_lock(sr);
	switch (sr->state) {
	case SFC_ADAPTER_STARTED:
		sfc_repr_stop_no_lock(dev);
		SFC_ASSERT(sr->state == SFC_ADAPTER_CONFIGURED);
		/* FALLTHROUGH */
	case SFC_ADAPTER_CONFIGURED:
		sfc_repr_close(sr);
		SFC_ASSERT(sr->state == SFC_ADAPTER_INITIALIZED);
		/* FALLTHROUGH */
	case SFC_ADAPTER_INITIALIZED:
		break;
	default:
		sfcr_err(sr, "unexpected adapter state %u on close", sr->state);
		break;
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		sfc_repr_rx_queue_release(dev->data->rx_queues[i]);
		dev->data->rx_queues[i] = NULL;
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		sfc_repr_tx_queue_release(dev->data->tx_queues[i]);
		dev->data->tx_queues[i] = NULL;
	}

	/*
	 * Cleanup all resources.
	 * Rollback primary process sfc_repr_eth_dev_init() below.
	 */

	sfc_repr_destroy_port(srs->pf_sa, srs->repr_id);

	dev->rx_pkt_burst = NULL;
	dev->tx_pkt_burst = NULL;
	dev->dev_ops = NULL;

	sfc_repr_unlock(sr);
	sfc_repr_lock_fini(sr);

	sfcr_info(sr, "%s() done", __func__);

	free(sr);

	return 0;
}

static int
sfc_repr_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct sfc_repr_shared *srs = sfc_repr_shared_by_eth_dev(dev);

	*stats = srs->stats;

	return 0;
}

static const struct eth_dev_ops sfc_repr_dev_ops = {
	.dev_configure			= sfc_repr_dev_configure,
	.dev_start			= sfc_repr_dev_start,
	.dev_stop			= sfc_repr_dev_stop,
	.dev_close			= sfc_repr_dev_close,
	.dev_infos_get			= sfc_repr_dev_infos_get,
	.link_update			= sfc_repr_dev_link_update,
	.stats_get			= sfc_repr_stats_get,
	.rx_queue_setup			= sfc_repr_rx_queue_setup,
	.rx_queue_release		= sfc_repr_rx_queue_release,
	.tx_queue_setup			= sfc_repr_tx_queue_setup,
	.tx_queue_release		= sfc_repr_tx_queue_release,
};


struct sfc_repr_init_data {
	struct sfc_adapter	*pf_sa;
	uint16_t		repr_id;
	uint16_t		switch_domain_id;
	efx_mport_sel_t		mport_sel;
};

static int
sfc_repr_eth_dev_init(struct rte_eth_dev *dev, void *init_params)
{
	const struct sfc_repr_init_data *repr_data = init_params;
	struct sfc_repr_shared *srs = sfc_repr_shared_by_eth_dev(dev);
	struct sfc_mae_switch_port_request switch_port_request;
	struct sfc_repr *sr;
	int rc;

	memset(&switch_port_request, 0, sizeof(switch_port_request));
	switch_port_request.type = SFC_MAE_SWITCH_PORT_REPRESENTOR;
	switch_port_request.entity_mportp = &repr_data->mport_sel;
	switch_port_request.ethdev_port_id = dev->data->port_id;

	rc = sfc_mae_assign_switch_port(repr_data->switch_domain_id,
					&switch_port_request,
					&srs->switch_port_id);
	if (rc != 0)
		goto fail_mae_assign_switch_port;

	rc = sfc_repr_create_port(repr_data->pf_sa, repr_data->repr_id,
				  dev->data->port_id);
	if (rc != 0)
		goto fail_create_port;

	/*
	 * Allocate process private data from heap, since it should not
	 * be located in shared memory allocated using rte_malloc() API.
	 */
	sr = calloc(1, sizeof(*sr));
	if (sr == NULL) {
		rc = ENOMEM;
		goto fail_alloc_sr;
	}

	sfc_repr_lock_init(sr);
	sfc_repr_lock(sr);

	dev->process_private = sr;

	srs->pf_sa = repr_data->pf_sa;
	srs->repr_id = repr_data->repr_id;
	srs->switch_domain_id = repr_data->switch_domain_id;

	dev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;

	dev->data->mac_addrs = rte_zmalloc("sfcr", RTE_ETHER_ADDR_LEN, 0);
	if (dev->data->mac_addrs == NULL) {
		rc = ENOMEM;
		goto fail_mac_addrs;
	}

#if 1
	int i;
	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++)
		dev->data->mac_addrs->addr_bytes[i] = i;

	dev->data->mac_addrs->addr_bytes[5] = repr_data->repr_id;
#endif

	dev->rx_pkt_burst = sfc_repr_rx_burst;
	dev->tx_pkt_burst = sfc_repr_tx_burst;
	dev->dev_ops = &sfc_repr_dev_ops;

	sr->state = SFC_ADAPTER_INITIALIZED;
	sfc_repr_unlock(sr);

	return 0;

fail_mac_addrs:
	sfc_repr_unlock(sr);

fail_alloc_sr:
	sfc_repr_destroy_port(repr_data->pf_sa, repr_data->repr_id);

fail_create_port:
fail_mae_assign_switch_port:
	SFC_ASSERT(rc >= 0);
	return -rc;
}

int
sfc_repr_create(struct rte_eth_dev *parent, uint16_t representor_id)
{
	struct sfc_adapter *sa_parent = sfc_adapter_by_eth_dev(parent);
	struct sfc_repr_init_data repr_data;
	char name[RTE_ETH_NAME_MAX_LEN];
	struct rte_eth_dev *dev;

	if (!sfc_repr_supported(sfc_sa2shared(sa_parent)))
		return -ENOTSUP;

	if (snprintf(name, sizeof(name), "net_%s_representor_%u",
		     parent->device->name, representor_id) >= (int)sizeof(name))
		return -ENAMETOOLONG;

	dev = rte_eth_dev_allocated(name);
	if (dev == NULL) {
		const efx_nic_cfg_t *encp = efx_nic_cfg_get(sa_parent->nic);
		int rc;

		memset(&repr_data, 0, sizeof(repr_data));
		repr_data.pf_sa = sa_parent;
		repr_data.repr_id = representor_id;
		repr_data.switch_domain_id = sa_parent->mae.switch_domain_id;

		rc = efx_mae_mport_by_pcie_function(encp->enc_pf,
						    representor_id,
						    &repr_data.mport_sel);
		if (rc != 0)
			return -rc;

		return rte_eth_dev_create(parent->device, name,
					  sizeof(struct sfc_repr_shared),
					  NULL, NULL,
					  sfc_repr_eth_dev_init, &repr_data);
	}

	return 0;
}
