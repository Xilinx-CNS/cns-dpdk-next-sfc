/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2019-2020 Xilinx, Inc.
 * Copyright(c) 2019 Solarflare Communications Inc.
 *
 * This software was jointly developed between OKTET Labs (under contract
 * for Solarflare) and Solarflare Communications, Inc.
 */

#include <rte_service.h>
#include <rte_service_component.h>

#include "sfc_log.h"
#include "sfc_service.h"
#include "sfc_repr_proxy.h"
#include "sfc_repr_proxy_api.h"
#include "sfc.h"
#include "sfc_ev.h"
#include "sfc_tx.h"
#include "sfc_rx.h"

static struct sfc_repr_proxy *
sfc_repr_proxy_by_pf_sa(struct sfc_adapter *pf_sa)
{
	return &pf_sa->repr_proxy;
}

static int32_t
sfc_repr_proxy_routine(void *arg)
{
	struct sfc_repr_proxy *rp = arg;
	unsigned int i;

	for (i = 0; i < rp->num_ports; i++) {
		struct sfc_repr_proxy_port *port = &rp->port[i];
		struct sfc_repr_proxy_dp_txq *txq = &rp->dp_txq;

		/* FIXME: thread safety */
		if (port->txq[0].ring == NULL)
			continue;

		if (txq->available < RTE_DIM(txq->tx_pkts)) {
			txq->available += rte_ring_sc_dequeue_burst(port->txq[0].ring,
					(void **)(&txq->tx_pkts[txq->available]),
					RTE_DIM(txq->tx_pkts) - txq->available, NULL);
			if (txq->available == txq->transmitted)
				continue;
		}

		txq->transmitted += txq->pkt_burst(txq->dp,
				&txq->tx_pkts[txq->transmitted],
				txq->available - txq->transmitted);
		if (txq->available == txq->transmitted) {
			txq->available = 0;
			txq->transmitted = 0;
		}
	}

	return 0;
}

static struct sfc_txq_info *
sfc_repr_proxy_txq_info_get(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared *sas = sfc_sa2shared(sa);

	return &sas->txq_info[sa->repr_proxy.dp_txq.sw_index];
}

static int
sfc_repr_proxy_txq_attach(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared *sas = sfc_sa2shared(sa);
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct sfc_repr_proxy_dp_txq *txq = &rp->dp_txq;

	txq->sw_index = sfc_repr_txq_sw_index(sas);

	return 0;
}

static void
sfc_repr_proxy_txq_detach(struct sfc_adapter *sa)
{
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct sfc_repr_proxy_dp_txq *txq = &rp->dp_txq;

	txq->sw_index = 0;
}

int
sfc_repr_proxy_txq_init(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct sfc_repr_proxy_dp_txq *txq = &rp->dp_txq;
	const struct rte_eth_txconf tx_conf = {
		.tx_free_thresh = SFC_REPR_PROXY_TXQ_REFILL_LEVEL,
	};
	struct sfc_txq_info *txq_info;

	if (!sfc_repr_supported(sas))
		return 0;

	txq_info = &sfc_sa2shared(sa)->txq_info[txq->sw_index];
	if (txq_info->state == SFC_TXQ_INITIALIZED)
		return 0;

	sfc_log_init(sa, "representor TxQ");

	sfc_tx_qinit_info(sa, txq->sw_index);

	return sfc_tx_qinit(sa, txq->sw_index,
			    SFC_REPR_PROXY_TX_DESC_COUNT, sa->socket_id,
			    &tx_conf);
}

void
sfc_repr_proxy_txq_fini(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct sfc_repr_proxy_dp_txq *txq = &rp->dp_txq;
	struct sfc_txq_info *txq_info;

	if (!sfc_repr_supported(sas))
		return;

	txq_info = &sfc_sa2shared(sa)->txq_info[txq->sw_index];
	if (txq_info->state != SFC_TXQ_INITIALIZED)
		return;

	sfc_tx_qfini(sa, txq->sw_index);
}

static int
sfc_repr_proxy_txq_start(struct sfc_adapter *sa)
{
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct sfc_repr_proxy_dp_txq *txq = &rp->dp_txq;

	sfc_log_init(sa, "representor TxQ");

	txq->dp = sfc_repr_proxy_txq_info_get(sa)->dp;
	txq->pkt_burst = sa->eth_dev->tx_pkt_burst;
	txq->available = 0;
	txq->transmitted = 0;

	return 0;
}

static void
sfc_repr_proxy_txq_stop(__rte_unused struct sfc_adapter *sa)
{
}

static int
sfc_repr_proxy_rxq_attach(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;
	unsigned int n_elements;
	unsigned int cache_size;
	/* The mempool is internal and private area is not required */
	const uint16_t priv_size = 0;
	/*
	 * Elements count is 1 less than the number of descriptors to avoid
	 * head and tail element collisions.
	 */
	const uint16_t data_room_size = RTE_PKTMBUF_HEADROOM +
		SFC_REPR_PROXY_MPOOL_DATA_ROOM_SIZE;
	int rc;

	sfc_log_init(sa, "entry");

	/*
	 * At least one element in the ring is always unused to distinguish
	 * between empty and full ring cases.
	 */
	n_elements = SFC_REPR_PROXY_RX_DESC_COUNT - 1;

	/*
	 * The cache must have sufficient space to put received buckets
	 * before they're reused on refill.
	 */
	cache_size = rte_align32pow2(SFC_REPR_PROXY_RXQ_REFILL_LEVEL +
				     SFC_REPR_PROXY_RX_BURST - 1);

	if (snprintf(name, sizeof(name), "repr-rxq-pool-%u", sas->port_id) >=
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

	rp->dp_rxq.sw_index = sfc_repr_rxq_sw_index(sas);
	rp->dp_rxq.mp = mp;

	return 0;

fail_mp_create:
	sfc_log_init(sa, "failed %d", rc);

	return rc;
}

static void
sfc_repr_proxy_rxq_detach(struct sfc_adapter *sa)
{
	sfc_log_init(sa, "entry");

	rte_mempool_free(sa->repr_proxy.dp_rxq.mp);
	sa->repr_proxy.dp_rxq.mp = NULL;
}

static struct sfc_rxq_info *
sfc_repr_proxy_rxq_info_get(struct sfc_adapter *sa)
{
	return &sfc_sa2shared(sa)->rxq_info[sa->repr_proxy.dp_rxq.sw_index];
}

int
sfc_repr_proxy_rxq_init(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	uint16_t nb_rx_desc = SFC_REPR_PROXY_RX_DESC_COUNT;
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct sfc_repr_proxy_dp_rxq *rxq = &rp->dp_rxq;
	struct sfc_rxq_info *rxq_info;
	struct rte_eth_rxconf rxconf = {
		.rx_free_thresh = SFC_REPR_PROXY_RXQ_REFILL_LEVEL,
		.rx_drop_en = 1,
	};
	int rc;

	if (!sfc_repr_supported(sas))
		return 0;

	rxq_info = &sas->rxq_info[rxq->sw_index];
	if (rxq_info->state == SFC_RXQ_INITIALIZED)
		return 0;

	sfc_log_init(sa, "entry");

	nb_rx_desc = RTE_MIN(nb_rx_desc, sa->rxq_max_entries);
	nb_rx_desc = RTE_MAX(nb_rx_desc, sa->rxq_min_entries);

	rc = sfc_rx_qinit_info(sa, rxq->sw_index, EFX_RXQ_FLAG_INGRESS_MPORT);
	if (rc != 0)
		goto fail_repr_rxq_init_info;

	rc = sfc_rx_qinit(sa, rxq->sw_index, nb_rx_desc, sa->socket_id, &rxconf,
			  rxq->mp);
	if (rc != 0)
		goto fail_repr_rxq_init;

	return 0;

fail_repr_rxq_init:
fail_repr_rxq_init_info:
	sfc_log_init(sa, "failed %d", rc);

	return rc;
}

void
sfc_repr_proxy_rxq_fini(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct sfc_repr_proxy_dp_rxq *rxq = &rp->dp_rxq;
	struct sfc_rxq_info *rxq_info;

	if (!sfc_repr_supported(sas))
		return;

	rxq_info = &sas->rxq_info[rxq->sw_index];
	if (rxq_info->state != SFC_RXQ_INITIALIZED)
		return;

	sfc_rx_qfini(sa, rxq->sw_index);
}

static int
sfc_repr_proxy_rxq_start(struct sfc_adapter *sa)
{
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct sfc_repr_proxy_dp_rxq *rxq = &rp->dp_rxq;

	sfc_log_init(sa, "entry");

	rxq->dp = sfc_repr_proxy_rxq_info_get(sa)->dp;
	rxq->pkt_burst = sa->eth_dev->rx_pkt_burst;
	rxq->available = 0;
	rxq->transmitted = 0;

	return 0;
}

static void
sfc_repr_proxy_rxq_stop(struct sfc_adapter *sa)
{
	sfc_log_init(sa, "entry");
}

static int
sfc_repr_proxy_mae_rule_insert(struct sfc_adapter *sa, uint16_t repr_id)
{
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	efx_mport_sel_t mport_alias_selector;
	efx_mport_sel_t mport_vf_selector;
	struct sfc_mae_rule *mae_rule;
	int rc;

	rc = efx_mae_mport_by_id(&rp->port[repr_id].egress_mport,
				 &mport_vf_selector);
	if (rc != 0)
		goto fail_get_vf;

	rc = efx_mae_mport_by_id(&rp->mport_alias, &mport_alias_selector);
	if (rc != 0)
		goto fail_get_alias;

	rc = sfc_mae_rule_add_mport_match_deliver(sa, &mport_vf_selector,
						  &mport_alias_selector, -1,
						  &mae_rule);
	if (rc != 0)
		goto fail_rule_add;

	rp->port[repr_id].mae_rule = mae_rule;

	return 0;

fail_rule_add:
fail_get_alias:
fail_get_vf:
	return rc;
}

static void
sfc_repr_proxy_mae_rule_remove(struct sfc_adapter *sa, uint16_t repr_id)
{
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct sfc_mae_rule *mae_rule = rp->port[repr_id].mae_rule;

	sfc_mae_rule_del(sa, mae_rule);
}

static int
sfc_repr_proxy_mport_filter_insert(struct sfc_adapter *sa)
{
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct sfc_repr_proxy_filter *filter = &rp->mport_filter;
	efx_mport_sel_t mport_alias_selector;
	static const efx_filter_match_flags_t flags[RTE_DIM(filter->specs)] = {
		EFX_FILTER_MATCH_UNKNOWN_UCAST_DST,
		EFX_FILTER_MATCH_UNKNOWN_MCAST_DST };
	unsigned int i;
	int rc;

	rc = efx_mae_mport_by_id(&rp->mport_alias, &mport_alias_selector);
	if (rc != 0)
		goto fail_get_selector;

	for (i = 0; i < RTE_DIM(filter->specs); i++) {
		memset(&filter->specs[i], 0, sizeof(filter->specs[0]));
		filter->specs[i].efs_priority = EFX_FILTER_PRI_MANUAL;
		filter->specs[i].efs_flags = EFX_FILTER_FLAG_RX;
		filter->specs[i].efs_dmaq_id = rp->dp_rxq.sw_index;
		filter->specs[i].efs_match_flags = flags[i];
		filter->specs[i].efs_ingress_mport = mport_alias_selector.sel;
		filter->specs[i].efs_match_flags |= EFX_FILTER_MATCH_MPORT;

		rc = efx_filter_insert(sa->nic, &filter->specs[i]);
		if (rc != 0)
			goto fail_insert;
	}

	return 0;

fail_insert:
	while (i-- > 0)
		efx_filter_remove(sa->nic, &filter->specs[i]);

fail_get_selector:
	return rc;
}

static void
sfc_repr_proxy_mport_filter_remove(struct sfc_adapter *sa)
{
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct sfc_repr_proxy_filter *filter = &rp->mport_filter;
	unsigned int i;

	for (i = 0; i < RTE_DIM(filter->specs); i++)
		efx_filter_remove(sa->nic, &filter->specs[i]);
}

static int
sfc_repr_proxy_filter_insert(struct sfc_adapter *sa, uint16_t repr_id)
{
	int rc;

	rc = sfc_repr_proxy_mae_rule_insert(sa, repr_id);
	if (rc != 0)
		goto fail_mae_rule_insert;

	return 0;

fail_mae_rule_insert:
	return rc;
}

static void
sfc_repr_proxy_filter_remove(struct sfc_adapter *sa, uint16_t repr_id)
{
	sfc_repr_proxy_mae_rule_remove(sa, repr_id);
}

static int
sfc_repr_proxy_ports_init(struct sfc_adapter *sa)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(sa->nic);
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct sfc_sriov *sriov = &sa->sriov;
	unsigned int i;
	int rc;

	rp->port = rte_calloc_socket("sfc-repr-proxy-port", sriov->num_vfs,
				     sizeof(*rp->port), 0, sa->socket_id);
	if (rp->port == NULL) {
		rc = ENOMEM;
		goto fail_alloc_port;
	}
	rp->num_ports = sriov->num_vfs;

	for (i = 0; i < rp->num_ports; i++) {
		efx_mport_sel_t vf_mport_selector;

		rc = efx_mae_mport_by_pcie_function(encp->enc_pf, i,
						    &vf_mport_selector);
		if (rc != 0)
			goto fail_mport_selector;

		rc = efx_mae_mport_id_by_selector(sa->nic, &vf_mport_selector,
						  &rp->port[i].egress_mport);
		if (rc != 0)
			goto fail_mport_id;
	}

	rc = efx_mae_mport_alloc_alias(sa->nic, &rp->mport_alias, NULL);
	if (rc != 0)
		goto fail_alloc_mport_alias;

	for (i = 0; i < rp->num_ports; i++)
		rp->port[i].rte_port_id = RTE_MAX_ETHPORTS;

	return 0;

fail_alloc_mport_alias:
fail_mport_id:
fail_mport_selector:
	rte_free(rp->port);
	rp->port = NULL;

fail_alloc_port:
	return rc;
}

static void
sfc_repr_proxy_port_fini(struct sfc_adapter *sa)
{
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	unsigned int i;

	for (i = 0; i < rp->num_ports; i++) {
		struct sfc_repr_proxy_port *port = &rp->port[i];

		if (port->rte_port_id != RTE_MAX_ETHPORTS) {
			rte_eth_dev_stop(port->rte_port_id);
			rte_eth_dev_close(port->rte_port_id);
		}
	}

	efx_mae_mport_free(sa->nic, &rp->mport_alias);
	rte_free(rp->port);
	rp->port = NULL;
}

int
sfc_repr_proxy_attach(struct sfc_adapter *sa)
{
	static const char * const ser = "port representors proxy";

	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct rte_service_spec service;
	uint32_t cid;
	uint32_t sid;
	int rc;

	if (!sfc_repr_supported(sas))
		return 0;

	rc = sfc_repr_proxy_txq_attach(sa);
	if (rc != 0)
		goto fail_txq_attach;

	rc = sfc_repr_proxy_rxq_attach(sa);
	if (rc != 0)
		goto fail_rxq_attach;

	rc = sfc_repr_proxy_ports_init(sa);
	if (rc != 0)
		goto fail_port_init;

	cid = sfc_get_service_lcore(sa->socket_id);
	if (cid == RTE_MAX_LCORE && sa->socket_id != SOCKET_ID_ANY) {
		/* Warn and try to allocate on any NUMA node */
		sfc_warn(sa,
			"Unable to get service lcore for %s at socket %d",
			ser, sa->socket_id);

		cid = sfc_get_service_lcore(SOCKET_ID_ANY);
	}
	if (cid == RTE_MAX_LCORE) {
		rc = ENOTSUP;
		sfc_err(sa, "Failed to get service lcore for %s", ser);
		goto fail_get_service_lcore;
	}

	memset(&service, 0, sizeof(service));
	snprintf(service.name, sizeof(service.name),
		 "net_sfc_%hu_repr_proxy", sfc_sa2shared(sa)->port_id);
	service.socket_id = rte_lcore_to_socket_id(cid);
	service.callback = sfc_repr_proxy_routine;
	service.callback_userdata = rp;

	rc = rte_service_component_register(&service, &sid);
	if (rc != 0) {
		rc = ENOEXEC;
		sfc_err(sa, "Failed to register %s component", ser);
		goto fail_register;
	}

	rc = rte_service_map_lcore_set(sid, cid, 1);
	if (rc != 0) {
		rc = -rc;
		sfc_err(sa, "Failed to map lcore for %s", ser);
		goto fail_map_lcore;
	}

	rp->service_core_id = cid;
	rp->service_id = sid;

	return 0;

fail_map_lcore:
	rte_service_component_unregister(sid);

fail_register:
	/*
	 * No need to rollback service lcore get since
	 * it just makes socket_id based search and remembers it.
	 */

fail_get_service_lcore:
	sfc_repr_proxy_port_fini(sa);

fail_port_init:
	sfc_repr_proxy_rxq_detach(sa);

fail_rxq_attach:
	sfc_repr_proxy_txq_detach(sa);

fail_txq_attach:
	return rc;
}

void
sfc_repr_proxy_detach(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	struct sfc_repr_proxy *rp = &sa->repr_proxy;

	if (!sfc_repr_supported(sas))
		return;

	rte_service_map_lcore_set(rp->service_id, rp->service_core_id, 0);
	rte_service_component_unregister(rp->service_id);
	sfc_repr_proxy_port_fini(sa);
	sfc_repr_proxy_rxq_detach(sa);
	sfc_repr_proxy_txq_detach(sa);
}

static int
sfc_repr_proxy_do_start_id(struct sfc_adapter *sa, uint16_t repr_id)
{
	int rc;

	rc = sfc_repr_proxy_filter_insert(sa, repr_id);
	if (rc != 0)
		goto fail_filter_insert;

	return 0;

fail_filter_insert:
	return rc;
}

static void
sfc_repr_proxy_do_stop_id(struct sfc_adapter *sa, uint16_t repr_id)
{
	sfc_repr_proxy_filter_remove(sa, repr_id);
}

static bool
sfc_repr_proxy_port_enabled(struct sfc_repr_proxy_port *port)
{
	return port->rte_port_id != RTE_MAX_ETHPORTS && port->enabled;
}

static bool
sfc_repr_proxy_ports_disabled(struct sfc_repr_proxy *rp)
{
	unsigned int i;

	for (i = 0; i < rp->num_ports; i++) {
		if (sfc_repr_proxy_port_enabled(&rp->port[i]))
			break;
	}

	return i == rp->num_ports;
}

int
sfc_repr_proxy_start(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	unsigned int port_i;
	int rc;

	/* Representor proxy is not started when no representors are started */
	if (!sfc_repr_supported(sas) || sfc_repr_proxy_ports_disabled(rp))
		return 0;

	rc = sfc_repr_proxy_txq_start(sa);
	if (rc != 0)
		goto fail_txq_start;

	rc = sfc_repr_proxy_rxq_start(sa);
	if (rc != 0)
		goto fail_rxq_start;

	/* Service core may be in "stopped" state, start it */
	rc = rte_service_lcore_start(rp->service_core_id);
	if (rc != 0 && rc != -EALREADY) {
		rc = -rc;
		sfc_err(sa, "Failed to start service core for %s: %s",
			rte_service_get_name(rp->service_id),
			rte_strerror(rc));
		goto fail_start_core;
	}

	/* Run the service */
	rc = rte_service_component_runstate_set(rp->service_id, 1);
	if (rc < 0) {
		rc = -rc;
		sfc_err(sa, "Failed to run %s component: %s",
			rte_service_get_name(rp->service_id),
			rte_strerror(rc));
		goto fail_component_runstate_set;
	}
	rc = rte_service_runstate_set(rp->service_id, 1);
	if (rc < 0) {
		rc = -rc;
		sfc_err(sa, "Failed to run %s: %s",
			rte_service_get_name(rp->service_id),
			rte_strerror(rc));
		goto fail_runstate_set;
	}

	for (port_i = 0; port_i < rp->num_ports; port_i++) {
		if (!sfc_repr_proxy_port_enabled(&rp->port[port_i]))
			continue;

		rc = sfc_repr_proxy_do_start_id(sa, port_i);
		if (rc != 0)
			goto fail_start_id;
	}

	rc = sfc_repr_proxy_mport_filter_insert(sa);
	if (rc != 0)
		goto fail_mport_filter_insert;

	return 0;

fail_mport_filter_insert:
fail_start_id:
	while (port_i-- > 0) {
		if (sfc_repr_proxy_port_enabled(&rp->port[port_i]))
			sfc_repr_proxy_do_stop_id(sa, port_i);
	}

	rte_service_runstate_set(rp->service_id, 0);

fail_runstate_set:
	rte_service_component_runstate_set(rp->service_id, 0);

fail_component_runstate_set:
	/* Service lcore may be shared and we never stop it */

fail_start_core:
	sfc_repr_proxy_rxq_stop(sa);

fail_rxq_start:
	sfc_repr_proxy_txq_stop(sa);

fail_txq_start:
	return rc;
}

void
sfc_repr_proxy_stop(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	const unsigned int wait_ms_total = 10000;
	unsigned int i;
	int rc;

	if (!sfc_repr_supported(sas) || sfc_repr_proxy_ports_disabled(rp))
		return;

	for (i = 0; i < rp->num_ports; i++) {
		if (!sfc_repr_proxy_port_enabled(&rp->port[i]))
			continue;

		sfc_repr_proxy_do_stop_id(sa, i);
	}

	sfc_repr_proxy_mport_filter_remove(sa);

	rc = rte_service_runstate_set(rp->service_id, 0);
	if (rc < 0) {
		sfc_err(sa, "Failed to stop %s: %s",
			rte_service_get_name(rp->service_id),
			rte_strerror(-rc));
	}

	rc = rte_service_component_runstate_set(rp->service_id, 0);
	if (rc < 0) {
		sfc_err(sa, "Failed to stop %s component: %s",
			rte_service_get_name(rp->service_id),
			rte_strerror(-rc));
	}

	/* Service lcore may be shared and we never stop it */

	/*
	 * Wait for the representor proxy routine to finish the last iteration.
	 * Give up on timeout.
	 */
	for (i = 0; i < wait_ms_total; i++) {
		if (rte_service_may_be_active(rp->service_id) == 0)
			break;

		rte_delay_ms(1);
	}
	sfc_repr_proxy_txq_stop(sa);
	sfc_repr_proxy_rxq_stop(sa);
}

int
sfc_repr_proxy_add_port(struct sfc_adapter *pf_sa, uint16_t repr_id,
			uint16_t rte_port_id)
{
	struct sfc_repr_proxy *rp = sfc_repr_proxy_by_pf_sa(pf_sa);
	struct sfc_repr_proxy_port *port = &rp->port[repr_id];

	if (port->rte_port_id != RTE_MAX_ETHPORTS)
		return EEXIST;

	port->rte_port_id = rte_port_id;

	return 0;
}

int
sfc_repr_proxy_del_port(struct sfc_adapter *pf_sa, uint16_t repr_id)
{
	struct sfc_repr_proxy *rp = sfc_repr_proxy_by_pf_sa(pf_sa);
	struct sfc_repr_proxy_port *port = &rp->port[repr_id];

	if (port->rte_port_id == RTE_MAX_ETHPORTS)
		return ENOENT;

	port->rte_port_id = RTE_MAX_ETHPORTS;

	return 0;
}

int
sfc_repr_proxy_add_rxq(struct sfc_adapter *pf_sa, uint16_t repr_id,
		       uint16_t queue_id, struct rte_ring *rx_ring,
		       struct rte_mempool *mp)
{
	struct sfc_repr_proxy *rp = sfc_repr_proxy_by_pf_sa(pf_sa);
	struct sfc_repr_proxy_port *port = &rp->port[repr_id];
	struct sfc_repr_proxy_rxq *rxq = &port->rxq[queue_id];

	rxq->ring = rx_ring;
	rxq->mb_pool = mp;

	return 0;
}

void
sfc_repr_proxy_del_rxq(struct sfc_adapter *pf_sa, uint16_t repr_id,
		       uint16_t queue_id)
{
	struct sfc_repr_proxy *rp = sfc_repr_proxy_by_pf_sa(pf_sa);
	struct sfc_repr_proxy_port *port = &rp->port[repr_id];
	struct sfc_repr_proxy_rxq *rxq = &port->rxq[queue_id];

	rxq->ring = NULL;
	rxq->mb_pool = NULL;
}

int
sfc_repr_proxy_add_txq(struct sfc_adapter *pf_sa, uint16_t repr_id,
		       uint16_t queue_id, struct rte_ring *tx_ring,
		       efx_mport_id_t *egress_mport)
{
	struct sfc_repr_proxy *rp = sfc_repr_proxy_by_pf_sa(pf_sa);
	struct sfc_repr_proxy_port *port = &rp->port[repr_id];
	struct sfc_repr_proxy_txq *txq = &port->txq[queue_id];

	txq->ring = tx_ring;

	*egress_mport = port->egress_mport;
	return 0;
}

void
sfc_repr_proxy_del_txq(struct sfc_adapter *pf_sa, uint16_t repr_id,
		       uint16_t queue_id)
{
	struct sfc_repr_proxy *rp = sfc_repr_proxy_by_pf_sa(pf_sa);
	struct sfc_repr_proxy_port *port = &rp->port[repr_id];
	struct sfc_repr_proxy_txq *txq = &port->txq[queue_id];

	txq->ring = NULL;
}

int
sfc_repr_proxy_start_id(struct sfc_adapter *pf_sa, uint16_t repr_id)
{
	struct sfc_repr_proxy *rp = sfc_repr_proxy_by_pf_sa(pf_sa);
	struct sfc_repr_proxy_port *port = &rp->port[repr_id];
	bool proxy_start_required = false;
	int rc;

	if (port->enabled)
		return EALREADY;

	if (pf_sa->state == SFC_ADAPTER_STARTED) {
		if (sfc_repr_proxy_ports_disabled(rp)) {
			proxy_start_required = true;
		} else {
			rc = sfc_repr_proxy_do_start_id(pf_sa, repr_id);
			if (rc != 0)
				goto fail_start_id;
		}
	}

	port->enabled = true;

	if (proxy_start_required) {
		rc = sfc_repr_proxy_start(pf_sa);
		if (rc != 0)
			goto fail_proxy_start;
	}

	return 0;

fail_proxy_start:
	port->enabled = false;

fail_start_id:
	return rc;
}

void
sfc_repr_proxy_stop_id(struct sfc_adapter *pf_sa, uint16_t repr_id)
{
	struct sfc_repr_proxy *rp = sfc_repr_proxy_by_pf_sa(pf_sa);
	struct sfc_repr_proxy_port *port = &rp->port[repr_id];
	unsigned int i;

	if (!port->enabled)
		return;

	if (pf_sa->state == SFC_ADAPTER_STARTED) {
		bool last_enabled = true;

		for (i = 0; i < rp->num_ports; i++) {
			if (i == repr_id)
				continue;

			if (sfc_repr_proxy_port_enabled(&rp->port[i])) {
				last_enabled = false;
				break;
			}
		}

		if (last_enabled)
			sfc_repr_proxy_stop(pf_sa);
		else
			sfc_repr_proxy_do_stop_id(pf_sa, repr_id);
	}

	port->enabled = false;
}
