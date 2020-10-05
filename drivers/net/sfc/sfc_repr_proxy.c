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

static struct sfc_repr_proxy *
sfc_repr_proxy_by_pf_sa(struct sfc_adapter *pf_sa)
{
	return &pf_sa->repr_proxy;
}

static int32_t
sfc_repr_proxy_routine(void *arg)
{
	struct sfc_repr_proxy *rp = arg;

	/* Representor proxy boilerplate will be here */

	return 0;
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
		/* FIXME: populate RxQ index */
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
	return rc;
}

void
sfc_repr_proxy_stop(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
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
