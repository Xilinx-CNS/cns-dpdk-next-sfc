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

		rp->port[i].rte_port_id = RTE_MAX_ETHPORTS;
	}

	return 0;

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

int
sfc_repr_proxy_start(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	int rc;

	/*
	 * The condition to start the proxy is insufficient. It will be
	 * complemented with representor port start/stop support.
	 */
	if (!sfc_repr_supported(sas))
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
	return 0;

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
	int rc;

	if (!sfc_repr_supported(sas))
		return;

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
