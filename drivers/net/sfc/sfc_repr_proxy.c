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
#include "sfc.h"

static int32_t
sfc_repr_proxy_routine(void *arg)
{
	struct sfc_repr_proxy *rp = arg;

	/* Representor proxy boilerplate will be here */

	return 0;
}

int
sfc_repr_proxy_attach(struct sfc_adapter *sa)
{
	static const char * const ser = "port representors proxy";

	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	struct rte_service_spec service;
	uint32_t cid;
	uint32_t sid;
	int rc;

	if (!sfc_repr_supported(sa))
		return 0;

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
	return rc;
}

void
sfc_repr_proxy_detach(struct sfc_adapter *sa)
{
	struct sfc_repr_proxy *rp = &sa->repr_proxy;

	if (!sfc_repr_supported(sa))
		return;

	rte_service_map_lcore_set(rp->service_id, rp->service_core_id, 0);
	rte_service_component_unregister(rp->service_id);
}

int
sfc_repr_proxy_start(struct sfc_adapter *sa)
{
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	int rc;

	/*
	 * The condition to start the proxy is insufficient. It will be
	 * complemented with representor port start/stop support.
	 */
	if (!sfc_repr_supported(sa))
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
	struct sfc_repr_proxy *rp = &sa->repr_proxy;
	int rc;

	if (!sfc_repr_supported(sa))
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
