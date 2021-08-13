/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "roc_api.h"

#include "cn9k_worker.h"

uint16_t __rte_hot
cn9k_sso_hws_enq(void *port, const struct rte_event *ev)
{
	struct cn9k_sso_hws *ws = port;

	switch (ev->op) {
	case RTE_EVENT_OP_NEW:
		return cn9k_sso_hws_new_event(ws, ev);
	case RTE_EVENT_OP_FORWARD:
		cn9k_sso_hws_forward_event(ws, ev);
		break;
	case RTE_EVENT_OP_RELEASE:
		cnxk_sso_hws_swtag_flush(ws->tag_op, ws->swtag_flush_op);
		break;
	default:
		return 0;
	}

	return 1;
}

uint16_t __rte_hot
cn9k_sso_hws_enq_burst(void *port, const struct rte_event ev[],
		       uint16_t nb_events)
{
	RTE_SET_USED(nb_events);
	return cn9k_sso_hws_enq(port, ev);
}

uint16_t __rte_hot
cn9k_sso_hws_enq_new_burst(void *port, const struct rte_event ev[],
			   uint16_t nb_events)
{
	struct cn9k_sso_hws *ws = port;
	uint16_t i, rc = 1;

	for (i = 0; i < nb_events && rc; i++)
		rc = cn9k_sso_hws_new_event(ws, &ev[i]);

	return nb_events;
}

uint16_t __rte_hot
cn9k_sso_hws_enq_fwd_burst(void *port, const struct rte_event ev[],
			   uint16_t nb_events)
{
	struct cn9k_sso_hws *ws = port;

	RTE_SET_USED(nb_events);
	cn9k_sso_hws_forward_event(ws, ev);

	return 1;
}

/* Dual ws ops. */

uint16_t __rte_hot
cn9k_sso_hws_dual_enq(void *port, const struct rte_event *ev)
{
	struct cn9k_sso_hws_dual *dws = port;
	struct cn9k_sso_hws_state *vws;

	vws = &dws->ws_state[!dws->vws];
	switch (ev->op) {
	case RTE_EVENT_OP_NEW:
		return cn9k_sso_hws_dual_new_event(dws, ev);
	case RTE_EVENT_OP_FORWARD:
		cn9k_sso_hws_dual_forward_event(dws, vws, ev);
		break;
	case RTE_EVENT_OP_RELEASE:
		cnxk_sso_hws_swtag_flush(vws->tag_op, vws->swtag_flush_op);
		break;
	default:
		return 0;
	}

	return 1;
}

uint16_t __rte_hot
cn9k_sso_hws_dual_enq_burst(void *port, const struct rte_event ev[],
			    uint16_t nb_events)
{
	RTE_SET_USED(nb_events);
	return cn9k_sso_hws_dual_enq(port, ev);
}

uint16_t __rte_hot
cn9k_sso_hws_dual_enq_new_burst(void *port, const struct rte_event ev[],
				uint16_t nb_events)
{
	struct cn9k_sso_hws_dual *dws = port;
	uint16_t i, rc = 1;

	for (i = 0; i < nb_events && rc; i++)
		rc = cn9k_sso_hws_dual_new_event(dws, &ev[i]);

	return nb_events;
}

uint16_t __rte_hot
cn9k_sso_hws_dual_enq_fwd_burst(void *port, const struct rte_event ev[],
				uint16_t nb_events)
{
	struct cn9k_sso_hws_dual *dws = port;

	RTE_SET_USED(nb_events);
	cn9k_sso_hws_dual_forward_event(dws, &dws->ws_state[!dws->vws], ev);

	return 1;
}
