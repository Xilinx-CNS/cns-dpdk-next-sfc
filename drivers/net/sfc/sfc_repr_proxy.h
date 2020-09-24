/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2019-2020 Xilinx, Inc.
 * Copyright(c) 2019 Solarflare Communications Inc.
 *
 * This software was jointly developed between OKTET Labs (under contract
 * for Solarflare) and Solarflare Communications, Inc.
 */

#ifndef _SFC_REPR_PROXY_H
#define _SFC_REPR_PROXY_H

#include <stdint.h>

#include <rte_ring.h>
#include <rte_mempool.h>

#include "efx.h"

#include "sfc_repr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Number of supported RxQs with different mbuf memory pools */
#define SFC_REPR_PROXY_NB_RXQ	(1)

/* One TxQ is required and sufficient for port representors support */
#define SFC_REPR_PROXY_NB_TXQ	(1)

struct sfc_repr_proxy_rxq {
	struct rte_ring			*ring;
	struct rte_mempool		*mb_pool;
};

struct sfc_repr_proxy_txq {
	struct rte_ring			*ring;
};

struct sfc_repr_proxy_port {
	uint16_t			rte_port_id;
	efx_mport_id_t			egress_mport;
	struct sfc_repr_proxy_rxq	rxq[SFC_REPR_RXQ_MAX];
	struct sfc_repr_proxy_txq	txq[SFC_REPR_TXQ_MAX];
};

struct sfc_repr_proxy {
	uint32_t			service_core_id;
	uint32_t			service_id;
	efx_mport_id_t			mport_alias;
	unsigned int			num_ports;
	struct sfc_repr_proxy_port	*port;
};

struct sfc_adapter;

int sfc_repr_proxy_attach(struct sfc_adapter *sa);
void sfc_repr_proxy_detach(struct sfc_adapter *sa);
int sfc_repr_proxy_start(struct sfc_adapter *sa);
void sfc_repr_proxy_stop(struct sfc_adapter *sa);

#ifdef __cplusplus
}
#endif
#endif  /* _SFC_REPR_PROXY_H */
