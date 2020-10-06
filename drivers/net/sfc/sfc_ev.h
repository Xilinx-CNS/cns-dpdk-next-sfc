/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2019-2020 Xilinx, Inc.
 * Copyright(c) 2016-2019 Solarflare Communications Inc.
 *
 * This software was jointly developed between OKTET Labs (under contract
 * for Solarflare) and Solarflare Communications, Inc.
 */

#ifndef _SFC_EV_H_
#define _SFC_EV_H_

#include <rte_ethdev_driver.h>

#include "efx.h"

#include "sfc.h"

#ifdef __cplusplus
extern "C" {
#endif

struct sfc_adapter;
struct sfc_dp_rxq;
struct sfc_dp_txq;

enum sfc_evq_state {
	SFC_EVQ_UNINITIALIZED = 0,
	SFC_EVQ_INITIALIZED,
	SFC_EVQ_STARTING,
	SFC_EVQ_STARTED,

	SFC_EVQ_NSTATES
};

enum sfc_evq_type {
	SFC_EVQ_TYPE_MGMT = 0,
	SFC_EVQ_TYPE_RX,
	SFC_EVQ_TYPE_TX,

	SFC_EVQ_NTYPES
};

struct sfc_evq {
	/* Used on datapath */
	efx_evq_t			*common;
	const efx_ev_callbacks_t	*callbacks;
	unsigned int			read_ptr;
	unsigned int			read_ptr_primed;
	boolean_t			exception;
	efsys_mem_t			mem;
	struct sfc_dp_rxq		*dp_rxq;
	struct sfc_dp_txq		*dp_txq;

	/* Not used on datapath */
	struct sfc_adapter		*sa;
	unsigned int			evq_index;
	enum sfc_evq_state		init_state;
	enum sfc_evq_type		type;
	unsigned int			entries;
};

/* Return the number of Rx queues reserved for driver's internal use */
static inline unsigned int
sfc_rxq_reserved(const struct sfc_adapter_shared *sas)
{
	return sfc_cnt_rxq_num(sas);
}

static inline unsigned int
sfc_evq_reserved(const struct sfc_adapter_shared *sas)
{
	/* An EvQ is required for each reserved RxQ */
	return 1 + sfc_rxq_reserved(sas);
}

static inline int
sfc_mgmt_evq_index(__rte_unused const struct sfc_adapter_shared *sas)
{
	return 0;
}

static inline int
sfc_cnt_rxq_sw_index(const struct sfc_adapter_shared *sas)
{
	return sas->cnt_rxq_supported ? 0 : -1;
}

/*
 * Functions below define event queue to transmit/receive queue and vice
 * versa mapping.
 * Own event queue is allocated for management, each Rx and each Tx queue.
 * Zero event queue is used for management events.
 * Rx event queues from 1 to RxQ number follow management event queue.
 * Tx event queues follow Rx event queues.
 */

static inline unsigned int
sfc_evq_index_by_txq_sw_index(struct sfc_adapter *sa, unsigned int txq_sw_index)
{
	return sfc_evq_reserved(sfc_sa2shared(sa)) +
		sa->eth_dev->data->nb_rx_queues + txq_sw_index;
}

static inline unsigned int
sfc_rxq_sw_index_by_ethdev_rx_qid(struct sfc_adapter_shared *sas,
				  unsigned int ethdev_rx_qid)
{
	return sfc_rxq_reserved(sas) + ethdev_rx_qid;
}

static inline int
sfc_ethdev_rx_qid_by_rxq_sw_index(struct sfc_adapter_shared *sas,
				  unsigned int rxq_sw_index)
{
	return rxq_sw_index - sfc_rxq_reserved(sas);
}

static inline unsigned int
sfc_evq_index_by_rxq_sw_index(struct sfc_adapter *sa,
			      unsigned int rxq_sw_index)
{
	struct sfc_adapter_shared *sas = sfc_sa2shared(sa);
	int ethdev_qid = sfc_ethdev_rx_qid_by_rxq_sw_index(sas, rxq_sw_index);

	if (ethdev_qid < 0)
		return 1 + rxq_sw_index;

	return sfc_evq_reserved(sas) + ethdev_qid;
}

int sfc_ev_attach(struct sfc_adapter *sa);
void sfc_ev_detach(struct sfc_adapter *sa);
int sfc_ev_start(struct sfc_adapter *sa);
void sfc_ev_stop(struct sfc_adapter *sa);

int sfc_ev_qinit(struct sfc_adapter *sa,
		 enum sfc_evq_type type, unsigned int type_index,
		 unsigned int entries, int socket_id, struct sfc_evq **evqp);
void sfc_ev_qfini(struct sfc_evq *evq);
int sfc_ev_qstart(struct sfc_evq *evq, unsigned int hw_index);
void sfc_ev_qstop(struct sfc_evq *evq);

int sfc_ev_qprime(struct sfc_evq *evq);
void sfc_ev_qpoll(struct sfc_evq *evq);

void sfc_ev_mgmt_qpoll(struct sfc_adapter *sa);

#ifdef __cplusplus
}
#endif
#endif /* _SFC_EV_H_ */
