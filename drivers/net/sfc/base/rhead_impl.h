/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2018 Solarflare Communications Inc.
 * All rights reserved.
 */

#ifndef	_SYS_RHEAD_IMPL_H
#define	_SYS_RHEAD_IMPL_H

#include "efx_mcdi.h"

#ifdef	__cplusplus
extern "C" {
#endif


#define	RHEAD_EVQ_MAXNEVS	16384
#define	RHEAD_EVQ_MINNEVS	256

#define	RHEAD_RXQ_MAXNDESCS	16384
#define	RHEAD_RXQ_MINNDESCS	256

#define	RHEAD_TXQ_MAXNDESCS	16384
#define	RHEAD_TXQ_MINNDESCS	256

#define	RHEAD_EVQ_DESC_SIZE	(sizeof (efx_qword_t))
#define	RHEAD_RXQ_DESC_SIZE	(sizeof (efx_qword_t))
#define	RHEAD_TXQ_DESC_SIZE	(sizeof (efx_oword_t))


/* NIC */

extern	__checkReturn	efx_rc_t
rhead_board_cfg(
	__in		efx_nic_t *enp);


/* EV */

	__checkReturn	efx_rc_t
rhead_ev_init(
	__in		efx_nic_t *enp);

			void
rhead_ev_fini(
	__in		efx_nic_t *enp);

	__checkReturn	efx_rc_t
rhead_ev_qcreate(
	__in		efx_nic_t *enp,
	__in		unsigned int index,
	__in		efsys_mem_t *esmp,
	__in		size_t ndescs,
	__in		uint32_t id,
	__in		uint32_t us,
	__in		uint32_t flags,
	__in		efx_evq_t *eep);

			void
rhead_ev_qdestroy(
	__in		efx_evq_t *eep);

	__checkReturn	efx_rc_t
rhead_ev_qprime(
	__in		efx_evq_t *eep,
	__in		unsigned int count);

			void
rhead_ev_qpost(
	__in	efx_evq_t *eep,
	__in	uint16_t data);

			void
rhead_ev_qpoll(
	__in		efx_evq_t *eep,
	__inout		unsigned int *countp,
	__in		const efx_ev_callbacks_t *eecp,
	__in_opt	void *arg);

	__checkReturn	efx_rc_t
rhead_ev_qmoderate(
	__in		efx_evq_t *eep,
	__in		unsigned int us);

#if EFSYS_OPT_QSTATS
			void
rhead_ev_qstats_update(
	__in				efx_evq_t *eep,
	__inout_ecount(EV_NQSTATS)	efsys_stat_t *stat);
#endif /* EFSYS_OPT_QSTATS */

		void
rhead_ev_rxlabel_init(
	__in		efx_evq_t *eep,
	__in		efx_rxq_t *erp,
	__in		unsigned int label,
	__in		efx_rxq_type_t type);

		void
rhead_ev_rxlabel_fini(
	__in		efx_evq_t *eep,
	__in		unsigned int label);


/* INTR */

	__checkReturn	efx_rc_t
rhead_intr_init(
	__in		efx_nic_t *enp,
	__in		efx_intr_type_t type,
	__in		efsys_mem_t *esmp);

			void
rhead_intr_enable(
	__in		efx_nic_t *enp);

			void
rhead_intr_disable(
	__in		efx_nic_t *enp);

			void
rhead_intr_disable_unlocked(
	__in		efx_nic_t *enp);

	__checkReturn	efx_rc_t
rhead_intr_trigger(
	__in		efx_nic_t *enp,
	__in		unsigned int level);

			void
rhead_intr_status_line(
	__in		efx_nic_t *enp,
	__out		boolean_t *fatalp,
	__out		uint32_t *qmaskp);

			void
rhead_intr_status_message(
	__in		efx_nic_t *enp,
	__in		unsigned int message,
	__out		boolean_t *fatalp);

			void
rhead_intr_fatal(
	__in		efx_nic_t *enp);
			void
rhead_intr_fini(
	__in		efx_nic_t *enp);


/* RX */

#if EFSYS_OPT_RX_SCATTER
extern	__checkReturn	efx_rc_t
rhead_rx_scatter_enable(
	__in		efx_nic_t *enp,
	__in		unsigned int buf_size);
#endif	/* EFSYS_OPT_RX_SCATTER */

#if EFSYS_OPT_RX_SCALE

extern	__checkReturn	uint32_t
rhead_rx_prefix_hash(
	__in		efx_nic_t *enp,
	__in		efx_rx_hash_alg_t func,
	__in		uint8_t *buffer);

#endif /* EFSYS_OPT_RX_SCALE */

extern	__checkReturn	efx_rc_t
rhead_rx_prefix_pktlen(
	__in		efx_nic_t *enp,
	__in		uint8_t *buffer,
	__out		uint16_t *lengthp);

extern				void
rhead_rx_qpost(
	__in			efx_rxq_t *erp,
	__in_ecount(ndescs)	efsys_dma_addr_t *addrp,
	__in			size_t size,
	__in			unsigned int ndescs,
	__in			unsigned int completed,
	__in			unsigned int added);

extern			void
rhead_rx_qpush(
	__in		efx_rxq_t *erp,
	__in		unsigned int added,
	__inout		unsigned int *pushedp);

extern	__checkReturn	efx_rc_t
rhead_rx_qflush(
	__in		efx_rxq_t *erp);

extern		void
rhead_rx_qenable(
	__in		efx_rxq_t *erp);

union efx_rxq_type_data_u;

extern	__checkReturn	efx_rc_t
rhead_rx_qcreate(
	__in		efx_nic_t *enp,
	__in		unsigned int index,
	__in		unsigned int label,
	__in		efx_rxq_type_t type,
	__in		const union efx_rxq_type_data_u *type_data,
	__in		efsys_mem_t *esmp,
	__in		size_t ndescs,
	__in		uint32_t id,
	__in		unsigned int flags,
	__in		efx_evq_t *eep,
	__in		efx_rxq_t *erp);

extern			void
rhead_rx_qdestroy(
	__in		efx_rxq_t *erp);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RHEAD_IMPL_H */
