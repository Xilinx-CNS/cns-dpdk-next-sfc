/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2019-2020 Xilinx, Inc.
 * Copyright(c) 2018-2019 Solarflare Communications Inc.
 */

#ifndef	_SYS_RHEAD_IMPL_H
#define	_SYS_RHEAD_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Riverhead requires physically contiguos event rings (so, just one
 * DMA address is sufficient to represent it), but MCDI interface is still
 * in terms of 4k size 4k-aligned DMA buffers.
 */
#define	RHEAD_EVQ_MAXNBUFS	32

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

extern	__checkReturn	efx_rc_t
rhead_nic_probe(
	__in		efx_nic_t *enp);

extern	__checkReturn	efx_rc_t
rhead_nic_set_drv_limits(
	__inout		efx_nic_t *enp,
	__in		efx_drv_limits_t *edlp);

extern	__checkReturn	efx_rc_t
rhead_nic_get_vi_pool(
	__in		efx_nic_t *enp,
	__out		uint32_t *vi_countp);

extern	__checkReturn	efx_rc_t
rhead_nic_get_bar_region(
	__in		efx_nic_t *enp,
	__in		efx_nic_region_t region,
	__out		uint32_t *offsetp,
	__out		size_t *sizep);

extern	__checkReturn	efx_rc_t
rhead_nic_reset(
	__in		efx_nic_t *enp);

extern	__checkReturn	efx_rc_t
rhead_nic_init(
	__in		efx_nic_t *enp);

extern	__checkReturn	boolean_t
rhead_nic_hw_unavailable(
	__in		efx_nic_t *enp);

extern			void
rhead_nic_set_hw_unavailable(
	__in		efx_nic_t *enp);

#if EFSYS_OPT_DIAG

extern	__checkReturn	efx_rc_t
rhead_nic_register_test(
	__in		efx_nic_t *enp);

#endif	/* EFSYS_OPT_DIAG */

extern			void
rhead_nic_fini(
	__in		efx_nic_t *enp);

extern			void
rhead_nic_unprobe(
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


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RHEAD_IMPL_H */
