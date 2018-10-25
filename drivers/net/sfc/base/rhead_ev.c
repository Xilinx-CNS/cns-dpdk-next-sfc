/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2018 Solarflare Communications Inc.
 * All rights reserved.
 */

#include "efx.h"
#include "efx_impl.h"
#if EFSYS_OPT_MON_STATS
#include "mcdi_mon.h"
#endif

#if EFSYS_OPT_RIVERHEAD

#if EFSYS_OPT_QSTATS
#define	EFX_EV_QSTAT_INCR(_eep, _stat)					\
	do {								\
		(_eep)->ee_stat[_stat]++;				\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)
#else
#define	EFX_EV_QSTAT_INCR(_eep, _stat)
#endif

/*
 * Non-interrupting event queue requires interrrupting event queue to
 * refer to for wake-up events even if wake ups are never used.
 * It could be even non-allocated event queue.
 */
#define	EFX_RHEAD_ALWAYS_INTERRUPTING_EVQ_INDEX	(0)

static	__checkReturn	boolean_t
rhead_ev_rx_pkts(
	__in		efx_evq_t *eep,
	__in		efx_qword_t *eqp,
	__in		const efx_ev_callbacks_t *eecp,
	__in_opt	void *arg);

static	__checkReturn	boolean_t
rhead_ev_tx_completion(
	__in		efx_evq_t *eep,
	__in		efx_qword_t *eqp,
	__in		const efx_ev_callbacks_t *eecp,
	__in_opt	void *arg);

static	__checkReturn	boolean_t
rhead_ev_mcdi(
	__in		efx_evq_t *eep,
	__in		efx_qword_t *eqp,
	__in		const efx_ev_callbacks_t *eecp,
	__in_opt	void *arg);


static	__checkReturn	efx_rc_t
efx_mcdi_init_evq(
	__in		efx_nic_t *enp,
	__in		unsigned int instance,
	__in		efsys_mem_t *esmp,
	__in		size_t nevs,
	__in		uint32_t irq,
	__in		uint32_t us,
	__in		uint32_t flags,
	__in		boolean_t low_latency)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload,
		MC_CMD_INIT_EVQ_V2_IN_LENMAX,
		MC_CMD_INIT_EVQ_OUT_LEN);
	efx_qword_t *dma_addr;
	uint64_t addr;
	int npages;
	int i;
	boolean_t interrupting;
	int ev_cut_through;
	efx_rc_t rc;

	npages = efx_evq_nbufs(enp, nevs);
	if (MC_CMD_INIT_EVQ_IN_LEN(npages) > MC_CMD_INIT_EVQ_IN_LENMAX) {
		rc = EINVAL;
		goto fail1;
	}

	req.emr_cmd = MC_CMD_INIT_EVQ;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_INIT_EVQ_IN_LEN(npages);
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_INIT_EVQ_OUT_LEN;

	MCDI_IN_SET_DWORD(req, INIT_EVQ_IN_SIZE, nevs);
	MCDI_IN_SET_DWORD(req, INIT_EVQ_IN_INSTANCE, instance);
	MCDI_IN_SET_DWORD(req, INIT_EVQ_IN_IRQ_NUM, irq);

	interrupting = ((flags & EFX_EVQ_FLAGS_NOTIFY_MASK) ==
	    EFX_EVQ_FLAGS_NOTIFY_INTERRUPT);

	/*
	 * On Huntington RX and TX event batching can only be requested together
	 * (even if the datapath firmware doesn't actually support RX
	 * batching). If event cut through is enabled no RX batching will occur.
	 *
	 * So always enable RX and TX event batching, and enable event cut
	 * through if we want low latency operation.
	 */
	switch (flags & EFX_EVQ_FLAGS_TYPE_MASK) {
	case EFX_EVQ_FLAGS_TYPE_AUTO:
		ev_cut_through = low_latency ? 1 : 0;
		break;
	case EFX_EVQ_FLAGS_TYPE_THROUGHPUT:
		ev_cut_through = 0;
		break;
	case EFX_EVQ_FLAGS_TYPE_LOW_LATENCY:
		ev_cut_through = 1;
		break;
	default:
		rc = EINVAL;
		goto fail2;
	}
	MCDI_IN_POPULATE_DWORD_6(req, INIT_EVQ_IN_FLAGS,
	    INIT_EVQ_IN_FLAG_INTERRUPTING, interrupting,
	    INIT_EVQ_IN_FLAG_RPTR_DOS, 0,
	    INIT_EVQ_IN_FLAG_INT_ARMD, 0,
	    INIT_EVQ_IN_FLAG_CUT_THRU, ev_cut_through,
	    INIT_EVQ_IN_FLAG_RX_MERGE, 1,
	    INIT_EVQ_IN_FLAG_TX_MERGE, 1);

	/* If the value is zero then disable the timer */
	if (us == 0) {
		MCDI_IN_SET_DWORD(req, INIT_EVQ_IN_TMR_MODE,
		    MC_CMD_INIT_EVQ_IN_TMR_MODE_DIS);
		MCDI_IN_SET_DWORD(req, INIT_EVQ_IN_TMR_LOAD, 0);
		MCDI_IN_SET_DWORD(req, INIT_EVQ_IN_TMR_RELOAD, 0);
	} else {
		unsigned int ticks;

		if ((rc = efx_ev_usecs_to_ticks(enp, us, &ticks)) != 0)
			goto fail3;

		MCDI_IN_SET_DWORD(req, INIT_EVQ_IN_TMR_MODE,
		    MC_CMD_INIT_EVQ_IN_TMR_INT_HLDOFF);
		MCDI_IN_SET_DWORD(req, INIT_EVQ_IN_TMR_LOAD, ticks);
		MCDI_IN_SET_DWORD(req, INIT_EVQ_IN_TMR_RELOAD, ticks);
	}

	MCDI_IN_SET_DWORD(req, INIT_EVQ_IN_COUNT_MODE,
	    MC_CMD_INIT_EVQ_IN_COUNT_MODE_DIS);
	MCDI_IN_SET_DWORD(req, INIT_EVQ_IN_COUNT_THRSHLD, 0);

	dma_addr = MCDI_IN2(req, efx_qword_t, INIT_EVQ_IN_DMA_ADDR);
	addr = EFSYS_MEM_ADDR(esmp);

	for (i = 0; i < npages; i++) {
		EFX_POPULATE_QWORD_2(*dma_addr,
		    EFX_DWORD_1, (uint32_t)(addr >> 32),
		    EFX_DWORD_0, (uint32_t)(addr & 0xffffffff));

		dma_addr++;
		addr += EFX_BUF_SIZE;
	}

	efx_mcdi_execute(enp, &req);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail4;
	}

	if (req.emr_out_length_used < MC_CMD_INIT_EVQ_OUT_LEN) {
		rc = EMSGSIZE;
		goto fail5;
	}

	/* NOTE: ignore the returned IRQ param as firmware does not set it. */

	return (0);

fail5:
	EFSYS_PROBE(fail5);
fail4:
	EFSYS_PROBE(fail4);
fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}


static	__checkReturn	efx_rc_t
efx_mcdi_init_evq_v2(
	__in		efx_nic_t *enp,
	__in		unsigned int instance,
	__in		efsys_mem_t *esmp,
	__in		size_t nevs,
	__in		uint32_t irq,
	__in		uint32_t us,
	__in		uint32_t flags)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload,
		MC_CMD_INIT_EVQ_V2_IN_LENMAX,
		MC_CMD_INIT_EVQ_V2_OUT_LEN);
	boolean_t interrupting;
	unsigned int evq_type;
	efx_qword_t *dma_addr;
	uint64_t addr;
	int npages;
	int i;
	efx_rc_t rc;

	npages = efx_evq_nbufs(enp, nevs);
	if (MC_CMD_INIT_EVQ_V2_IN_LEN(npages) > MC_CMD_INIT_EVQ_V2_IN_LENMAX) {
		rc = EINVAL;
		goto fail1;
	}

	req.emr_cmd = MC_CMD_INIT_EVQ;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_INIT_EVQ_V2_IN_LEN(npages);
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_INIT_EVQ_V2_OUT_LEN;

	MCDI_IN_SET_DWORD(req, INIT_EVQ_V2_IN_SIZE, nevs);
	MCDI_IN_SET_DWORD(req, INIT_EVQ_V2_IN_INSTANCE, instance);
	MCDI_IN_SET_DWORD(req, INIT_EVQ_V2_IN_IRQ_NUM, irq);

	interrupting = ((flags & EFX_EVQ_FLAGS_NOTIFY_MASK) ==
	    EFX_EVQ_FLAGS_NOTIFY_INTERRUPT);

	switch (flags & EFX_EVQ_FLAGS_TYPE_MASK) {
	case EFX_EVQ_FLAGS_TYPE_AUTO:
		evq_type = MC_CMD_INIT_EVQ_V2_IN_FLAG_TYPE_AUTO;
		break;
	case EFX_EVQ_FLAGS_TYPE_THROUGHPUT:
		evq_type = MC_CMD_INIT_EVQ_V2_IN_FLAG_TYPE_THROUGHPUT;
		break;
	case EFX_EVQ_FLAGS_TYPE_LOW_LATENCY:
		evq_type = MC_CMD_INIT_EVQ_V2_IN_FLAG_TYPE_LOW_LATENCY;
		break;
	default:
		rc = EINVAL;
		goto fail2;
	}
	MCDI_IN_POPULATE_DWORD_4(req, INIT_EVQ_V2_IN_FLAGS,
	    INIT_EVQ_V2_IN_FLAG_INTERRUPTING, interrupting,
	    INIT_EVQ_V2_IN_FLAG_RPTR_DOS, 0,
	    INIT_EVQ_V2_IN_FLAG_INT_ARMD, 0,
	    INIT_EVQ_V2_IN_FLAG_TYPE, evq_type);

	/* If the value is zero then disable the timer */
	if (us == 0) {
		MCDI_IN_SET_DWORD(req, INIT_EVQ_V2_IN_TMR_MODE,
		    MC_CMD_INIT_EVQ_V2_IN_TMR_MODE_DIS);
		MCDI_IN_SET_DWORD(req, INIT_EVQ_V2_IN_TMR_LOAD, 0);
		MCDI_IN_SET_DWORD(req, INIT_EVQ_V2_IN_TMR_RELOAD, 0);
	} else {
		unsigned int ticks;

		if ((rc = efx_ev_usecs_to_ticks(enp, us, &ticks)) != 0)
			goto fail3;

		MCDI_IN_SET_DWORD(req, INIT_EVQ_V2_IN_TMR_MODE,
		    MC_CMD_INIT_EVQ_V2_IN_TMR_INT_HLDOFF);
		MCDI_IN_SET_DWORD(req, INIT_EVQ_V2_IN_TMR_LOAD, ticks);
		MCDI_IN_SET_DWORD(req, INIT_EVQ_V2_IN_TMR_RELOAD, ticks);
	}

	MCDI_IN_SET_DWORD(req, INIT_EVQ_V2_IN_COUNT_MODE,
	    MC_CMD_INIT_EVQ_V2_IN_COUNT_MODE_DIS);
	MCDI_IN_SET_DWORD(req, INIT_EVQ_V2_IN_COUNT_THRSHLD, 0);

	dma_addr = MCDI_IN2(req, efx_qword_t, INIT_EVQ_V2_IN_DMA_ADDR);
	addr = EFSYS_MEM_ADDR(esmp);

	for (i = 0; i < npages; i++) {
		EFX_POPULATE_QWORD_2(*dma_addr,
		    EFX_DWORD_1, (uint32_t)(addr >> 32),
		    EFX_DWORD_0, (uint32_t)(addr & 0xffffffff));

		dma_addr++;
		addr += EFX_BUF_SIZE;
	}

	efx_mcdi_execute(enp, &req);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail4;
	}

	if (req.emr_out_length_used < MC_CMD_INIT_EVQ_V2_OUT_LEN) {
		rc = EMSGSIZE;
		goto fail5;
	}

	/* NOTE: ignore the returned IRQ param as firmware does not set it. */

	EFSYS_PROBE1(mcdi_evq_flags, uint32_t,
		    MCDI_OUT_DWORD(req, INIT_EVQ_V2_OUT_FLAGS));

	return (0);

fail5:
	EFSYS_PROBE(fail5);
fail4:
	EFSYS_PROBE(fail4);
fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

static	__checkReturn	efx_rc_t
efx_mcdi_fini_evq(
	__in		efx_nic_t *enp,
	__in		uint32_t instance)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload, MC_CMD_FINI_EVQ_IN_LEN,
		MC_CMD_FINI_EVQ_OUT_LEN);
	efx_rc_t rc;

	req.emr_cmd = MC_CMD_FINI_EVQ;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_FINI_EVQ_IN_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_FINI_EVQ_OUT_LEN;

	MCDI_IN_SET_DWORD(req, FINI_EVQ_IN_INSTANCE, instance);

	efx_mcdi_execute_quiet(enp, &req);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail1;
	}

	return (0);

fail1:
	/*
	 * EALREADY is not an error, but indicates that the MC has rebooted and
	 * that the EVQ has already been destroyed.
	 */
	if (rc != EALREADY)
		EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}



	__checkReturn	efx_rc_t
rhead_ev_init(
	__in		efx_nic_t *enp)
{
	_NOTE(ARGUNUSED(enp))
	return (0);
}

			void
rhead_ev_fini(
	__in		efx_nic_t *enp)
{
	_NOTE(ARGUNUSED(enp))
}

	__checkReturn	efx_rc_t
rhead_ev_qcreate(
	__in		efx_nic_t *enp,
	__in		unsigned int index,
	__in		efsys_mem_t *esmp,
	__in		size_t ndescs,
	__in		uint32_t id,
	__in		uint32_t us,
	__in		uint32_t flags,
	__in		efx_evq_t *eep)
{
	efx_nic_cfg_t *encp = &(enp->en_nic_cfg);
	uint32_t irq;
	efx_rc_t rc;

	_NOTE(ARGUNUSED(id))	/* buftbl id managed by MC */
	EFSYS_ASSERT(ISP2(encp->enc_evq_max_nevs));
	EFSYS_ASSERT(ISP2(encp->enc_evq_min_nevs));

	if (index >= encp->enc_evq_limit) {
		rc = EINVAL;
		goto fail1;
	}

	if (us > encp->enc_evq_timer_max_us) {
		rc = EINVAL;
		goto fail2;
	}

	/* Set up the handler table */
	eep->ee_rx	= rhead_ev_rx_pkts;
	eep->ee_tx	= rhead_ev_tx_completion;
	eep->ee_mcdi	= rhead_ev_mcdi;

	/* Set up the event queue */
	/* INIT_EVQ expects function-relative vector number */
	if ((flags & EFX_EVQ_FLAGS_NOTIFY_MASK) ==
	    EFX_EVQ_FLAGS_NOTIFY_INTERRUPT) {
		irq = index;
	} else if (index == EFX_RHEAD_ALWAYS_INTERRUPTING_EVQ_INDEX) {
		irq = index;
		flags = (flags & ~EFX_EVQ_FLAGS_NOTIFY_MASK) |
		    EFX_EVQ_FLAGS_NOTIFY_INTERRUPT;
	} else {
		irq = EFX_RHEAD_ALWAYS_INTERRUPTING_EVQ_INDEX;
	}

	/*
	 * Interrupts may be raised for events immediately after the queue is
	 * created. See bug58606.
	 */

	if (encp->enc_init_evq_v2_supported) {
		/*
		 * On Medford the low latency license is required to enable RX
		 * and event cut through and to disable RX batching.  If event
		 * queue type in flags is auto, we let the firmware decide the
		 * settings to use. If the adapter has a low latency license,
		 * it will choose the best settings for low latency, otherwise
		 * it will choose the best settings for throughput.
		 */
		rc = efx_mcdi_init_evq_v2(enp, index, esmp, ndescs, irq, us,
		    flags);
		if (rc != 0)
			goto fail3;
	} else {
		/*
		 * On Huntington we need to specify the settings to use.
		 * If event queue type in flags is auto, we favour throughput
		 * if the adapter is running virtualization supporting firmware
		 * (i.e. the full featured firmware variant)
		 * and latency otherwise. The Ethernet Virtual Bridging
		 * capability is used to make this decision. (Note though that
		 * the low latency firmware variant is also best for
		 * throughput and corresponding type should be specified
		 * to choose it.)
		 */
		boolean_t low_latency = encp->enc_datapath_cap_evb ? 0 : 1;
		rc = efx_mcdi_init_evq(enp, index, esmp, ndescs, irq, us, flags,
		    low_latency);
		if (rc != 0)
			goto fail4;
	}

	return (0);

fail4:
	EFSYS_PROBE(fail4);
fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

			void
rhead_ev_qdestroy(
	__in		efx_evq_t *eep)
{
	efx_nic_t *enp = eep->ee_enp;

	EFSYS_ASSERT(enp->en_family == EFX_FAMILY_RIVERHEAD);

	(void) efx_mcdi_fini_evq(enp, eep->ee_index);
}

	__checkReturn	efx_rc_t
rhead_ev_qprime(
	__in		efx_evq_t *eep,
	__in		unsigned int count)
{
	_NOTE(ARGUNUSED(eep))
	_NOTE(ARGUNUSED(count))
	return (ENOTSUP);
}

static	__checkReturn	efx_rc_t
efx_mcdi_driver_event(
	__in		efx_nic_t *enp,
	__in		uint32_t evq,
	__in		efx_qword_t data)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload, MC_CMD_DRIVER_EVENT_IN_LEN,
		MC_CMD_DRIVER_EVENT_OUT_LEN);
	efx_rc_t rc;

	req.emr_cmd = MC_CMD_DRIVER_EVENT;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_DRIVER_EVENT_IN_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_DRIVER_EVENT_OUT_LEN;

	MCDI_IN_SET_DWORD(req, DRIVER_EVENT_IN_EVQ, evq);

	MCDI_IN_SET_DWORD(req, DRIVER_EVENT_IN_DATA_LO,
	    EFX_QWORD_FIELD(data, EFX_DWORD_0));
	MCDI_IN_SET_DWORD(req, DRIVER_EVENT_IN_DATA_HI,
	    EFX_QWORD_FIELD(data, EFX_DWORD_1));

	efx_mcdi_execute(enp, &req);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail1;
	}

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

			void
rhead_ev_qpost(
	__in	efx_evq_t *eep,
	__in	uint16_t data)
{
	efx_nic_t *enp = eep->ee_enp;
	efx_qword_t event;

	EFX_POPULATE_QWORD_3(event,
	    ESF_DZ_DRV_CODE, ESE_DZ_EV_CODE_DRV_GEN_EV,
	    ESF_DZ_DRV_SUB_CODE, 0,
	    ESF_DZ_DRV_SUB_DATA_DW0, (uint32_t)data);

	(void) efx_mcdi_driver_event(enp, eep->ee_index, event);
}

#define	EF100_EV_BATCH	8

#define	EF100_EV_PRESENT(_qword, _phase_bit)				\
	(EFX_QWORD_FIELD((_qword), ESF_GZ_EV_EVQ_PHASE) == _phase_bit)

			void
rhead_ev_qpoll(
	__in		efx_evq_t *eep,
	__inout		unsigned int *countp,
	__in		const efx_ev_callbacks_t *eecp,
	__in_opt	void *arg)
{
	efx_qword_t ev[EF100_EV_BATCH];
	unsigned int batch;
	unsigned int phase_bit;
	unsigned int total;
	unsigned int count;
	unsigned int index;
	size_t offset;

	EFSYS_ASSERT3U(eep->ee_magic, ==, EFX_EVQ_MAGIC);
	EFSYS_ASSERT(countp != NULL);
	EFSYS_ASSERT(eecp != NULL);

	count = *countp;
	do {
		/* Read up until the end of the batch period */
		batch = EF100_EV_BATCH - (count & (EF100_EV_BATCH - 1));
		phase_bit = (count >> eep->ee_size_log2) & 1;
		offset = (count & eep->ee_mask) * sizeof (efx_qword_t);
		for (total = 0; total < batch; ++total) {
			EFSYS_MEM_READQ(eep->ee_esmp, offset, &(ev[total]));

			if (!EF100_EV_PRESENT(ev[total], phase_bit))
				break;

			EFSYS_PROBE3(event, unsigned int, eep->ee_index,
			    uint32_t, EFX_QWORD_FIELD(ev[total], EFX_DWORD_1),
			    uint32_t, EFX_QWORD_FIELD(ev[total], EFX_DWORD_0));

			offset += sizeof (efx_qword_t);
		}

#if EFSYS_OPT_EV_PREFETCH && (EFSYS_OPT_EV_PREFETCH_PERIOD > 1)
		/*
		 * Prefetch the next batch when we get within PREFETCH_PERIOD
		 * of a completed batch. If the batch is smaller, then prefetch
		 * immediately.
		 */
		if (total == batch && total < EFSYS_OPT_EV_PREFETCH_PERIOD)
			EFSYS_MEM_PREFETCH(eep->ee_esmp, offset);
#endif	/* EFSYS_OPT_EV_PREFETCH */

		/* Process the batch of events */
		for (index = 0; index < total; ++index) {
			boolean_t should_abort;
			uint32_t code;

#if EFSYS_OPT_EV_PREFETCH
			/* Prefetch if we've now reached the batch period */
			if (total == batch &&
			    index + EFSYS_OPT_EV_PREFETCH_PERIOD == total) {
				offset = (count + batch) & eep->ee_mask;
				offset *= sizeof (efx_qword_t);

				EFSYS_MEM_PREFETCH(eep->ee_esmp, offset);
			}
#endif	/* EFSYS_OPT_EV_PREFETCH */

			EFX_EV_QSTAT_INCR(eep, EV_ALL);

			code = EFX_QWORD_FIELD(ev[index], ESF_GZ_EV_TYPE);
			switch (code) {
			case ESE_GZ_EF100_EV_RX_PKTS:
				should_abort = eep->ee_rx(eep,
				    &(ev[index]), eecp, arg);
				break;
			case ESE_GZ_EF100_EV_TX_COMPLETION:
				should_abort = eep->ee_tx(eep,
				    &(ev[index]), eecp, arg);
				break;
			case ESE_GZ_EF100_EV_MCDI: {
				efx_qword_t ef10_mcdi_ev;

				/* Recode EF100 MCDI event to EF10 */
				EFX_POPULATE_QWORD_5(ef10_mcdi_ev,
				    MCDI_EVENT_DATA,
				    EFX_QWORD_FIELD(ev[index],
						    EF100_MCDI_EVENT_DATA),
				    MCDI_EVENT_CONT,
				    EFX_QWORD_FIELD(ev[index],
						    EF100_MCDI_EVENT_CONT),
				    MCDI_EVENT_LEVEL,
				    EFX_QWORD_FIELD(ev[index],
						    EF100_MCDI_EVENT_LEVEL),
				    MCDI_EVENT_SRC,
				    EFX_QWORD_FIELD(ev[index],
						    EF100_MCDI_EVENT_PTP_DATA),
				    MCDI_EVENT_CODE,
				    EFX_QWORD_FIELD(ev[index],
						    EF100_MCDI_EVENT_CODE));
				should_abort = eep->ee_mcdi(eep,
				    &ef10_mcdi_ev, eecp, arg);
				break;
			}
			default:
				EFSYS_PROBE3(bad_event,
				    unsigned int, eep->ee_index,
				    uint32_t,
				    EFX_QWORD_FIELD(ev[index], EFX_DWORD_1),
				    uint32_t,
				    EFX_QWORD_FIELD(ev[index], EFX_DWORD_0));

				EFSYS_ASSERT(eecp->eec_exception != NULL);
				(void) eecp->eec_exception(arg,
					EFX_EXCEPTION_EV_ERROR, code);
				should_abort = B_TRUE;
			}
			if (should_abort) {
				/* Ignore subsequent events */
				total = index + 1;
				break;
			}
		}

		/*
		 * There is no necessity to clear processed events since
		 * phase bit which is flipping on each write index wrap
		 * is used for event presence indication.
		 */

		count += total;

	} while (total == batch);

	*countp = count;
}

	__checkReturn	efx_rc_t
rhead_ev_qmoderate(
	__in		efx_evq_t *eep,
	__in		unsigned int us)
{
	_NOTE(ARGUNUSED(eep))
	_NOTE(ARGUNUSED(us))
	return (ENOTSUP);
}


#if EFSYS_OPT_QSTATS
			void
rhead_ev_qstats_update(
	__in				efx_evq_t *eep,
	__inout_ecount(EV_NQSTATS)	efsys_stat_t *stat)
{
	unsigned int id;

	for (id = 0; id < EV_NQSTATS; id++) {
		efsys_stat_t *essp = &stat[id];

		EFSYS_STAT_INCR(essp, eep->ee_stat[id]);
		eep->ee_stat[id] = 0;
	}
}
#endif /* EFSYS_OPT_QSTATS */

static	__checkReturn	boolean_t
rhead_ev_rx_pkts(
	__in		efx_evq_t *eep,
	__in		efx_qword_t *eqp,
	__in		const efx_ev_callbacks_t *eecp,
	__in_opt	void *arg)
{
	efx_nic_t *enp = eep->ee_enp;
	uint32_t size;
	uint32_t label;
	uint32_t num_pkt_lbits;
	efx_evq_rxq_state_t *eersp;
	unsigned int pkt_count;
	boolean_t should_abort;

	EFX_EV_QSTAT_INCR(eep, EV_RX);

	/* Discard events after RXQ/TXQ errors, or hardware not available */
	if (enp->en_reset_flags &
	    (EFX_RESET_RXQ_ERR | EFX_RESET_TXQ_ERR | EFX_RESET_HW_UNAVAIL))
		return (B_FALSE);

	/* Basic packet information */
	label = EFX_QWORD_FIELD(*eqp, ESF_GZ_EV_Q_LABEL);
	eersp = &eep->ee_rxq_state[label];

	num_pkt_lbits = EFX_QWORD_FIELD(*eqp, ESF_GZ_EV_NUM_PACKETS);

	/* Increment the count of descriptors read */
	pkt_count = (num_pkt_lbits - eersp->eers_rx_read_ptr) &
	    EFX_MASK32(ESF_GZ_EV_NUM_PACKETS);
	eersp->eers_rx_read_ptr += pkt_count;

	EFSYS_PROBE2(rx_complete, uint32_t, label, uint32_t, pkt_count);

	EFSYS_ASSERT(eecp->eec_rx != NULL);
	should_abort = eecp->eec_rx(arg, label, pkt_count, 0, 0);

	return (should_abort);
}

static	__checkReturn	boolean_t
rhead_ev_tx_completion(
	__in		efx_evq_t *eep,
	__in		efx_qword_t *eqp,
	__in		const efx_ev_callbacks_t *eecp,
	__in_opt	void *arg)
{
	efx_nic_t *enp = eep->ee_enp;
	uint32_t num_descs_lbits;
	uint32_t label;
	boolean_t should_abort;

	EFX_EV_QSTAT_INCR(eep, EV_TX);

	/* Discard events after RXQ/TXQ errors, or hardware not available */
	if (enp->en_reset_flags &
	    (EFX_RESET_RXQ_ERR | EFX_RESET_TXQ_ERR | EFX_RESET_HW_UNAVAIL))
		return (B_FALSE);

	num_descs_lbits = EFX_QWORD_FIELD(*eqp, ESF_GZ_EV_NUM_DESCS);
	label = EFX_QWORD_FIELD(*eqp, ESF_GZ_EV_Q_LABEL);

	EFSYS_PROBE2(tx_complete, uint32_t, label, uint32_t, num_descs_lbits);

	EFSYS_ASSERT(eecp->eec_tx != NULL);
	should_abort = eecp->eec_tx(arg, label, num_descs_lbits);

	return (should_abort);
}

static	__checkReturn	boolean_t
rhead_ev_mcdi(
	__in		efx_evq_t *eep,
	__in		efx_qword_t *eqp,
	__in		const efx_ev_callbacks_t *eecp,
	__in_opt	void *arg)
{
	efx_nic_t *enp = eep->ee_enp;
	unsigned int code;
	boolean_t should_abort = B_FALSE;

	EFX_EV_QSTAT_INCR(eep, EV_MCDI_RESPONSE);

	code = EFX_QWORD_FIELD(*eqp, MCDI_EVENT_CODE);
	switch (code) {
	case MCDI_EVENT_CODE_BADSSERT:
		efx_mcdi_ev_death(enp, EINTR);
		break;

	case MCDI_EVENT_CODE_CMDDONE:
		efx_mcdi_ev_cpl(enp,
		    MCDI_EV_FIELD(eqp, CMDDONE_SEQ),
		    MCDI_EV_FIELD(eqp, CMDDONE_DATALEN),
		    MCDI_EV_FIELD(eqp, CMDDONE_ERRNO));
		break;

#if EFSYS_OPT_MCDI_PROXY_AUTH
	case MCDI_EVENT_CODE_PROXY_RESPONSE:
		/*
		 * This event notifies a function that an authorization request
		 * has been processed. If the request was authorized then the
		 * function can now re-send the original MCDI request.
		 * See SF-113652-SW "SR-IOV Proxied Network Access Control".
		 */
		efx_mcdi_ev_proxy_response(enp,
		    MCDI_EV_FIELD(eqp, PROXY_RESPONSE_HANDLE),
		    MCDI_EV_FIELD(eqp, PROXY_RESPONSE_RC));
		break;
#endif /* EFSYS_OPT_MCDI_PROXY_AUTH */

	case MCDI_EVENT_CODE_LINKCHANGE: {
		efx_link_mode_t link_mode;

		ef10_phy_link_ev(enp, eqp, &link_mode);
		should_abort = eecp->eec_link_change(arg, link_mode);
		break;
	}

	case MCDI_EVENT_CODE_SENSOREVT: {
#if EFSYS_OPT_MON_STATS
		efx_mon_stat_t id;
		efx_mon_stat_value_t value;
		efx_rc_t rc;

		/* Decode monitor stat for MCDI sensor (if supported) */
		if ((rc = mcdi_mon_ev(enp, eqp, &id, &value)) == 0) {
			/* Report monitor stat change */
			should_abort = eecp->eec_monitor(arg, id, value);
		} else if (rc == ENOTSUP) {
			should_abort = eecp->eec_exception(arg,
				EFX_EXCEPTION_UNKNOWN_SENSOREVT,
				MCDI_EV_FIELD(eqp, DATA));
		} else {
			EFSYS_ASSERT(rc == ENODEV);	/* Wrong port */
		}
#endif
		break;
	}

	case MCDI_EVENT_CODE_SCHEDERR:
		/* Informational only */
		break;

	case MCDI_EVENT_CODE_REBOOT:
		/* Falcon/Siena only (should not been seen with Huntington). */
		efx_mcdi_ev_death(enp, EIO);
		break;

	case MCDI_EVENT_CODE_MC_REBOOT:
		/* MC_REBOOT event is used for Huntington (EF10) and later. */
		efx_mcdi_ev_death(enp, EIO);
		break;

	case MCDI_EVENT_CODE_MAC_STATS_DMA:
#if EFSYS_OPT_MAC_STATS
		if (eecp->eec_mac_stats != NULL) {
			eecp->eec_mac_stats(arg,
			    MCDI_EV_FIELD(eqp, MAC_STATS_DMA_GENERATION));
		}
#endif
		break;

	case MCDI_EVENT_CODE_FWALERT: {
		uint32_t reason = MCDI_EV_FIELD(eqp, FWALERT_REASON);

		if (reason == MCDI_EVENT_FWALERT_REASON_SRAM_ACCESS)
			should_abort = eecp->eec_exception(arg,
				EFX_EXCEPTION_FWALERT_SRAM,
				MCDI_EV_FIELD(eqp, FWALERT_DATA));
		else
			should_abort = eecp->eec_exception(arg,
				EFX_EXCEPTION_UNKNOWN_FWALERT,
				MCDI_EV_FIELD(eqp, DATA));
		break;
	}

	case MCDI_EVENT_CODE_TX_ERR: {
		/*
		 * After a TXQ error is detected, firmware sends a TX_ERR event.
		 * This may be followed by TX completions (which we discard),
		 * and then finally by a TX_FLUSH event. Firmware destroys the
		 * TXQ automatically after sending the TX_FLUSH event.
		 */
		enp->en_reset_flags |= EFX_RESET_TXQ_ERR;

		EFSYS_PROBE2(tx_descq_err,
			    uint32_t, EFX_QWORD_FIELD(*eqp, EFX_DWORD_1),
			    uint32_t, EFX_QWORD_FIELD(*eqp, EFX_DWORD_0));

		/* Inform the driver that a reset is required. */
		eecp->eec_exception(arg, EFX_EXCEPTION_TX_ERROR,
		    MCDI_EV_FIELD(eqp, TX_ERR_DATA));
		break;
	}

	case MCDI_EVENT_CODE_TX_FLUSH: {
		uint32_t txq_index = MCDI_EV_FIELD(eqp, TX_FLUSH_TXQ);

		/*
		 * EF10 firmware sends two TX_FLUSH events: one to the txq's
		 * event queue, and one to evq 0 (with TX_FLUSH_TO_DRIVER set).
		 * We want to wait for all completions, so ignore the events
		 * with TX_FLUSH_TO_DRIVER.
		 */
		if (MCDI_EV_FIELD(eqp, TX_FLUSH_TO_DRIVER) != 0) {
			should_abort = B_FALSE;
			break;
		}

		EFX_EV_QSTAT_INCR(eep, EV_DRIVER_TX_DESCQ_FLS_DONE);

		EFSYS_PROBE1(tx_descq_fls_done, uint32_t, txq_index);

		EFSYS_ASSERT(eecp->eec_txq_flush_done != NULL);
		should_abort = eecp->eec_txq_flush_done(arg, txq_index);
		break;
	}

	case MCDI_EVENT_CODE_RX_ERR: {
		/*
		 * After an RXQ error is detected, firmware sends an RX_ERR
		 * event. This may be followed by RX events (which we discard),
		 * and then finally by an RX_FLUSH event. Firmware destroys the
		 * RXQ automatically after sending the RX_FLUSH event.
		 */
		enp->en_reset_flags |= EFX_RESET_RXQ_ERR;

		EFSYS_PROBE2(rx_descq_err,
			    uint32_t, EFX_QWORD_FIELD(*eqp, EFX_DWORD_1),
			    uint32_t, EFX_QWORD_FIELD(*eqp, EFX_DWORD_0));

		/* Inform the driver that a reset is required. */
		eecp->eec_exception(arg, EFX_EXCEPTION_RX_ERROR,
		    MCDI_EV_FIELD(eqp, RX_ERR_DATA));
		break;
	}

	case MCDI_EVENT_CODE_RX_FLUSH: {
		uint32_t rxq_index = MCDI_EV_FIELD(eqp, RX_FLUSH_RXQ);

		/*
		 * EF10 firmware sends two RX_FLUSH events: one to the rxq's
		 * event queue, and one to evq 0 (with RX_FLUSH_TO_DRIVER set).
		 * We want to wait for all completions, so ignore the events
		 * with RX_FLUSH_TO_DRIVER.
		 */
		if (MCDI_EV_FIELD(eqp, RX_FLUSH_TO_DRIVER) != 0) {
			should_abort = B_FALSE;
			break;
		}

		EFX_EV_QSTAT_INCR(eep, EV_DRIVER_RX_DESCQ_FLS_DONE);

		EFSYS_PROBE1(rx_descq_fls_done, uint32_t, rxq_index);

		EFSYS_ASSERT(eecp->eec_rxq_flush_done != NULL);
		should_abort = eecp->eec_rxq_flush_done(arg, rxq_index);
		break;
	}

	default:
		EFSYS_PROBE3(bad_event, unsigned int, eep->ee_index,
		    uint32_t, EFX_QWORD_FIELD(*eqp, EFX_DWORD_1),
		    uint32_t, EFX_QWORD_FIELD(*eqp, EFX_DWORD_0));
		break;
	}

	return (should_abort);
}

		void
rhead_ev_rxlabel_init(
	__in		efx_evq_t *eep,
	__in		efx_rxq_t *erp,
	__in		unsigned int label,
	__in		efx_rxq_type_t type)
{
	efx_evq_rxq_state_t *eersp;

	_NOTE(ARGUNUSED(type))
	EFSYS_ASSERT3U(label, <, EFX_ARRAY_SIZE(eep->ee_rxq_state));
	eersp = &eep->ee_rxq_state[label];

	EFSYS_ASSERT3U(eersp->eers_rx_mask, ==, 0);

	eersp->eers_rx_read_ptr = 0;
	eersp->eers_rx_mask = erp->er_mask;
}

		void
rhead_ev_rxlabel_fini(
	__in		efx_evq_t *eep,
	__in		unsigned int label)
{
	efx_evq_rxq_state_t *eersp;

	EFSYS_ASSERT3U(label, <, EFX_ARRAY_SIZE(eep->ee_rxq_state));
	eersp = &eep->ee_rxq_state[label];

	EFSYS_ASSERT3U(eersp->eers_rx_mask, !=, 0);

	eersp->eers_rx_read_ptr = 0;
	eersp->eers_rx_mask = 0;
}

#endif	/* EFSYS_OPT_RIVERHEAD */
