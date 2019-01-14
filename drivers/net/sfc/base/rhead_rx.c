/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2018-2019 Solarflare Communications Inc.
 * All rights reserved.
 */

#include "efx.h"
#include "efx_impl.h"


#if EFSYS_OPT_RIVERHEAD

	__checkReturn	efx_rc_t
rhead_rx_init(
	__in		efx_nic_t *enp)
{
	efx_rc_t rc;

	rc = ef10_rx_init(enp);
	if (rc != 0)
		goto fail1;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

		void
rhead_rx_fini(
	__in	efx_nic_t *enp)
{
	ef10_rx_fini(enp);
}

#if EFSYS_OPT_RX_SCATTER
	__checkReturn	efx_rc_t
rhead_rx_scatter_enable(
	__in		efx_nic_t *enp,
	__in		unsigned int buf_size)
{
	_NOTE(ARGUNUSED(enp, buf_size))
	/* Nothing to do here */
	return (0);
}
#endif	/* EFSYS_OPT_RX_SCATTER */

#if EFSYS_OPT_RX_SCALE

	__checkReturn	efx_rc_t
rhead_rx_scale_context_alloc(
	__in		efx_nic_t *enp,
	__in		efx_rx_scale_context_type_t type,
	__in		uint32_t num_queues,
	__out		uint32_t *rss_contextp)
{
	efx_rc_t rc;

	rc = ef10_rx_scale_context_alloc(enp, type, num_queues, rss_contextp);
	if (rc != 0)
		goto fail1;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

	__checkReturn	efx_rc_t
rhead_rx_scale_context_free(
	__in		efx_nic_t *enp,
	__in		uint32_t rss_context)
{
	efx_rc_t rc;

	rc = ef10_rx_scale_context_free(enp, rss_context);
	if (rc != 0)
		goto fail1;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

	__checkReturn	efx_rc_t
rhead_rx_scale_mode_set(
	__in		efx_nic_t *enp,
	__in		uint32_t rss_context,
	__in		efx_rx_hash_alg_t alg,
	__in		efx_rx_hash_type_t type,
	__in		boolean_t insert)
{
	efx_rc_t rc;

	rc = ef10_rx_scale_mode_set(enp, rss_context, alg, type, insert);
	if (rc != 0)
		goto fail1;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

	__checkReturn	efx_rc_t
rhead_rx_scale_key_set(
	__in		efx_nic_t *enp,
	__in		uint32_t rss_context,
	__in_ecount(n)	uint8_t *key,
	__in		size_t n)
{
	efx_rc_t rc;

	rc = ef10_rx_scale_key_set(enp, rss_context, key, n);
	if (rc != 0)
		goto fail1;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

	__checkReturn	efx_rc_t
rhead_rx_scale_tbl_set(
	__in		efx_nic_t *enp,
	__in		uint32_t rss_context,
	__in_ecount(n)	unsigned int *table,
	__in		size_t n)
{
	efx_rc_t rc;

	rc = ef10_rx_scale_tbl_set(enp, rss_context, table, n);
	if (rc != 0)
		goto fail1;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

	__checkReturn	uint32_t
rhead_rx_prefix_hash(
	__in		efx_nic_t *enp,
	__in		efx_rx_hash_alg_t func,
	__in		uint8_t *buffer)
{
	const efx_oword_t *rx_prefix = (const efx_oword_t *)buffer;

	_NOTE(ARGUNUSED(enp))

	switch (func) {
	case EFX_RX_HASHALG_TOEPLITZ:
		if (EFX_TEST_OWORD_BIT(rx_prefix[0], ESF_GZ_RSS_HSH_VALID_LBN))
			return (EFX_OWORD_FIELD(rx_prefix[0], ESF_GZ_RSS_HASH));
		else
			return (0);

	default:
		EFSYS_ASSERT(0);
		return (0);
	}
}

#endif /* EFSYS_OPT_RX_SCALE */

	__checkReturn	efx_rc_t
rhead_rx_prefix_pktlen(
	__in		efx_nic_t *enp,
	__in		uint8_t *buffer,
	__out		uint16_t *lengthp)
{
	const efx_oword_t *rx_prefix = (const efx_oword_t *)buffer;

	_NOTE(ARGUNUSED(enp))

	*lengthp = EFX_OWORD_FIELD(rx_prefix[0], ESF_GZ_LEN);
	return (0);
}

				void
rhead_rx_qpost(
	__in			efx_rxq_t *erp,
	__in_ecount(ndescs)	efsys_dma_addr_t *addrp,
	__in			size_t size,
	__in			unsigned int ndescs,
	__in			unsigned int completed,
	__in			unsigned int added)
{
	efx_qword_t qword;
	unsigned int i;
	unsigned int offset;
	unsigned int id;

	_NOTE(ARGUNUSED(size))
	_NOTE(ARGUNUSED(completed))

	/* The client driver must not overfill the queue */
	EFSYS_ASSERT3U(added - completed + ndescs, <=,
	    EFX_RXQ_LIMIT(erp->er_mask + 1));

	id = added & erp->er_mask;
	for (i = 0; i < ndescs; i++) {
		EFSYS_PROBE4(rx_post, unsigned int, erp->er_index,
		    unsigned int, id, efsys_dma_addr_t, addrp[i],
		    size_t, size);

		EFX_STATIC_ASSERT(sizeof (qword) == RHEAD_RXQ_DESC_SIZE);
		EFX_POPULATE_QWORD_1(qword, ESF_GZ_RX_BUF_ADDR, addrp[i]);

		offset = id * RHEAD_RXQ_DESC_SIZE;
		EFSYS_MEM_WRITEQ(erp->er_esmp, offset, &qword);

		id = (id + 1) & (erp->er_mask);
	}
}

			void
rhead_rx_qpush(
	__in	efx_rxq_t *erp,
	__in	unsigned int added,
	__inout	unsigned int *pushedp)
{
	efx_nic_t *enp = erp->er_enp;
	unsigned int pushed = *pushedp;
	uint32_t wptr;
	efx_dword_t dword;

	/* Hardware has no restriction for WPTR alignment */

	*pushedp = added;

	/* Push the populated descriptors out */
	wptr = added & erp->er_mask;
	EFX_POPULATE_DWORD_1(dword, ERF_GZ_RX_RING_PIDX, wptr);

	/* Guarantee ordering of memory (descriptors) and PIO (doorbell) */
	EFX_DMA_SYNC_QUEUE_FOR_DEVICE(erp->er_esmp, erp->er_mask + 1,
	    RHEAD_RXQ_DESC_SIZE, wptr, pushed & erp->er_mask);
	EFSYS_PIO_WRITE_BARRIER();
	EFX_BAR_VI_WRITED(enp, ER_GZ_RX_RING_DOORBELL,
	    erp->er_index, &dword, B_FALSE);
}

	__checkReturn	efx_rc_t
rhead_rx_qflush(
	__in	efx_rxq_t *erp)
{
	efx_nic_t *enp = erp->er_enp;
	efx_rc_t rc;

	if ((rc = efx_mcdi_fini_rxq(enp, erp->er_index)) != 0)
		goto fail1;

	return (0);

fail1:
	/*
	 * EALREADY is not an error, but indicates that the MC has rebooted and
	 * that the RXQ has already been destroyed. Callers need to know that
	 * the RXQ flush has completed to avoid waiting until timeout for a
	 * flush done event that will not be delivered.
	 */
	if (rc != EALREADY)
		EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

		void
rhead_rx_qenable(
	__in	efx_rxq_t *erp)
{
	_NOTE(ARGUNUSED(erp))
}

	__checkReturn	efx_rc_t
rhead_rx_qcreate(
	__in		efx_nic_t *enp,
	__in		unsigned int index,
	__in		unsigned int label,
	__in		efx_rxq_type_t type,
	__in		const efx_rxq_type_data_t *type_data,
	__in		efsys_mem_t *esmp,
	__in		size_t ndescs,
	__in		uint32_t id,
	__in		unsigned int flags,
	__in		efx_evq_t *eep,
	__in		efx_rxq_t *erp)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(enp);
	efx_rc_t rc;
	boolean_t disable_scatter;

	_NOTE(ARGUNUSED(id))

	EFX_STATIC_ASSERT(EFX_EV_RX_NLABELS <= (1 << ESF_GZ_EV_Q_LABEL_WIDTH));
	EFSYS_ASSERT3U(label, <, EFX_EV_RX_NLABELS);

	switch (type) {
	case EFX_RXQ_TYPE_DEFAULT:
		if (type_data == NULL) {
			rc = EINVAL;
			goto fail1;
		}
		erp->er_buf_size = type_data->ertd_default.ed_buf_size;
		break;
	default:
		rc = ENOTSUP;
		goto fail2;
	}

	/* Scatter can only be disabled if the firmware supports doing so */
	if (flags & EFX_RXQ_FLAG_SCATTER)
		disable_scatter = B_FALSE;
	else
		disable_scatter = encp->enc_rx_disable_scatter_supported;

	/*
	 * Ignore EFX_RXQ_FLAG_INNER_CLASSES since in accordance with
	 * EF100 host interface both inner and outer classes are provided
	 * by HW if applicable.
	 */

	if ((rc = efx_mcdi_init_rxq(enp, ndescs, eep, label, index,
		    esmp, disable_scatter, B_FALSE, erp->er_buf_size,
		    0, 0, 0, 0, 0)) != 0)
		goto fail3;

	erp->er_eep = eep;
	erp->er_label = label;

	return (0);

fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

		void
rhead_rx_qdestroy(
	__in	efx_rxq_t *erp)
{
	_NOTE(ARGUNUSED(erp))
	/* Nothing to do here */
}

#endif /* EFSYS_OPT_RIVERHEAD */
