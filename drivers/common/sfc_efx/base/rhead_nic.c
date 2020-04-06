/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2019-2020 Xilinx, Inc.
 * Copyright(c) 2018-2019 Solarflare Communications Inc.
 */

#include "efx.h"
#include "efx_impl.h"


#if EFSYS_OPT_RIVERHEAD

/*
 * Size of design parameters area in bits.
 * TODO: use value from a generated header (not available yet).
 */
#define	ER_GZ_PARAMS_TLV_WIDTH	8160

/* Maximum count of design parameters specified in a parameters TLV */
#define	EF100_MAX_DESIGN_PARAMS	(ER_GZ_PARAMS_TLV_WIDTH / 8 / 3)

typedef struct ef100_dp_tlv_cursor_s {
	uint8_t		*current;
	uint8_t		*limit;
} ef100_dp_tlv_cursor_t;

typedef struct ef100_dp_view_s {
	uint16_t	type;
	uint8_t		length;
	uint8_t		*value;
} ef100_dp_view_t;

typedef struct ef100_design_params_s {
	uint8_t		*tlv;
	uint32_t	tlv_len;
	ef100_dp_view_t	*dp_views;
	uint32_t	dp_views_size;
	uint32_t	dp_views_max;
} ef100_design_params_t;

static	__checkReturn	boolean_t
ef100_dp_tlv_cursor_space_available(
	__in		const ef100_dp_tlv_cursor_t *cursorp,
	__in		size_t size)
{
	return (cursorp->current + size <= cursorp->limit);
}

static	__checkReturn	efx_rc_t
ef100_dp_tlv_cursor_init(
	__out		ef100_dp_tlv_cursor_t *cursorp,
	__in		uint8_t *currentp,
	__in		uint8_t *limitp)
{
	cursorp->current = currentp;
	cursorp->limit = limitp;

	if (ef100_dp_tlv_cursor_space_available(cursorp, 0) == B_FALSE)
		return (EACCES);

	return (0);
}

static			uint8_t *
ef100_dp_tlv_cursor_get_current(
	__in		ef100_dp_tlv_cursor_t *cursorp)
{
	return (cursorp->current);
}

static	__checkReturn	efx_rc_t
ef100_dp_tlv_cursor_advance(
	__inout		ef100_dp_tlv_cursor_t *cursorp,
	__in		size_t size)
{
	if (ef100_dp_tlv_cursor_space_available(cursorp, size) == B_FALSE)
		return (EACCES);

	cursorp->current += size;

	return (0);
}

static	__checkReturn	efx_rc_t
ef100_dp_tlv_cursor_read(
	__inout		ef100_dp_tlv_cursor_t *cursorp,
	__in		size_t size,
	__out		uint8_t *buf)
{
	efx_rc_t rc;
	uint8_t *begin = cursorp->current;

	rc = ef100_dp_tlv_cursor_advance(cursorp, size);
	if (rc != 0)
		goto fail1;

	memcpy(buf, begin, size);

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

static	__checkReturn	efx_rc_t
ef100_dp_tlv_cursor_read_byte(
	__inout		ef100_dp_tlv_cursor_t *cursorp,
	__out		uint8_t *bytep)
{
	return (ef100_dp_tlv_cursor_read(cursorp, sizeof (*bytep), bytep));
}

static	__checkReturn	ef100_dp_view_t *
ef100_dp_find(
	__in		ef100_design_params_t *paramsp,
	__in		uint16_t type)
{
	unsigned int i;

	for (i = 0; i < paramsp->dp_views_size; i++) {
		if (paramsp->dp_views[i].type == type)
			return (&paramsp->dp_views[i]);
	}

	return (NULL);
}

static	__checkReturn	efx_rc_t
ef100_dp_add(
	__in		ef100_design_params_t *paramsp,
	__in		uint16_t type,
	__in		uint8_t length,
	__in		uint8_t *valuep)
{
	unsigned int i;
	ef100_dp_view_t *dp;
	efx_rc_t rc;

	dp = ef100_dp_find(paramsp, type);
	if (dp == NULL) {
		if (paramsp->dp_views_size >= paramsp->dp_views_max) {
			rc = ENOSPC;
			goto fail1;
		}

		dp = &paramsp->dp_views[paramsp->dp_views_size];
		paramsp->dp_views_size++;
	}

	dp->type = type;
	dp->length = length;
	dp->value = valuep;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

static	__checkReturn	efx_rc_t
ef100_dp_decode_type_len(
	__inout		ef100_dp_tlv_cursor_t *cursorp,
	__out		uint16_t *typep,
	__out		uint8_t *lengthp)
{
	uint16_t type = 0;
	uint8_t type_low;
	uint8_t type_high;
	uint8_t length;
	efx_rc_t rc;

	rc = ef100_dp_tlv_cursor_read_byte(cursorp, &type_low);
	if (rc != 0)
		goto fail1;

	/*
	 * The type of a design parameter is encoded by 1 or 2 bytes in the TLV.
	 * It depends on the top bit of the first byte.
	 * See SF-119689-TC section 4.5.4.
	 */
	if (type_low & 0x80) {
		/* The type is a 15 bit value encoded in 2 bytes */
		rc = ef100_dp_tlv_cursor_read_byte(cursorp, &type_high);
		if (rc != 0)
			goto fail2;

		type = (type_low & 0x7F) | (type_high << 7);
	} else {
		/* The type is a 7 bit value */
		type = type_low;
	}

	/* Length is always encoded in 1 byte */
	rc = ef100_dp_tlv_cursor_read_byte(cursorp, &length);
	if (rc != 0)
		goto fail3;

	*typep = type;
	*lengthp = length;

	return (0);

fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

static	__checkReturn	efx_rc_t
ef100_dp_get_int64(
	__in		ef100_dp_view_t *paramp,
	__out		int64_t *valuep)
{
	int64_t value_le = 0;

	if (paramp->length > sizeof (*valuep))
		return (EINVAL);

	memcpy(&value_le, paramp->value, paramp->length);
	*valuep = __LE_TO_CPU_64(value_le);

	return (0);
}


static	__checkReturn	efx_rc_t
ef100_dp_parse_tlv(
	__in		ef100_design_params_t *paramsp,
	__in		ef100_dp_tlv_cursor_t *cursorp)
{
	efx_rc_t rc;

	/*
	 * Scan the whole design parameter area, as described in
	 * SF-119689-TC section 4.5.4.
	 *
	 * Check that at least 2 bytes are available since a valid
	 * design parameter cannot fit into 1 byte.
	 */
	while (ef100_dp_tlv_cursor_space_available(cursorp, 2)) {
		uint16_t dp_type;
		uint8_t dp_len;
		uint8_t *dp_val;

		/* Get the type and length of a parameter */
		rc = ef100_dp_decode_type_len(cursorp, &dp_type, &dp_len);
		if (rc != 0)
			goto fail1;

		dp_val = ef100_dp_tlv_cursor_get_current(cursorp);
		rc = ef100_dp_tlv_cursor_advance(cursorp, dp_len);
		if (rc != 0)
			goto fail2;

		/*
		 * Skip dedicated for padding parameter and zero-length
		 * parameters.
		 */
		if (dp_type != ESE_EF100_DP_GZ_PAD && dp_len != 0) {
			rc = ef100_dp_add(paramsp, dp_type, dp_len, dp_val);
			if (rc != 0)
				goto fail3;
		}
	}

	return (0);

fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

static	__checkReturn	efx_rc_t
ef100_design_params_init(
	__in		efx_nic_t *enp,
	__out		ef100_design_params_t *paramsp)
{
	ef100_dp_tlv_cursor_t cursor;
	uint32_t n_reads;
	uint32_t tlv_len;
	uint32_t remainder;
	efx_dword_t ed;
	efx_rc_t rc;
	uint32_t i;

	memset(paramsp, 0, sizeof(*paramsp));

	/*
	 * All VIs have a copy of design parameters. Read them from the
	 * first one.
	 */
	EFX_BAR_VI_READD(enp, ER_GZ_PARAMS_TLV_LEN, 0, &ed, B_FALSE);

	tlv_len = EFX_DWORD_FIELD(ed, EFX_DWORD_0);

	if (tlv_len == 0)
		return (0);

	if (tlv_len > ER_GZ_PARAMS_TLV_WIDTH / 8) {
		rc = EINVAL;
		goto fail1;
	}

	EFSYS_KMEM_ALLOC(enp->en_esip, tlv_len, paramsp->tlv);
	if (paramsp->tlv == NULL) {
		rc = ENOMEM;
		goto fail2;
	}

	paramsp->dp_views_max = EF100_MAX_DESIGN_PARAMS;
	EFSYS_KMEM_ALLOC(enp->en_esip, paramsp->dp_views_max *
			 sizeof (*paramsp->dp_views), paramsp->dp_views);
	if (paramsp->dp_views == NULL) {
		rc = ENOMEM;
		goto fail3;
	}

	paramsp->tlv_len = tlv_len;
	n_reads = tlv_len / sizeof(efx_dword_t);

	for (i = 0; i < n_reads; i++) {
		EFX_BAR_VI_READD_INDEXED(enp, ER_GZ_PARAMS_TLV, 0, i, &ed,
					 B_FALSE);
		memcpy(&paramsp->tlv[i * sizeof (efx_dword_t)], ed.ed_u32,
		       sizeof (efx_dword_t));
	}

	remainder = tlv_len % sizeof(efx_dword_t);
	if (remainder != 0) {
		EFX_BAR_VI_READD_INDEXED(enp, ER_GZ_PARAMS_TLV, 0, n_reads,
					 &ed, B_FALSE);
		memcpy(&paramsp->tlv[paramsp->tlv_len - remainder], ed.ed_u32,
		       remainder);
	}

	rc = ef100_dp_tlv_cursor_init(&cursor, paramsp->tlv,
				      paramsp->tlv + paramsp->tlv_len);
	if (rc != 0)
		goto fail4;

	rc = ef100_dp_parse_tlv(paramsp, &cursor);
	if (rc != 0)
		goto fail5;

	return (0);

fail5:
	EFSYS_PROBE(fail5);
fail4:
	EFSYS_PROBE(fail4);
	EFSYS_KMEM_FREE(enp->en_esip, paramsp->dp_views_max, paramsp->dp_views);

fail3:
	EFSYS_PROBE(fail3);
	EFSYS_KMEM_FREE(enp->en_esip, tlv_len, paramsp->tlv);

fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

static			void
ef100_design_params_fini(
	__in		efx_nic_t *enp,
	__in		ef100_design_params_t *paramsp)
{
	if (paramsp->tlv != NULL)
		EFSYS_KMEM_FREE(enp->en_esip, paramsp->tlv_len, paramsp->tlv);

	if (paramsp->dp_views != NULL) {
		EFSYS_KMEM_FREE(enp->en_esip, paramsp->dp_views_max,
				paramsp->dp_views);
	}
}

#define ESE_EF100_DP_GZ_DEF_MAP_ENTRY(_field) \
	{ ESE_EF100_DP_GZ_##_field, ESE_EF100_DP_GZ_##_field##_DEFAULT }

static	__checkReturn	efx_rc_t
ef100_design_param_get_default_int64(
	__in		uint16_t type,
	__out		int64_t *valuep)
{
	static const struct default_params_map {
		uint16_t type;
		int64_t value;
	} map[] = {
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(COMPAT),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(EVQ_TIMER_TICK_NANOS),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(EVQ_UNSOL_CREDIT_SEQ_BITS),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(MEM2MEM_MAX_LEN),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(NMMU_GROUP_SIZE),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(NMMU_PAGE_SIZES),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(PARTIAL_TSTAMP_SUB_NANO_BITS),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(RX_MAX_RUNT),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(RXQ_SIZE_GRANULARITY),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(TSO_MAX_HDR_LEN),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(TSO_MAX_HDR_NUM_SEGS),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(TSO_MAX_NUM_FRAMES),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(TSO_MAX_PAYLOAD_LEN),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(TSO_MAX_PAYLOAD_NUM_SEGS),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(TXQ_SIZE_GRANULARITY),
		ESE_EF100_DP_GZ_DEF_MAP_ENTRY(VI_STRIDES),
	};

	boolean_t found = B_FALSE;
	unsigned int i;
	efx_rc_t rc;

	for (i = 0; i < EFX_ARRAY_SIZE(map); i++) {
		if (map[i].type == type) {
			found = B_TRUE;
			*valuep = map[i].value;
			break;
		}
	}

	if (found == B_FALSE) {
		rc = ENOENT;
		goto fail1;
	}

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

#undef ESE_EF100_DP_GZ_DEF_MAP_ENTRY

static	__checkReturn	efx_rc_t
ef100_design_param_get_int64(
	__in		ef100_design_params_t *paramsp,
	__in		uint16_t type,
	__out		int64_t *valuep)
{
	ef100_dp_view_t *dp;
	efx_rc_t rc;

	dp = ef100_dp_find(paramsp, type);
	if (dp == NULL) {
		rc = ef100_design_param_get_default_int64(type, valuep);
		if (rc != 0)
			goto fail1;
	} else {
		rc = ef100_dp_get_int64(dp, valuep);
		if (rc != 0)
			goto fail2;
	}

	return (0);

fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

static	__checkReturn	efx_rc_t
rhead_design_params_populate(
	__in		efx_nic_t *enp)
{
	efx_nic_cfg_t *encp = &(enp->en_nic_cfg);
	ef100_design_params_t params;
	const struct design_params_map {
		uint16_t type;
		uint32_t *ptr;
	} dp_map[] = {
		{ ESE_EF100_DP_GZ_TSO_MAX_HDR_NUM_SEGS,
		  &encp->enc_tx_tso_max_header_ndescs },
		{ ESE_EF100_DP_GZ_TSO_MAX_HDR_LEN,
		  &encp->enc_tx_tso_max_header_length },
		{ ESE_EF100_DP_GZ_TSO_MAX_PAYLOAD_NUM_SEGS,
		  &encp->enc_tx_tso_max_payload_ndescs },
		{ ESE_EF100_DP_GZ_TSO_MAX_PAYLOAD_LEN,
		  &encp->enc_tx_tso_max_payload_length },
		{ ESE_EF100_DP_GZ_TSO_MAX_NUM_FRAMES,
		  &encp->enc_tx_tso_max_nframes },
	};
	unsigned int i;
	efx_rc_t rc;

	rc = ef100_design_params_init(enp, &params);
	if (rc != 0)
		goto fail1;

	for (i = 0; i < EFX_ARRAY_SIZE(dp_map); i++) {
		int64_t value;

		rc = ef100_design_param_get_int64(&params, dp_map[i].type,
						  &value);
		if (rc != 0)
			goto fail2;

		if (((uint64_t)value) > UINT32_MAX) {
			rc = EINVAL;
			goto fail3;
		}

		*dp_map[i].ptr = (uint32_t)value;
	}

	ef100_design_params_fini(enp, &params);

	return (0);

fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
	ef100_design_params_fini(enp, &params);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

	__checkReturn	efx_rc_t
rhead_board_cfg(
	__in		efx_nic_t *enp)
{
	efx_nic_cfg_t *encp = &(enp->en_nic_cfg);
	uint32_t end_padding;
	uint32_t bandwidth;
	efx_rc_t rc;

	if ((rc = efx_mcdi_nic_board_cfg(enp)) != 0)
		goto fail1;

	/*
	 * The tunnel encapsulation initialization happens unconditionally
	 * for now.
	 */
	encp->enc_tunnel_encapsulations_supported =
	    (1u << EFX_TUNNEL_PROTOCOL_VXLAN) |
	    (1u << EFX_TUNNEL_PROTOCOL_GENEVE) |
	    (1u << EFX_TUNNEL_PROTOCOL_NVGRE);

	/*
	 * Software limitation inherited from EF10. This limit is not
	 * increased since the hardware does not report this limit, it is
	 * handled internally resulting in a tunnel add error when there is no
	 * space for more UDP tunnels.
	 */
	encp->enc_tunnel_config_udp_entries_max = EFX_TUNNEL_MAXNENTRIES;

	encp->enc_clk_mult = 1; /* not used for Riverhead */

	/*
	 * FIXME There are TxSend and TxSeg descriptors on Riverhead.
	 * TxSeg is bigger than TxSend.
	 */
	encp->enc_tx_dma_desc_size_max = EFX_MASK32(ESF_GZ_TX_SEND_LEN);
	/* No boundary crossing limits */
	encp->enc_tx_dma_desc_boundary = 0;

	/*
	 * Riverhead does not put any restrictions on TCP header offset limit.
	 */
	encp->enc_tx_tso_tcp_header_offset_limit = UINT32_MAX;

	/*
	 * Set resource limits for MC_CMD_ALLOC_VIS. Note that we cannot use
	 * MC_CMD_GET_RESOURCE_LIMITS here as that reports the available
	 * resources (allocated to this PCIe function), which is zero until
	 * after we have allocated VIs.
	 */
	encp->enc_evq_limit = 1024;
	encp->enc_rxq_limit = EFX_RXQ_LIMIT_TARGET;
	encp->enc_txq_limit = EFX_TXQ_LIMIT_TARGET;

	encp->enc_buftbl_limit = UINT32_MAX;

	/*
	 * Riverhead event queue creation completes
	 * immediately (no initial event).
	 */
	encp->enc_evq_init_done_ev_supported = B_FALSE;

	/*
	 * Enable firmware workarounds for hardware errata.
	 * Expected responses are:
	 *  - 0 (zero):
	 *	Success: workaround enabled or disabled as requested.
	 *  - MC_CMD_ERR_ENOSYS (reported as ENOTSUP):
	 *	Firmware does not support the MC_CMD_WORKAROUND request.
	 *	(assume that the workaround is not supported).
	 *  - MC_CMD_ERR_ENOENT (reported as ENOENT):
	 *	Firmware does not support the requested workaround.
	 *  - MC_CMD_ERR_EPERM  (reported as EACCES):
	 *	Unprivileged function cannot enable/disable workarounds.
	 *
	 * See efx_mcdi_request_errcode() for MCDI error translations.
	 */

	/*
	 * Replay engine on Riverhead should suppress duplicate packets
	 * (e.g. because of exact multicast and all-multicast filters
	 * match) to the same RxQ.
	 */
	encp->enc_bug26807_workaround = B_FALSE;

	/*
	 * Checksums for TSO sends should always be correct on Riverhead.
	 * FIXME: revisit when TSO support is implemented.
	 */
	encp->enc_bug61297_workaround = B_FALSE;

	encp->enc_evq_max_nevs = RHEAD_EVQ_MAXNEVS;
	encp->enc_evq_min_nevs = RHEAD_EVQ_MINNEVS;
	encp->enc_rxq_max_ndescs = RHEAD_RXQ_MAXNDESCS;
	encp->enc_rxq_min_ndescs = RHEAD_RXQ_MINNDESCS;
	encp->enc_txq_max_ndescs = RHEAD_TXQ_MAXNDESCS;
	encp->enc_txq_min_ndescs = RHEAD_TXQ_MINNDESCS;

	/* Riverhead FW does not support event queue timers yet. */
	encp->enc_evq_timer_quantum_ns = 0;
	encp->enc_evq_timer_max_us = 0;

	encp->enc_ev_desc_size = RHEAD_EVQ_DESC_SIZE;
	encp->enc_rx_desc_size = RHEAD_RXQ_DESC_SIZE;
	encp->enc_tx_desc_size = RHEAD_TXQ_DESC_SIZE;

	/* No required alignment for WPTR updates */
	encp->enc_rx_push_align = 1;

	/* Riverhead supports a single Rx prefix size. */
	encp->enc_rx_prefix_size = ESE_GZ_RX_PKT_PREFIX_LEN;

	/* Alignment for receive packet DMA buffers. */
	encp->enc_rx_buf_align_start = 1;

	/* Get the RX DMA end padding alignment configuration. */
	if ((rc = efx_mcdi_get_rxdp_config(enp, &end_padding)) != 0) {
		if (rc != EACCES)
			goto fail2;

		/* Assume largest tail padding size supported by hardware. */
		end_padding = 128;
	}
	encp->enc_rx_buf_align_end = end_padding;

	/* FIXME: It should be extracted from design parameters (Bug 86844) */
	encp->enc_rx_scatter_max = 7;

	/*
	 * Riverhead stores a single global copy of VPD, not per-PF as on
	 * Huntington.
	 */
	encp->enc_vpd_is_global = B_TRUE;

	rc = ef10_nic_get_port_mode_bandwidth(enp, &bandwidth);
	if (rc != 0)
		goto fail3;
	encp->enc_required_pcie_bandwidth_mbps = bandwidth;
	encp->enc_max_pcie_link_gen = EFX_PCIE_LINK_SPEED_GEN3;

	return (0);

fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

	__checkReturn	efx_rc_t
rhead_nic_probe(
	__in		efx_nic_t *enp)
{
	const efx_nic_ops_t *enop = enp->en_enop;
	efx_nic_cfg_t *encp = &(enp->en_nic_cfg);
	efx_drv_cfg_t *edcp = &(enp->en_drv_cfg);
	efx_dword_t hw_rev_id;
	efx_dword_t nic_rev_id;
	efx_rc_t rc;

	EFSYS_ASSERT(EFX_FAMILY_IS_EF100(enp));

	EFX_BAR_FCW_READD(enp, ER_GZ_HW_REV_ID_REG, &hw_rev_id);
	EFX_BAR_FCW_READD(enp, ER_GZ_NIC_REV_ID, &nic_rev_id);
	printf("HW revision: %#x, NIC revision: %#x\n",
	       hw_rev_id.ed_u32[0], nic_rev_id.ed_u32[0]);

	/* Read and clear any assertion state */
	if ((rc = efx_mcdi_read_assertion(enp)) != 0)
		goto fail1;

	/* Exit the assertion handler */
	if ((rc = efx_mcdi_exit_assertion_handler(enp)) != 0)
		if (rc != EACCES)
			goto fail2;

	if ((rc = efx_mcdi_drv_attach(enp, B_TRUE)) != 0)
		goto fail3;

	/* Get remaining controller-specific board config */
	if ((rc = enop->eno_board_cfg(enp)) != 0)
		goto fail4;

	/*
	 * Set default driver config limits (based on board config).
	 *
	 * FIXME: For now allocate a fixed number of VIs which is likely to be
	 * sufficient and small enough to allow multiple functions on the same
	 * port.
	 */
	edcp->edc_min_vi_count = edcp->edc_max_vi_count =
	    MIN(128, MAX(encp->enc_rxq_limit, encp->enc_txq_limit));

	/*
	 * The client driver must configure and enable PIO buffer support,
	 * but there is no PIO support on Riverhead anyway.
	 */
	edcp->edc_max_piobuf_count = 0;
	edcp->edc_pio_alloc_size = 0;

#if EFSYS_OPT_MAC_STATS
	/* Wipe the MAC statistics */
	if ((rc = efx_mcdi_mac_stats_clear(enp)) != 0)
		goto fail5;
#endif

#if EFSYS_OPT_LOOPBACK
	if ((rc = efx_mcdi_get_loopback_modes(enp)) != 0)
		goto fail6;
#endif

	return (0);

#if EFSYS_OPT_LOOPBACK
fail6:
	EFSYS_PROBE(fail6);
#endif
#if EFSYS_OPT_MAC_STATS
fail5:
	EFSYS_PROBE(fail5);
#endif
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

	__checkReturn	efx_rc_t
rhead_nic_set_drv_limits(
	__inout		efx_nic_t *enp,
	__in		efx_drv_limits_t *edlp)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(enp);
	efx_drv_cfg_t *edcp = &(enp->en_drv_cfg);
	uint32_t min_evq_count, max_evq_count;
	uint32_t min_rxq_count, max_rxq_count;
	uint32_t min_txq_count, max_txq_count;
	efx_rc_t rc;

	if (edlp == NULL) {
		rc = EINVAL;
		goto fail1;
	}

	/* Get minimum required and maximum usable VI limits */
	min_evq_count = MIN(edlp->edl_min_evq_count, encp->enc_evq_limit);
	min_rxq_count = MIN(edlp->edl_min_rxq_count, encp->enc_rxq_limit);
	min_txq_count = MIN(edlp->edl_min_txq_count, encp->enc_txq_limit);

	edcp->edc_min_vi_count =
	    MAX(min_evq_count, MAX(min_rxq_count, min_txq_count));

	max_evq_count = MIN(edlp->edl_max_evq_count, encp->enc_evq_limit);
	max_rxq_count = MIN(edlp->edl_max_rxq_count, encp->enc_rxq_limit);
	max_txq_count = MIN(edlp->edl_max_txq_count, encp->enc_txq_limit);

	edcp->edc_max_vi_count =
	    MAX(max_evq_count, MAX(max_rxq_count, max_txq_count));

	/* There is no PIO support on Riverhead */
	edcp->edc_max_piobuf_count = 0;
	edcp->edc_pio_alloc_size = 0;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

	__checkReturn	efx_rc_t
rhead_nic_reset(
	__in		efx_nic_t *enp)
{
	efx_rc_t rc;

	/* ef10_nic_reset() is called to recover from BADASSERT failures. */
	if ((rc = efx_mcdi_read_assertion(enp)) != 0)
		goto fail1;
	if ((rc = efx_mcdi_exit_assertion_handler(enp)) != 0)
		goto fail2;

	if ((rc = efx_mcdi_entity_reset(enp)) != 0)
		goto fail3;

	/* Clear RX/TX DMA queue errors */
	enp->en_reset_flags &= ~(EFX_RESET_RXQ_ERR | EFX_RESET_TXQ_ERR);

	return (0);

fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

static	__checkReturn	efx_rc_t
rhead_upstream_port_vadaptor_alloc(
	__in		efx_nic_t *enp)
{
	uint32_t retry;
	uint32_t delay_us;
	efx_rc_t rc;

	/*
	 * On a VF, this may fail with MC_CMD_ERR_NO_EVB_PORT (ENOENT) if the PF
	 * driver has yet to bring up the EVB port. See bug 56147. In this case,
	 * retry the request several times after waiting a while. The wait time
	 * between retries starts small (10ms) and exponentially increases.
	 * Total wait time is a little over two seconds. Retry logic in the
	 * client driver may mean this whole loop is repeated if it continues to
	 * fail.
	 */
	retry = 0;
	delay_us = 10000;
	while ((rc = efx_mcdi_vadaptor_alloc(enp, EVB_PORT_ID_ASSIGNED)) != 0) {
		if (EFX_PCI_FUNCTION_IS_PF(&enp->en_nic_cfg) ||
		    (rc != ENOENT)) {
			/*
			 * Do not retry alloc for PF, or for other errors on
			 * a VF.
			 */
			goto fail1;
		}

		/* VF startup before PF is ready. Retry allocation. */
		if (retry > 5) {
			/* Too many attempts */
			rc = EINVAL;
			goto fail2;
		}
		EFSYS_PROBE1(mcdi_no_evb_port_retry, int, retry);
		EFSYS_SLEEP(delay_us);
		retry++;
		if (delay_us < 500000)
			delay_us <<= 2;
	}

	return (0);

fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

	__checkReturn	efx_rc_t
rhead_nic_init(
	__in		efx_nic_t *enp)
{
	const efx_drv_cfg_t *edcp = &(enp->en_drv_cfg);
	uint32_t min_vi_count, max_vi_count;
	uint32_t vi_count, vi_base, vi_shift;
	uint32_t vi_window_size;
	efx_rc_t rc;
	boolean_t alloc_vadaptor = B_TRUE;

	EFSYS_ASSERT(EFX_FAMILY_IS_EF100(enp));
	EFSYS_ASSERT3U(edcp->edc_max_piobuf_count, ==, 0);

	/* Enable reporting of some events (e.g. link change) */
	if ((rc = efx_mcdi_log_ctrl(enp)) != 0)
		goto fail1;

	min_vi_count = edcp->edc_min_vi_count;
	max_vi_count = edcp->edc_max_vi_count;

	/* Ensure that the previously attached driver's VIs are freed */
	if ((rc = efx_mcdi_free_vis(enp)) != 0)
		goto fail2;

	/*
	 * Reserve VI resources (EVQ+RXQ+TXQ) for this PCIe function. If this
	 * fails then retrying the request for fewer VI resources may succeed.
	 */
	vi_count = 0;
	if ((rc = efx_mcdi_alloc_vis(enp, min_vi_count, max_vi_count,
		    &vi_base, &vi_count, &vi_shift)) != 0)
		goto fail3;

	EFSYS_PROBE2(vi_alloc, uint32_t, vi_base, uint32_t, vi_count);

	if (vi_count < min_vi_count) {
		rc = ENOMEM;
		goto fail4;
	}

	rc = rhead_design_params_populate(enp);
	if (rc != 0)
		goto fail5;

	enp->en_arch.ef10.ena_vi_base = vi_base;
	enp->en_arch.ef10.ena_vi_count = vi_count;
	enp->en_arch.ef10.ena_vi_shift = vi_shift;

	EFSYS_ASSERT3U(enp->en_nic_cfg.enc_vi_window_shift, !=,
	    EFX_VI_WINDOW_SHIFT_INVALID);
	EFSYS_ASSERT3U(enp->en_nic_cfg.enc_vi_window_shift, <=,
	    EFX_VI_WINDOW_SHIFT_64K);
	vi_window_size = 1U << enp->en_nic_cfg.enc_vi_window_shift;

	/* Save UC memory mapping details */
	enp->en_arch.ef10.ena_uc_mem_map_offset = 0;
	enp->en_arch.ef10.ena_uc_mem_map_size =
	    vi_window_size * enp->en_arch.ef10.ena_vi_count;

	/* No WC memory mapping since PIO is not supported */
	enp->en_arch.ef10.ena_pio_write_vi_base = 0;
	enp->en_arch.ef10.ena_wc_mem_map_offset = 0;
	enp->en_arch.ef10.ena_wc_mem_map_size = 0;

	enp->en_nic_cfg.enc_mcdi_max_payload_length = MCDI_CTL_SDU_LEN_MAX_V2;

	/*
	 * For SR-IOV use case, vAdaptor is allocated for PF and associated VFs
	 * during NIC initialization when vSwitch is created and vports are
	 * allocated. Hence, skip vAdaptor allocation for EVB and update vport
	 * id in NIC structure with the one allocated for PF.
	 */

	enp->en_vport_id = EVB_PORT_ID_ASSIGNED;
#if EFSYS_OPT_EVB
	if ((enp->en_vswitchp != NULL) && (enp->en_vswitchp->ev_evcp != NULL)) {
		/* For EVB use vport allocated on vswitch */
		enp->en_vport_id = enp->en_vswitchp->ev_evcp->evc_vport_id;
		alloc_vadaptor = B_FALSE;
	}
#endif
	if (alloc_vadaptor != B_FALSE) {
		/* Allocate a vAdaptor attached to our upstream vPort/pPort */
		if ((rc = rhead_upstream_port_vadaptor_alloc(enp)) != 0)
			goto fail6;
	}

	return (0);

fail6:
	EFSYS_PROBE(fail6);

fail5:
	EFSYS_PROBE(fail5);

fail4:
	EFSYS_PROBE(fail4);

	(void) efx_mcdi_free_vis(enp);

fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

	__checkReturn	efx_rc_t
rhead_nic_get_vi_pool(
	__in		efx_nic_t *enp,
	__out		uint32_t *vi_countp)
{
	/*
	 * Report VIs that the client driver can use.
	 * Do not include VIs used for PIO buffer writes.
	 */
	*vi_countp = enp->en_arch.ef10.ena_vi_count;

	return (0);
}

	__checkReturn	efx_rc_t
rhead_nic_get_bar_region(
	__in		efx_nic_t *enp,
	__in		efx_nic_region_t region,
	__out		uint32_t *offsetp,
	__out		size_t *sizep)
{
	efx_rc_t rc;

	EFSYS_ASSERT(EFX_FAMILY_IS_EF100(enp));

	/*
	 * TODO: Specify host memory mapping alignment and granularity
	 * in efx_drv_limits_t so that they can be taken into account
	 * when allocating extra VIs for PIO writes.
	 */
	switch (region) {
	case EFX_REGION_VI:
		/* UC mapped memory BAR region for VI registers */
		*offsetp = enp->en_arch.ef10.ena_uc_mem_map_offset;
		*sizep = enp->en_arch.ef10.ena_uc_mem_map_size;
		break;

	case EFX_REGION_PIO_WRITE_VI:
		/* WC mapped memory BAR region for piobuf writes */
		*offsetp = enp->en_arch.ef10.ena_wc_mem_map_offset;
		*sizep = enp->en_arch.ef10.ena_wc_mem_map_size;
		break;

	default:
		rc = EINVAL;
		goto fail1;
	}

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

	__checkReturn	boolean_t
rhead_nic_hw_unavailable(
	__in		efx_nic_t *enp)
{
	efx_dword_t dword;

	if (enp->en_reset_flags & EFX_RESET_HW_UNAVAIL)
		return (B_TRUE);

	EFX_BAR_FCW_READD(enp, ER_GZ_MC_SFT_STATUS, &dword);
	if (EFX_DWORD_FIELD(dword, EFX_DWORD_0) == 0xffffffff)
		goto unavail;

	return (B_FALSE);

unavail:
	rhead_nic_set_hw_unavailable(enp);

	return (B_TRUE);
}

			void
rhead_nic_set_hw_unavailable(
	__in		efx_nic_t *enp)
{
	EFSYS_PROBE(hw_unavail);
	enp->en_reset_flags |= EFX_RESET_HW_UNAVAIL;
}

			void
rhead_nic_fini(
	__in		efx_nic_t *enp)
{
	boolean_t do_vadaptor_free = B_TRUE;

#if EFSYS_OPT_EVB
	if (enp->en_vswitchp != NULL) {
		/*
		 * For SR-IOV the vAdaptor is freed with the vswitch,
		 * so do not free it here.
		 */
		do_vadaptor_free = B_FALSE;
	}
#endif
	if (do_vadaptor_free != B_FALSE) {
		(void) efx_mcdi_vadaptor_free(enp, enp->en_vport_id);
		enp->en_vport_id = EVB_PORT_ID_NULL;
	}

	(void) efx_mcdi_free_vis(enp);
	enp->en_arch.ef10.ena_vi_count = 0;
}

			void
rhead_nic_unprobe(
	__in		efx_nic_t *enp)
{
	(void) efx_mcdi_drv_attach(enp, B_FALSE);
}

#if EFSYS_OPT_DIAG

	__checkReturn	efx_rc_t
rhead_nic_register_test(
	__in		efx_nic_t *enp)
{
	efx_rc_t rc;

	/* FIXME */
	_NOTE(ARGUNUSED(enp))
	_NOTE(CONSTANTCONDITION)
	if (B_FALSE) {
		rc = ENOTSUP;
		goto fail1;
	}
	/* FIXME */

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

#endif	/* EFSYS_OPT_DIAG */

	__checkReturn			efx_rc_t
rhead_nic_xilinx_cap_tbl_read_ef100_locator(
	__in				efsys_bar_t *esbp,
	__in				efsys_dma_addr_t offset,
	__out				efx_bar_region_t *ebrp)
{
	efx_oword_t entry;
	uint32_t rev;
	uint32_t len;
	efx_rc_t rc;

	/*
	 * Xilinx Capabilities Table requries 32bit aligned reads.
	 * See SF-119689-TC section 4.2.2 "Discovery Steps".
	 */
	EFSYS_BAR_READD(esbp, offset +
			(EFX_LOW_BIT(ESF_GZ_CFGBAR_ENTRY_FORMAT) / 8),
			&entry.eo_dword[0], B_FALSE);
	EFSYS_BAR_READD(esbp, offset +
			(EFX_LOW_BIT(ESF_GZ_CFGBAR_ENTRY_SIZE) / 8),
			&entry.eo_dword[1], B_FALSE);

	rev = EFX_OWORD_FIELD32(entry, ESF_GZ_CFGBAR_ENTRY_REV);
	len = EFX_OWORD_FIELD32(entry, ESF_GZ_CFGBAR_ENTRY_SIZE);

	if (rev != ESE_GZ_CFGBAR_ENTRY_REV_EF100 ||
	    len < ESE_GZ_CFGBAR_ENTRY_SIZE_EF100) {
		rc = EINVAL;
		goto fail1;
	}

	EFSYS_BAR_READD(esbp, offset +
			(EFX_LOW_BIT(ESF_GZ_CFGBAR_EF100_BAR) / 8),
			&entry.eo_dword[2], B_FALSE);

	ebrp->ebr_index = EFX_OWORD_FIELD32(entry, ESF_GZ_CFGBAR_EF100_BAR);
	ebrp->ebr_offset = EFX_OWORD_FIELD32(entry,
			ESF_GZ_CFGBAR_EF100_FUNC_CTL_WIN_OFF) <<
			ESE_GZ_EF100_FUNC_CTL_WIN_OFF_SHIFT;
	ebrp->ebr_type = EFX_BAR_TYPE_MEM;
	ebrp->ebr_length = 0;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

#endif	/* EFSYS_OPT_RIVERHEAD */
