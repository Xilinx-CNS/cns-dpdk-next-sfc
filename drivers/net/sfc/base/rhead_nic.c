/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2018 Solarflare Communications Inc.
 * All rights reserved.
 */

#include "efx.h"
#include "efx_impl.h"


#if EFSYS_OPT_RIVERHEAD

static	__checkReturn	efx_rc_t
rhead_nic_get_required_pcie_bandwidth(
	__in		efx_nic_t *enp,
	__out		uint32_t *bandwidth_mbpsp)
{
	uint32_t bandwidth;
	efx_rc_t rc;

	/* FIXME: support new Medford2 dynamic port modes */

	if ((rc = ef10_nic_get_port_mode_bandwidth(enp, &bandwidth)) != 0)
		goto fail1;

	*bandwidth_mbpsp = bandwidth;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

	__checkReturn	efx_rc_t
rhead_board_cfg(
	__in		efx_nic_t *enp)
{
	efx_nic_cfg_t *encp = &(enp->en_nic_cfg);
	uint32_t sss_clk, slice_clk;
	uint32_t end_padding;
	uint32_t bandwidth;
	efx_rc_t rc;

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

	/* Interrupt testing does not work on Riverhead yet */
	encp->enc_bug41750_workaround = B_TRUE;

	/* Chained multicast is always enabled on Medford2 */
	encp->enc_bug26807_workaround = B_TRUE;

	/* Medford only */
	encp->enc_bug61265_workaround = B_FALSE;

	/* Checksums for TSO sends should always be correct on Riverhead. */
	encp->enc_bug61297_workaround = B_FALSE;

	encp->enc_rx_prefix_size = 22;

	/* Get clock frequencies (in MHz). */
	if ((rc = efx_mcdi_get_clock(enp, &sss_clk, &slice_clk)) != 0)
		goto fail1;

#if 0
	/*
	 * The Medford2 timer quantum is 1536 dpcpu_clk cycles, documented for
	 * the EV_TMR_VAL field of EV_TIMER_TBL. Scale for MHz and ns units.
	 */
	encp->enc_evq_timer_quantum_ns = 1536000UL / dpcpu_clk; /* 1536 cycles */
	encp->enc_evq_timer_max_us = (encp->enc_evq_timer_quantum_ns <<
		    FRF_CZ_TC_TIMER_VAL_WIDTH) / 1000;
#endif

	encp->enc_ev_desc_size = RHEAD_EVQ_DESC_SIZE;
	encp->enc_rx_desc_size = RHEAD_RXQ_DESC_SIZE;
	encp->enc_tx_desc_size = RHEAD_TXQ_DESC_SIZE;

	/* Alignment for receive packet DMA buffers */
	encp->enc_rx_buf_align_start = 1;

#if 0
	/* Get the RX DMA end padding alignment configuration */
	if ((rc = efx_mcdi_get_rxdp_config(enp, &end_padding)) != 0) {
		if (rc != EACCES)
			goto fail2;

		/* Assume largest tail padding size supported by hardware */
		end_padding = 256;
	}
	encp->enc_rx_buf_align_end = end_padding;
#else
	encp->enc_rx_buf_align_end = 1;
#endif

	encp->enc_evq_max_nevs = RHEAD_EVQ_MAXNEVS;
	encp->enc_evq_min_nevs = RHEAD_EVQ_MINNEVS;
	encp->enc_rxq_max_ndescs = RHEAD_RXQ_MAXNDESCS;
	encp->enc_rxq_min_ndescs = RHEAD_RXQ_MINNDESCS;
	encp->enc_txq_max_ndescs = RHEAD_TXQ_MAXNDESCS;
	encp->enc_txq_min_ndescs = RHEAD_TXQ_MINNDESCS;

	/*
	 * Riverhead stores a single global copy of VPD, not per-PF as on
	 * Huntington.
	 */
	encp->enc_vpd_is_global = B_TRUE;

	rc = rhead_nic_get_required_pcie_bandwidth(enp, &bandwidth);
	if (rc != 0)
		goto fail3;
	encp->enc_required_pcie_bandwidth_mbps = bandwidth;
	encp->enc_max_pcie_link_gen = EFX_PCIE_LINK_SPEED_GEN3;

	return (0);

fail3:
	EFSYS_PROBE(fail3);
#if 0
fail2:
	EFSYS_PROBE(fail2);
#endif
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

#endif	/* EFSYS_OPT_RIVERHEAD */
