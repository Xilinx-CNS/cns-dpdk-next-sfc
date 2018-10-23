/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2018-2019 Solarflare Communications Inc.
 * All rights reserved.
 *
 * This software was jointly developed between OKTET Labs (under contract
 * for Solarflare) and Solarflare Communications, Inc.
 */

#ifndef _SFC_EF100_H
#define _SFC_EF100_H

#ifdef __cplusplus
extern "C" {
#endif

static inline bool
sfc_ef100_ev_present(const efx_qword_t *ev, bool phase_bit)
{
	return !((ev->eq_u64[0] &
		  EFX_INPLACE_MASK64(0, 63, ESF_GZ_EV_EVQ_PHASE)) ^
		 (phase_bit << ESF_GZ_EV_EVQ_PHASE_LBN));
}

static inline bool
sfc_ef100_ev_type_is(const efx_qword_t *ev, unsigned int type)
{
	return (ev->eq_u64[0] & EFX_INPLACE_MASK64(0, 63, ESF_GZ_EV_TYPE)) ==
		EFX_INSERT_FIELD64(0, 63, ESF_GZ_EV_TYPE, type);
}

#ifdef __cplusplus
}
#endif
#endif /* _SFC_EF100_H */
