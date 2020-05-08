/*
 * Copyright (c) 2020 Xilinx, Inc.
 * Copyright (c) 2017-2019 Solarflare Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "efx.h"
#include "efx_impl.h"

#if EFSYS_OPT_VIRTIO

#if EFSYS_OPT_RIVERHEAD
static const efx_virtio_ops_t	__efx_virtio_rhead_ops = {
	rhead_virtio_virtq_create,		/* evo_virtq_create */
	rhead_virtio_virtq_destroy,		/* evo_virtq_destroy */
	rhead_virtio_get_doorbell_offset,	/* evo_get_doorbell_offset */
};
#endif /* EFSYS_OPT_RIVERHEAD */

	__checkReturn	efx_rc_t
efx_virtio_init(
	__in		efx_nic_t *enp)
{
	const efx_virtio_ops_t *evop;
	efx_rc_t rc;

	EFSYS_ASSERT3U(enp->en_magic, ==, EFX_NIC_MAGIC);
	EFSYS_ASSERT3U(enp->en_mod_flags, &, EFX_MOD_PROBE);
	//EFSYS_ASSERT(!(enp->en_mod_flags & EFX_MOD_VIRTIO));
#if 1
if (enp->en_mod_flags == EFX_MOD_VIRTIO)
	return 0;
#endif

	switch (enp->en_family) {
#if EFSYS_OPT_RIVERHEAD
	case EFX_FAMILY_RIVERHEAD:
		evop = &__efx_virtio_rhead_ops;
		break;
#endif /* EFSYS_OPT_RIVERHEAD */

	default:
		EFSYS_ASSERT(0);
		rc = ENOTSUP;
		goto fail1;
	}

	enp->en_evop = evop;
	enp->en_mod_flags |= EFX_MOD_VIRTIO;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	enp->en_evop = NULL;
	enp->en_mod_flags &= ~EFX_MOD_VIRTIO;

	return (rc);
}

			void
efx_virtio_fini(
	__in		efx_nic_t *enp)
{
	EFSYS_ASSERT3U(enp->en_magic, ==, EFX_NIC_MAGIC);
	EFSYS_ASSERT3U(enp->en_mod_flags, &, EFX_MOD_PROBE);
	EFSYS_ASSERT3U(enp->en_mod_flags, &, EFX_MOD_VIRTIO);

	enp->en_evop = NULL;
	enp->en_mod_flags &= ~EFX_MOD_VIRTIO;
}

	__checkReturn   efx_rc_t
efx_virtio_virtq_create(
	__in		efx_nic_t *enp,
	__in		efx_virtio_vq_t *evvp,
	__in		efx_virtio_vq_cfg_t *evvcp)
{
	const efx_virtio_ops_t *evop = enp->en_evop;
	efx_evq_t *eep;
	efx_rc_t rc;

	EFSYS_ASSERT3U(enp->en_magic, ==, EFX_NIC_MAGIC);
	EFSYS_ASSERT3U(enp->en_mod_flags, &, EFX_MOD_VIRTIO);

	if ((rc = evop->evo_virtq_create(enp, evvp, evvcp)) != 0)
		goto fail1;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

	__checkReturn   efx_rc_t
efx_virtio_virtq_destroy (
	__in		efx_nic_t *enp,
	__in		efx_virtio_vq_t *evvp,
	__out		uint32_t *pidxp,
	__out		uint32_t *cidxp)
{
	const efx_virtio_ops_t *evop = enp->en_evop;
	efx_rc_t rc;

	EFSYS_ASSERT3U(enp->en_magic, ==, EFX_NIC_MAGIC);
	EFSYS_ASSERT3U(enp->en_mod_flags, &, EFX_MOD_VIRTIO);

	if ((rc = evop->evo_virtq_destroy(enp, evvp, pidxp, cidxp)) != 0)
		goto fail1;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

	extern	__checkReturn	efx_rc_t
efx_virtio_get_doorbell_offset(
	__in		efx_nic_t *enp,
	__in		efx_virtio_device_type_t type,
	__in		efx_virtio_vq_t *evvp,
	__out		uint32_t *offsetp)
{
	const efx_virtio_ops_t *evop = enp->en_evop;
	efx_rc_t rc;

	EFSYS_ASSERT3U(enp->en_magic, ==, EFX_NIC_MAGIC);
	EFSYS_ASSERT3U(enp->en_mod_flags, &, EFX_MOD_VIRTIO);
printf("\n\n in efx_virtio_get_doorbell_offset ... ");
	if ((rc = evop->evo_get_doorbell_offset(enp, type, evvp, offsetp)) != 0)
		goto fail1;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

#endif /* EFSYS_OPT_VIRTIO */
