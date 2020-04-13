/*
 * Copyright (c) 2019-2020 Solarflare Communications Inc.
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
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#include "efx.h"
#include "efx_impl.h"

#if EFSYS_OPT_RIVERHEAD 

uint32_t sfc_logtype_driver_ccr;

#define DRV_LOG_CCR(level, fmt, args...) \
        rte_log(RTE_LOG_ ## level, sfc_logtype_driver_ccr, \
                "SFC_VDPA_CCR %s(): " fmt "\n", __func__, ##args)

static const efx_virtio_ops_t	__efx_virtio_rhead_ops = {
	rhead_virtio_init,			/* evo_init */
	rhead_virtio_fini,			/* evo_fini */
	rhead_virtio_virtq_create,		/* evo_virtq_create */
	rhead_virtio_virtq_destroy,		/* evo_virtq_destroy */
	rhead_virtio_get_doorbell_offset,	/* evo_get_doorbell_offset */
	rhead_virtio_get_features,		/* evo_get_features */
	rhead_virtio_verify_features,		/* evo_verify_features */
};

__checkReturn	efx_rc_t
efx_virtio_init(
	__in		efx_nic_t *enp)
{
	const efx_virtio_ops_t *evop;
	efx_rc_t rc;

	EFSYS_ASSERT3U(enp->en_magic, ==, EFX_NIC_MAGIC);

	DRV_LOG_CCR(ERR, "virtio Ops init : enp->en_family : 0x%x , enp->en_mod_flags : 0x%x", enp->en_family, enp->en_mod_flags) ;

	if (enp->en_mod_flags & EFX_MOD_VIRTIO) {
		rc = EINVAL;
		goto fail1;
	}

	DRV_LOG_CCR(ERR, "virtio Ops init");

	switch (enp->en_family) {
		
	case EFX_FAMILY_RIVERHEAD:
		DRV_LOG_CCR(ERR, "virtio Ops init done");
		evop = &__efx_virtio_rhead_ops;
		break;
	default:
		EFSYS_ASSERT(0);
		rc = ENOTSUP;
		goto fail1;
	}

	/* Check !! if anything needs to be done in the init */
	if ((rc = evop->evo_init(enp)) != 0)
		goto fail2;

	enp->en_evop = evop;
	enp->en_mod_flags |= EFX_MOD_VIRTIO;
	return (0);

fail2:
	EFSYS_PROBE(fail2);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	enp->en_evop = NULL;
	enp->en_mod_flags &= ~EFX_MOD_VIRTIO;
	return (rc);
}


		void
efx_virtio_fini(
	__in	efx_nic_t *enp)
{
	const efx_virtio_ops_t *evop = enp->en_evop;

	EFSYS_ASSERT3U(enp->en_magic, ==, EFX_NIC_MAGIC);

	/* Check !! if anything needs to be done in the fini */
	evop->evo_fini(enp);

	enp->en_eevop = NULL;
	enp->en_mod_flags &= ~EFX_MOD_VIRTIO;
}

	__checkReturn	efx_rc_t
efx_virtio_virtq_create(
		 __in			 efx_nic_t *enp,
		 __in			 efx_virtio_vq_type_t type,
		 __in			 uint16_t target_vf,
		 __in			 uint32_t vq_num,
		 __in			 efx_virtio_vq_cfg_t *evvcp)
{
	const efx_virtio_ops_t *evop = enp->en_evop;
	efx_evq_t *eep;
	efx_rc_t rc;

	EFSYS_ASSERT3U(enp->en_magic, ==, EFX_NIC_MAGIC);
	EFSYS_ASSERT3U(enp->en_mod_flags, &, EFX_MOD_VIRTIO);

	if ((rc = evop->evo_virtq_create(enp, type, target_vf, vq_num, evvcp)) != 0)
		goto fail1;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

extern  __checkReturn   efx_rc_t
efx_virtio_virtq_destroy (
	__in		efx_nic_t *enp,
        __in            efx_virtio_vq_t *evvp,
        __out           uint32_t *pidxp,
        __out           uint32_t *cidxp)
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
efx_virtio_get_features(
	__in			efx_nic_t *enp,
	__in			efx_virtio_device_type_t type,
	__out			uint64_t *featuresp)
{

	const efx_virtio_ops_t *evop = enp->en_evop;
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(enp);
	efx_rc_t rc;

	EFSYS_ASSERT3U(enp->en_magic, ==, EFX_NIC_MAGIC);
	EFSYS_ASSERT3U(enp->en_mod_flags, &, EFX_MOD_VIRTIO);

	if (type >= EFX_VIRTIO_DEVICE_NTYPES) {
		rc = EINVAL;
		goto fail1;
	}

	if ((rc = evop->evo_get_features(enp, type, featuresp)) != 0)
		goto fail2;

	return (0);

fail2:
	EFSYS_PROBE1(fail2, efx_rc_t, rc);
fail1:
	EFSYS_PROBE(fail1);
	return (rc);
}

extern	__checkReturn	efx_rc_t
efx_virtio_get_doorbell_offset(
	__in			efx_nic_t *enp,
	__in			efx_virtio_device_type_t type,
	__in			efx_virtio_vq_t *evvp,
	__out			uint32_t *offsetp)
{
	const efx_virtio_ops_t *evop = enp->en_evop;
	efx_rc_t rc;

	EFSYS_ASSERT3U(enp->en_magic, ==, EFX_NIC_MAGIC);
	EFSYS_ASSERT3U(enp->en_mod_flags, &, EFX_MOD_VIRTIO);

	if ((rc = evop->evo_get_doorbell_offset(enp, type, evvp, offsetp)) != 0)
		goto fail1;

	return (0);
	
	fail1:
		EFSYS_PROBE1(fail1, efx_rc_t, rc);
		return (rc);
}

extern	__checkReturn	efx_rc_t
efx_virtio_verify_features(
	__in			efx_nic_t *enp,
	__in			efx_virtio_device_type_t type,
	__in			uint64_t features)
{
	const efx_virtio_ops_t *evop = enp->en_evop;
	efx_rc_t rc;

	EFSYS_ASSERT3U(enp->en_magic, ==, EFX_NIC_MAGIC);
	EFSYS_ASSERT3U(enp->en_mod_flags, &, EFX_MOD_VIRTIO);
	
	if(evop == NULL)
		DRV_LOG_CCR(ERR, "\n In efx_virtio_verify_features ... eovp is NULL");

	
	if ((rc = evop->evo_verify_features(enp, type, features)) != 0)
		goto fail1;
	
	return (0);
	
	fail1:
		EFSYS_PROBE1(fail1, efx_rc_t, rc);
		return (rc);

}

#endif /* EFSYS_OPT_RIVERHEAD */
