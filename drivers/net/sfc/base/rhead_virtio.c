/*
 * Copyright (c) 2012-2019 Solarflare Communications Inc.
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

uint32_t sfc_logtype_driver_cc;

#define DRV_LOG_CC(level, fmt, args...) \
        rte_log(RTE_LOG_ ## level, sfc_logtype_driver_cc, \
                "SFC_VDPA_CC %s(): " fmt "\n", __func__, ##args)

__checkReturn	efx_rc_t
rhead_virtio_init(efx_nic_t *enp)
{

	DRV_LOG_CC(ERR, "Configuring device using libefx API : rhead_virtio_init ");
	printf("Configuring device using libefx API : rhead_virtio_init");
	return (0);
}

__checkReturn	efx_rc_t
rhead_virtio_fini(efx_nic_t *enp)
{
	DRV_LOG_CC(ERR, "Configuring device using libefx API : rhead_virtio_fini ");
	printf("Configuring device using libefx API : rhead_virtio_fini");
	return (0);
}


__checkReturn	efx_rc_t
rhead_virtio_get_features(
	__in	efx_nic_t *enp,
	__in	efx_virtio_device_type_t type,
	__out	uint64_t *featuresp)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload, MC_CMD_VIRTIO_GET_FEATURES_IN_LEN,
		MC_CMD_VIRTIO_GET_FEATURES_OUT_LEN);
	efx_rc_t rc;
	uint64_t features_hi;

	req.emr_cmd = MC_CMD_VIRTIO_GET_FEATURES;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_VIRTIO_GET_FEATURES_IN_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_VIRTIO_GET_FEATURES_OUT_LEN;

	MCDI_IN_SET_DWORD(req, VIRTIO_GET_FEATURES_IN_DEVICE_ID, type);

	DRV_LOG_CC(ERR, "Configuring device using libefx API : rhead_virtio_get_features");

	/* Added for testing only should be removed */
	
	printf("\n\n ##### For VIRTIO MCDI MC_CMD_VIRTIO_GET_FEATURES Invoked libefx API : rhead_virtio_get_features ##### \n\n");

	efx_mcdi_execute(enp, &req);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail1;
	}

	if (req.emr_out_length_used < MC_CMD_VIRTIO_GET_FEATURES_OUT_LEN) {
		rc = EMSGSIZE;
		goto fail2;
	}

	*featuresp = MCDI_OUT_DWORD(req, VIRTIO_GET_FEATURES_OUT_FEATURES_LO);
	printf("\n LO *featuresp : %d", (unsigned int) *featuresp);
	
	printf("\n LO 0x%x", (unsigned int) (MCDI_OUT_DWORD(req, VIRTIO_GET_FEATURES_OUT_FEATURES_LO)));
	
	features_hi = (MCDI_OUT_DWORD(req, VIRTIO_GET_FEATURES_OUT_FEATURES_HI));
	*featuresp |= features_hi << 32;
	
	printf("\n HI 0x%x", (unsigned int) (MCDI_OUT_DWORD(req, VIRTIO_GET_FEATURES_OUT_FEATURES_HI)));
	return (0);
	
	fail1:
		EFSYS_PROBE1(fail1, efx_rc_t, rc);
	fail2:
		EFSYS_PROBE1(fail2, efx_rc_t, rc);

	return (rc);
}

__checkReturn	efx_rc_t
rhead_virtio_verify_features(
	__in			efx_nic_t *enp,
	__in			efx_virtio_device_type_t type,
	__out			uint64_t features)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload, MC_CMD_VIRTIO_TEST_FEATURES_IN_LEN,
		MC_CMD_VIRTIO_TEST_FEATURES_OUT_LEN);
	efx_rc_t rc;

	req.emr_cmd = MC_CMD_VIRTIO_TEST_FEATURES;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_VIRTIO_TEST_FEATURES_IN_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_VIRTIO_TEST_FEATURES_OUT_LEN;

	MCDI_IN_SET_DWORD(req, VIRTIO_TEST_FEATURES_IN_FEATURES_LO, features & 0xFFFFFFFF);
	MCDI_IN_SET_DWORD(req, VIRTIO_TEST_FEATURES_IN_FEATURES_LO, features & 0xFFFFFFFF);
		
	printf("\n\n ##### For VIRTIO MCDI MC_CMD_VIRTIO_TEST_FEATURES Invoked libefx API : rhead_virtio_get_features ##### \n\n");

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

__checkReturn	efx_rc_t
rhead_virtio_get_doorbell_offset(
	__in			efx_nic_t *enp,
	__in			efx_virtio_device_type_t type,
	__in			efx_virtio_vq_t *evvp,
	__out			uint32_t *offsetp)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload, MC_CMD_VIRTIO_GET_DOORBELL_OFFSET_REQ_LEN,
		MC_CMD_VIRTIO_GET_BLOCK_DOORBELL_OFFSET_RESP_LEN);
	efx_rc_t rc;

	req.emr_cmd = MC_CMD_VIRTIO_GET_DOORBELL_OFFSET;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_VIRTIO_GET_DOORBELL_OFFSET_REQ_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_VIRTIO_GET_BLOCK_DOORBELL_OFFSET_RESP_LEN;

	MCDI_IN_SET_BYTE(req, VIRTIO_GET_DOORBELL_OFFSET_REQ_DEVICE_ID, type);
	MCDI_IN_SET_WORD(req, VIRTIO_GET_DOORBELL_OFFSET_REQ_TARGET_VF, evvp->evv_target_vf);
	MCDI_IN_SET_DWORD(req, VIRTIO_GET_DOORBELL_OFFSET_REQ_INSTANCE, evvp->evv_vi_index); // VI NUM
		
	printf("\n\n ####### Configuring device using libefx API : rhead_virtio_get_doorbell_offset ####### \n\n");

	efx_mcdi_execute(enp, &req);
	printf("\n ## RC of VIRTIO MCDI MC_CMD_VIRTIO_GET_DOORBELL_OFFSET : %d ## \n", (int)req.emr_rc);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail1;
	}

	if (type == EFX_VIRTIO_DEVICE_TYPE_NET) {
		if (req.emr_out_length_used < MC_CMD_VIRTIO_GET_BLOCK_DOORBELL_OFFSET_RESP_LEN) {
			rc = EMSGSIZE;
			goto fail2;
		}

		if(evvp->evv_type == EFX_VIRTIO_VQ_TYPE_NET_RXQ)
			*offsetp = MCDI_OUT_DWORD(req, VIRTIO_GET_NET_DOORBELL_OFFSET_RESP_RX_DBL_OFFSET);
		else if(evvp->evv_type == EFX_VIRTIO_VQ_TYPE_NET_TXQ)
			*offsetp = MCDI_OUT_DWORD(req, VIRTIO_GET_NET_DOORBELL_OFFSET_RESP_TX_DBL_OFFSET);
		
	}
	else if (type == EFX_VIRTIO_DEVICE_TYPE_BLOCK) {
		if (req.emr_out_length_used < MC_CMD_VIRTIO_GET_BLOCK_DOORBELL_OFFSET_RESP_LEN) {
			rc = EMSGSIZE;
			goto fail2;
		}

		*offsetp = MCDI_OUT_DWORD(req, VIRTIO_GET_BLOCK_DOORBELL_OFFSET_RESP_DBL_OFFSET);
	}

	return (0);
	
	fail1:
		EFSYS_PROBE1(fail1, efx_rc_t, rc);
	fail2:
		EFSYS_PROBE1(fail2, efx_rc_t, rc);

	return (rc);
}


__checkReturn   efx_rc_t
rhead_virtio_virtq_create(
                 __in                    efx_nic_t *enp,
                 __in                    efx_virtio_vq_type_t type,
                 __in                    uint16_t target_vf,
                 __in                    uint32_t vi_index,
                 __in                    efx_virtio_vq_cfg_t *evvcp)
{
   	efx_mcdi_req_t req;
        EFX_MCDI_DECLARE_BUF(payload, MC_CMD_VIRTIO_INIT_QUEUE_REQ_LEN,
                MC_CMD_VIRTIO_INIT_QUEUE_RESP_LEN);
	efx_rc_t rc = 0;
        uint8_t virtq_type = 0;
	uint32_t flags = 0;

	printf("\n In rhead_virtio_virtq_create : target_vf : %d", target_vf);

	req.emr_cmd = MC_CMD_VIRTIO_INIT_QUEUE;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_VIRTIO_INIT_QUEUE_REQ_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_VIRTIO_INIT_QUEUE_RESP_LEN;

	if (type == EFX_VIRTIO_VQ_TYPE_NET_RXQ)
		virtq_type = MC_CMD_VIRTIO_INIT_QUEUE_REQ_NET_RXQ;
	else if (type == EFX_VIRTIO_VQ_TYPE_NET_TXQ)
		virtq_type = MC_CMD_VIRTIO_INIT_QUEUE_REQ_NET_TXQ;

	MCDI_IN_SET_BYTE(req, VIRTIO_INIT_QUEUE_REQ_QUEUE_TYPE, virtq_type);
	MCDI_IN_SET_WORD(req, VIRTIO_INIT_QUEUE_REQ_TARGET_VF, target_vf);
	
	//printf("\n vi_index : %d", vi_index);
	
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_INSTANCE, vi_index);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_SIZE, evvcp->evvc_vq_size);
	flags |= evvcp->evvc_use_pasid ? B_TRUE : B_FALSE;
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_FLAGS, flags);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_DESC_TBL_ADDR_LO, evvcp->evvc_desc_tbl_addr);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_DESC_TBL_ADDR_HI, evvcp->evvc_desc_tbl_addr);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_AVAIL_RING_ADDR_LO, evvcp->evvc_avail_ring_addr);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_AVAIL_RING_ADDR_HI, evvcp->evvc_avail_ring_addr);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_USED_RING_ADDR_LO, evvcp->evvc_used_ring_addr);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_USED_RING_ADDR_HI, evvcp->evvc_used_ring_addr);

	if (evvcp->evvc_use_pasid)
		MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_PASID, evvcp->evvc_pas_id);

	MCDI_IN_SET_WORD(req, VIRTIO_INIT_QUEUE_REQ_MSIX_VECTOR, evvcp->evvc_msix_vector);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_FEATURES_LO, (evvcp->evcc_features & 0xFFFFFFFF));
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_FEATURES_HI, ((evvcp->evcc_features >> 32) & 0xFFFFFFFF));
	
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_INITIAL_PIDX, evvcp->evvc_vq_pidx);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_INITIAL_CIDX, evvcp->evvc_vq_cidx);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_MPORT_SELECTOR, evvcp->evcc_mport_selector);


    printf("\n\n ######### Configuring device using libefx API : rhead_virtio_virtq_create (virtio MCDI : MC_CMD_VIRTIO_INIT_QUEUE)####### \n\n");
	printf("\n enp : %p,", enp);
	
	efx_mcdi_execute(enp, &req);
	
	printf("\n ## RC of VIRTIO MCDI MC_CMD_VIRTIO_INIT_QUEUE : %d ## \n", (int)req.emr_rc);


	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail1;
	}


	return (0);

fail1:
		EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

__checkReturn   efx_rc_t
rhead_virtio_virtq_destroy (
        __in                    efx_nic_t *enp,
	__in            efx_virtio_vq_t *evvp,
	__out           uint32_t *pidxp,
	__out           uint32_t *cidxp)
{
        efx_mcdi_req_t req;
        EFX_MCDI_DECLARE_BUF(payload, MC_CMD_VIRTIO_FINI_QUEUE_REQ_LEN,
                MC_CMD_VIRTIO_FINI_QUEUE_RESP_LEN);
        efx_rc_t rc;
        uint8_t virtq_type = 0;

        req.emr_cmd = MC_CMD_VIRTIO_FINI_QUEUE;
        req.emr_in_buf = payload;
        req.emr_in_length = MC_CMD_VIRTIO_FINI_QUEUE_REQ_LEN;
        req.emr_out_buf = payload;
        req.emr_out_length = MC_CMD_VIRTIO_FINI_QUEUE_RESP_LEN;

        if (evvp->evv_type == EFX_VIRTIO_VQ_TYPE_NET_RXQ)
                virtq_type = MC_CMD_VIRTIO_INIT_QUEUE_REQ_NET_RXQ;
        else if (evvp->evv_type == EFX_VIRTIO_VQ_TYPE_NET_TXQ)
                virtq_type = MC_CMD_VIRTIO_INIT_QUEUE_REQ_NET_TXQ;

        MCDI_IN_SET_BYTE(req, VIRTIO_FINI_QUEUE_REQ_QUEUE_TYPE, virtq_type);
        MCDI_IN_SET_WORD(req, VIRTIO_INIT_QUEUE_REQ_TARGET_VF, evvp->evv_target_vf);
        MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_INSTANCE, evvp->evv_vi_index);

		printf("\n\n ######### Configuring device using libefx API : rhead_virtio_virtq_destroy (MC_CMD_VIRTIO_FINI_QUEUE) ######## \n\n ");
		printf("\n enp : %p, evvp->evv_target_vf : %d, evvp->evv_index : %d", enp, evvp->evv_target_vf, evvp->evv_vi_index);

        efx_mcdi_execute(enp, &req);
		printf("\n req.emr_rc : %d", (int)req.emr_rc);
		
		printf("\n ## RC of VIRTIO MCDI MC_CMD_VIRTIO_FINI_QUEUE : %d ## \n", (int)req.emr_rc);

        if (req.emr_rc != 0) {
                rc = req.emr_rc;
                goto fail1;
        }

        if (req.emr_out_length_used < MC_CMD_VIRTIO_FINI_QUEUE_RESP_LEN) {
                rc = EMSGSIZE;
                goto fail2;
        }

	*pidxp = MCDI_OUT_DWORD(req, VIRTIO_FINI_QUEUE_RESP_FINAL_PIDX);
	*cidxp = MCDI_OUT_DWORD(req, VIRTIO_FINI_QUEUE_RESP_FINAL_CIDX);
		
	printf("\n Exit from rhead_virtio_virtq_destroy ----" );
	return (0);
		
    fail1:
		EFSYS_PROBE1(fail1, efx_rc_t, rc);
	fail2:
		EFSYS_PROBE1(fail2, efx_rc_t, rc);

	return (rc);
}

#endif /* EFSYS_OPT_RIVERHEAD */

