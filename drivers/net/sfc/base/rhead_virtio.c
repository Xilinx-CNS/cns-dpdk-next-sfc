/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2020 Xilinx, Inc. All rights reserved.
 */

#include "efx.h"
#include "efx_impl.h"

#if EFSYS_OPT_RIVERHEAD && EFSYS_OPT_VIRTIO

	__checkReturn   efx_rc_t
rhead_virtio_virtq_create(
	__in		efx_nic_t *enp,
	__in		efx_virtio_vq_t *evvp,
	__in		efx_virtio_vq_cfg_t *evvcp)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload, MC_CMD_VIRTIO_INIT_QUEUE_REQ_LEN,
		MC_CMD_VIRTIO_INIT_QUEUE_RESP_LEN);
	efx_rc_t rc;
	uint8_t virtq_type = 0;

	req.emr_cmd = MC_CMD_VIRTIO_INIT_QUEUE;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_VIRTIO_INIT_QUEUE_REQ_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_VIRTIO_INIT_QUEUE_RESP_LEN;

	if (evvp->evv_type == EFX_VIRTIO_VQ_TYPE_NET_RXQ)
		virtq_type = MC_CMD_VIRTIO_INIT_QUEUE_REQ_NET_RXQ;
	else if (evvp->evv_type == EFX_VIRTIO_VQ_TYPE_NET_TXQ)
		virtq_type = MC_CMD_VIRTIO_INIT_QUEUE_REQ_NET_TXQ;
	else {
		rc = EINVAL;
		goto fail1;
	}

	/* Queue size must be power of 2 */
	if (!(evvcp->evvc_vq_size  &&
		!(evvcp->evvc_vq_size & (evvcp->evvc_vq_size - 1)))) {
		rc = EINVAL;
		goto fail2;
	}

	MCDI_IN_SET_BYTE(req, VIRTIO_INIT_QUEUE_REQ_QUEUE_TYPE, virtq_type);
	MCDI_IN_SET_WORD(req, VIRTIO_INIT_QUEUE_REQ_TARGET_VF, evvp->evv_target_vf);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_INSTANCE, evvp->evv_vi_index);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_SIZE,
		evvcp->evvc_vq_size);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_DESC_TBL_ADDR_LO,
		evvcp->evvc_desc_tbl_addr & 0xFFFFFFFF);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_DESC_TBL_ADDR_HI,
		evvcp->evvc_desc_tbl_addr >> 32);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_AVAIL_RING_ADDR_LO,
		evvcp->evvc_avail_ring_addr & 0xFFFFFFFF);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_AVAIL_RING_ADDR_HI,
		evvcp->evvc_avail_ring_addr >> 32);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_USED_RING_ADDR_LO,
		evvcp->evvc_used_ring_addr & 0xFFFFFFFF);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_USED_RING_ADDR_HI,
		evvcp->evvc_used_ring_addr >> 32);

	if (evvcp->evvc_use_pasid) {
		MCDI_IN_POPULATE_DWORD_1(req, VIRTIO_INIT_QUEUE_REQ_FLAGS,
			VIRTIO_INIT_QUEUE_REQ_USE_PASID, 1);
		MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_PASID,
			evvcp->evvc_pas_id);
	} else {
		MCDI_IN_POPULATE_DWORD_1(req, VIRTIO_INIT_QUEUE_REQ_FLAGS,
			VIRTIO_INIT_QUEUE_REQ_USE_PASID, 0);
	}

	MCDI_IN_SET_WORD(req, VIRTIO_INIT_QUEUE_REQ_MSIX_VECTOR,
		evvcp->evvc_msix_vector);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_FEATURES_LO,
		evvcp->evcc_features.eq_u32[0]);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_FEATURES_HI,
		evvcp->evcc_features.eq_u32[1]);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_INITIAL_PIDX,
		evvcp->evvc_vq_pidx);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_INITIAL_CIDX,
		evvcp->evvc_vq_cidx);

	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_MPORT_SELECTOR,
		evvcp->evcc_mport_selector);

	efx_mcdi_execute(enp, &req);
printf("\n MC_CMD_VIRTIO_INIT_QUEUE req.emr_rc : %d", req.emr_rc);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail3;
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

	__checkReturn   efx_rc_t
rhead_virtio_virtq_destroy (
	__in		efx_nic_t *enp,
	__in		efx_virtio_vq_t *evvp,
	__out		uint32_t *pidxp,
	__out		uint32_t *cidxp)
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
	else {
		rc = EINVAL;
		goto fail1;
	}

	MCDI_IN_SET_BYTE(req, VIRTIO_FINI_QUEUE_REQ_QUEUE_TYPE, virtq_type);
	MCDI_IN_SET_WORD(req, VIRTIO_INIT_QUEUE_REQ_TARGET_VF,
		evvp->evv_target_vf);
	MCDI_IN_SET_DWORD(req, VIRTIO_INIT_QUEUE_REQ_INSTANCE,
		evvp->evv_vi_index);

	efx_mcdi_execute(enp, &req);
printf("\n MC_CMD_VIRTIO_FINI_QUEUE req.emr_rc : %d", req.emr_rc);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail2;
	}

	if (req.emr_out_length_used < MC_CMD_VIRTIO_FINI_QUEUE_RESP_LEN) {
		rc = EMSGSIZE;
		goto fail3;
	}

        *pidxp = MCDI_OUT_DWORD(req, VIRTIO_FINI_QUEUE_RESP_FINAL_PIDX);
	*cidxp = MCDI_OUT_DWORD(req, VIRTIO_FINI_QUEUE_RESP_FINAL_CIDX);

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
rhead_virtio_get_doorbell_offset(
	__in		efx_nic_t *enp,
	__in		efx_virtio_device_type_t type,
	__in		efx_virtio_vq_t *evvp,
	__out		uint32_t *offsetp)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload, MC_CMD_VIRTIO_GET_DOORBELL_OFFSET_REQ_LEN,
		MC_CMD_VIRTIO_GET_NET_DOORBELL_OFFSET_RESP_LEN);
	efx_rc_t rc;

	req.emr_cmd = MC_CMD_VIRTIO_GET_DOORBELL_OFFSET;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_VIRTIO_GET_DOORBELL_OFFSET_REQ_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_VIRTIO_GET_NET_DOORBELL_OFFSET_RESP_LEN;
printf("\n MC_CMD_VIRTIO_GET_DOORBELL_OFFSET req.emr_rc : %d", req.emr_rc);

	EFX_STATIC_ASSERT(EFX_VIRTIO_DEVICE_TYPE_NET ==
	    MC_CMD_VIRTIO_GET_FEATURES_IN_NET);
	EFX_STATIC_ASSERT(EFX_VIRTIO_DEVICE_TYPE_BLOCK ==
	    MC_CMD_VIRTIO_GET_FEATURES_IN_BLOCK);

	MCDI_IN_SET_BYTE(req, VIRTIO_GET_DOORBELL_OFFSET_REQ_DEVICE_ID,
		type);
	MCDI_IN_SET_WORD(req, VIRTIO_GET_DOORBELL_OFFSET_REQ_TARGET_VF,
		evvp->evv_target_vf);
	MCDI_IN_SET_DWORD(req, VIRTIO_GET_DOORBELL_OFFSET_REQ_INSTANCE,
		evvp->evv_vi_index);

	efx_mcdi_execute(enp, &req);
printf("\n MC_CMD_VIRTIO_GET_DOORBELL_OFFSET req.emr_rc : %d", req.emr_rc);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail1;
	}

	if (type == EFX_VIRTIO_DEVICE_TYPE_NET) {
		if (req.emr_out_length_used <
			MC_CMD_VIRTIO_GET_NET_DOORBELL_OFFSET_RESP_LEN) {
			rc = EMSGSIZE;
			goto fail2;
                }

                if(evvp->evv_type == EFX_VIRTIO_VQ_TYPE_NET_RXQ)
                        *offsetp = MCDI_OUT_DWORD(req,
			VIRTIO_GET_NET_DOORBELL_OFFSET_RESP_RX_DBL_OFFSET);
                else if(evvp->evv_type == EFX_VIRTIO_VQ_TYPE_NET_TXQ)
			*offsetp = MCDI_OUT_DWORD(req,
			VIRTIO_GET_NET_DOORBELL_OFFSET_RESP_TX_DBL_OFFSET);
	}
	else if (type == EFX_VIRTIO_DEVICE_TYPE_BLOCK) {
		if (req.emr_out_length_used <
			 MC_CMD_VIRTIO_GET_BLOCK_DOORBELL_OFFSET_RESP_LEN) {
			rc = EMSGSIZE;
			goto fail2;
		}

		*offsetp = MCDI_OUT_DWORD(req,
			VIRTIO_GET_BLOCK_DOORBELL_OFFSET_RESP_DBL_OFFSET);
        }

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
fail2:
	EFSYS_PROBE1(fail2, efx_rc_t, rc);

	return (rc);
}

#endif	/* EFSYS_OPT_RIVERHEAD && EFSYS_OPT_VIRTIO */
