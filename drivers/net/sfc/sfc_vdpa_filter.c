#include "sfc_vdpa.h"
#include "efx.h"
#include "efx_mcdi.h"
#include "efx_regs_mcdi.h"
#include "efx_impl.h"
#include <rte_vhost.h>

uint32_t sfc_vdpa_ops_logtype_driver;
#define DRV_FILTER_LOG(level, fmt, args...) \
        rte_log(RTE_LOG_ ## level, sfc_vdpa_ops_logtype_driver, \
                "SFC_VDPA_OPS %s(): " fmt "\n", __func__, ##args)

int
sfc_vdpa_proxy_filter_insert(efx_nic_t *enp, unsigned int pf_index, 
							unsigned int vf_index, unsigned int vport_id, uint8_t *src_mac_addr,
							ef10_filter_handle_t *handle)
{
	int rc;
	efx_dword_t *proxy_hdr = NULL;
	size_t request_size = 0;
	size_t response_size = 0;
	size_t response_size_actual;
	sfc_inbuf_t req;
	sfc_outbuf_t resp;
	
	EFX_MCDI_DECLARE_BUF(inbuf,
                       sizeof(efx_dword_t) * 2 + MC_CMD_FILTER_OP_V3_IN_LEN, 0);
	EFX_MCDI_DECLARE_BUF(outbuf, 8 + MC_CMD_FILTER_OP_EXT_OUT_LEN, 0);

	/* Prepare proxy header */
	proxy_hdr = (efx_dword_t *)inbuf;

	EFX_POPULATE_DWORD_2(proxy_hdr[0],
				MCDI_HEADER_CODE, MC_CMD_V2_EXTN,
					MCDI_HEADER_RESYNC, 1);

	EFX_POPULATE_DWORD_2(proxy_hdr[1],
				MC_CMD_V2_EXTN_IN_EXTENDED_CMD, MC_CMD_FILTER_OP,
				MC_CMD_V2_EXTN_IN_ACTUAL_LEN, MC_CMD_FILTER_OP_V3_IN_LEN);

	req.emr_in_buf = (uint8_t *)&inbuf[PROXY_HDR_SIZE];
 
	/* Prepare filter command */
	MCDI_IN_SET_DWORD(req, FILTER_OP_EXT_IN_OP, MC_CMD_FILTER_OP_IN_OP_INSERT);
	/* Set port id */	
	MCDI_IN_SET_DWORD(req, FILTER_OP_EXT_IN_PORT_ID, vport_id);
	/* Set Flag */
	MCDI_IN_SET_DWORD(req, FILTER_OP_EXT_IN_MATCH_FIELDS, EFX_FILTER_MATCH_LOC_MAC);
	/* Set MAC */
	memcpy(MCDI_IN2(req, uint8_t, FILTER_OP_EXT_IN_SRC_MAC), src_mac_addr, EFX_MAC_ADDR_LEN);
				
	/* Populate proxy request buff with driver MCDI command */
	request_size = MC_CMD_FILTER_OP_V3_IN_LEN + PROXY_HDR_SIZE;
	response_size = MC_CMD_FILTER_OP_EXT_OUT_LEN + PROXY_HDR_SIZE; 
	
	/* Send proxy command */
	rc = efx_mcdi_proxy_cmd(enp, pf_index, vf_index, 
				inbuf, request_size,
				outbuf, response_size,
				&response_size_actual);
				
	printf("\n from filter insert rc : %d", (int)rc);
	
	/* Process proxy command response */
	if (response_size_actual < response_size) {
		rc = EMSGSIZE;		
	}

	proxy_hdr = (efx_dword_t *)&inbuf[0];
	
	if(EFX_DWORD_FIELD(*proxy_hdr, MCDI_HEADER_ERROR)) {
		DRV_FILTER_LOG(ERR, "Proxied cmd failed");
		return rc;
	}
	
    /* Reasponse is after proxy header */
  	resp.emr_out_buf = (uint8_t *)&outbuf[PROXY_HDR_SIZE];
	
	handle->efh_lo = MCDI_OUT_DWORD(resp, FILTER_OP_EXT_OUT_HANDLE_LO);
	handle->efh_hi = MCDI_OUT_DWORD(resp, FILTER_OP_EXT_OUT_HANDLE_HI);
	
	return rc;
}

int
sfc_vdpa_proxy_filter_remove(efx_nic_t *enp, unsigned int pf_index, 
							unsigned int vf_index, ef10_filter_handle_t *handle)
{
	int rc;
	efx_dword_t *proxy_hdr = NULL;
	size_t request_size = 0;
	size_t response_size = 0;
	size_t response_size_actual;
	sfc_inbuf_t req;
	
	EFX_MCDI_DECLARE_BUF(inbuf,
                       sizeof(efx_dword_t) * 2 + MC_CMD_FILTER_OP_V3_IN_LEN, 0);
	EFX_MCDI_DECLARE_BUF(outbuf, 8 + MC_CMD_FILTER_OP_EXT_OUT_LEN, 0);

	/* Prepare proxy header */
	proxy_hdr = (efx_dword_t *)inbuf;

	EFX_POPULATE_DWORD_2(proxy_hdr[0],
				MCDI_HEADER_CODE, MC_CMD_V2_EXTN,
					MCDI_HEADER_RESYNC, 1);

	EFX_POPULATE_DWORD_2(proxy_hdr[1],
				MC_CMD_V2_EXTN_IN_EXTENDED_CMD, MC_CMD_FILTER_OP,
				MC_CMD_V2_EXTN_IN_ACTUAL_LEN, MC_CMD_FILTER_OP_V3_IN_LEN);

	req.emr_in_buf = (uint8_t *)&inbuf[PROXY_HDR_SIZE];
 
	/* Prepare filter command */
	MCDI_IN_SET_DWORD(req, FILTER_OP_EXT_IN_OP, MC_CMD_FILTER_OP_IN_OP_REMOVE);
	MCDI_IN_SET_DWORD(req, FILTER_OP_EXT_IN_HANDLE_LO, handle->efh_lo);
	MCDI_IN_SET_DWORD(req, FILTER_OP_EXT_IN_HANDLE_HI, handle->efh_hi);
		
	/* Populate proxy request buff with driver MCDI command */
	request_size = MC_CMD_FILTER_OP_V3_IN_LEN + PROXY_HDR_SIZE;
	response_size = MC_CMD_FILTER_OP_EXT_OUT_LEN + PROXY_HDR_SIZE;
	
	/* Send proxy command */
	rc = efx_mcdi_proxy_cmd(enp, pf_index, vf_index, 
				inbuf, request_size,
				outbuf, response_size,
				&response_size_actual);
	
	
	printf("\n From filter remove  rc : %d", (int)rc);
	
	/* Process proxy command response */
	if (response_size_actual < response_size) {
		rc = EMSGSIZE;		
	}

	proxy_hdr = (efx_dword_t *)&outbuf[0];
	
	if(EFX_DWORD_FIELD(*proxy_hdr, MCDI_HEADER_ERROR)) {
		DRV_FILTER_LOG(ERR, "Proxied cmd failed");
		return rc;
	}

	return rc;
}

int sfc_vdpa_filter_config(struct sfc_vdpa_ops_data *vdpa_data)
{
	int rc = 0;
	uint8_t bcast_eth_addr[6];
	
	ef10_filter_handle_t filter_handle = {0,0};
	
	if(vdpa_data == NULL)
		return -1;
	
	/* Configure broadcast MAC Filter */
	EFX_MAC_BROADCAST_ADDR_SET(bcast_eth_addr);
	printf("\n Using vport id for filter creation: %u", vdpa_data->vport_id);
	rc = sfc_vdpa_proxy_filter_insert(vdpa_data->nic, vdpa_data->pf_index, 
					vdpa_data->vf_index, vdpa_data->vport_id, bcast_eth_addr, &filter_handle);

	if (rc == 0) {
		vdpa_data->bcast_mac_filter_handle.efh_lo = filter_handle.efh_lo;
		vdpa_data->bcast_mac_filter_handle.efh_hi = filter_handle.efh_hi;
	}

	/* Configure unicast MAC Filter */
	rc = sfc_vdpa_proxy_filter_insert(vdpa_data->nic, vdpa_data->pf_index, 
					vdpa_data->vf_index, vdpa_data->vport_id, vdpa_data->eth_addr, &filter_handle);
	if (rc == 0) {		
		vdpa_data->unicast_mac_filter_handle.efh_lo = filter_handle.efh_lo;
		vdpa_data->unicast_mac_filter_handle.efh_hi = filter_handle.efh_hi;
	}
	
	return rc;
}

int sfc_vdpa_filter_remove(struct sfc_vdpa_ops_data *vdpa_data)
{
	int rc = 0;
	
	if(vdpa_data == NULL)
		return -1;
	
	/* Remove broadcast MAC Filter */
	rc = sfc_vdpa_proxy_filter_remove(vdpa_data->nic, vdpa_data->pf_index, 
					vdpa_data->vf_index, &vdpa_data->bcast_mac_filter_handle);

	if (rc != 0) 
		return rc;
		
	/* Remove unicast MAC Filter */
	rc = sfc_vdpa_proxy_filter_remove(vdpa_data->nic, vdpa_data->pf_index, 
					vdpa_data->vf_index, &vdpa_data->unicast_mac_filter_handle);
	
	return rc;
}