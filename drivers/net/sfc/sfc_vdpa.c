/* 
 *   Copyright(c) 2019 Solarflare Inc. TBD 
 */

#include "sfc_vdpa.h"
#include "sfc.h"
#include "efx.h"
#include "rte_ethdev.h"
#include "efx_mcdi.h"
#include "efx_regs_mcdi.h"
#include "efx_impl.h"
#include <rte_vhost.h>

/* ToDO : PF is hardcoded for testing only */
#define HARD_CODED_PF_ADDR

#define DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, sfc_logtype_driver, \
		"SFC_VDPA %s(): " fmt "\n", __func__, ##args)

void rte_get_vf_to_pf_index(char *vf, char *pf);
struct rte_eth_dev * rte_get_pf_to_eth_dev(const char * pf_name);
uint16_t get_rid_from_pci_addr(struct rte_pci_addr pci_addr);

uint32_t sfc_logtype_driver;

int 
sfc_vdpa_get_vfpf_id(struct sfc_vdpa_ops_data *vdpa_data, uint16_t pf_rid, uint16_t vf_rid, uint32_t *pf_index, uint32_t *vf_index);

static const char * const sfc_vdpa_valid_arguments[] = {
	SFC_VDPA_MODE
};
static pthread_mutex_t sfc_vdpa_adapter_list_lock = PTHREAD_MUTEX_INITIALIZER;


// DPDK API : Find PF index for a VF
void rte_get_vf_to_pf_index(char *vf, char *pf)
{
	char cmd[100];
	/* cut command needs to be replaced with some rte func */
	snprintf(cmd, 1000, "ls -l  /sys/bus/pci/devices/%s/physfn | cut -d ' ' -f 12 | cut -b 4-15", vf);

	FILE *fp = popen(cmd, "r");
	if (fp == NULL) {
                printf ("failed to open popen");
		return;
	}

        fgets(pf, RTE_DEV_NAME_MAX_LEN, fp);
        if (!pf)
            printf(" failed to find phy device");

         printf("\n Parent PF :  %s \n", pf);

	if (pclose(fp) != 0)
        	fprintf(stderr," Error: Failed to close command stream \n");
         return;
}

// DPDK/SFC API name TBD :: Find ethdev for a PF
struct rte_eth_dev * rte_get_pf_to_eth_dev(const char * pf_name)
{
	int i = 0;
	uint16_t ports = rte_eth_dev_count_avail();
	struct rte_eth_dev *eth_dev = NULL;
	
	char port_name[RTE_ETH_NAME_MAX_LEN];

	printf("\n In rte_get_pf_to_eth_dev for PF : %s" , pf_name );
	printf("\n Available Port : %d", ports);

	for (i = 0; i < ports; i++)
	{
		DRV_LOG(ERR,"\n i=%d Port : %d", i, ports);

		/* Compare PCI address */
		if (rte_eth_dev_get_name_by_port(i, port_name) == 0) {

	   	printf("\n In rte_get_pf_to_eth_dev for PF : %s, port_name : %s" , pf_name, port_name);

			if (strncmp(port_name, pf_name, 12) == 0) {
				eth_dev = &rte_eth_devices[i];
				if (eth_dev == NULL)
					return NULL;
			}
		}
	
	}

	return eth_dev;
}

struct sfc_vdpa_ops_data *
get_vdpa_data_by_did(int did)
{
	int found = 0;
	struct sfc_vdpa_adapter_list *list;
	pthread_mutex_lock(&sfc_vdpa_adapter_list_lock);

	TAILQ_FOREACH(list, &sfc_vdpa_adapter_list, next) {
		if (did == list->sva->vdpa_data->did) {
			found = 1;
			break;
		}
	}

	pthread_mutex_unlock(&sfc_vdpa_adapter_list_lock);

	if (!found) {
		return NULL;
	}

	return list->sva->vdpa_data;
}

struct sfc_vdpa_adapter_list *
get_adapter_by_dev(struct rte_pci_device *pdev)
{
	int found = 0;
	struct sfc_vdpa_adapter_list *list;

	pthread_mutex_lock(&sfc_vdpa_adapter_list_lock);

	TAILQ_FOREACH(list, &sfc_vdpa_adapter_list, next) {
		if (pdev == list->sva->pdev) {
			found = 1;
			break;
		}
	}

	pthread_mutex_unlock(&sfc_vdpa_adapter_list_lock);

	if (!found)
		return NULL;

	return list;
}

// TODO : Revisit this function after UT.
static int
sfc_vdpa_mem_bar_init(struct sfc_vdpa_adapter *sva, const efx_bar_region_t *mem_ebrp)
{
	struct rte_pci_device *pci_dev = sva->pdev;
	efsys_bar_t *ebp = &sva->mem_bar;
	struct rte_mem_resource *res = &pci_dev->mem_resource[mem_ebrp->ebr_index];
	return 0; // TODO : remove it after testing

	SFC_BAR_LOCK_INIT(ebp, "memBAR");
	ebp->esb_rid = mem_ebrp->ebr_index;
	ebp->esb_dev = pci_dev;
	ebp->esb_base = res->addr;

	sva->vdpa_data->fcw_offset = mem_ebrp->ebr_offset;

	return 0;
}

static void
sfc_vdpa_mem_bar_fini(struct sfc_vdpa_adapter *sva)
{
	efsys_bar_t *ebp = &sva->mem_bar;

	SFC_BAR_LOCK_DESTROY(ebp);
	memset(ebp, 0, sizeof(*ebp));
}

static int
sfc_vdpa_proxy_driver_attach(efx_nic_t *enp, 
				unsigned int pf_index, unsigned int vf_index, boolean_t attach)
{
	int rc;
	efx_dword_t *proxy_hdr = NULL;
	size_t request_size = 0, req_length = 0;
	size_t response_size = 0;
	size_t response_size_actual;
	sfc_inbuf_t req;
	
	printf("\n in sfc_vdpa_proxy_driver_attach .. ");
	
	EFX_MCDI_DECLARE_BUF(inbuf,
                       sizeof(efx_dword_t) * 2 + MC_CMD_DRV_ATTACH_IN_V2_LEN, 0);

	//	EFX_MCDI_DECLARE_BUF(outbuf, MC_CMD_DRV_ATTACH_OUT_LEN, 0);

   	proxy_hdr = (efx_dword_t *)inbuf;

	EFX_POPULATE_DWORD_2(proxy_hdr[0],
				MCDI_HEADER_CODE, MC_CMD_V2_EXTN,
					MCDI_HEADER_RESYNC, 1);

	EFX_POPULATE_DWORD_2(proxy_hdr[1],
				MC_CMD_V2_EXTN_IN_EXTENDED_CMD, MC_CMD_DRV_ATTACH,
				MC_CMD_V2_EXTN_IN_ACTUAL_LEN, MC_CMD_DRV_ATTACH_IN_LEN);


	req.emr_in_buf = (uint8_t *)&inbuf[8];

	/* Prepare DRV_ATTACH command */
	if (enp->en_drv_version[0] == '\0') {
		req_length = MC_CMD_DRV_ATTACH_IN_LEN;
	} else {
		req_length = MC_CMD_DRV_ATTACH_IN_V2_LEN;
	}
	
	MCDI_IN_POPULATE_DWORD_2(req, DRV_ATTACH_IN_NEW_STATE,
	    DRV_ATTACH_IN_ATTACH, attach ? 1 : 0,
	    DRV_ATTACH_IN_SUBVARIANT_AWARE, EFSYS_OPT_FW_SUBVARIANT_AWARE);
	
	MCDI_IN_SET_DWORD(req, DRV_ATTACH_IN_UPDATE, 1);
	MCDI_IN_SET_DWORD(req, DRV_ATTACH_IN_FIRMWARE_ID, enp->efv);

	if (req_length >= MC_CMD_DRV_ATTACH_IN_V2_LEN) {
		EFX_STATIC_ASSERT(sizeof (enp->en_drv_version) ==
		    MC_CMD_DRV_ATTACH_IN_V2_DRIVER_VERSION_LEN);
		memcpy(MCDI_IN2(req, char, DRV_ATTACH_IN_V2_DRIVER_VERSION),
		    enp->en_drv_version,
		    MC_CMD_DRV_ATTACH_IN_V2_DRIVER_VERSION_LEN);
	}

	/* Populate proxy request buff with driver MCDI command */
	request_size = req_length + 8; 
	response_size = MC_CMD_DRV_ATTACH_EXT_OUT_LEN + 8;
	
	/* Send proxy command */
	rc = efx_mcdi_proxy_cmd(enp, pf_index, vf_index, 
				inbuf, request_size,
				inbuf, response_size,
				&response_size_actual);
						
	/* Process proxy command response */
	if (response_size_actual < response_size) {
	printf("\n proxy cmd failed ...response_size_actual:%d response_size: %d ", (int)response_size_actual, (int)response_size);
		rc = EMSGSIZE;		
	}


	return rc;
}

static int
sfc_vdpa_proxy_vi_alloc(efx_nic_t *enp, 
				unsigned int pf_index, unsigned int vf_index,
				unsigned int min_vi_count, unsigned int max_vi_count)
{
	int rc;
	efx_dword_t *proxy_hdr = NULL;
	size_t request_size = 0;
	size_t response_size = 0;
	size_t response_size_actual;
	uint32_t vi_base=0, vi_count=0, vi_shift=0;
	sfc_inbuf_t req;
	sfc_outbuf_t resp;

	printf("\n In sfc_vdpa_proxy_vi_alloc ...  .. ");
	EFX_MCDI_DECLARE_BUF(inbuf,
                       sizeof(efx_dword_t) * 2 + MC_CMD_ALLOC_VIS_IN_LEN, 0);
	EFX_MCDI_DECLARE_BUF(outbuf, 8 + MC_CMD_ALLOC_VIS_EXT_OUT_LEN, 0);

	/* Prepare proxy header */
	proxy_hdr = (efx_dword_t *)inbuf;

	EFX_POPULATE_DWORD_2(proxy_hdr[0],
				MCDI_HEADER_CODE, MC_CMD_V2_EXTN,
					MCDI_HEADER_RESYNC, 1);

	EFX_POPULATE_DWORD_2(proxy_hdr[1],
				MC_CMD_V2_EXTN_IN_EXTENDED_CMD, MC_CMD_ALLOC_VIS,
				MC_CMD_V2_EXTN_IN_ACTUAL_LEN, MC_CMD_ALLOC_VIS_IN_LEN);


	req.emr_in_buf = (uint8_t *)&inbuf[8];

	/* Prepare VI_ALLOC command */	
	MCDI_IN_SET_DWORD(req, ALLOC_VIS_IN_MIN_VI_COUNT, min_vi_count);
	MCDI_IN_SET_DWORD(req, ALLOC_VIS_IN_MAX_VI_COUNT, max_vi_count);
	
	/* Populate proxy request buff with driver MCDI command */
	request_size = MC_CMD_ALLOC_VIS_IN_LEN +8; 
	response_size = MC_CMD_ALLOC_VIS_EXT_OUT_LEN +8;
	
	/* Send proxy command */
	rc = efx_mcdi_proxy_cmd(enp, pf_index, vf_index, 
				inbuf, request_size,
				outbuf, response_size,
				&response_size_actual);
						
	/* Process proxy command response */
	if (response_size_actual < response_size) {
		rc = EMSGSIZE;		
	}

  	resp.emr_out_buf = (uint8_t *)&outbuf[8];

	vi_base = MCDI_OUT_DWORD(resp, ALLOC_VIS_OUT_VI_BASE);
	vi_count = MCDI_OUT_DWORD(resp, ALLOC_VIS_OUT_VI_COUNT);

	/* Report VI_SHIFT if available (always zero for Huntington) */
	if (response_size < MC_CMD_ALLOC_VIS_EXT_OUT_LEN)
		vi_shift = 0;
	else
		vi_shift = MCDI_OUT_DWORD(resp, ALLOC_VIS_EXT_OUT_VI_SHIFT);

printf("\n vi_base : %d, vi_count : %d, vi_shift : %d \n", vi_base, vi_count, vi_shift);	

	return rc;
}

static int
sfc_vdpa_proxy_vadapter_alloc(efx_nic_t *enp, 
				unsigned int pf_index, unsigned int vf_index, uint32_t port_id)
{
	return 0;

	int rc;
	efx_dword_t *proxy_hdr = NULL;
	size_t request_size = 0;
	size_t response_size = 0;
	size_t response_size_actual;
	sfc_inbuf_t req;

	printf("\n in sfc_vdpa_proxy_vadopter_alloc .. ");

	EFX_MCDI_DECLARE_BUF(inbuf,
                       sizeof(efx_dword_t) * 2 + MC_CMD_VADAPTOR_ALLOC_IN_LEN, 0);
	EFX_MCDI_DECLARE_BUF(outbuf, MC_CMD_VADAPTOR_ALLOC_OUT_LEN, 0);

	/* Prepare proxy header */
        proxy_hdr = (efx_dword_t *)inbuf;

        EFX_POPULATE_DWORD_2(proxy_hdr[0],
                    MCDI_HEADER_CODE, MC_CMD_V2_EXTN,
                        MCDI_HEADER_RESYNC, 1);

        EFX_POPULATE_DWORD_2(proxy_hdr[1],
                    MC_CMD_V2_EXTN_IN_EXTENDED_CMD, MC_CMD_VADAPTOR_ALLOC,
                    MC_CMD_V2_EXTN_IN_ACTUAL_LEN, MC_CMD_VADAPTOR_ALLOC_IN_LEN);

	req.emr_in_buf = (uint8_t *)&inbuf[8];
   
	/* Prepare VI_ALLOC command */
	MCDI_IN_SET_DWORD(req, VADAPTOR_ALLOC_IN_UPSTREAM_PORT_ID, port_id);
	MCDI_IN_POPULATE_DWORD_1(req, VADAPTOR_ALLOC_IN_FLAGS,
	    VADAPTOR_ALLOC_IN_FLAG_PERMIT_SET_MAC_WHEN_FILTERS_INSTALLED,
	    1);

	/* Populate proxy request buff with driver MCDI command */
	/* Request size must be multiple of 4word */
	request_size = MC_CMD_VADAPTOR_ALLOC_IN_LEN + 8; 
	response_size = MC_CMD_VADAPTOR_ALLOC_OUT_LEN + 8;
	
	printf("\n pf_index : %d,vf_index %d , cmd : %d \n\n", pf_index, vf_index, *((uint32_t *)inbuf +4) );

	/* Send proxy command */
	rc = efx_mcdi_proxy_cmd(enp, pf_index, vf_index, 
				inbuf, request_size,
				outbuf, response_size,
				&response_size_actual);
						
	/* Process proxy command response */
	if (response_size_actual < response_size) {
		rc = EMSGSIZE;		
	}
	
	return rc;
}

/* TODO : Remove all prints */
int
efx_get_sriov_cfg(efx_nic_t *enp,
				unsigned int *vf_current, unsigned int *vf_offset, unsigned int *vf_stride)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload, MC_CMD_GET_SRIOV_CFG_IN_LEN,
		MC_CMD_GET_SRIOV_CFG_OUT_LEN);
	efx_rc_t rc = 0;
	enp =enp;

	req.emr_cmd = MC_CMD_GET_SRIOV_CFG;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_GET_SRIOV_CFG_IN_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_GET_SRIOV_CFG_OUT_LEN;
	printf("\n\n");

	efx_mcdi_execute(enp, &req);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail1;
	}

	//DRV_LOG(ERR,"\n In111 efx_get_sriov_cfg : vf_current : %d ", *vf_current);

	if (req.emr_out_length_used < MC_CMD_GET_SRIOV_CFG_OUT_LEN) {
		rc = EMSGSIZE;
		goto fail2;
	}

	*vf_current = MCDI_OUT_DWORD(req, GET_SRIOV_CFG_OUT_VF_CURRENT);
	*vf_offset  = MCDI_OUT_DWORD(req, GET_SRIOV_CFG_OUT_VF_OFFSET);
	*vf_stride  = MCDI_OUT_DWORD(req, GET_SRIOV_CFG_OUT_VF_STRIDE);

fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);

	return (rc);
}

/*Todo: Remove all debug prints which uses printf */
int
sfc_vdpa_get_vfpf_id(struct sfc_vdpa_ops_data *vdpa_data, uint16_t pf_rid, uint16_t vf_rid, uint32_t *pf_index, uint32_t *vf_index)
{	
	uint32_t vf_current=0, vf_offset=0, vf_stride=0;
	uint32_t vf_rid_base, rid_offset;
	uint32_t pf_rid_base;
	int rc = 0;
	uint32_t pf = 0, vf = 0;
	
	/* Get PF Index */
	rc = efx_mcdi_get_function_info(vdpa_data->nic, &pf, &vf);
	printf("\n rc from efx_mcdi_get_function_info : %d, vf:%d, pf:%d", rc, vf, pf);
	*pf_index = (uint16_t) pf;
	
	printf("\n In sfc_vdpa_get_vfpf_id : pf_index : %d ", *pf_index);

	/* Calculate PF's RID base */
	pf_rid_base = pf_rid - pf;
	
	/* Use mcdi MC_CMD_GET_SRIOV_CFG to get vf/pf index */
	rc = efx_get_sriov_cfg(vdpa_data->nic, &vf_current, &vf_offset, &vf_stride);
	
	vf_rid_base = pf_rid_base + vf_offset;
	printf("\n vf_rid : %d, vf_rid_base %d ", vf_rid, vf_rid_base);
    
	if (vf_rid >= vf_rid_base) 
	{
		printf("\n vf_rid_base %d ", vf_rid_base);
		rid_offset = (vf_rid - vf_rid_base);
	  
		if (rid_offset % vf_stride == 0) {
			vf = rid_offset / vf_stride;
			printf("\n vf %d ", vf);
			if (vf <= vf_current) {
				printf("\n In sfc_vdpa_get_vfpf_id : vf_index %d ", *vf_index);
				*vf_index = (uint16_t)vf;
				printf("\n final In sfc_vdpa_get_vfpf_id : vf_index %d ", *vf_index);
			
				return 0;
			}
	  	}
	} 
		
	printf("\n Error from sfc_vdpa_get_vfpf_id : pf_index : %d, vf_index : %d ", *pf_index, *vf_index );
	
	return rc;
}

uint16_t get_rid_from_pci_addr(struct rte_pci_addr pci_addr)
{
	uint16_t rid;  
	rid = (((pci_addr.bus & 0xff) << 8) | ((pci_addr.devid & 0xff) << 5) | (pci_addr.function & 0x7));
	return rid;
}
	
int
sfc_vdpa_device_init(struct sfc_vdpa_adapter *sva)
{
	struct rte_pci_device *pci_dev = sva->pdev;
	efx_nic_t *enp = NULL;
	efx_bar_region_t mem_ebr;
	efsys_pci_config_t espc;
	uint32_t min_vi_count, max_vi_count;
	uint32_t pf_index=0, vf_index=0;
	uint32_t port_id;
	int rc;
	struct rte_pci_addr vf_pci_addr;
	uint16_t vf_rid = 0, pf_rid = 0; 
	
	vf_pci_addr = pci_dev->addr;

	/* Initialize NIC pointer with PF's NIC */
	enp = sva->vdpa_data->nic;
	if(enp == NULL)	{
		printf("\n enp : NULL");
		return -1;
	}
	
	/* Get VF's RID from vf pci address */
//	printf("\n vf_pci_addr.bus %x, vf_pci_addr.devid %x, vf_pci_addr.function %x \n", vf_pci_addr.bus, vf_pci_addr.devid, vf_pci_addr.function);

	vf_rid = (((vf_pci_addr.bus & 0xff) << 8) | ((vf_pci_addr.devid & 0xff) << 5) | (vf_pci_addr.function & 0x7));
	printf("vf_rid : %d", vf_rid);

	vf_rid = get_rid_from_pci_addr(vf_pci_addr);
	pf_rid = get_rid_from_pci_addr(sva->vdpa_data->pf_pci_addr);

	printf("\n From function : vf_rid : %d", vf_rid);
	printf("\n From function : pf_rid : %d \n\n", pf_rid);
	
	espc.espc_dev = pci_dev;
	rc = efx_family_probe_bar(pci_dev->id.vendor_id, pci_dev->id.device_id,
				  &espc, &sva->family, &mem_ebr);

	/* Get vf index */
	sfc_vdpa_get_vfpf_id(sva->vdpa_data, pf_rid, vf_rid, &pf_index, &vf_index);
	vf_index = 0; // TODO : For testing only
	printf("\n pf_index : %d vf_index :%d \n", pf_index,vf_index);
	sva->vdpa_data->pf_index = pf_index;
	sva->vdpa_data->vf_index = vf_index;

	/* Send proxy cmd for DRIVER_ATTACH */
	printf("\n Call proxy_driver_attach() ... ");
	rc = sfc_vdpa_proxy_driver_attach(enp, pf_index, vf_index, 1);

	/* Send proxy cmd for VIs_ALLOC */
	min_vi_count = 2;
	max_vi_count = 2;
	printf("\n Call proxy_vi_alloc() ... ");
	rc = sfc_vdpa_proxy_vi_alloc(enp, pf_index, vf_index, min_vi_count, max_vi_count);
	
	/* Send proxy cmd for VADAPTOR_ALLOC */
	port_id = EVB_PORT_ID_ASSIGNED;
	printf("\n Call proxy_vadapter_alloc() ... ");
	/* On a VF, this may fail with MC_CMD_ERR_NO_EVB_PORT (ENOENT) if the PF
	 * driver has yet to bring up the EVB port */
	rc = sfc_vdpa_proxy_vadapter_alloc(enp, pf_index, vf_index, port_id);

	rc = sfc_vdpa_mem_bar_init(sva, &mem_ebr);
	if (rc != 0)
		goto fail_mem_bar_init;

	rc = efx_virtio_init(enp);
	if (rc != 0)
		goto fail_virtio_init;

	sva->vdpa_data->state = SFC_VDPA_STATE_INITIALIZED;

	DRV_LOG(ERR,"\n Exit from probe");
	return 0;

fail_virtio_init:
fail_mem_bar_init:

	return rc;
}

void
sfc_vdpa_device_fini(struct sfc_vdpa_adapter *sva)
{
	SFC_ASSERT(sfc_vdpa_adapter_is_locked(sva->vdpa_data));

	sfc_vdpa_mem_bar_fini(sva);

	sva->vdpa_data->state = SFC_VDPA_STATE_UNINITIALIZED;
}
/* TODO: Remove all debug logs from this function */
static int
sfc_vdpa_vfio_setup(struct sfc_vdpa_adapter *sva)
{
	struct rte_pci_device *dev = sva->pdev;
	struct sfc_vdpa_ops_data *vdpa_data = sva->vdpa_data;
	
	char dev_name[RTE_DEV_NAME_MAX_LEN] = {0};
	int iommu_group_num;
	
	DRV_LOG(ERR,"\n IN sfc_vdpa_vfio_setup .. vdpa_data %p, dev.bus : %d ", vdpa_data, dev->addr.bus);
	DRV_LOG(ERR,"\n IN sfc_vdpa_vfio_setup .. vdpa_data %p, dev.devid: %d ", vdpa_data, dev->addr.devid);
	DRV_LOG(ERR,"\n IN sfc_vdpa_vfio_setup .. vdpa_data %p, dev.function %d ", vdpa_data, dev->addr.function);
	
	if ((vdpa_data == NULL) || (dev == NULL))
		return -1;
		
	vdpa_data->vfio_dev_fd = -1;
	vdpa_data->vfio_group_fd = -1;
	vdpa_data->vfio_container_fd = -1;

	rte_pci_device_name(&dev->addr, dev_name, RTE_DEV_NAME_MAX_LEN);

	vdpa_data->vfio_container_fd = rte_vfio_container_create();
	if (vdpa_data->vfio_container_fd < 0)
		return -1;

	rte_vfio_get_group_num(rte_pci_get_sysfs_path(), dev_name,
			&iommu_group_num);
			
	DRV_LOG(ERR,"\n sfc_vdpa_vfio_setup : vdpa_data->vfio_container_fd : ..%d ", vdpa_data->vfio_container_fd);
	DRV_LOG(ERR,"\n sfc_vdpa_vfio_setup : iommu_group_num :  %d", iommu_group_num);

	vdpa_data->vfio_group_fd = rte_vfio_container_group_bind(
			vdpa_data->vfio_container_fd, iommu_group_num);
	
	DRV_LOG(ERR,"\n sfc_vdpa_vfio_setup : vdpa_data->vfio_group_fd :  %d", vdpa_data->vfio_group_fd);

	if (vdpa_data->vfio_group_fd < 0)
		goto error;
	if (rte_pci_map_device(dev))
		goto error;
	
	vdpa_data->vfio_dev_fd = dev->intr_handle.vfio_dev_fd;
	
	return 0;

error:
	rte_vfio_container_destroy(vdpa_data->vfio_container_fd);
	return -1;
}

static inline int
check_vdpa_mode(const char *key __rte_unused, const char *value, void *extra_args)
{
	uint16_t *n = extra_args;

	if (value == NULL || extra_args == NULL)
		return -EINVAL;

	*n = (uint16_t)strtoul(value, NULL, 0);
	if (*n == USHRT_MAX && errno == ERANGE)
		return -1;

	return 0;
}
static struct rte_pci_id pci_id_sfc_vdpa_efx_map[] = {
#define RTE_PCI_DEV_ID_DECL_XNIC(vend, dev) {RTE_PCI_DEVICE(vend, dev)},
	RTE_PCI_DEV_ID_DECL_XNIC(EFX_PCI_VENID_XILINX, EFX_PCI_DEVID_RIVERHEAD_VF)
    { .vendor_id = 0, /* sentinel */ },
};

static int sfc_vdpa_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	struct sfc_vdpa_adapter *sva = NULL;
	struct sfc_vdpa_adapter_list  *sva_list = NULL;
	int vdpa_mode = 0, ret = 0;
	struct rte_kvargs *kvlist = NULL;
	struct sfc_vdpa_ops_data *vdpa_data;
	struct rte_pci_device *pf_pci_dev = NULL;
	struct rte_eth_dev *pf_eth_dev = NULL; 
	struct sfc_adapter *sa = NULL;
	char pf_dev_name[RTE_DEV_NAME_MAX_LEN] = {0};	
	char vf_dev_name[RTE_DEV_NAME_MAX_LEN] = {0};		

	DRV_LOG(ERR,"\n Enter in probe");

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	kvlist = rte_kvargs_parse(pci_dev->device.devargs->args,
				sfc_vdpa_valid_arguments);
	if (kvlist == NULL)
		return 1;

	/* Do not probe if vdpa mode is not specified */
	if (rte_kvargs_count(kvlist, SFC_VDPA_MODE) == 0) {
		rte_kvargs_free(kvlist);
		return 1;
	}

	ret = rte_kvargs_process(kvlist, SFC_VDPA_MODE, &check_vdpa_mode,
				&vdpa_mode);
	if (ret < 0 || vdpa_mode == 0) {
		rte_kvargs_free(kvlist);
		return 1;
	}

	sva_list = rte_zmalloc("sfc_vdpa", sizeof(struct sfc_vdpa_adapter_list), 0);
	if (sva_list == NULL)
		goto error;

	sva = rte_zmalloc("sfc_vdpa", sizeof(struct sfc_vdpa_adapter), 0);
	if (sva == NULL)
		goto error;

	sva->pdev = pci_dev;

	/* Create vdpa context */
	vdpa_data = sfc_vdpa_create_context();
	if (vdpa_data == NULL)
		goto error;
		
	vdpa_data->vdpa_context = SFC_VDPA_AS_VF;
	vdpa_data->pci_dev = pci_dev;

	/* Store vdpa context in the adpopter structure */
	sva->vdpa_data = vdpa_data;

	if (sfc_vdpa_vfio_setup(sva) < 0) {
		DRV_LOG(ERR, "failed to setup device %s", pci_dev->name);
		goto error;
	} else
		DRV_LOG(ERR, "Successfully setup devices %s", pci_dev->name);

	/* Find Parent PF's and its rte_eth_dev to access process_private fields */
	rte_pci_device_name(&pci_dev->addr, vf_dev_name, RTE_DEV_NAME_MAX_LEN);
	DRV_LOG(ERR,"\n vf_dev_name : %s, pf_dev_name %s ", vf_dev_name, pf_dev_name);

#ifndef HARD_CODED_PF_ADDR /*TODO: Need to use generic function to get parent's ID*/
	rte_get_vf_to_pf_index(vf_dev_name, pf_dev_name);
	if(pf_dev_name == NULL) {
		DRV_LOG(ERR,"\n Could not find any PF device ");
		return 0;
	}
#endif

	/* Get PF's rte_eth_dev to access process_private (PF's adapter) fields */
#ifdef HARD_CODED_PF_ADDR
	/* ToDO : PF is hardcoded for testing only */
	pf_eth_dev = rte_get_pf_to_eth_dev("01:00.2");
#else
	pf_eth_dev = rte_get_pf_to_eth_dev(pf_dev_name);
#endif

	DRV_LOG(ERR,"\n pf_eth_dev : %p ", pf_eth_dev);

	if (pf_eth_dev != NULL) {
        	sa = (struct sfc_adapter *)pf_eth_dev->process_private;
		if (sa == NULL)
			goto error;
		
       	 	DRV_LOG(ERR,"\n state : %d,", sa->state);
	}
	else {		
		DRV_LOG(ERR,"\n PF's ethdev could not found");
		return 0;
	}
	
	/* Update vdpa context vdpa_data fields */
	vdpa_data->nic = sa->nic;
	pf_pci_dev = RTE_ETH_DEV_TO_PCI(pf_eth_dev);
	vdpa_data->pf_pci_addr = pf_pci_dev->addr;
	
	rte_spinlock_init(&sva->lock);
	
	vdpa_data->lock = sva->lock;

	if (sfc_vdpa_device_init(sva) < 0) {
		DRV_LOG(ERR, "failed to init device %s", pci_dev->name);
		goto error;
	}
	
	DRV_LOG(ERR,"\n vf_dev_name : %s, pf_dev_name %s ", vf_dev_name, pf_dev_name);

	sva->dev_addr.pci_addr = pci_dev->addr;
	sva->dev_addr.type = PCI_ADDR;
	sva_list->sva = sva;
	
	/* Register vdpa ops */
	sfc_vdpa_register_device(vdpa_data, &sva->dev_addr);
	
	DRV_LOG(ERR,"\n sfc_vdpa_register_device Done");

	pthread_mutex_lock(&sfc_vdpa_adapter_list_lock);
	TAILQ_INSERT_TAIL(&sfc_vdpa_adapter_list, sva_list, next);
	pthread_mutex_unlock(&sfc_vdpa_adapter_list_lock);

	rte_kvargs_free(kvlist);
	
	DRV_LOG(ERR,"\n Probe Complete");
	
	return 0;

error:
	rte_kvargs_free(kvlist);
	rte_free(sva_list);
	rte_free(sva);
	return -1;
}

static int sfc_vdpa_pci_remove(struct rte_pci_device *pci_dev)
{
	struct sfc_vdpa_adapter *sva = NULL;
	struct sfc_vdpa_adapter_list  *sva_list = NULL;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	sva_list = get_adapter_by_dev(pci_dev);
	if (sva_list == NULL) {
		DRV_LOG(ERR, "Invalid device: %s", pci_dev->name);
		return -1;
	}

	sva = sva_list->sva;

	sfc_vdpa_device_fini(sva);

	rte_pci_unmap_device(sva->pdev);
	rte_vfio_container_destroy(sva->vdpa_data->vfio_container_fd);
	sfc_vdpa_unregister_device(sva->vdpa_data);

	pthread_mutex_lock(&sfc_vdpa_adapter_list_lock);
	TAILQ_REMOVE(&sfc_vdpa_adapter_list, sva_list, next);
	pthread_mutex_unlock(&sfc_vdpa_adapter_list_lock);

	rte_free(sva_list);
	rte_free(sva);

	return 0;
}

static struct rte_pci_driver rte_sfc_vdpa = {
	.id_table = pci_id_sfc_vdpa_efx_map,
	.drv_flags = 0,
	.probe = sfc_vdpa_pci_probe,
	.remove = sfc_vdpa_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_sfc_vdpa, rte_sfc_vdpa);
RTE_PMD_REGISTER_PCI_TABLE(net_sfc_vdpa, pci_id_sfc_vdpa_efx_map);
RTE_PMD_REGISTER_KMOD_DEP(net_sfc_vdpa, "vfio-pci");

RTE_INIT(sfc_driver_register_logtype)
{
	int ret;

	ret = rte_log_register_type_and_pick_level(SFC_LOGTYPE_PREFIX "driver",
						   RTE_LOG_NOTICE);
	sfc_logtype_driver = (ret < 0) ? RTE_LOGTYPE_PMD : ret;
}
