#include "sfc_vdpa.h"
#include "efx.h"
#include "efx_mcdi.h"
#include "efx_regs_mcdi.h"
#include "efx_impl.h"
#include <rte_vhost.h>
#include <inttypes.h>

uint32_t sfc_vdpa_ops_logtype_driver;
#define DRV_OPS_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, sfc_vdpa_ops_logtype_driver, \
		"SFC_VDPA_OPS %s(): " fmt "\n", __func__, ##args)

/* Get function-local index of the associated VI from the 
 * virtqueue number queue 0 is reserved for MCDI 
 */
#define SFC_GET_VI_INDEX(vq_num) ((vq_num/2) + 1)

/* TODD : Move it to proper place */
/* This value has been taken from FW */
#define  MAE_MPORT_SELECTOR_ASSIGNED 0x1000000

static int
sfc_vdpa_dma_map(struct sfc_vdpa_ops_data *vdpa_data, bool do_map)
{
	uint32_t i;
	int status;
	struct rte_vhost_memory *vhost_mem = NULL;
	struct rte_vhost_mem_region *mem_reg = NULL;

	status = rte_vhost_get_mem_table(vdpa_data->vid, &vhost_mem);
	if (status < 0) {
			DRV_OPS_LOG(ERR, "failed to get VM memory layout.");
			goto exit;
	}

	for (i = 0; i < vhost_mem->nregions; i++) {
			mem_reg = &vhost_mem->regions[i];

		if (do_map) {
			status = rte_vfio_container_dma_map(vdpa_data->vfio_container_fd,
									mem_reg->host_user_addr,
									mem_reg->guest_phys_addr,
									mem_reg->size);
			if (status < 0) {
					DRV_OPS_LOG(ERR, "DMA map failed.");
					goto exit;
			}
		} else {
			status = rte_vfio_container_dma_unmap(vdpa_data->vfio_container_fd,
									mem_reg->host_user_addr, mem_reg->guest_phys_addr,
									mem_reg->size);
			if (status < 0) {
					DRV_OPS_LOG(ERR, "DMA unmap failed.");
					goto exit;
			}
		}
	}

exit:
	if (vhost_mem)
			free(vhost_mem);
	return status;
}

static int
sfc_vdpa_configure(struct sfc_vdpa_ops_data *vdpa_data)
{
	int ret;

	SFC_ASSERT(vdpa_data->state == SFC_VDPA_STATE_INITIALIZED);

	if (rte_atomic32_read(&vdpa_data->dev_attached)){
		vdpa_data->state = SFC_VDPA_STATE_CONFIGURING;
		ret = sfc_vdpa_dma_map(vdpa_data, 1);
		if (ret)
				goto fail_dma_map;
		vdpa_data->state = SFC_VDPA_STATE_CONFIGURED;
	}
	
    return 0;

fail_dma_map:
	vdpa_data->state = SFC_VDPA_STATE_INITIALIZED;
	
	return ret;
}

static int
sfc_vdpa_enable_vfio_intr(struct sfc_vdpa_ops_data *vdpa_data)
{
	int ret;
	uint32_t i, num_vring;
	char irq_set_buf[SFC_VDPA_MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int *irq_fd_ptr;
	struct rte_vhost_vring vring;

	num_vring = rte_vhost_get_vring_num(vdpa_data->vid);

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = sizeof(irq_set_buf);
	irq_set->count = num_vring + 1;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD |
			 VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;
	irq_set->start = 0;
	irq_fd_ptr = (int *)&irq_set->data;
	irq_fd_ptr[RTE_INTR_VEC_ZERO_OFFSET] = vdpa_data->pci_dev->intr_handle.fd;

	for (i = 0; i < num_vring; i++) {
		rte_vhost_get_vhost_vring(vdpa_data->vid, i, &vring);
		irq_fd_ptr[RTE_INTR_VEC_RXTX_OFFSET + i] = vring.callfd;
	}

	ret = ioctl(vdpa_data->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret) {
		DRV_OPS_LOG(ERR, "Error enabling MSI-X interrupts: %s",
				strerror(errno));
		return -1;
	}

	return 0;
}

static int
sfc_vdpa_disable_vfio_intr(struct sfc_vdpa_ops_data *vdpa_data)
{
	int ret;
	char irq_set_buf[SFC_VDPA_MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = sizeof(irq_set_buf);
	irq_set->count = 0;
	irq_set->flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;
	irq_set->start = 0;

	ret = ioctl(vdpa_data->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret) {
		DRV_OPS_LOG(ERR, "Error disabling MSI-X interrupts: %s",
				strerror(errno));
		return -1;
	}

	return 0;
}

static int
sfc_vdpa_virtq_init(struct sfc_vdpa_ops_data *vdpa_data)
{
	int i, rc = 0;
	efx_virtio_vq_cfg_t vq_cfg;
	efx_virtio_vq_type_t type;
	uint16_t target_vf = 0;
	uint32_t vi_index = 0;
	
	if (vdpa_data->vdpa_context == SFC_VDPA_AS_PF)
		target_vf = SFC_VDPA_VF_NULL;
	else if (vdpa_data->vdpa_context == SFC_VDPA_AS_VF)
		target_vf = vdpa_data->vf_index;
	
	for (i = 0; i < vdpa_data->num_vring; i++) {
		if(i%2) /* Even VQ for RX and odd for TX */
			type = EFX_VIRTIO_VQ_TYPE_NET_TXQ;
		else
			type = EFX_VIRTIO_VQ_TYPE_NET_RXQ;

		/* Get function-local index of the associated VI from the virtqueue number */ 
		vi_index = SFC_GET_VI_INDEX(i);
		
		vq_cfg.evvc_vq_size = vdpa_data->vring[i].size;
		vq_cfg.evvc_vq_pidx = vdpa_data->vring[i].last_used_idx;
		vq_cfg.evvc_vq_cidx = vdpa_data->vring[i].last_avail_idx;
		vq_cfg.evvc_desc_tbl_addr = vdpa_data->vring[i].desc;
		vq_cfg.evvc_avail_ring_addr = vdpa_data->vring[i].avail;
		vq_cfg.evvc_used_ring_addr = vdpa_data->vring[i].used;
		/* MSI-X vector is function-relative */	
		vq_cfg.evvc_msix_vector = i;
		vq_cfg.evvc_use_pasid = 0;
		vq_cfg.evvc_pas_id = 0;
		vq_cfg.evcc_features = (vdpa_data->dev_features & vdpa_data->req_features);
		vq_cfg.evcc_mport_selector = 0;
		vq_cfg.evcc_mport_selector = MAE_MPORT_SELECTOR_ASSIGNED;
	
		rc = efx_virtio_virtq_create(vdpa_data->nic, type, target_vf,
					vi_index, &vq_cfg);
		if(rc == 0) {
			/* Store created virtqueue context */
			vdpa_data->vq_cxt[i].vq.evv_vi_index = vi_index;
			vdpa_data->vq_cxt[i].vq.evv_type = type;
			vdpa_data->vq_cxt[i].vq.evv_target_vf = target_vf;
			vdpa_data->vq_cxt[i].vq_valid = B_TRUE;
		}
	}

	return rc;
}

static void
sfc_vdpa_virtq_fini(struct sfc_vdpa_ops_data *vdpa_data)
{
	int i, rc;
	uint32_t pidx;
	uint32_t cidx;
	efx_virtio_vq_t vq;

	for (i = 0; i < vdpa_data->num_vring; i++) {
		if(vdpa_data->vq_cxt[i].vq_valid != B_TRUE)
			continue; 

		vq.evv_vi_index = vdpa_data->vq_cxt[i].vq.evv_vi_index;
		vq.evv_type = vdpa_data->vq_cxt[i].vq.evv_type;
		vq.evv_target_vf = vdpa_data->vq_cxt[i].vq.evv_target_vf;
		
		rc = efx_virtio_virtq_destroy(vdpa_data->nic, &vq, &pidx, &cidx);
		if (rc == 0) {
			vdpa_data->vq_cxt[i].cidx = cidx;
			vdpa_data->vq_cxt[i].pidx = pidx;
			vdpa_data->vq_cxt[i].vq_valid = B_FALSE;
		}
	}
}

static void
sfc_vdpa_close(struct sfc_vdpa_ops_data *vdpa_data)
{
	int ret;

	SFC_ASSERT(vdpa_data->state == SFC_VDPA_STATE_STARTED);
	vdpa_data->state = SFC_VDPA_STATE_CLOSING;

	ret = sfc_vdpa_dma_map(vdpa_data, 0);
	if (ret)
		goto fail_dma_map;

	/* TODO: Bypassed filter remove due to issue FWRIVERHD-940 
	   It will be enabled once EVb support would be available */
	#if 0
	sfc_vdpa_filter_remove(vdpa_data);
	#endif
	
	printf("\n Calling virtq fini ");
	sfc_vdpa_virtq_fini(vdpa_data);

	vdpa_data->state = SFC_VDPA_STATE_INITIALIZED;
	return;

fail_dma_map:
	vdpa_data->state = SFC_VDPA_STATE_INITIALIZED;
}

static uint64_t
hva_to_gpa(int vid, uint64_t hva)
{
	struct rte_vhost_memory *vhost_mem = NULL;
	struct rte_vhost_mem_region *mem_reg = NULL;
	uint32_t i;
	uint64_t gpa = 0;

	if (rte_vhost_get_mem_table(vid, &vhost_mem) < 0)
		goto exit;

	for (i = 0; i < vhost_mem->nregions; i++) {
		mem_reg = &vhost_mem->regions[i];

		if (hva >= mem_reg->host_user_addr &&
				hva < mem_reg->host_user_addr + mem_reg->size) {
			gpa = hva - mem_reg->host_user_addr + mem_reg->guest_phys_addr;
			break;
		}
	}

exit:
	if (vhost_mem)
		free(vhost_mem);
	return gpa;
}

static int
sfc_vdpa_start(struct sfc_vdpa_ops_data *vdpa_data)
{
	int i, nr_vring;
	struct rte_vhost_vring vq;
	uint64_t gpa;
	int ret;

	SFC_ASSERT(vdpa_data->state == SFC_VDPA_STATE_CONFIGURED);

	vdpa_data->state = SFC_VDPA_STATE_STARTING;

	ret = sfc_vdpa_enable_vfio_intr(vdpa_data);
	if (ret < 0) {
		printf("\n\n\n sfc_vdpa_enable_vfio_intr failed ...");
		goto fail_enable_vfio_intr;
	}

	nr_vring = rte_vhost_get_vring_num(vdpa_data->vid);
	
	rte_vhost_get_negotiated_features(vdpa_data->vid, &vdpa_data->req_features);
	printf("\n from rte_vhost_get_negotiated_features : %llx \n\n ", (long long unsigned int)vdpa_data->req_features);
	
	for (i = 0; i < nr_vring; i++) {
		rte_vhost_get_vhost_vring(vdpa_data->vid, i, &vq);
		gpa = hva_to_gpa(vdpa_data->vid, (uint64_t)(uintptr_t)vq.desc);
		if (gpa == 0) {
			DRV_OPS_LOG(ERR, "Fail to get GPA for descriptor ring.");
			goto fail_vring_map;
		}
		vdpa_data->vring[i].desc = gpa;

		gpa = hva_to_gpa(vdpa_data->vid, (uint64_t)(uintptr_t)vq.avail);
		if (gpa == 0) {
			DRV_OPS_LOG(ERR, "Fail to get GPA for available ring.");
			goto fail_vring_map;
		}
		vdpa_data->vring[i].avail = gpa;

		gpa = hva_to_gpa(vdpa_data->vid, (uint64_t)(uintptr_t)vq.used);
		if (gpa == 0) {
			DRV_OPS_LOG(ERR, "Fail to get GPA for used ring.");
			goto fail_vring_map;
		}
		vdpa_data->vring[i].used = gpa;

		vdpa_data->vring[i].size = vq.size;
		rte_vhost_get_vring_base(vdpa_data->vid, i, &vdpa_data->vring[i].last_avail_idx,
				&vdpa_data->vring[i].last_used_idx);
	}
	vdpa_data->num_vring = i;

	ret = sfc_vdpa_virtq_init(vdpa_data);
	if (ret < 0) {
		goto fail_virtio_init;
	}

	vdpa_data->state = SFC_VDPA_STATE_STARTED;

	return 0;

fail_virtio_init:
fail_vring_map:
	sfc_vdpa_disable_vfio_intr(vdpa_data);

fail_enable_vfio_intr:
	vdpa_data->state = SFC_VDPA_STATE_CONFIGURED;
	return ret;
}

static int
sfc_vdpa_dev_config(int vid)
{
	int did;
	int ret = 0;
	struct sfc_vdpa_ops_data *vdpa_data;

	printf("\n ## VDPA_OPS : sfc_vdpa_config Invoked ## \n");
	
	did = rte_vhost_get_vdpa_device_id(vid);

	DRV_OPS_LOG(ERR, "device id: %d", did);

	vdpa_data = get_vdpa_data_by_did(did);
	if (vdpa_data == NULL) {
		DRV_OPS_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	vdpa_data->vid = vid;
	rte_atomic32_set(&vdpa_data->dev_attached, 1);

	sfc_vdpa_adapter_lock(vdpa_data);
	ret = sfc_vdpa_configure(vdpa_data);
	if(ret != 0)
		return -1;
	
	ret = sfc_vdpa_start(vdpa_data);
	if(ret != 0)
		return -1;
	
	#if 0
	ret = sfc_vdpa_filter_config(vdpa_data);
	if(ret != 0)
		return -1;
	#endif	
	sfc_vdpa_adapter_unlock(vdpa_data);
	
	if (rte_vhost_host_notifier_ctrl(vid, true) != 0)
		DRV_OPS_LOG(NOTICE, "vDPA (%d): software relay for notify is used.", did);

	return 0;
}

static int
sfc_virtio_proxy_get_features(efx_nic_t *enp,
				unsigned int pf_index, unsigned int vf_index,
				efx_virtio_device_type_t type, uint64_t *dev_features)
{
	int rc;
	efx_dword_t *proxy_hdr = NULL;
	size_t request_size = 0;
	size_t response_size = 0;
	size_t response_size_actual;
	sfc_inbuf_t req;
	uint64_t dev_features_lo = 0;
	uint64_t dev_features_hi = 0;

	sfc_outbuf_t resp;

	EFX_MCDI_DECLARE_BUF(inbuf,
                       sizeof(efx_dword_t) * 2 + MC_CMD_VIRTIO_GET_FEATURES_IN_LEN, 0);
	EFX_MCDI_DECLARE_BUF(outbuf,
                       sizeof(efx_dword_t) * 2 + MC_CMD_VIRTIO_GET_FEATURES_OUT_LEN, 0);

	proxy_hdr = (efx_dword_t *)inbuf;

	EFX_POPULATE_DWORD_2(proxy_hdr[0],
				MCDI_HEADER_CODE, MC_CMD_V2_EXTN,
					MCDI_HEADER_RESYNC, 1);

	EFX_POPULATE_DWORD_2(proxy_hdr[1],
				MC_CMD_V2_EXTN_IN_EXTENDED_CMD, MC_CMD_VIRTIO_GET_FEATURES,
				MC_CMD_V2_EXTN_IN_ACTUAL_LEN, MC_CMD_VIRTIO_GET_FEATURES_IN_LEN);

	req.emr_in_buf = (uint8_t *)&inbuf[PROXY_HDR_SIZE];

	/* Prepare get feature command */
	MCDI_IN_SET_DWORD(req, VIRTIO_GET_FEATURES_IN_DEVICE_ID, type);

	/* Populate proxy request buff with driver MCDI command */
	request_size = MC_CMD_VIRTIO_GET_FEATURES_IN_LEN + PROXY_HDR_SIZE;
	response_size = MC_CMD_VIRTIO_GET_FEATURES_OUT_LEN + PROXY_HDR_SIZE;

	/* Send proxy command */
	rc = efx_mcdi_proxy_cmd(enp, pf_index, vf_index,
				inbuf, request_size,
				outbuf, response_size,
				&response_size_actual);
		
	printf("\n ## RC of VIRTIO MCDI MC_CMD_VIRTIO_GET_FEATURES (proxy) : %d ## \n", (int)rc);

	if (rc != 0)
		goto fail_proxy_cmd;

	/* Process proxy command response */
	if (response_size_actual < response_size) {
		rc = EMSGSIZE;		
	}
	
	resp.emr_out_buf = (uint8_t *)&outbuf[MCDI_RESP_HDR_SIZE];
	
	dev_features_lo = MCDI_OUT_DWORD(resp, VIRTIO_GET_FEATURES_OUT_FEATURES_LO);
	printf("\n LO 0x%x", (unsigned int) dev_features_lo);
	*dev_features = dev_features_lo & 0xFFFFFFFF;
	
	dev_features_hi = (MCDI_OUT_DWORD(resp, VIRTIO_GET_FEATURES_OUT_FEATURES_HI));
	printf("\n HI 0x%x", (unsigned int) dev_features_hi);
	*dev_features |= dev_features_hi << 32;

	return rc;
	
fail_proxy_cmd:
	DRV_OPS_LOG(ERR, "\n Proxy Cmd failed with error : %d  \n", (int)rc);
	return rc;
}

static int
sfc_virtio_proxy_verify_features(efx_nic_t *enp,
				unsigned int pf_index, unsigned int vf_index,
				efx_virtio_device_type_t type, uint64_t dev_features)
{
	int rc;
	efx_dword_t *proxy_hdr = NULL;
	size_t request_size = 0;
	size_t response_size = 0;
	size_t response_size_actual;
	sfc_inbuf_t req;

	EFX_MCDI_DECLARE_BUF(inbuf,
                       sizeof(efx_dword_t) * 2 + MC_CMD_VIRTIO_TEST_FEATURES_IN_LEN, 0);

	proxy_hdr = (efx_dword_t *)inbuf;
	
	EFX_POPULATE_DWORD_2(proxy_hdr[0],
				MCDI_HEADER_CODE, MC_CMD_V2_EXTN,
					MCDI_HEADER_RESYNC, 1);

	EFX_POPULATE_DWORD_2(proxy_hdr[1],
				MC_CMD_V2_EXTN_IN_EXTENDED_CMD, MC_CMD_VIRTIO_TEST_FEATURES,
				MC_CMD_V2_EXTN_IN_ACTUAL_LEN, MC_CMD_VIRTIO_TEST_FEATURES_IN_LEN);

	req.emr_in_buf = (uint8_t *)&inbuf[PROXY_HDR_SIZE];

	/* Prepare get feature command */
	MCDI_IN_SET_DWORD(req, VIRTIO_TEST_FEATURES_IN_DEVICE_ID, type);
	MCDI_IN_SET_DWORD(req, VIRTIO_TEST_FEATURES_IN_FEATURES, dev_features);

	/* Populate proxy request buff with driver MCDI command */
	request_size = MC_CMD_VIRTIO_TEST_FEATURES_IN_LEN + PROXY_HDR_SIZE;
	response_size = MC_CMD_VIRTIO_TEST_FEATURES_OUT_LEN + PROXY_HDR_SIZE;
	
	/* Send proxy command */
	rc = efx_mcdi_proxy_cmd(enp, pf_index, vf_index,
				inbuf, request_size,
				inbuf, response_size,
				&response_size_actual);
	
	printf("\n ## RC of VIRTIO MCDI MC_CMD_VIRTIO_TEST_FEATURES (proxy) : %d ## \n", (int)rc);

	if (rc != 0)
		goto fail_proxy_cmd;

	/* Process proxy command response */
	if (response_size_actual < response_size) {
		rc = EMSGSIZE;	
	}
	
	return rc;
	
fail_proxy_cmd:
	DRV_OPS_LOG(ERR, "\n Proxy Cmd failed with error : %d  \n", (int)rc);
	return rc;
}

static int
sfc_vdpa_get_device_features(struct sfc_vdpa_ops_data *vdpa_data)
{
	int rc = -1; 
	uint64_t dev_features = 0;
	
	if (vdpa_data->vdpa_context == SFC_VDPA_AS_PF) {
		rc = efx_virtio_get_features(vdpa_data->nic, 
						EFX_VIRTIO_DEVICE_TYPE_NET, 
						&dev_features);
	}
	else if (vdpa_data->vdpa_context == SFC_VDPA_AS_VF) {
		/* Send proxy command */
		rc = sfc_virtio_proxy_get_features(vdpa_data->nic, vdpa_data->pf_index, 
					vdpa_data->vf_index, EFX_VIRTIO_DEVICE_TYPE_NET, &dev_features);
	}
    
	vdpa_data->dev_features = dev_features;

	printf("\n vdpa_data->dev_features :: %" PRIu64 "\n", vdpa_data->dev_features );

	return rc;
}

/* vDPA OPs callbacks */
static int
sfc_vdpa_set_features(int vid)
{
	int did, rc = 0;
	struct sfc_vdpa_ops_data *vdpa_data = NULL;

	printf("\n ## VDPA_OPS : get_vfio_set_features Invoked ## \n");

	did = rte_vhost_get_vdpa_device_id(vid);
	vdpa_data = get_vdpa_data_by_did(did);
	
	if (vdpa_data == NULL) {
		DRV_OPS_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	if (vdpa_data->vdpa_context == SFC_VDPA_AS_PF) {
		rc = efx_virtio_verify_features(vdpa_data->nic, 
						EFX_VIRTIO_DEVICE_TYPE_NET, 
						vdpa_data->req_features);
	}
	else if (vdpa_data->vdpa_context == SFC_VDPA_AS_VF) {
		/* Send proxy command */
		rc = sfc_virtio_proxy_verify_features(vdpa_data->nic, vdpa_data->pf_index, 
						vdpa_data->vf_index, EFX_VIRTIO_DEVICE_TYPE_NET, 
						vdpa_data->req_features);
	}
	
	printf("\n RC from sfc_vdpa_set_features : %d ", rc);
	
	/* Check for ENOSUP and EINVAL values */
	if (rc  == MC_CMD_ERR_ENOTSUP /*ENOSUP*/) { 
		DRV_OPS_LOG(ERR, "Unsupported feature is requested");
	}
	else if (rc  == MC_CMD_ERR_EINVAL /*EINVAL*/) {
		DRV_OPS_LOG(ERR, "Required feature is not requested");
	}

	return rc;
}

static int
sfc_vdpa_get_vfio_group_fd(int vid)
{
	int did;
	struct sfc_vdpa_ops_data *vdpa_data = NULL;

	printf("\n ## VDPA_OPS : get_vfio_group_fd Invoked ## \n");

	did = rte_vhost_get_vdpa_device_id(vid);
	vdpa_data = get_vdpa_data_by_did(did);
	
	if (vdpa_data == NULL) {
		DRV_OPS_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	return vdpa_data->vfio_group_fd;
}

static int
sfc_vdpa_get_vfio_device_fd(int vid)
{
	int did;
	struct sfc_vdpa_ops_data *vdpa_data = NULL;

	printf("\n ## VDPA_OPS : get_vfio_device_fd Invoked ## \n");

	did = rte_vhost_get_vdpa_device_id(vid);
	vdpa_data = get_vdpa_data_by_did(did);
	
	if (vdpa_data == NULL) {
		DRV_OPS_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	return vdpa_data->vfio_dev_fd;
}

static int
sfc_vdpa_dev_close(int vid)
{
	int did;
	struct sfc_vdpa_ops_data *vdpa_data = NULL;

	printf("\n ## VDPA_OPS : get_close Invoked ## \n");

	did = rte_vhost_get_vdpa_device_id(vid);
	vdpa_data = get_vdpa_data_by_did(did);
	
	if (vdpa_data == NULL) {
		DRV_OPS_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	rte_atomic32_set(&vdpa_data->dev_attached, 0);
	sfc_vdpa_close(vdpa_data);

	sfc_vdpa_disable_vfio_intr(vdpa_data);
	
	return 0;
}

static int
sfc_vdpa_get_queue_num(int did, uint32_t *queue_num)
{
	struct sfc_vdpa_ops_data *vdpa_data = NULL;

	vdpa_data = get_vdpa_data_by_did(did);
	
	printf("\n ## VDPA_OPS : get_queue Invoked ## \n");
	
	if (vdpa_data == NULL) {
		DRV_OPS_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}
	
	*queue_num = vdpa_data->max_queues; /*Revisit */
	DRV_OPS_LOG(DEBUG, " number of queues For DID %d is %d \n", did, *queue_num);

	return 0;
}

static int
sfc_vdpa_get_features(int did, uint64_t *features)
{
	struct sfc_vdpa_ops_data *vdpa_data = NULL;

	DRV_OPS_LOG(ERR, "device id: %d", did);

	printf("\n ## VDPA_OPS : get_features Invoked ## \n");
		
	vdpa_data = get_vdpa_data_by_did(did);
	
	if (vdpa_data == NULL) {
		DRV_OPS_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}
	
	*features = vdpa_data->drv_features;
	printf("\n features : 0x%lx", *features);

	return 0;
}

#define VDPA_SUPPORTED_PROTOCOL_FEATURES \
		(1ULL << VHOST_USER_PROTOCOL_F_REPLY_ACK | \
		 1ULL << VHOST_USER_PROTOCOL_F_SLAVE_REQ | \
		 1ULL << VHOST_USER_PROTOCOL_F_SLAVE_SEND_FD | \
		 1ULL << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER | \
		 1ULL << VHOST_USER_PROTOCOL_F_LOG_SHMFD)
static int
sfc_vdpa_get_protocol_features(int did __rte_unused, uint64_t *features)
{
	printf("\n ## VDPA_OPS : get_protocol_features Invoked ## \n");

	*features = VDPA_SUPPORTED_PROTOCOL_FEATURES;
	return 0;
}

static int
sfc_vdpa_get_notify_area(int vid, int qid, uint64_t *offset, uint64_t *size)
{
	struct sfc_vdpa_ops_data *vdpa_data = NULL;
	efx_virtio_vq_t evv_data;
	unsigned int bar_offset = 0;
	unsigned int fcw_base = 0;
	efx_rc_t rc = 0;
	int did;
		
	printf("\n ## VDPA_OPS : get_notify_area Invoked ## \n");

	did = rte_vhost_get_vdpa_device_id(vid);
	vdpa_data = get_vdpa_data_by_did(did);
	
	if (vdpa_data == NULL) {
		DRV_OPS_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}
	
	evv_data.evv_vi_index = SFC_GET_VI_INDEX(qid);

	if (vdpa_data->vdpa_context == SFC_VDPA_AS_PF)
		evv_data.evv_target_vf = SFC_VDPA_VF_NULL;
	else if (vdpa_data->vdpa_context == SFC_VDPA_AS_VF)
		evv_data.evv_target_vf = vdpa_data->vf_index; 	

	if (evv_data.evv_vi_index % 2) /* Even Id for RX and odd for TX */
		evv_data.evv_type = EFX_VIRTIO_VQ_TYPE_NET_TXQ;
	else
		evv_data.evv_type = EFX_VIRTIO_VQ_TYPE_NET_RXQ;

	rc = efx_virtio_get_doorbell_offset(vdpa_data->nic, EFX_VIRTIO_DEVICE_TYPE_NET,
						&evv_data, &bar_offset);

	if (rc != 0)
		return rc;

	fcw_base = vdpa_data->fcw_offset;
	*offset = fcw_base + bar_offset;
	*size = 0x1000; /* FIXME */

	return 0;
}

static struct rte_vdpa_dev_ops sfc_vdpa_ops = {
	.get_queue_num = sfc_vdpa_get_queue_num,
	.get_features = sfc_vdpa_get_features,
	.get_protocol_features = sfc_vdpa_get_protocol_features,
	.dev_conf = sfc_vdpa_dev_config,
	.dev_close = sfc_vdpa_dev_close,
	.set_vring_state = NULL,
	.set_features = sfc_vdpa_set_features,
	.migration_done = NULL,
	.get_vfio_group_fd = sfc_vdpa_get_vfio_group_fd,
	.get_vfio_device_fd = sfc_vdpa_get_vfio_device_fd,
	.get_notify_area = sfc_vdpa_get_notify_area,
};

struct sfc_vdpa_ops_data *
sfc_vdpa_create_context(void)
{
	struct sfc_vdpa_ops_data *vdpa_data;
	
	/* Allocate memory for ops data */
	vdpa_data = rte_zmalloc("vdpa", sizeof(struct sfc_vdpa_ops_data), 0);
	if (vdpa_data == NULL)
	   return NULL;
	   
	return vdpa_data;
}

void
sfc_vdpa_delete_context(struct sfc_vdpa_ops_data *vdpa_data)
{
  /* Deallocate memory used for vDPA */
  rte_free(vdpa_data);
}

uint32_t
sfc_vdpa_register_device(struct sfc_vdpa_ops_data *vdpa_data, struct rte_vdpa_dev_addr *dev_addr)
{
	int rc = 0;
	
	/* Register VDPA Device */ 
	vdpa_data->did = rte_vdpa_register_device(dev_addr, &sfc_vdpa_ops);
	
	/** Open Items: rte_vdpa_register_device() takes 'struct rte_vdpa_dev_addr *' as parameter which has dev_addr in the BDF format. 
	For PASID, how it would be registered to vhost and how passid information to be passed ? If this struct would be updated for 
	pasid support then pasid can be registered to vhost. **/
	if (vdpa_data->did < 0) {
		return 0;
	}
	
	vdpa_data->max_queues = SFC_VDPA_MAX_QUEUES;
	/* Read supported device features */
	rc = sfc_vdpa_get_device_features(vdpa_data);
	if (rc == 0) {
		
		vdpa_data->drv_features = (vdpa_data->dev_features &
					~(1ULL << VIRTIO_F_IOMMU_PLATFORM)) |					 
					(1ULL << VIRTIO_NET_F_STATUS) |
					(1ULL << VHOST_USER_F_PROTOCOL_FEATURES) |
					(1ULL << VIRTIO_F_VERSION_1) |
					(1ULL << VHOST_F_LOG_ALL);
	}
	
	return rc;
}

void
sfc_vdpa_unregister_device(struct sfc_vdpa_ops_data *vdpa_data)
{
	/* Clear out vdpa data */
	rte_vdpa_unregister_device(vdpa_data->did);
}
