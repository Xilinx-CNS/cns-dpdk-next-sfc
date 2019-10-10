/* 
 *   Copyright(c) 2019 Solarflare Inc. TBD 
 */

#include "sfc_vdpa.h"

#define DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, sfc_logtype_driver, \
		"SFC_VDPA %s(): " fmt "\n", __func__, ##args)

uint32_t sfc_logtype_driver;

static const char * const sfc_vdpa_valid_arguments[] = {
	SFC_VDPA_MODE
};
static pthread_mutex_t sfc_vdpa_adapter_list_lock = PTHREAD_MUTEX_INITIALIZER;

static int
sfc_vdpa_dma_map(struct sfc_vdpa_adapter *adapter, bool do_map)
{
	uint32_t i;
	int status;
	struct rte_vhost_memory *vhost_mem = NULL;
	struct rte_vhost_mem_region *mem_reg = NULL;

	status = rte_vhost_get_mem_table(adapter->vid, &vhost_mem);
	if (status < 0) {
		DRV_LOG(ERR, "failed to get VM memory layout.");
		goto exit;
	}

	for (i = 0; i < vhost_mem->nregions; i++) {
		mem_reg = &vhost_mem->regions[i];

		if (do_map) {
			status = rte_vfio_container_dma_map(adapter->vfio_container_fd,
						mem_reg->host_user_addr,
						mem_reg->guest_phys_addr,
						mem_reg->size);
			if (status < 0) {
				DRV_LOG(ERR, "DMA map failed.");
				goto exit;
			}
		} else {
			status = rte_vfio_container_dma_unmap(adapter->vfio_container_fd,
						mem_reg->host_user_addr, mem_reg->guest_phys_addr,
						mem_reg->size);
			if (status < 0) {
				DRV_LOG(ERR, "DMA unmap failed.");
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
sfc_vdpa_configure(struct sfc_vdpa_adapter *sva)
{
        int ret;

        sfc_log_init(sva, "entry");

        SFC_ASSERT(sfc_adapter_is_locked(sva));

        SFC_ASSERT(sva->state == SFC_VDPA_ADAPTER_INITIALIZED ||
                   sva->state == SFC_VDPA_ADAPTER_CONFIGURED);

        if (rte_atomic32_read(&sva->dev_attached)){
                sva->state = SFC_VDPA_ADAPTER_CONFIGURING;

                ret = sfc_vdpa_dma_map(sva, 1);
                if (ret)
                        goto fail_dma_map;

                sfc_log_init(sva, "done");
                sva->state = SFC_VDPA_ADAPTER_CONFIGURED;
        }
        return 0;

fail_dma_map:
        sva->state = SFC_VDPA_ADAPTER_INITIALIZED;
        sfc_log_init(sva, "failed %d", ret);
        return ret;
}

static void
sfc_vdpa_virtq_fini(struct sfc_vdpa_adapter *sva)
{
	int i, rc;
	uint32_t pidx;
	uint32_t cidx;
	
	for (i = 0; i < sva->num_vring; i++) {
		if(sva->vq[i] == NULL)
			continue; 

		rc = efx_virtio_virtq_destroy(sva->vq[i],
					&pidx, &cidx);
		if (rc == 0) {
			sva->cidx[i] = cidx;
			sva->pidx[i] = pidx;
			sva->vq[i] = NULL;
		}
	}
}

static void
sfc_vdpa_close(struct sfc_vdpa_adapter *sva)
{
        int ret;

        sfc_log_init(sva, "entry");

        SFC_ASSERT(sfc_adapter_is_locked(sva));

        SFC_ASSERT(sva->state == SFC_VDPA_ADAPTER_CONFIGURED);
        sva->state = SFC_VDPA_ADAPTER_CLOSING;

        ret = sfc_vdpa_dma_map(sva, 0);
        if (ret)
                goto fail_dma_map;

	sfc_vdpa_virtq_fini(sva);

        sfc_log_init(sva, "done");
        sva->state = SFC_VDPA_ADAPTER_INITIALIZED;
        return;

fail_dma_map:
        sva->state = SFC_VDPA_ADAPTER_INITIALIZED;
        sfc_log_init(sva, "failed %d", ret);
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
sfc_vdpa_enable_vfio_intr(struct sfc_vdpa_adapter *sva)
{
	int ret;
	uint32_t i, num_vring;
	char irq_set_buf[SFC_VDPA_MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int *irq_fd_ptr;
	struct rte_vhost_vring vring;

	num_vring = rte_vhost_get_vring_num(sva->vid);

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = sizeof(irq_set_buf);
	irq_set->count = num_vring + 1;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD |
			 VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;
	irq_set->start = 0;
	irq_fd_ptr = (int *)&irq_set->data;
	irq_fd_ptr[RTE_INTR_VEC_ZERO_OFFSET] = sva->pdev->intr_handle.fd;

	for (i = 0; i < num_vring; i++) {
		rte_vhost_get_vhost_vring(sva->vid, i, &vring);
		irq_fd_ptr[RTE_INTR_VEC_RXTX_OFFSET + i] = vring.callfd;
	}

	ret = ioctl(sva->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret) {
		DRV_LOG(ERR, "Error enabling MSI-X interrupts: %s",
				strerror(errno));
		return -1;
	}

	return 0;
}

static int
sfc_vdpa_disable_vfio_intr(struct sfc_vdpa_adapter *sva)
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

	ret = ioctl(sva->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret) {
		DRV_LOG(ERR, "Error disabling MSI-X interrupts: %s",
				strerror(errno));
		return -1;
	}

	return 0;
}

static int
sfc_vdpa_virtq_init(struct sfc_vdpa_adapter *sva)
{
	int i, rc = 0;
	efx_virtio_vq_t *vq=NULL;
	efx_virtio_vq_cfg_t vq_cfg;
	efx_virtio_vq_type_t type;
	uint16_t target_vf = SFC_VDPA_VF_NULL;

	for (i = 0; i < sva->num_vring; i++) {
		if(i%2) /* Even VQ for RX and odd for TX */
			type = EFX_VIRTIO_VQ_TYPE_NET_TXQ;
		else
			type = EFX_VIRTIO_VQ_TYPE_NET_RXQ;
		
		vq_cfg.evvc_vq_size = sva->vring[i].size;
		vq_cfg.evvc_vq_pidx = sva->vring[i].last_used_idx;
		vq_cfg.evvc_vq_cidx = sva->vring[i].last_avail_idx;
		vq_cfg.evvc_desc_tbl_addr = sva->vring[i].desc;
		vq_cfg.evvc_avail_ring_addr = sva->vring[i].avail;
		vq_cfg.evvc_used_ring_addr = sva->vring[i].used;
		vq_cfg.evvc_msix_vector = 0;
		vq_cfg.evvc_use_pasid = 0;
		vq_cfg.evvc_pas_id = 0;
		vq_cfg.evcc_features = 0;
		vq_cfg.evcc_mport_selector = 0;

		rc = efx_virtio_virtq_create(sva->nic, type, target_vf,
					i, &vq_cfg, &vq);
		if(rc == 0) 
			sva->vq[i] = vq;
	}

	return rc;
}

static int
sfc_vdpa_start(struct sfc_vdpa_adapter *sva)
{
	int i, nr_vring;
	struct rte_vhost_vring vq;
	uint64_t gpa;
	int ret;

        sfc_log_init(sva, "entry");

        SFC_ASSERT(sfc_adapter_is_locked(sva));
        SFC_ASSERT(sva->state == SFC_VDPA_ADAPTER_CONFIGURED);

	sva->state = SFC_VDPA_ADAPTER_STARTING;

        ret = sfc_vdpa_enable_vfio_intr(sva);
	if (ret < 0) {
		sfc_warn(sva, "failed to initialized vfio intr");
		goto fail_enable_vfio_intr;
	}

	nr_vring = rte_vhost_get_vring_num(sva->vid);
	rte_vhost_get_negotiated_features(sva->vid, &sva->req_features);
	
	for (i = 0; i < nr_vring; i++) {
		rte_vhost_get_vhost_vring(sva->vid, i, &vq);
		gpa = hva_to_gpa(sva->vid, (uint64_t)(uintptr_t)vq.desc);
		if (gpa == 0) {
			DRV_LOG(ERR, "Fail to get GPA for descriptor ring.");
			goto fail_vring_map;
		}
		sva->vring[i].desc = gpa;

		gpa = hva_to_gpa(sva->vid, (uint64_t)(uintptr_t)vq.avail);
		if (gpa == 0) {
			DRV_LOG(ERR, "Fail to get GPA for available ring.");
			goto fail_vring_map;
		}
		sva->vring[i].avail = gpa;

		gpa = hva_to_gpa(sva->vid, (uint64_t)(uintptr_t)vq.used);
		if (gpa == 0) {
			DRV_LOG(ERR, "Fail to get GPA for used ring.");
			goto fail_vring_map;
		}
		sva->vring[i].used = gpa;

		sva->vring[i].size = vq.size;
		rte_vhost_get_vring_base(sva->vid, i, &sva->vring[i].last_avail_idx,
				&sva->vring[i].last_used_idx);
	}
	sva->num_vring = i;

	ret = sfc_vdpa_virtq_init(sva);
	if (ret < 0) {
		sfc_warn(sva, "Failed to initialize virtqs");
		goto fail_virtio_init;
	}

	sva->state = SFC_VDPA_ADAPTER_STARTED;
        sfc_log_init(sva, "done");

	return 0;

fail_virtio_init:
fail_vring_map:
	sfc_vdpa_disable_vfio_intr(sva);

fail_enable_vfio_intr:
	sva->state = SFC_VDPA_ADAPTER_CONFIGURED;
	return ret;
}

static struct sfc_vdpa_adapter *
get_adapter_by_did(int did)
{
	int found = 0;
	struct sfc_vdpa_adapter_list *list;
	pthread_mutex_lock(&sfc_vdpa_adapter_list_lock);

	TAILQ_FOREACH(list, &sfc_vdpa_adapter_list, next) {
		if (did == list->sva->did) {
			found = 1;
			break;
		}
	}

	pthread_mutex_unlock(&sfc_vdpa_adapter_list_lock);

	if (!found) {
		return NULL;
	}

	return list->sva;
}

static struct sfc_vdpa_adapter_list *
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

static int
sfc_vdpa_dev_config(int vid)
{
	int did;
	struct sfc_vdpa_adapter *adapter;

	did = rte_vhost_get_vdpa_device_id(vid);
	adapter = get_adapter_by_did(did);
	if (adapter == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	adapter->vid = vid;
	rte_atomic32_set(&adapter->dev_attached, 1);
	sfc_warn(adapter, "sfc_vdpa_dev_config");

	sfc_vdpa_adapter_lock(adapter);
	sfc_vdpa_configure(adapter);
	sfc_vdpa_start(adapter);
	sfc_vdpa_adapter_unlock(adapter);


	if (rte_vhost_host_notifier_ctrl(vid, true) != 0)
		DRV_LOG(NOTICE, "vDPA (%d): software relay for notify is used.", did);
	
	return 0;
}

static int
sfc_vdpa_set_features(int vid)
{
	int did, rc;
	struct sfc_vdpa_adapter *sva;

	did = rte_vhost_get_vdpa_device_id(vid);
	sva = get_adapter_by_did(did);
	if (sva == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	rc = efx_virtio_verify_features(sva->nic, 
					EFX_VIRTIO_DEVICE_TYPE_NET, 
					sva->req_features);

	/* TBD : ENOSUP and EINVAL values ?? */	
	if (rc  == 0 /*ENOSUP*/) {
		DRV_LOG(ERR, "Unsupported feature is requested");
	}
	else if (rc  == 1/*EINVAL*/) {
		DRV_LOG(ERR, "Required feature is not requested");
	}

	return rc;
}

static int
sfc_vdpa_get_vfio_group_fd(int vid)
{
	int did;
	struct sfc_vdpa_adapter *sva = NULL;

	did = rte_vhost_get_vdpa_device_id(vid);
	sva = get_adapter_by_did(did);
	if (sva == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}
	sfc_warn(sva, "sfc_vdpa_get_vfio_group_fd");

	return sva->vfio_group_fd;
}

static int
sfc_vdpa_get_vfio_device_fd(int vid)
{
	int did;
	struct sfc_vdpa_adapter *sva = NULL;

	did = rte_vhost_get_vdpa_device_id(vid);
	sva = get_adapter_by_did(did);
	if (sva == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	sfc_warn(sva, "sfc_vdpa_get_vfio_device_fd");
	return sva->vfio_dev_fd;
}
static int
sfc_vdpa_dev_close(int vid)
{
	int did;
	struct sfc_vdpa_adapter *adapter;

	did = rte_vhost_get_vdpa_device_id(vid);
	adapter = get_adapter_by_did(did);
	if (adapter == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	rte_atomic32_set(&adapter->dev_attached, 0);
	sfc_vdpa_close(adapter);
	sfc_warn(adapter, "sfc_vdpa_dev_close ...");

	return 0;
}

static int
sfc_vdpa_get_queue_num(int did, uint32_t *queue_num)
{
	struct sfc_vdpa_adapter *adapter = NULL;

	adapter = get_adapter_by_did(did);
	if (adapter == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	sfc_warn(adapter, "sfc_vdpa_get_queue_num");
	*queue_num = adapter->max_queues;
	DRV_LOG(DEBUG, " number of queues For DID %d is %d \n", did, *queue_num);

	return 0;
}


static int
sfc_vdpa_get_features(int did, uint64_t *features)
{
	struct sfc_vdpa_adapter *adapter = NULL;

	adapter = get_adapter_by_did(did);
	if (adapter == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	sfc_warn(adapter, "sfc_vdpa_get_features");
	*features = adapter->drv_features;

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
	*features = VDPA_SUPPORTED_PROTOCOL_FEATURES;
	return 0;
}

static int
sfc_vdpa_get_notify_area(int vid, int qid, uint64_t *offset, uint64_t *size)
{
	struct sfc_vdpa_adapter *adapter = NULL;
	efx_virtio_vq_t evv_data;
	unsigned int bar_offset = 0;
	unsigned int viw_base = 0;
	efx_rc_t rc = 0;
	int did;

	did = rte_vhost_get_vdpa_device_id(vid);
	adapter = get_adapter_by_did(did);
	if (adapter == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	evv_data.evv_enp = adapter->nic;
	evv_data.evv_index = vid;
	evv_data.evv_target_vf = SFC_VDPA_VF_NULL;
	evv_data.evv_vq_num = qid;

	if (evv_data.evv_index % 2) /* CHECK : Even Id for RX and odd for TX */
		evv_data.evv_type = EFX_VIRTIO_VQ_TYPE_NET_TXQ;
	else
		evv_data.evv_type = EFX_VIRTIO_VQ_TYPE_NET_RXQ;

	rc = efx_virtio_get_doorbell_offset(EFX_VIRTIO_DEVICE_TYPE_NET,
                        		&evv_data, &bar_offset);

	if (rc != 0)
		return rc;

	/* notify offset = base addr of VIW + doorbell offset in the bar */
	viw_base = 0; /* TBD: It wouls be updated using bar discovery */ 
	*offset = viw_base + bar_offset;
	*size = 0x1000;

	return 0;
}

static struct rte_pci_id pci_id_sfc_vdpa_efx_map[] = {
#define RTE_PCI_DEV_ID_DECL_XNIC(vend, dev) {RTE_PCI_DEVICE(vend, dev)},
    RTE_PCI_DEV_ID_DECL_XNIC(EFX_PCI_VENID_SFC, EFX_PCI_DEVID_MEDFORD)
    RTE_PCI_DEV_ID_DECL_XNIC(EFX_PCI_VENID_SFC, EFX_PCI_DEVID_MEDFORD_VF)
    RTE_PCI_DEV_ID_DECL_XNIC(EFX_PCI_VENID_SFC, EFX_PCI_DEVID_MEDFORD2)
    RTE_PCI_DEV_ID_DECL_XNIC(EFX_PCI_VENID_SFC, EFX_PCI_DEVID_MEDFORD2_VF)
    { .vendor_id = 0, /* sentinel */ },
};

static int
sfc_vdpa_vfio_setup(struct sfc_vdpa_adapter *sva)
{
	struct rte_pci_device *dev = sva->pdev;
	char dev_name[RTE_DEV_NAME_MAX_LEN] = {0};
	int iommu_group_num;

	sva->vfio_dev_fd = -1;
	sva->vfio_group_fd = -1;
	sva->vfio_container_fd = -1;

	rte_pci_device_name(&dev->addr, dev_name, RTE_DEV_NAME_MAX_LEN);

	sva->vfio_container_fd = rte_vfio_container_create();
	if (sva->vfio_container_fd < 0)
		return -1;

	rte_vfio_get_group_num(rte_pci_get_sysfs_path(), dev_name,
			&iommu_group_num);

	sva->vfio_group_fd = rte_vfio_container_group_bind(
			sva->vfio_container_fd, iommu_group_num);
	if (sva->vfio_group_fd < 0)
		goto error;

	if (rte_pci_map_device(dev))
		goto error;

	sva->vfio_dev_fd = dev->intr_handle.vfio_dev_fd;
	
	return 0;

error:
	rte_vfio_container_destroy(sva->vfio_container_fd);
	return -1;
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

static int sfc_vdpa_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	struct sfc_vdpa_adapter *sva = NULL;
	struct sfc_vdpa_adapter_list  *sva_list = NULL;
	int vdpa_mode = 0;
	struct rte_kvargs *kvlist = NULL;
	int ret = 0;

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
	rte_spinlock_init(&sva->lock);

	if (sfc_vdpa_vfio_setup(sva) < 0) {
		DRV_LOG(ERR, "failed to setup device %s", pci_dev->name);
		goto error;
	}

	if (sfc_vdpa_device_init(sva) < 0) {
		DRV_LOG(ERR, "failed to init device %s", pci_dev->name);
		goto error;
	}

	sva->max_queues = SFC_VDPA_MAX_QUEUES;
		
	sva->drv_features = (sva->dev_features &
				~(1ULL << VIRTIO_F_IOMMU_PLATFORM)) |
				(1ULL << VIRTIO_NET_F_GUEST_ANNOUNCE) |
				(1ULL << VIRTIO_NET_F_CTRL_VQ) |
				(1ULL << VIRTIO_NET_F_STATUS) |
				(1ULL << VHOST_USER_F_PROTOCOL_FEATURES) |
				(1ULL << VIRTIO_F_VERSION_1) |
				(1ULL << VHOST_F_LOG_ALL);

	sva->dev_addr.pci_addr = pci_dev->addr;
	sva->dev_addr.type = PCI_ADDR;
	sva_list->sva = sva;

	sva->did = rte_vdpa_register_device(&sva->dev_addr,
						&sfc_vdpa_ops);
	if (sva->did < 0) {
		DRV_LOG(ERR, "failed to register device %s", pci_dev->name);
		goto error;
	}

	pthread_mutex_lock(&sfc_vdpa_adapter_list_lock);
	TAILQ_INSERT_TAIL(&sfc_vdpa_adapter_list, sva_list, next);
	pthread_mutex_unlock(&sfc_vdpa_adapter_list_lock);

	rte_kvargs_free(kvlist);
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
	rte_vfio_container_destroy(sva->vfio_container_fd);
	rte_vdpa_unregister_device(sva->did);

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
