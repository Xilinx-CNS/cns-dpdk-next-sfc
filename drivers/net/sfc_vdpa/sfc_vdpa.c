
#include "sfc_vdpa.h"

uint32_t sfc_logtype_driver;

#define SFC_VDPA_MODE		"vdpa"

#define DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, sfc_logtype_driver, \
		"SFC_VDPA %s(): " fmt "\n", __func__, ##args)


#define SFC_VDPA_MSIX_IRQ_SET_BUF_LEN (sizeof(struct vfio_irq_set) + \
				sizeof(int) * (SFC_VDPA_MAX_QUEUES * 2 + 1))



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

		/*
		DRV_LOG(INFO, "%s, region %u: HVA 0x%" PRIx64 ", "
			"GPA 0x%" PRIx64 ", size 0x%" PRIx64 ".",
			do_map ? "DMA map" : "DMA unmap", i,
			reg->host_user_addr, reg->guest_phys_addr, reg->size);

	*/

		if (do_map) {
			status = rte_vfio_container_dma_map(adapter->vfio_container_fd,
				mem_reg->host_user_addr, mem_reg->guest_phys_addr,
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
	if (ret<0) {
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

//	return ifcvf_start_hw(&internal->hw);
	sva->state = SFC_VDPA_ADAPTER_STARTED;
        sfc_log_init(sva, "done");
	return 0;

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
		if (did == list->adapter->did) {
			found = 1;
			break;
		}
	}

	pthread_mutex_unlock(&sfc_vdpa_adapter_list_lock);

	if (!found) {
		return NULL;
	}

	return list->adapter;
}


static struct sfc_vdpa_adapter_list *
get_adapter_by_dev(struct rte_pci_device *pdev)
{
	int found = 0;
	struct sfc_vdpa_adapter_list *list;

	pthread_mutex_lock(&sfc_vdpa_adapter_list_lock);

	TAILQ_FOREACH(list, &sfc_vdpa_adapter_list, next) {
		if (pdev == list->adapter->pdev) {
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


	return 0;
}
static int
sfc_vdpa_set_features(int vid)
{
	(void) vid;
	return -1;
}

static int
sfc_vdpa_get_vfio_group_fd(int vid)
{
	int did;
	struct sfc_vdpa_adapter *adapter = NULL;

	did = rte_vhost_get_vdpa_device_id(vid);
	adapter = get_adapter_by_did(did);
	if (adapter == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}
	sfc_warn(adapter, "sfc_vdpa_get_vfio_group_fd");

	return adapter->vfio_group_fd;
}

static int
sfc_vdpa_get_vfio_device_fd(int vid)
{
	int did;
	struct sfc_vdpa_adapter *adapter = NULL;

	did = rte_vhost_get_vdpa_device_id(vid);
	adapter = get_adapter_by_did(did);
	if (adapter == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	sfc_warn(adapter, "sfc_vdpa_get_vfio_device_fd");
	return adapter->vfio_dev_fd;
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
	sfc_warn(adapter, "sfc_vdpa_dev_close");

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
	*features = adapter->features;

	return 0;
}

#if 0 
static int
sfc_vdpa_get_notify_area(int vid, int qid, uint64_t *offset, uint64_t *size)
{
	return 0;
}
#endif 

static struct rte_pci_id pci_id_sfc_vdpa_efx_map[] = {
#define RTE_PCI_DEV_ID_DECL_XNIC(vend, dev) {RTE_PCI_DEVICE(vend, dev)},
#ifndef PCI_VENDOR_ID_XILINX
#define PCI_VENDOR_ID_XILINX 0x10EE
#endif

    /** Gen 1 VF */
    /** PCIe lane width x1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa011)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa111)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa211)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa311)  /* VF on PF 3 */
    /** PCIe lane width x4 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa014)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa114)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa214)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa314)  /* VF on PF 3 */
    /** PCIe lane width x8 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa018)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa118)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa218)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa318)  /* VF on PF 3 */
    /** PCIe lane width x16 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa01f)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa11f)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa21f)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa31f)  /* VF on PF 3 */

    /** Gen 2 VF */
    /** PCIe lane width x1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa021)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa121)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa221)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa321)  /* VF on PF 3 */
    /** PCIe lane width x4 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa024)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa124)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa224)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa324)  /* VF on PF 3 */
    /** PCIe lane width x8 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa028)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa128)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa228)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa328)  /* VF on PF 3 */
    /** PCIe lane width x16 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa02f)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa12f)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa22f)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa32f)  /* VF on PF 3 */

    /** Gen 3 VF */
    /** PCIe lane width x1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa031)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa131)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa231)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa331)  /* VF on PF 3 */
    /** PCIe lane width x4 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa034)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa134)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa234)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa334)  /* VF on PF 3 */
    /** PCIe lane width x8 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa038)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa138)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa238)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa338)  /* VF on PF 3 */
    /** PCIe lane width x16 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa03f)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa13f)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa23f)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa33f)  /* VF on PF 3 */

    /** Gen 4 VF */
    /** PCIe lane width x1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa041)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa141)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa241)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa341)  /* VF on PF 3 */
    /** PCIe lane width x4 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa044)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa144)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa244)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa344)  /* VF on PF 3 */
    /** PCIe lane width x8 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa048)  /* VF on PF 0 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa148)  /* VF on PF 1 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa248)  /* VF on PF 2 */
    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0xa348)  /* VF on PF 3 */

    RTE_PCI_DEV_ID_DECL_XNIC(PCI_VENDOR_ID_XILINX, 0x0100)

    { .vendor_id = 0, /* sentinel */ },
};

static int
sfc_vdpa_vfio_setup(struct sfc_vdpa_adapter *adapter)
{
	struct rte_pci_device *dev = adapter->pdev;
	char dev_name[RTE_DEV_NAME_MAX_LEN] = {0};
	int iommu_group_num;

	adapter->vfio_dev_fd = -1;
	adapter->vfio_group_fd = -1;
	adapter->vfio_container_fd = -1;

	rte_pci_device_name(&dev->addr, dev_name, RTE_DEV_NAME_MAX_LEN);

	adapter->vfio_container_fd = rte_vfio_container_create();
	if (adapter->vfio_container_fd < 0)
		return -1;

	rte_vfio_get_group_num(rte_pci_get_sysfs_path(), dev_name,
			&iommu_group_num);

	adapter->vfio_group_fd = rte_vfio_container_group_bind(
			adapter->vfio_container_fd, iommu_group_num);
	if (adapter->vfio_group_fd < 0)
		goto err;

	if (rte_pci_map_device(dev))
		goto err;

	adapter->vfio_dev_fd = dev->intr_handle.vfio_dev_fd;
#if 0
        adapter->vfio_container_fd = vfio_get_default_container_fd();
	if (adapter->vfio_container_fd < 0)
		return -1;

	adapter->vfio_group_fd = rte_vfio_get_group_fd(iommu_group_num);
	if (adapter->vfio_group_fd < 0)
		goto err;
#endif
	return 0;

err:
	//rte_vfio_container_destroy(adapter->vfio_container_fd);
	return -1;
}

#if 0 
static struct rte_vdpa_dev_ops sfc_vdpa_ops = {
	.get_notify_area = sfc_vdpa_get_notify_area,
};
#endif 
static struct rte_vdpa_dev_ops sfc_vdpa_ops = {
        .get_queue_num = sfc_vdpa_get_queue_num,
        .get_features = sfc_vdpa_get_features,
        .get_protocol_features = NULL,
        .dev_conf = sfc_vdpa_dev_config,
        .dev_close = sfc_vdpa_dev_close,
        .set_vring_state = NULL,
        .set_features = sfc_vdpa_set_features,
        .migration_done = NULL,
        .get_vfio_group_fd = sfc_vdpa_get_vfio_group_fd,
        .get_vfio_device_fd = sfc_vdpa_get_vfio_device_fd,
        .get_notify_area = NULL,
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

		struct sfc_vdpa_adapter *adapter = NULL;
		struct sfc_vdpa_adapter_list  *list = NULL;
		int vdpa_mode = 0;
		struct rte_kvargs *kvlist = NULL;
		int ret = 0;

                DRV_LOG(ERR, "Praveen: sfc_vdpa_pci_probe ");

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

		list = rte_zmalloc("sfc_vdpa", sizeof(sfc_vdpa_adapter_list), 0);
		if (list == NULL)
			goto error;

		adapter = rte_zmalloc("sfc_vdpa", sizeof(struct sfc_vdpa_adapter), 0);
		if (adapter == NULL)
			goto error;

		adapter->pdev = pci_dev;
		rte_spinlock_init(&adapter->lock);

		if (sfc_vdpa_vfio_setup(adapter) < 0) {
			DRV_LOG(ERR, "failed to setup device %s", pci_dev->name);
			goto error;
		}

		if (sfc_vdpa_device_init(adapter) < 0) {
			DRV_LOG(ERR, "failed to init device %s", pci_dev->name);
			goto error;
		}

		adapter->max_queues = SFC_VDPA_MAX_QUEUES;
		adapter->features = (adapter->features &
			~(1ULL << VIRTIO_F_IOMMU_PLATFORM)) |
			(1ULL << VIRTIO_NET_F_GUEST_ANNOUNCE) |
			(1ULL << VIRTIO_NET_F_CTRL_VQ) |
			(1ULL << VIRTIO_NET_F_STATUS) |
			(1ULL << VHOST_USER_F_PROTOCOL_FEATURES) |
			(1ULL << VHOST_F_LOG_ALL);

		adapter->dev_addr.pci_addr = pci_dev->addr;
		adapter->dev_addr.type = PCI_ADDR;
		list->adapter = adapter;

		adapter->did = rte_vdpa_register_device(&adapter->dev_addr,
					&sfc_vdpa_ops);
		if (adapter->did < 0) {
			DRV_LOG(ERR, "failed to register device %s", pci_dev->name);
			goto error;
		}

		pthread_mutex_lock(&sfc_vdpa_adapter_list_lock);
		TAILQ_INSERT_TAIL(&sfc_vdpa_adapter_list, list, next);
		pthread_mutex_unlock(&sfc_vdpa_adapter_list_lock);

		//update_datapath(adapter);

		rte_kvargs_free(kvlist);
		return 0;

	error:
		rte_kvargs_free(kvlist);
		rte_free(list);
		rte_free(adapter);
		return -1;

}

static int sfc_vdpa_pci_remove(struct rte_pci_device *pci_dev)
{
	struct sfc_vdpa_adapter *adapter = NULL;
	struct sfc_vdpa_adapter_list  *list = NULL;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	list = get_adapter_by_dev(pci_dev);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device: %s", pci_dev->name);
		return -1;
	}

	adapter = list->adapter;

	sfc_vdpa_device_fini(adapter);

//	rte_pci_unmap_device(adapter->pdev);
//	rte_vfio_container_destroy(adapter->vfio_container_fd);
	rte_vdpa_unregister_device(adapter->did);

	pthread_mutex_lock(&sfc_vdpa_adapter_list_lock);
	TAILQ_REMOVE(&sfc_vdpa_adapter_list, list, next);
	pthread_mutex_unlock(&sfc_vdpa_adapter_list_lock);

	rte_free(list);
	rte_free(adapter);

	return 0;
}

static struct rte_pci_driver rte_sfc_vdpa = {
	.id_table = pci_id_sfc_vdpa_efx_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
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


