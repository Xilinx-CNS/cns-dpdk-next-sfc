
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <linux/virtio_net.h>

#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_bus_pci.h>
#include <rte_vhost.h>
#include <rte_vdpa.h>
#include <rte_vfio.h>
#include <rte_spinlock.h>
#include <rte_log.h>

static int qdma_vdpa_logtype;
/*
 *  * The set of PCI devices this driver supports
 *   */
static struct rte_pci_id sfc_vdpa_pci_id_tbl[] = {
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

    { .vendor_id = 0, /* sentinel */ },
};

#if 0
static int
sfc_dev_config(int vid)
{
	int did;
	struct internal_list *list;
	struct ifcvf_internal *internal;

	did = rte_vhost_get_vdpa_device_id(vid);
	list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	internal = list->internal;
	internal->vid = vid;
	rte_atomic32_set(&internal->dev_attached, 1);
	//update_datapath(internal);

	return 0;
}

static int
sfc_dev_close(int vid)
{
	int did;
	struct internal_list *list;
	struct ifcvf_internal *internal;

	did = rte_vhost_get_vdpa_device_id(vid);
	list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	internal = list->internal;
	rte_atomic32_set(&internal->dev_attached, 0);
	update_datapath(internal);

	return 0;
}

static int
sfc_set_features(int vid)
{
	uint64_t features;
	int did;
	struct internal_list *list;
	struct ifcvf_internal *internal;
	uint64_t log_base, log_size;

	did = rte_vhost_get_vdpa_device_id(vid);
	list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	internal = list->internal;
	rte_vhost_get_negotiated_features(vid, &features);

	if (RTE_VHOST_NEED_LOG(features)) {
		rte_vhost_get_log_base(vid, &log_base, &log_size);
		rte_vfio_container_dma_map(internal->vfio_container_fd,
				log_base, SFC_LOG_BASE, log_size);

 		/* Call common code function */
		//sfc_enable_logging(&internal->hw, SFC_LOG_BASE, log_size);
	}

	return 0;
}

static int
sfc_get_vfio_group_fd(int vid)
{
	int did;
	struct internal_list *list;

	did = rte_vhost_get_vdpa_device_id(vid);
	//list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	return list->internal->vfio_group_fd;
}

static int
sfc_get_vfio_device_fd(int vid)
{
	int did;
	struct internal_list *list;

	did = rte_vhost_get_vdpa_device_id(vid);
	list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	return list->internal->vfio_dev_fd;
}

static int
sfc_get_notify_area(int vid, int qid, uint64_t *offset, uint64_t *size)
{
	int did;
	struct internal_list *list;
	struct ifcvf_internal *internal;
	struct vfio_region_info reg = { .argsz = sizeof(reg) };
	int ret;

	did = rte_vhost_get_vdpa_device_id(vid);
	list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	internal = list->internal;

	/* Call common code API */
        // Common Code API
	
	*offset = ifcvf_get_queue_notify_off(&internal->hw, qid) + reg.offset;
	*size = 0x1000;

	return 0;
}

static int
sfc_get_queue_num(int did, uint32_t *queue_num)
{
	struct internal_list *list;

	list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	*queue_num = list->internal->max_queues;

	return 0;
}

static int
sfc_get_vdpa_features(int did, uint64_t *features)
{
	struct internal_list *list;

	list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	*features = list->internal->features;

	return 0;
}

#define VDPA_SUPPORTED_PROTOCOL_FEATURES \
		(1ULL << VHOST_USER_PROTOCOL_F_REPLY_ACK | \
		 1ULL << VHOST_USER_PROTOCOL_F_SLAVE_REQ | \
		 1ULL << VHOST_USER_PROTOCOL_F_SLAVE_SEND_FD | \
		 1ULL << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER | \
		 1ULL << VHOST_USER_PROTOCOL_F_LOG_SHMFD)
static int
sfc_get_protocol_features(int did __rte_unused, uint64_t *features)
{
	*features = VDPA_SUPPORTED_PROTOCOL_FEATURES;
	return 0;
}

static struct rte_vdpa_dev_ops sfc_ops = {
	.get_queue_num = sfc_get_queue_num,
	.get_features = sfc_get_vdpa_features,
	.get_protocol_features = sfc_get_protocol_features,
	.dev_conf = sfc_dev_config,
	.dev_close = sfc_dev_close,
	.set_vring_state = NULL,
	.set_features = sfc_set_features,
	.migration_done = NULL,
	.get_vfio_group_fd = sfc_get_vfio_group_fd,
	.get_vfio_device_fd = sfc_get_vfio_device_fd,
	.get_notify_area = sfc_get_notify_area,
};

#endif

#if 0
static int
sfc_vdpa_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
                    struct rte_pci_device *pci_dev)
{
   return 0;
}

static int
sfc_vdpa_pci_remove(struct rte_pci_device *pci_dev)
{
   return 0;
}

#endif
static struct rte_pci_driver rte_sfc_vdpa = {
        .id_table = sfc_vdpa_pci_id_tbl,
        .drv_flags = 0,
        .probe = NULL,
        .remove = NULL,
};

RTE_PMD_REGISTER_PCI(net_sfc_vdpa, rte_sfc_vdpa);
RTE_PMD_REGISTER_PCI_TABLE(net_sfc_vdpa, sfc_vdpa_pci_id_tbl);
RTE_PMD_REGISTER_KMOD_DEP(net_sfc_vdpa, "* vfio-pci");

RTE_INIT(qdma_vdpa_init_log)
{
        qdma_vdpa_logtype = rte_log_register("pmd.net.qdma_vdpa");
        if (qdma_vdpa_logtype >= 0)
                rte_log_set_level(qdma_vdpa_logtype, RTE_LOG_NOTICE);
}

