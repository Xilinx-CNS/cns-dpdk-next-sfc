/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2020-2021 Xilinx, Inc.
 */

#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_vfio.h>
#include <rte_vhost.h>

#include "efx.h"
#include "sfc_efx.h"
#include "sfc_vdpa.h"

uint32_t sfc_vdpa_logtype_driver;

TAILQ_HEAD(sfc_vdpa_adapter_list_head, sfc_vdpa_adapter);
static struct sfc_vdpa_adapter_list_head sfc_vdpa_adapter_list =
	TAILQ_HEAD_INITIALIZER(sfc_vdpa_adapter_list);

static pthread_mutex_t sfc_vdpa_adapter_list_lock = PTHREAD_MUTEX_INITIALIZER;

struct sfc_vdpa_adapter *
sfc_vdpa_get_adapter_by_dev(struct rte_pci_device *pdev)
{
	bool found = false;
	struct sfc_vdpa_adapter *sva;

	pthread_mutex_lock(&sfc_vdpa_adapter_list_lock);

	TAILQ_FOREACH(sva, &sfc_vdpa_adapter_list, next) {
		if (pdev == sva->pdev) {
			found = true;
			break;
		}
	}

	pthread_mutex_unlock(&sfc_vdpa_adapter_list_lock);

	return found ? sva : NULL;
}

static int
sfc_vdpa_vfio_setup(struct sfc_vdpa_adapter *sva)
{
	struct rte_pci_device *dev = sva->pdev;
	char dev_name[RTE_DEV_NAME_MAX_LEN] = {0};
	int rc;

	if (dev == NULL)
		goto fail_inval;

	rte_pci_device_name(&dev->addr, dev_name, RTE_DEV_NAME_MAX_LEN);

	sva->vfio_container_fd = rte_vfio_container_create();
	if (sva->vfio_container_fd < 0)	{
		sfc_vdpa_err(sva, "failed to create VFIO container");
		goto fail_container_create;
	}

	rc = rte_vfio_get_group_num(rte_pci_get_sysfs_path(), dev_name,
				    &sva->iommu_group_num);
	if (rc <= 0) {
		sfc_vdpa_err(sva, "failed to get IOMMU group for %s : %s",
			     dev_name, rte_strerror(-rc));
		goto fail_get_group_num;
	}

	sva->vfio_group_fd =
		rte_vfio_container_group_bind(sva->vfio_container_fd,
					      sva->iommu_group_num);
	if (sva->vfio_group_fd < 0) {
		sfc_vdpa_err(sva,
			     "failed to bind IOMMU group %d to container %d",
			     sva->iommu_group_num, sva->vfio_container_fd);
		goto fail_group_bind;
	}

	if (rte_pci_map_device(dev) != 0) {
		sfc_vdpa_err(sva, "failed to map PCI device %s : %s",
			     dev_name, rte_strerror(rte_errno));
		goto fail_pci_map_device;
	}

	sva->vfio_dev_fd = dev->intr_handle.vfio_dev_fd;

	return 0;

fail_pci_map_device:
	if (rte_vfio_container_group_unbind(sva->vfio_container_fd,
					sva->iommu_group_num) != 0) {
		sfc_vdpa_err(sva,
			     "failed to unbind IOMMU group %d from container %d",
			     sva->iommu_group_num, sva->vfio_container_fd);
	}

fail_group_bind:
fail_get_group_num:
	if (rte_vfio_container_destroy(sva->vfio_container_fd) != 0) {
		sfc_vdpa_err(sva, "failed to destroy container %d",
			     sva->vfio_container_fd);
	}

fail_container_create:
fail_inval:
	return -1;
}

static void
sfc_vdpa_vfio_teardown(struct sfc_vdpa_adapter *sva)
{
	rte_pci_unmap_device(sva->pdev);

	if (rte_vfio_container_group_unbind(sva->vfio_container_fd,
					    sva->iommu_group_num) != 0) {
		sfc_vdpa_err(sva,
			     "failed to unbind IOMMU group %d from container %d",
			     sva->iommu_group_num, sva->vfio_container_fd);
	}

	if (rte_vfio_container_destroy(sva->vfio_container_fd) != 0) {
		sfc_vdpa_err(sva,
			     "failed to destroy container %d",
			     sva->vfio_container_fd);
	}
}

static int
sfc_vdpa_set_log_prefix(struct sfc_vdpa_adapter *sva)
{
	struct rte_pci_device *pci_dev = sva->pdev;
	int ret;

	ret = snprintf(sva->log_prefix, sizeof(sva->log_prefix),
		       "PMD: sfc_vdpa " PCI_PRI_FMT " : ",
		       pci_dev->addr.domain, pci_dev->addr.bus,
		       pci_dev->addr.devid, pci_dev->addr.function);

	if (ret < 0 || ret >= (int)sizeof(sva->log_prefix)) {
		SFC_VDPA_GENERIC_LOG(ERR,
			"reserved log prefix is too short for " PCI_PRI_FMT,
			pci_dev->addr.domain, pci_dev->addr.bus,
			pci_dev->addr.devid, pci_dev->addr.function);
		return -EINVAL;
	}

	return 0;
}

uint32_t
sfc_vdpa_register_logtype(const struct rte_pci_addr *pci_addr,
			  const char *lt_prefix_str, uint32_t ll_default)
{
	size_t lt_prefix_str_size = strlen(lt_prefix_str);
	size_t lt_str_size_max;
	char *lt_str = NULL;
	int ret;

	if (SIZE_MAX - PCI_PRI_STR_SIZE - 1 > lt_prefix_str_size) {
		++lt_prefix_str_size; /* Reserve space for prefix separator */
		lt_str_size_max = lt_prefix_str_size + PCI_PRI_STR_SIZE + 1;
	} else {
		return RTE_LOGTYPE_PMD;
	}

	lt_str = rte_zmalloc("logtype_str", lt_str_size_max, 0);
	if (lt_str == NULL)
		return RTE_LOGTYPE_PMD;

	strncpy(lt_str, lt_prefix_str, lt_prefix_str_size);
	lt_str[lt_prefix_str_size - 1] = '.';
	rte_pci_device_name(pci_addr, lt_str + lt_prefix_str_size,
			    lt_str_size_max - lt_prefix_str_size);
	lt_str[lt_str_size_max - 1] = '\0';

	ret = rte_log_register_type_and_pick_level(lt_str, ll_default);
	rte_free(lt_str);

	return (ret < 0) ? RTE_LOGTYPE_PMD : ret;
}

static struct rte_pci_id pci_id_sfc_vdpa_efx_map[] = {
	{ RTE_PCI_DEVICE(EFX_PCI_VENID_XILINX, EFX_PCI_DEVID_RIVERHEAD_VF) },
	{ .vendor_id = 0, /* sentinel */ },
};

static int
sfc_vdpa_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	struct sfc_vdpa_adapter *sva = NULL;
	uint32_t logtype_main;
	int ret = 0;

	if (sfc_efx_dev_class_get(pci_dev->device.devargs) !=
			SFC_EFX_DEV_CLASS_VDPA) {
		SFC_VDPA_GENERIC_LOG(INFO,
			"Incompatible device class: skip probing, should be probed by other sfc driver.");
			return 1;
	}

	/*
	 * It will not be probed in the secondary process. As device class
	 * is vdpa so return 0 to avoid probe by other sfc driver
	 */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	logtype_main = sfc_vdpa_register_logtype(&pci_dev->addr,
						 SFC_VDPA_LOGTYPE_MAIN_STR,
						 RTE_LOG_NOTICE);

	sva = rte_zmalloc("sfc_vdpa", sizeof(struct sfc_vdpa_adapter), 0);
	if (sva == NULL)
		goto fail_zmalloc;

	sva->pdev = pci_dev;
	sva->logtype_main = logtype_main;

	ret = sfc_vdpa_set_log_prefix(sva);
	if (ret != 0)
		goto fail_set_log_prefix;

	sfc_vdpa_log_init(sva, "entry");

	sfc_vdpa_log_init(sva, "vfio init");
	if (sfc_vdpa_vfio_setup(sva) < 0) {
		sfc_vdpa_err(sva, "failed to setup device %s", pci_dev->name);
		goto fail_vfio_setup;
	}

	pthread_mutex_lock(&sfc_vdpa_adapter_list_lock);
	TAILQ_INSERT_TAIL(&sfc_vdpa_adapter_list, sva, next);
	pthread_mutex_unlock(&sfc_vdpa_adapter_list_lock);

	sfc_vdpa_log_init(sva, "done");

	return 0;

fail_vfio_setup:
fail_set_log_prefix:
	rte_free(sva);

fail_zmalloc:
	return -1;
}

static int
sfc_vdpa_pci_remove(struct rte_pci_device *pci_dev)
{
	struct sfc_vdpa_adapter *sva = NULL;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return -1;

	sva = sfc_vdpa_get_adapter_by_dev(pci_dev);
	if (sva == NULL) {
		sfc_vdpa_info(sva, "invalid device: %s", pci_dev->name);
		return -1;
	}

	pthread_mutex_lock(&sfc_vdpa_adapter_list_lock);
	TAILQ_REMOVE(&sfc_vdpa_adapter_list, sva, next);
	pthread_mutex_unlock(&sfc_vdpa_adapter_list_lock);

	sfc_vdpa_vfio_teardown(sva);

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
RTE_PMD_REGISTER_KMOD_DEP(net_sfc_vdpa, "* vfio-pci");

RTE_INIT(sfc_driver_register_logtype)
{
	int ret;

	ret = rte_log_register_type_and_pick_level(SFC_VDPA_LOGTYPE_PREFIX "driver",
						   RTE_LOG_NOTICE);
	sfc_vdpa_logtype_driver = (ret < 0) ? RTE_LOGTYPE_PMD : ret;
}
