/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022-2023, Advanced Micro Devices, Inc.
 */

/*
 * Architecture Overview
 * =====================
 * CDX is a Hardware Architecture designed for AMD FPGA devices. It
 * consists of sophisticated mechanism for interaction between FPGA,
 * Firmware and the APUs (Application CPUs).
 *
 * Firmware resides on RPU (Realtime CPUs) which interacts with
 * the FPGA program manager and the APUs. The RPU provides memory-mapped
 * interface (RPU if) which is used to communicate with APUs.
 *
 * The diagram below shows an overview of the CDX architecture:
 *
 *          +--------------------------------------+
 *          |   DPDK                               |
 *          |                    DPDK CDX drivers  |
 *          |                             |        |
 *          |                      DPDK CDX bus    |
 *          |                             |        |
 *          +-----------------------------|--------+
 *                                        |
 *          +-----------------------------|--------+
 *          |    Application CPUs (APU)   |        |
 *          |                             |        |
 *          |                     VFIO CDX driver  |
 *          |     Linux OS                |        |
 *          |                      Linux CDX bus   |
 *          |                             |        |
 *          +-----------------------------|--------+
 *                                        |
 *                                        |
 *          +------------------------| RPU if |----+
 *          |                             |        |
 *          |                             V        |
 *          |          Realtime CPUs (RPU)         |
 *          |                                      |
 *          +--------------------------------------+
 *                                |
 *          +---------------------|----------------+
 *          |  FPGA               |                |
 *          |      +-----------------------+       |
 *          |      |           |           |       |
 *          | +-------+    +-------+   +-------+   |
 *          | | dev 1 |    | dev 2 |   | dev 3 |   |
 *          | +-------+    +-------+   +-------+   |
 *          +--------------------------------------+
 *
 * The RPU firmware extracts the device information from the loaded FPGA
 * image and implements a mechanism that allows the APU drivers to
 * enumerate such devices (device personality and resource details) via
 * a dedicated communication channel.
 *
 * VFIO CDX driver provides the CDX device resources like MMIO and interrupts
 * to map to user-space. DPDK CDX bus uses sysfs interface and the vfio-cdx
 * driver to discover and initialize the CDX devices for user-space
 * applications.
 */

#include <string.h>
#include <dirent.h>

#include <rte_log.h>
#include <rte_bus.h>
#include <rte_bus_cdx.h>
#include <rte_eal_paging.h>
#include <rte_errno.h>
#include <rte_devargs.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_vfio.h>

#include <eal_filesystem.h>

#include "cdx.h"
#include "cdx_logs.h"

#define SYSFS_CDX_DEVICES "/sys/bus/cdx/devices"
#define CDX_BUS_NAME	cdx
#define CDX_DEV_PREFIX	"cdx-"

/**
 * @file
 * CDX probing using Linux sysfs.
 */

/* Add a device to CDX bus */
static void
rte_cdx_add_device(struct rte_cdx_device *cdx_dev)
{
	TAILQ_INSERT_TAIL(&rte_cdx_bus.device_list, cdx_dev, next);
}

static int
cdx_get_kernel_driver_by_path(const char *filename, char *driver_name,
		size_t len)
{
	int count;
	char path[PATH_MAX];
	char *name;

	if (!filename || !driver_name)
		return -1;

	count = readlink(filename, path, PATH_MAX);
	if (count >= PATH_MAX)
		return -1;

	/* For device does not have a driver */
	if (count < 0)
		return 1;

	path[count] = '\0';

	name = strrchr(path, '/');
	if (name) {
		strlcpy(driver_name, name + 1, len);
		return 0;
	}

	return -1;
}

int rte_cdx_map_device(struct rte_cdx_device *dev)
{
	return cdx_vfio_map_resource(dev);
}

void rte_cdx_unmap_device(struct rte_cdx_device *dev)
{
	cdx_vfio_unmap_resource(dev);
}

static int
find_max_end_va(const struct rte_memseg_list *msl, void *arg)
{
	size_t sz = msl->len;
	void *end_va = RTE_PTR_ADD(msl->base_va, sz);
	void **max_va = arg;

	if (*max_va < end_va)
		*max_va = end_va;
	return 0;
}

void *
cdx_find_max_end_va(void)
{
	void *va = NULL;

	rte_memseg_list_walk(find_max_end_va, &va);
	return va;
}

static struct rte_devargs *
cdx_devargs_lookup(const char *dev_name)
{
	struct rte_devargs *devargs;

	RTE_EAL_DEVARGS_FOREACH("cdx", devargs) {
		if (strcmp(devargs->name, dev_name) == 0)
			return devargs;
	}
	return NULL;
}

static bool
cdx_ignore_device(const char *dev_name)
{
	struct rte_devargs *devargs = cdx_devargs_lookup(dev_name);

	switch (rte_cdx_bus.bus.conf.scan_mode) {
	case RTE_BUS_SCAN_ALLOWLIST:
		if (devargs && devargs->policy == RTE_DEV_ALLOWED)
			return false;
		break;
	case RTE_BUS_SCAN_UNDEFINED:
	case RTE_BUS_SCAN_BLOCKLIST:
		if (devargs == NULL || devargs->policy != RTE_DEV_BLOCKED)
			return false;
		break;
	}
	return true;
}

/*
 * Scan one cdx sysfs entry, and fill the devices list from it.
 * It checks if the CDX device is bound to vfio-cdx driver. In case
 * the device is vfio bound, it reads the vendor and device id and
 * stores it for device-driver matching.
 */
static int
cdx_scan_one(const char *dirname, const char *dev_name)
{
	char filename[PATH_MAX];
	struct rte_cdx_device *dev = NULL;
	char driver[PATH_MAX];
	unsigned long tmp;
	char *name = NULL;
	int ret;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return -ENOMEM;

	name = calloc(1, RTE_DEV_NAME_MAX_LEN);
	if (!name) {
		ret = -ENOMEM;
		goto err;
	}

	dev->device.bus = &rte_cdx_bus.bus;
	memcpy(name, dev_name, RTE_DEV_NAME_MAX_LEN);
	dev->device.name = name;

	/* parse driver */
	snprintf(filename, sizeof(filename), "%s/driver", dirname);
	ret = cdx_get_kernel_driver_by_path(filename, driver, sizeof(driver));
	if (ret < 0) {
		CDX_BUS_ERR("Fail to get kernel driver");
		ret = -1;
		goto err;
	}

	/* Allocate interrupt instance for cdx device */
	dev->intr_handle =
		rte_intr_instance_alloc(RTE_INTR_INSTANCE_F_PRIVATE);
	if (dev->intr_handle == NULL) {
		CDX_BUS_ERR("Failed to create interrupt instance for %s\n",
			dev->device.name);
		return -ENOMEM;
	}

	/*
	 * Check if device is bound to 'vfio-cdx' driver, so that user-space
	 * can gracefully access the device.
	 */
	if (ret || strcmp(driver, "vfio-cdx")) {
		ret = 0;
		goto err;
	}

	/* get vendor id */
	snprintf(filename, sizeof(filename), "%s/vendor", dirname);
	if (eal_parse_sysfs_value(filename, &tmp) < 0) {
		ret = -1;
		goto err;
	}
	dev->id.vendor_id = (uint16_t)tmp;

	/* get device id */
	snprintf(filename, sizeof(filename), "%s/device", dirname);
	if (eal_parse_sysfs_value(filename, &tmp) < 0) {
		free(dev);
		return -1;
	}
	dev->id.device_id = (uint16_t)tmp;

	rte_cdx_add_device(dev);

	return 0;

err:
	if (name)
		free(name);
	if (dev)
		free(dev);
	return ret;
}

/*
 * Scan the content of the CDX bus, and the devices in the devices
 * list.
 */
static int
rte_cdx_scan(void)
{
	struct dirent *e;
	DIR *dir;
	char dirname[PATH_MAX];

	dir = opendir(rte_cdx_get_sysfs_path());
	if (dir == NULL) {
		CDX_BUS_ERR("%s(): opendir failed: %s", __func__,
			strerror(errno));
		return -1;
	}

	while ((e = readdir(dir)) != NULL) {
		if (e->d_name[0] == '.')
			continue;

		if (cdx_ignore_device(e->d_name))
			continue;

		snprintf(dirname, sizeof(dirname), "%s/%s",
				rte_cdx_get_sysfs_path(), e->d_name);

		if (cdx_scan_one(dirname, e->d_name) < 0)
			goto error;
	}
	closedir(dir);
	return 0;

error:
	closedir(dir);
	return -1;
}

const char *
rte_cdx_get_sysfs_path(void)
{
	return SYSFS_CDX_DEVICES;
}

/* map a particular resource from a file */
void *
cdx_map_resource(void *requested_addr, int fd, off_t offset, size_t size,
		int additional_flags)
{
	void *mapaddr;

	/* Map the cdx MMIO memory resource of device */
	mapaddr = rte_mem_map(requested_addr, size,
		RTE_PROT_READ | RTE_PROT_WRITE,
		RTE_MAP_SHARED | additional_flags, fd, offset);
	if (mapaddr == NULL) {
		CDX_BUS_ERR("%s(): cannot map resource(%d, %p, 0x%zx, 0x%llx): %s (%p)",
			__func__, fd, requested_addr, size,
			(unsigned long long)offset,
			rte_strerror(rte_errno), mapaddr);
	}
	CDX_BUS_DEBUG("CDX MMIO memory mapped at %p", mapaddr);

	return mapaddr;
}

/* unmap a particular resource */
void
cdx_unmap_resource(void *requested_addr, size_t size)
{
	if (requested_addr == NULL)
		return;

	/* Unmap the CDX memory resource of device */
	if (rte_mem_unmap(requested_addr, size)) {
		CDX_BUS_ERR("%s(): cannot mem unmap(%p, %#zx): %s", __func__,
			requested_addr, size, rte_strerror(rte_errno));
	}
	CDX_BUS_DEBUG("CDX memory unmapped at %p", requested_addr);
}
/*
 * Match the CDX Driver and Device using device id and vendor id.
 */
static int
rte_cdx_match(const struct rte_cdx_driver *cdx_drv,
		const struct rte_cdx_device *cdx_dev)
{
	const struct rte_cdx_id *id_table;

	for (id_table = cdx_drv->id_table; id_table->vendor_id != 0;
	     id_table++) {
		/* check if device's identifiers match the driver's ones */
		if (id_table->vendor_id != cdx_dev->id.vendor_id &&
				id_table->vendor_id != RTE_CDX_ANY_ID)
			continue;
		if (id_table->device_id != cdx_dev->id.device_id &&
				id_table->device_id != RTE_CDX_ANY_ID)
			continue;

		return 1;
	}

	return 0;
}

/*
 * If vendor id and device id match, call the probe() function of the
 * driver.
 */
static int
rte_cdx_probe_one_driver(struct rte_cdx_driver *dr,
		struct rte_cdx_device *dev)
{
	const char *dev_name = dev->device.name;
	bool already_probed;
	int ret;

	if ((dr == NULL) || (dev == NULL))
		return -EINVAL;

	/* The device is not blocked; Check if driver supports it */
	if (!rte_cdx_match(dr, dev))
		/* Match of device and driver failed */
		return 1;

	already_probed = rte_dev_is_probed(&dev->device);
	if (already_probed) {
		CDX_BUS_INFO("Device %s is already probed", dev->device.name);
		return -EEXIST;
	}

	CDX_BUS_DEBUG("  probe device %s using driver: %s", dev_name,
		dr->driver.name);

	ret = cdx_vfio_map_resource(dev);
	if (ret != 0) {
		CDX_BUS_ERR("CDX map device failed: %d", ret);
		goto error_map_device;
	}

	/* call the driver probe() function */
	ret = dr->probe(dr, dev);
	if (ret) {
		CDX_BUS_ERR("Probe CDX driver: %s device: %s failed: %d",
			dr->driver.name, dev_name, ret);
		goto error_probe;
	} else {
		dev->device.driver = &dr->driver;
	}

	return ret;

error_probe:
	rte_intr_instance_free(dev->intr_handle);
	dev->intr_handle = NULL;
	cdx_vfio_unmap_resource(dev);
error_map_device:
	return ret;
}

/*
 * If vendor/device ID match, call the probe() function of all
 * registered driver for the given device. Return < 0 if initialization
 * failed, return 1 if no driver is found for this device.
 */
static int
cdx_probe_all_drivers(struct rte_cdx_device *dev)
{
	struct rte_cdx_driver *dr = NULL;
	int rc = 0;

	if (dev == NULL)
		return -EINVAL;

	FOREACH_DRIVER_ON_CDXBUS(dr) {
		rc = rte_cdx_probe_one_driver(dr, dev);
		if (rc < 0)
			/* negative value is an error */
			return rc;
		if (rc > 0)
			/* positive value means driver doesn't support it */
			continue;
		return 0;
	}
	return 1;
}

/*
 * Scan the content of the CDX bus, and call the probe() function for
 * all registered drivers that have a matching entry in its id_table
 * for discovered devices.
 */
static int
cdx_probe(void)
{
	struct rte_cdx_device *dev = NULL;
	size_t probed = 0, failed = 0;
	int ret = 0;

	FOREACH_DEVICE_ON_CDXBUS(dev) {
		probed++;

		ret = cdx_probe_all_drivers(dev);
		if (ret < 0) {
			CDX_BUS_ERR("Requested device %s cannot be used",
				dev->device.name);
			rte_errno = errno;
			failed++;
			ret = 0;
		}
	}

	return (probed && probed == failed) ? -1 : 0;
}

/* dump one device */
static int
cdx_dump_one_device(FILE *f, struct rte_cdx_device *dev)
{
	int i;

	fprintf(f, "cdx device %s\n", dev->device.name);

	for (i = 0; i != sizeof(dev->mem_resource) /
		sizeof(dev->mem_resource[0]); i++) {
		if (dev->mem_resource[i].len)
			fprintf(f, "   Resource[%d]: %p %16.16"PRIx64"\n",
				i, dev->mem_resource[i].addr,
				dev->mem_resource[i].len);
	}
	return 0;
}

/* dump devices on the bus */
void
rte_cdx_dump(FILE *f)
{
	struct rte_cdx_device *dev = NULL;

	FOREACH_DEVICE_ON_CDXBUS(dev)
		cdx_dump_one_device(f, dev);
}

static int
cdx_parse(const char *name, void *addr)
{
	const char **out = addr;
	int ret;

	ret = strncmp(name, CDX_DEV_PREFIX, strlen(CDX_DEV_PREFIX));

	if (ret == 0 && addr)
		*out = name;

	return ret;
}

/* register a driver */
void
rte_cdx_register(struct rte_cdx_driver *driver)
{
	TAILQ_INSERT_TAIL(&rte_cdx_bus.driver_list, driver, next);
	driver->bus = &rte_cdx_bus;
}

/* unregister a driver */
void
rte_cdx_unregister(struct rte_cdx_driver *driver)
{
	TAILQ_REMOVE(&rte_cdx_bus.driver_list, driver, next);
	driver->bus = NULL;
}

static struct rte_device *
cdx_find_device(const struct rte_device *start, rte_dev_cmp_t cmp,
		const void *data)
{
	const struct rte_cdx_device *cdx_start;
	struct rte_cdx_device *cdx_dev;

	if (start != NULL) {
		cdx_start = RTE_DEV_TO_CDX_DEV_CONST(start);
		cdx_dev = TAILQ_NEXT(cdx_start, next);
	} else {
		cdx_dev = TAILQ_FIRST(&rte_cdx_bus.device_list);
	}
	while (cdx_dev != NULL) {
		if (cmp(&cdx_dev->device, data) == 0)
			return &cdx_dev->device;
		cdx_dev = TAILQ_NEXT(cdx_dev, next);
	}
	return NULL;
}

static int
cdx_dma_map(struct rte_device *dev, void *addr, uint64_t iova, size_t len)
{
	struct rte_cdx_device *cdx_dev = RTE_DEV_TO_CDX_DEV(dev);

	if (!cdx_dev) {
		rte_errno = EINVAL;
		return -1;
	}

	return rte_vfio_container_dma_map(RTE_VFIO_DEFAULT_CONTAINER_FD,
					  (uintptr_t)addr, iova, len);
}

static int
cdx_dma_unmap(struct rte_device *dev, void *addr, uint64_t iova, size_t len)
{
	struct rte_cdx_device *cdx_dev = RTE_DEV_TO_CDX_DEV(dev);

	if (!cdx_dev) {
		rte_errno = EINVAL;
		return -1;
	}

	return rte_vfio_container_dma_unmap(RTE_VFIO_DEFAULT_CONTAINER_FD,
					    (uintptr_t)addr, iova, len);
}

static enum rte_iova_mode
rte_cdx_get_iommu_class(void)
{
	if (TAILQ_EMPTY(&rte_cdx_bus.device_list))
		return RTE_IOVA_DC;

	return RTE_IOVA_VA;
}

struct rte_cdx_bus rte_cdx_bus = {
	.bus = {
		.scan = rte_cdx_scan,
		.probe = cdx_probe,
		.find_device = cdx_find_device,
		.parse = cdx_parse,
		.dma_map = cdx_dma_map,
		.dma_unmap = cdx_dma_unmap,
		.get_iommu_class = rte_cdx_get_iommu_class,
	},
	.device_list = TAILQ_HEAD_INITIALIZER(rte_cdx_bus.device_list),
	.driver_list = TAILQ_HEAD_INITIALIZER(rte_cdx_bus.driver_list),
};

RTE_REGISTER_BUS(cdx, rte_cdx_bus.bus);
RTE_LOG_REGISTER_DEFAULT(cdx_logtype_bus, NOTICE);
