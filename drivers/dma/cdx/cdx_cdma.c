/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, Advanced Micro Devices, Inc.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include <rte_bus_cdx.h>
#include <rte_eal.h>
#include <rte_dmadev.h>
#include <rte_dmadev_pmd.h>
#include <rte_kvargs.h>
#include <rte_malloc.h>

#include "cdx_cdma.h"
#include "cdx_cdma_logs.h"

/* Dynamic log type identifier */
int cdma_logtype;

#define CDMA_CDX_VENDOR_ID 0x10EE
#define CDMA_CDX_DEVICE_ID 0x8084
static const struct rte_cdx_id cdma_match_id_tbl[] = {
	{ RTE_CDX_DEVICE(CDMA_CDX_VENDOR_ID, CDMA_CDX_DEVICE_ID) },
	{ .vendor_id = 0, }
};

static struct rte_dma_dev_ops cdma_ops = {
};

static int
cdma_dev_init(struct rte_cdx_device *cdx_dev, struct rte_dma_dev *dmadev)
{
	struct cdma_dev_t *cdma_dev = dmadev->data->dev_private;

	CDMA_DEBUG("Probing CDMA cdx device %s", cdx_dev->device.name);

	if (cdx_dev->mem_resource[0].addr == 0) {
		CDMA_ERR("Address not populated in cdx device");
		return -EINVAL;
	}

	cdma_dev->addr = cdx_dev->mem_resource[0].addr;
	cdma_dev->len = cdx_dev->mem_resource[0].len;
	cdma_dev->cdx_dev = cdx_dev;
	cdma_dev->dmadev = dmadev;

	return 0;
}

static int
cdma_probe(struct rte_cdx_driver *cdx_driver,
	   struct rte_cdx_device *cdx_dev)
{
	struct rte_dma_dev *dmadev;
	int ret;

	CDMA_INFO("Probing CDMA cdx device %s", cdx_dev->device.name);

	RTE_SET_USED(cdx_driver);

	dmadev = rte_dma_pmd_allocate(cdx_dev->device.name, 0,
				      sizeof(struct cdma_dev_t));
	if (!dmadev) {
		CDMA_ERR("Unable to allocate dmadevice");
		return -EINVAL;
	}

	dmadev->dev_ops = &cdma_ops;
	dmadev->device = &cdx_dev->device;
	dmadev->fp_obj->dev_private = dmadev->data->dev_private;

	/* Invoke PMD device initialization function */
	ret = cdma_dev_init(cdx_dev, dmadev);
	if (ret) {
		rte_dma_pmd_release(cdx_dev->device.name);
		return ret;
	}

	dmadev->state = RTE_DMA_DEV_REGISTERED;

	return 0;
}

static int
cdma_remove(struct rte_cdx_device *cdx_dev)
{
	int ret;

	CDMA_FUNC_TRACE();

	ret = rte_dma_pmd_release(cdx_dev->device.name);
	if (ret)
		CDMA_ERR("Device cleanup failed");

	return 0;
}

static struct rte_cdx_driver cdma_drv = {
	.id_table = cdma_match_id_tbl,
	.probe = cdma_probe,
	.remove = cdma_remove
};

RTE_PMD_REGISTER_CDX(cdma_driver, cdma_drv);
RTE_LOG_REGISTER_DEFAULT(cdma_logtype, INFO);
