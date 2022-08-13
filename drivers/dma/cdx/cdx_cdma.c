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

static int
cdma_info_get(const struct rte_dma_dev *dmadev,
	      struct rte_dma_info *dev_info,
	      uint32_t info_sz)
{
	CDMA_FUNC_TRACE();

	RTE_SET_USED(dmadev);
	RTE_SET_USED(info_sz);

	dev_info->dev_capa = RTE_DMA_CAPA_MEM_TO_MEM |
			     RTE_DMA_CAPA_SILENT |
			     RTE_DMA_CAPA_OPS_COPY;
	dev_info->max_vchans = CDMA_MAX_VHANS;
	dev_info->max_desc = CDMA_NUM_DESC;
	dev_info->min_desc = CDMA_NUM_DESC;

	return 0;
}

static int
cdma_configure(struct rte_dma_dev *dmadev,
	       const struct rte_dma_conf *dev_conf,
	       uint32_t conf_sz)
{
	char name[32]; /* RTE_MEMZONE_NAMESIZE = 32 */
	struct cdma_dev_t *cdma_dev = dmadev->data->dev_private;

	CDMA_FUNC_TRACE();

	RTE_SET_USED(conf_sz);

	/* Allocate Virtual Queues */
	sprintf(name, "cdma_%d_vq", dmadev->data->dev_id);
	cdma_dev->vqs = rte_zmalloc(name,
			(sizeof(struct cdma_virt_queue_t) * dev_conf->nb_vchans),
			RTE_CACHE_LINE_SIZE);
	if (!cdma_dev->vqs) {
		CDMA_ERR("cdma_virtual_queues allocation failed");
		return -ENOMEM;
	}

	cdma_dev->vqs[0].vq_id = 0;

	return 0;
}

static int
cdma_vchan_setup(struct rte_dma_dev *dmadev, uint16_t vchan,
		const struct rte_dma_vchan_conf *conf,
		uint32_t conf_sz)
{
	CDMA_FUNC_TRACE();

	RTE_SET_USED(dmadev);
	RTE_SET_USED(vchan);
	RTE_SET_USED(conf);
	RTE_SET_USED(conf_sz);

	return 0;
}

static int
cdma_start(struct rte_dma_dev *dmadev)
{
	CDMA_FUNC_TRACE();

	dmadev->state = RTE_DMA_DEV_READY;

	return 0;
}

static int
cdma_stop(struct rte_dma_dev *dmadev)
{
	CDMA_FUNC_TRACE();

	dmadev->state = RTE_DMA_DEV_REGISTERED;

	return 0;
}

static int
cdma_reset(struct rte_dma_dev *dmadev)
{
	struct cdma_dev_t *cdma_dev = dmadev->data->dev_private;
	uint8_t *dev_addr = cdma_dev->addr;
	uint32_t value;

	CDMA_FUNC_TRACE();

	value = cdma_read32(dev_addr + CDMA_CR);
	SET_BIT_AT_POS(value, CDMA_RESET);
	cdma_write32(dev_addr + CDMA_CR, value);

	return 0;
}

static int
cdma_close(struct rte_dma_dev *dmadev)
{
	CDMA_FUNC_TRACE();

	RTE_SET_USED(dmadev);

	return 0;
}

static uint16_t
cdma_burst_capacity(const void *dev_private, uint16_t vchan)
{
	CDMA_FUNC_TRACE();

	RTE_SET_USED(dev_private);
	RTE_SET_USED(vchan);

	return CDMA_NUM_DESC;
}

static struct rte_dma_dev_ops cdma_ops = {
	.dev_info_get     = cdma_info_get,
	.dev_configure    = cdma_configure,
	.dev_start        = cdma_start,
	.dev_stop         = cdma_stop,
	.dev_close        = cdma_close,
	.vchan_setup      = cdma_vchan_setup,
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
	dmadev->fp_obj->burst_capacity = cdma_burst_capacity;

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
