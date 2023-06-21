/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, Advanced Micro Devices, Inc.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bus_cdx_driver.h>
#include <rte_eal.h>
#include <rte_dmadev.h>
#include <rte_dmadev_pmd.h>
#include <rte_kvargs.h>
#include <rte_malloc.h>

#include "rte_pmd_cdx_cdma.h"
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

/*
 * Note: CDMA devices does not support MSIs by default, but they can fake
 * up MSI's by writing (or DMA) eventID's to the GITS_TRANSLATOR (ITS
 * doorbell). In order to do this, GITS_TRANSLATOR address needs to be mapped
 * to IOMMU, and CDMA can trigger a DMA for source address containing the
 * eventID and destination address with IOVA allocated for the GITS_TRANSLATOR
 * physical address.
 */
/* Variable required for setup and generating fake MSI's. */
void *p_gits_translator_page;
uint32_t *p_event_id;

static int
cdma_reset(struct rte_dma_dev *dmadev);

static inline int
cdma_submit(void *dev_private, uint16_t vchan)
{
	struct cdma_dev_t *cdma_dev = dev_private;
	struct cdma_virt_queue_t *cdma_vq = &cdma_dev->vqs[vchan];
	uint8_t *dev_addr = cdma_dev->addr;
	rte_iova_t src, dst;
	uint32_t length;

	if (!cdma_vq->pending_job.job_valid) {
		CDMA_DP_DEBUG("No job pending to submit on VQ: %d\n", vchan);
		return -EINVAL;
	}

	src = cdma_vq->pending_job.src;
	dst = cdma_vq->pending_job.dst;
	length = cdma_vq->pending_job.length;

	/* Write source and destination addresses */
	cdma_write32(dev_addr + CDMA_SA, lower_32_bits(src));
	cdma_write32(dev_addr + CDMA_SA_MSB, upper_32_bits(src));
	cdma_write32(dev_addr + CDMA_DA, lower_32_bits(dst));
	cdma_write32(dev_addr + CDMA_DA_MSB, upper_32_bits(dst));

	/* Writing to len initiates the DMA */
	cdma_write32(dev_addr + CDMA_BTT, length);

	cdma_vq->pending_job.job_valid = 0;
	cdma_vq->stats.submitted++;

	return 0;
}

static int
cdma_copy(void *dev_private, uint16_t vchan,
	  rte_iova_t src, rte_iova_t dst,
	  uint32_t length, uint64_t flags)
{
	struct cdma_dev_t *cdma_dev = dev_private;
	struct cdma_virt_queue_t *cdma_vq = &cdma_dev->vqs[vchan];
	uint16_t idx;

	idx = (uint16_t)(cdma_vq->stats.submitted);

	if (length > MAX_DMA_LEN) {
		CDMA_ERR("Invalid length: %d. Max supported len: %d\n",
			length, MAX_DMA_LEN);
		return -EINVAL;
	}

	if (cdma_vq->pending_job.job_valid) {
		CDMA_DP_DEBUG("Job already pending on the VQ: %d\n", vchan);
		return -EBUSY;
	}

	cdma_vq->pending_job.src = src;
	cdma_vq->pending_job.dst = dst;
	cdma_vq->pending_job.length = length;
	cdma_vq->pending_job.job_valid = 1;

	if (flags & RTE_DMA_OP_FLAG_SUBMIT)
		cdma_submit(dev_private, vchan);

	return idx;
}

static uint16_t
cdma_completed_status(void *dev_private, uint16_t vchan,
		const uint16_t nb_cpls,
		uint16_t *last_idx,
		enum rte_dma_status_code *st)
{
	struct cdma_dev_t *cdma_dev = dev_private;
	struct cdma_virt_queue_t *cdma_vq = &cdma_dev->vqs[vchan];
	uint8_t *dev_addr = cdma_dev->addr;
	uint32_t status, ret = 0;

	RTE_SET_USED(nb_cpls);

	if (cdma_vq->stats.completed == cdma_vq->stats.submitted) {
		CDMA_DP_DEBUG("No DMA is pending");
		goto exit;
	}

	status = cdma_read32(dev_addr + CDMA_SR);

	if (IS_BIT_SET_AT_POS(status, CDMA_IDLE)) {
		cdma_vq->stats.completed++;

		if (st != NULL) {
			*st = 0;
			if (IS_BIT_SET_AT_POS(status, CDMA_DMA_SLV_ERR))
				*st |= RTE_DMA_STATUS_BUS_ERROR;
			if (IS_BIT_SET_AT_POS(status, CDMA_DMA_INT_ERR) ||
			    IS_BIT_SET_AT_POS(status, CDMA_DMA_DEC_ERR))
				*st |= RTE_DMA_STATUS_ERROR_UNKNOWN;
			if (*st != 0)
				cdma_reset(cdma_dev->dmadev);
		}

		ret = 1;
	}

exit:
	if (last_idx != NULL)
		*last_idx = (uint16_t)(cdma_vq->stats.completed - 1);

	return ret;
}

static uint16_t
cdma_completed(void *dev_private,
	       uint16_t vchan, const uint16_t nb_cpls,
	       uint16_t *last_idx, bool *has_error)
{
	struct cdma_dev_t *cdma_dev = dev_private;
	struct cdma_virt_queue_t *cdma_vq = &cdma_dev->vqs[vchan];
	uint8_t *dev_addr = cdma_dev->addr;
	uint32_t status, ret = 0;

	RTE_SET_USED(nb_cpls);

	if (cdma_vq->stats.completed == cdma_vq->stats.submitted) {
		CDMA_DP_DEBUG("No DMA is pending");
		goto exit;
	}

	status = cdma_read32(dev_addr + CDMA_SR);

	if (IS_BIT_SET_AT_POS(status, CDMA_IDLE)) {
		cdma_vq->stats.completed++;

		if (has_error != NULL) {
			if (IS_BIT_SET_AT_POS(status, CDMA_DMA_INT_ERR) ||
			    IS_BIT_SET_AT_POS(status, CDMA_DMA_SLV_ERR) ||
			    IS_BIT_SET_AT_POS(status, CDMA_DMA_DEC_ERR)) {
				*has_error = true;
				cdma_reset(cdma_dev->dmadev);
			} else {
				*has_error = false;
			}
		}

		ret = 1;
	}

exit:
	if (last_idx != NULL)
		*last_idx = (uint16_t)(cdma_vq->stats.completed - 1);

	return ret;
}

static int
cdma_vchan_status(const struct rte_dma_dev *dev,
		uint16_t vchan, enum rte_dma_vchan_status *st)
{
	struct cdma_dev_t *cdma_dev = dev->data->dev_private;
	uint8_t *dev_addr = cdma_dev->addr;
	uint32_t status;

	RTE_SET_USED(vchan);

	status = cdma_read32(dev_addr + CDMA_SR);

	if (IS_BIT_SET_AT_POS(status, CDMA_IDLE))
		*st = RTE_DMA_VCHAN_IDLE;
	else
		*st = RTE_DMA_VCHAN_ACTIVE;

	return 0;
}

int
rte_dma_cdx_cdma_num_msi(int dev_id)
{
	struct rte_dma_fp_object *obj = &rte_dma_fp_objs[dev_id];
	struct cdma_dev_t *cdma_dev = obj->dev_private;

	CDMA_FUNC_TRACE();

	if (!rte_dma_is_valid(dev_id))
		return -EINVAL;

	return cdma_dev->num_msi;
}

int
rte_dma_cdx_cdma_get_efd(int dev_id, int msi_id)
{
	struct rte_dma_fp_object *obj = &rte_dma_fp_objs[dev_id];
	struct cdma_dev_t *cdma_dev = obj->dev_private;

	CDMA_FUNC_TRACE();

	if (!rte_dma_is_valid(dev_id))
		return -EINVAL;

	if (msi_id >= cdma_dev->num_msi) {
		CDMA_ERR("Invalid IRQ No: %d\n", msi_id);
		return -EINVAL;
	}

	return rte_intr_efds_index_get(cdma_dev->cdx_dev->intr_handle, msi_id);
}

int
rte_dma_cdx_cdma_trigger_fake_msi(int dev_id, int msi_id)
{
	struct rte_dma_fp_object *obj = &rte_dma_fp_objs[dev_id];
	struct cdma_dev_t *cdma_dev = obj->dev_private;
	int ret;

	CDMA_FUNC_TRACE();

	if (!rte_dma_is_valid(dev_id))
		return -EINVAL;

	if (msi_id >= cdma_dev->num_msi) {
		CDMA_ERR("Invalid IRQ No: %d\n", msi_id);
		return -EINVAL;
	}

	*p_event_id = msi_id;

	ret = cdma_copy(cdma_dev, 0, (rte_iova_t)(p_event_id),
		(rte_iova_t)((uint8_t *)(p_gits_translator_page) +
		GITS_TRANSLATOR_OFFSET),
		sizeof(uint32_t), RTE_DMA_OP_FLAG_SUBMIT);
	if (ret < 0) {
		CDMA_ERR("cdma_copy failed for MSI: %d\n", msi_id);
		return ret;
	}

	return 0;
}

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

static int
cdma_stats_get(const struct rte_dma_dev *dmadev, uint16_t vchan,
	       struct rte_dma_stats *rte_stats, uint32_t size)
{
	struct cdma_dev_t *cdma_dev = dmadev->data->dev_private;
	struct cdma_virt_queue_t *cdma_vq = &cdma_dev->vqs[vchan];

	CDMA_FUNC_TRACE();

	RTE_SET_USED(size);

	memcpy(rte_stats, &cdma_vq->stats, sizeof(struct rte_dma_stats));

	return 0;
}

static int
cdma_stats_reset(struct rte_dma_dev *dmadev, uint16_t vchan)
{
	struct cdma_dev_t *cdma_dev = dmadev->data->dev_private;
	struct cdma_virt_queue_t *cdma_vq = &cdma_dev->vqs[vchan];

	CDMA_FUNC_TRACE();

	memset(&cdma_vq->stats, 0, sizeof(struct rte_dma_stats));

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
	.vchan_status     = cdma_vchan_status,
	.stats_get        = cdma_stats_get,
	.stats_reset      = cdma_stats_reset,
};

static void
unset_fake_msi(struct rte_cdx_device *cdx_dev)
{
	void *vaddr = p_gits_translator_page;

	CDMA_FUNC_TRACE();

	if (p_event_id) {
		rte_free(p_event_id);
		p_event_id = NULL;
	}

	if (p_gits_translator_page) {
		cdx_dev->device.bus->dma_unmap(&cdx_dev->device, vaddr,
			(uint64_t)vaddr, GITS_TRANSLATOR_MAP_SIZE);
		p_gits_translator_page = NULL;
	}
}

static void
cdma_dev_uninit(struct rte_cdx_device *cdx_dev)
{
	CDMA_DEBUG("Closing CDMA device %s", cdx_dev->device.name);

	/* Disable interrupts */
	rte_cdx_vfio_intr_disable(cdx_dev->intr_handle);
	rte_intr_efd_disable(cdx_dev->intr_handle);

	unset_fake_msi(cdx_dev);
}

/*
 * CDMA devices do not support MSI. So fake MSI is being generated
 * We are creating eventIDs and then writing them to p_gits_translator_page
 * to trigger an MSI.
 */
static int
setup_for_fake_msi(struct rte_cdx_device *cdx_dev)
{
	int map_fd = -1, ret = 0;
	void *vaddr;

	CDMA_FUNC_TRACE();

	/* Map GITS_TRANSLATOR (present in GIC ITS) region */
	if (p_gits_translator_page == NULL) {
		/* Get virtual address using devmem */
		map_fd = open("/dev/mem", O_RDWR);
		if (unlikely(map_fd < 0)) {
			CDMA_ERR("Unable to open (/dev/mem)");
			ret = map_fd;
			goto err;
		}
		p_gits_translator_page = mmap(NULL, GITS_TRANSLATOR_MAP_SIZE,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				map_fd, GITS_TRANSLATOR_ADDR);
		if (p_gits_translator_page == MAP_FAILED) {
			CDMA_ERR("Memory map failed");
			ret = -EINVAL;
			goto err;
		}

		p_event_id = rte_malloc(NULL, sizeof(uint32_t),
			RTE_CACHE_LINE_SIZE);
	}

	/* MAP GITS translator page via VFIO */
	vaddr = p_gits_translator_page;
	ret = cdx_dev->device.bus->dma_map(&cdx_dev->device, vaddr,
			(uint64_t)vaddr, GITS_TRANSLATOR_MAP_SIZE);
	if (ret) {
		CDMA_ERR("GITS TRANSLATOR DMA map failed");
		goto err;
	}

	close(map_fd);
	return 0;

err:
	if (p_event_id) {
		rte_free(p_event_id);
		p_event_id = NULL;
	}
	if (map_fd != -1)
		close(map_fd);

	return ret;
}

static int
cdma_dev_init(struct rte_cdx_device *cdx_dev, struct rte_dma_dev *dmadev)
{
	struct cdma_dev_t *cdma_dev = dmadev->data->dev_private;
	int ret = 0;

	CDMA_DEBUG("Probing CDMA cdx device %s", cdx_dev->device.name);

	if (cdx_dev->mem_resource[0].addr == 0) {
		CDMA_ERR("Address not populated in cdx device");
		return ret;
	}

	cdma_dev->addr = cdx_dev->mem_resource[0].addr;
	cdma_dev->len = cdx_dev->mem_resource[0].len;
	cdma_dev->num_msi = rte_intr_nb_intr_get(cdx_dev->intr_handle);
	cdma_dev->cdx_dev = cdx_dev;
	cdma_dev->dmadev = dmadev;

	if (cdma_dev->num_msi >= 1) {
		ret = setup_for_fake_msi(cdx_dev);
		if (ret) {
			CDMA_ERR("setup for fske MSI failed");
			return ret;
		}

		/* Enable interrupts */
		rte_intr_efd_enable(cdx_dev->intr_handle, cdma_dev->num_msi);
		rte_cdx_vfio_intr_enable(cdx_dev->intr_handle);
	}

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
	dmadev->fp_obj->copy = cdma_copy;
	dmadev->fp_obj->submit = cdma_submit;
	dmadev->fp_obj->completed = cdma_completed;
	dmadev->fp_obj->completed_status = cdma_completed_status;
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

	cdma_dev_uninit(cdx_dev);

	ret = rte_dma_pmd_release(cdx_dev->device.name);
	if (ret)
		CDMA_ERR("Device cleanup failed");

	return 0;
}

static struct rte_cdx_driver cdma_drv = {
	.id_table = cdma_match_id_tbl,
	.probe = cdma_probe,
	.remove = cdma_remove,
	.drv_flags = RTE_CDX_DRV_NEED_MAPPING
};

RTE_PMD_REGISTER_CDX(cdma_driver, cdma_drv);
RTE_LOG_REGISTER_DEFAULT(cdma_logtype, INFO);
