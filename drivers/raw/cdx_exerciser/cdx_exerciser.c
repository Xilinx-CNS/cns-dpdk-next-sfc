/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bus_cdx_driver.h>
#include <rte_eal.h>
#include <rte_kvargs.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_rawdev.h>
#include <rte_rawdev_pmd.h>
#include "cdx_exerciser.h"
#include "rte_pmd_cdx_exerciser.h"


static const struct rte_cdx_id cdx_exerciser_match_id_tbl[] = {
		{ RTE_CDX_DEVICE(RTE_CDX_ANY_ID, RTE_CDX_ANY_ID) }
};

static void write32_cdm(volatile uint32_t *addr, uint32_t offset, int value)
{
		*(addr + ((CDM_OFFSET + offset) / 4)) = value;
}

static int read32_cdm(volatile uint32_t *addr, uint32_t offset)
{
		return *(addr + ((CDM_OFFSET + offset) / 4));
}

static void write32_csi(volatile uint32_t *addr, uint32_t offset, int value)
{
		*(addr + ((CSI_OFFSET + offset) / 4)) = value;
}

static void decode_device_id(struct rte_cdx_device *cdx_dev, uint32_t *id)
{
	char *token, buf[BUF_SIZE];

	/*Decode device ID*/
	strcpy(buf, cdx_dev->device.name);
	/*Ignore first token as it is bus ID*/
	token = strtok(buf, ":");
	token = strtok(NULL, ":");
	*id = token ? strtoul(token, NULL, 0) : 0;
}

static int init_csi_exerciser(struct rte_cdx_device *cdx_dev)
{
	volatile uint32_t *addr;

	if (!cdx_dev->mem_resource[1].len) {
		CDX_EXERCISER_LOG(ERR, "Invalid resource address for BAR1, device : %s", cdx_dev->device.name);
		return -EINVAL;
	}

	/*Initialize CSI exerciser*/
	addr = cdx_dev->mem_resource[1].addr;
	//Set NPR, CMPL, PR dest_id for returning the dest credit
	write32_csi(addr, CSI_NPR_DEST_ID, CSI_UPORT_DST_ID_BASE);
	write32_csi(addr, CSI_CMPL_DEST_ID, CSI_UPORT_DST_ID_BASE + 1);
	write32_csi(addr, CSI_PR_DEST_ID, CSI_UPORT_DST_ID_BASE + 2);
	//Set CMPL init credits
	write32_csi(addr, CSI_CMPL_CREDIT, CSI_UPORT_CMPL_CREDITS);
	write32_csi(addr, CSI_INIT_CREDITS_SOURCE2, CSI_UPORT_CMPL_CREDITS);
	// Set destination FIFO ID
	write32_csi(addr, CSI_CMPL_DEST_FIFO_ID_SOURCE1, CSI_UPORT_CMPL_DEST_FIFO_ID);
	write32_csi(addr, CSI_CMPL_DEST_FIFO_ID_SOURCE2, CSI_UPORT_CMPL_DEST_FIFO_ID);
	write32_csi(addr, CSI_BUF_ID_SOURCE2, CSI_UPORT_CMPL_DEST_FIFO_ID);
	write32_csi(addr, CSI_INPUT_SOURCE1, CSI_EXER_INPUT_SOURCE_PCIE0);
	write32_csi(addr, CSI_INPUT_SOURCE2, CSI_EXER_INPUT_SOURCE_PSX);
	//Reset counters, encode & req_gen logic
	write32_csi(addr, CSI_CTRL, CSI_CTRL_RESET_COUNTERS);
	//Load Initial credit for all the flow
	write32_csi(addr, CSI_CTRL, CSI_CTRL_LOAD_CREDITS);
	//Enabling CMPL txn at user port if it receives NPR
	write32_csi(addr, CSI_CTRL, CSI_CTRL_INITIATE_CMPL);
	write32_csi(addr, CSI_CTRL, CSI_CTRL_CLEAR);

	return 0;
}

static int test_usr_port_mmio(struct rte_cdx_device *cdx_dev)
{
	volatile uint32_t *addr;
	int i, j, pr_len;

	if (!cdx_dev->mem_resource[1].len) {
		CDX_EXERCISER_LOG(ERR, "Invalid resource address for BAR1, device %s", cdx_dev->device.name);
		return -EINVAL;
	}

	for (i = 0; i < RTE_CDX_MAX_RESOURCE; i++) {
		if (!cdx_dev->mem_resource[i].len)
				continue;
		fprintf(stderr, "Resource %d (total len: %ld)\n", i,
			   cdx_dev->mem_resource[i].len);
		fprintf(stderr, "--------------------------------");

		addr = cdx_dev->mem_resource[i].addr;
		pr_len = cdx_dev->mem_resource[i].len < NUM_WORDS_TO_PRINT ?
				cdx_dev->mem_resource[i].len : NUM_WORDS_TO_PRINT;

		for (j = 0; j < pr_len ; j++) {
			if (j % 4 == 0)
				fprintf(stderr, "\n %lx:\t", j * sizeof(addr[0]));
			fprintf(stderr, "%08x ", addr[j]);
		}
		fprintf(stderr, "\n");
	}

	return 0;
}

int rte_raw_cdx_exerciser_test_msg_store(int dev_id)
{
	uint32_t dma_low, dma_high, func_id;
	volatile uint32_t *addr;
	uint8_t *dst = NULL;
	bool result = false;
	int i;
	struct rte_rawdev *dev;
	struct rte_cdx_device *cdx_dev;

	if (!rte_rawdev_pmd_is_valid_dev(dev_id))
		return -ENODEV;

	dev = &rte_rawdevs[dev_id];
	cdx_dev = RTE_DEV_TO_CDX_DEV(dev->device);
	if (!cdx_dev) {
		CDX_EXERCISER_LOG(ERR, "Invalid CDX device, raw device index %d", dev_id);
		return -EINVAL;
	}

	if (!cdx_dev->mem_resource[1].len) {
		CDX_EXERCISER_LOG(ERR, "Invalid resource address, device %s", cdx_dev->device.name);
		return -EINVAL;
	}

	decode_device_id(cdx_dev, &func_id);

	addr = cdx_dev->mem_resource[1].addr;
	dst = rte_zmalloc(NULL, DMA_SIZE, RTE_CACHE_LINE_SIZE);
	if (!dst) {
		CDX_EXERCISER_LOG(ERR, "Dst memory allocation failed, device %s", cdx_dev->device.name);
		return -ENOMEM;
	}

	dma_low = (uint32_t)(uint64_t)dst;
	dma_high = (((uint64_t)dst) >> 32);

	write32_cdm(addr, CDM_GLOBAL_START, 0x0);
	write32_cdm(addr, CDM_SOFT_RSTN, 0x1);
	write32_cdm(addr, CDM_HOST_CTRL_REG_DST2, 0x0);
	write32_cdm(addr, CDM_MSGST_HOST_START_ADDR_0_DST2, dma_low);
	write32_cdm(addr, CDM_MSGST_HOST_START_ADDR_1_DST2, dma_high);
	write32_cdm(addr, CDM_HOST_CTRL_REG_DST2, 0x1);
	/*Initialize CMD RAM*/
	write32_cdm(addr, MSGST_CTRL0, (func_id << MSG_ST_FUNC_ID_SHIFT) | DMA_SIZE);
	/*Setting up PSX as destination*/
	write32_cdm(addr, MSGST_CTRL1, (CSI_DST << CSI_DST_SHIFT));
	write32_cdm(addr, MSGST_CTRL2, (1 << CLIENT_ID_SHIFT) | (1 << DATA_WIDTH_SHIFT));
	write32_cdm(addr, MSGST_CTRL3, (1 << PATTERN_SHIFT) | (0 << MSG_ST_SEED_SHIFT));//pattern - increment, seed - 0
	write32_cdm(addr, CDM_MSGST_CTRL_REG, MSG_STORE_START);
	/*starting Msg store engine*/
	write32_cdm(addr, CDM_GLOBAL_START, 0x1);
	sleep(1);
	/*Exerciser will write incremental data into memory starting from zero.
	 *Incremental data in memory is verified here.
	 */
	for (i = 0; i < DMA_SIZE; i++) {
		if (dst[i] != i) {
			result = true;
			CDX_EXERCISER_LOG(ERR,"Device: %s, Msg store transfer failed for Index %d,\
					 Expected: 0x%x, Actual: 0x%x", cdx_dev->device.name, i, i, dst[i]);
			break;
		}
	}

	rte_free(dst);

	return result ? 1: 0;
}

int rte_raw_cdx_exerciser_test_msg_load(int dev_id)
{
	uint32_t dma_low, dma_high, func_id;
	volatile uint32_t *addr;
	uint8_t *dst = NULL;
	volatile uint32_t data;
	int i;
	struct rte_rawdev *dev;
	struct rte_cdx_device *cdx_dev;

	if (!rte_rawdev_pmd_is_valid_dev(dev_id))
		return -ENODEV;

	dev = &rte_rawdevs[dev_id];
	cdx_dev = RTE_DEV_TO_CDX_DEV(dev->device);
	if (!cdx_dev) {
		CDX_EXERCISER_LOG(ERR, "Invalid CDX device, raw device index %d", dev_id);
		return -EINVAL;
	}

	if (!cdx_dev->mem_resource[1].len) {
		CDX_EXERCISER_LOG(ERR, "Invalid resource address, device %s", cdx_dev->device.name);
		return -EINVAL;
	}

	addr = cdx_dev->mem_resource[1].addr;

	decode_device_id(cdx_dev, &func_id);
	dst = rte_zmalloc(NULL, DMA_SIZE, RTE_CACHE_LINE_SIZE);
	if (!dst) {
		CDX_EXERCISER_LOG(ERR, "Dst memory allocation failed, device %s", cdx_dev->device.name);
		return -ENOMEM;
	}
	/*Fill memory with incremental data*/
	for (i = 0; i < DMA_SIZE; i++)
		dst[i] = i;

	dma_low = (uint32_t)(uint64_t)dst;
	dma_high = (((uint64_t)dst) >> 32);

	write32_cdm(addr, CDM_GLOBAL_START, 0x0);
	write32_cdm(addr, CDM_SOFT_RSTN, 0x1);
	write32_cdm(addr, CDM_HOST_CTRL_REG_DST2, 0x0);
	write32_cdm(addr, CDM_MSGLD_HOST_START_ADDR_0_DST2, dma_low);
	write32_cdm(addr, CDM_MSGLD_HOST_START_ADDR_1_DST2, dma_high);
	write32_cdm(addr, CDM_HOST_CTRL_REG_DST2, 0x1);
	/*Initialize CMD RAM*/
	/*set length as 1 byte, data width 32B interface, function ID*/
	data =  (func_id << MSG_ST_FUNC_ID_SHIFT) | (MSG_LD_LENGTH << MSG_LD_LENGTH_SHIFT) \
		| (MSG_LD_DATA_WIDTH << MSG_LD_DATA_WIDTH_SHIFT);
	write32_cdm(addr, MSGLD_CTRL0, data);
	/*Set PSX as destination*/
	data = (MSG_LD_RC_ID << MSG_LD_RC_ID_SHIFT) | (MSG_LD_DST << MSG_LD_DST_SHIFT) \
	       | (MSG_LD_CLIENT_ID << MSG_LD_CLIENT_ID_SHIFT);
	write32_cdm(addr, MSGLD_CTRL1, data);
	data = MSG_LD_RSP_COOKIE | (MSG_LD_TYPE_OF_PATTERN << MSG_LD_TYPE_OF_PATTERN_SHIFT);
	write32_cdm(addr, MSGLD_CTRL2, data);
	/*Clear msg store*/
	write32_cdm(addr, CDM_MSGST_CTRL_REG, 0x0);
	/*Set msg load start bit*/
	data = (1 << MSG_LD_PKT_COUNTERS_SHIFT) | (1 << MSG_LD_NUM_REQUESTS_SHIFT);
	write32_cdm(addr, CDM_MSGLD_CTRL_REG, data);
	/*starting Msg load engine*/
	write32_cdm(addr, CDM_GLOBAL_START, (1 << MSG_LD_START_SHIFT));
	sleep(1);

	if (read32_cdm(addr, CDM_MSGLD_RSP_STAT) != MSG_LOAD_STATUS)
		return -ENODATA;

	return 0;
}

static int cdx_exerciser_selftest(uint16_t dev_id)
{
	int ret = 0;
	struct rte_rawdev *dev;
	struct rte_cdx_device *cdx_dev;

	if (!rte_rawdev_pmd_is_valid_dev(dev_id))
		return -ENODEV;

	dev = &rte_rawdevs[dev_id];
	cdx_dev = RTE_DEV_TO_CDX_DEV(dev->device);
	if (!cdx_dev) {
		CDX_EXERCISER_LOG(ERR, "Invalid CDX device, raw device index %d", dev_id);
		return -EINVAL;
	}

	/*MMIO test*/
	ret = test_usr_port_mmio(cdx_dev);
	if (ret) {
		CDX_EXERCISER_LOG(ERR,"User port MMIO test failed for device %s\n", cdx_dev->device.name);
		return ret;
	}

	return ret;
}

/*Dummy op to bypass device remove error*/
static int
cdx_exerciser_dev_close(struct rte_rawdev *dev)
{
	RTE_SET_USED(dev);

	return 0;
}
static const struct rte_rawdev_ops cdx_exerciser_ops = {
	.dev_close = cdx_exerciser_dev_close,
	.dev_selftest = cdx_exerciser_selftest,
};

int
rte_raw_cdx_exerciser_num_msi(int dev_id)
{
	struct rte_rawdev *dev;
	struct rte_cdx_device *cdx_dev;

	if (!rte_rawdev_pmd_is_valid_dev(dev_id))
		return -ENODEV;

	dev = &rte_rawdevs[dev_id];
	cdx_dev = RTE_DEV_TO_CDX_DEV(dev->device);
	if (!cdx_dev) {
		CDX_EXERCISER_LOG(ERR, "Invalid CDX device, raw device index %d", dev_id);
		return -EINVAL;
	}

	return rte_intr_nb_intr_get(cdx_dev->intr_handle);
}

int
rte_raw_cdx_exerciser_get_efd(int dev_id, int msi_id)
{
	struct rte_rawdev *dev;
	struct rte_cdx_device *cdx_dev;

	if (!rte_rawdev_pmd_is_valid_dev(dev_id))
		return -ENODEV;

	dev = &rte_rawdevs[dev_id];
	cdx_dev = RTE_DEV_TO_CDX_DEV(dev->device);
	if (!cdx_dev) {
		CDX_EXERCISER_LOG(ERR, "Invalid CDX device, raw device index %d", dev_id);
		return -EINVAL;
	}

	if (msi_id >= rte_intr_nb_intr_get(cdx_dev->intr_handle)) {
		CDX_EXERCISER_LOG(ERR, "Invalid IRQ No: %d for device %s\n", msi_id, cdx_dev->device.name);
		return -EINVAL;
	}

	return rte_intr_efds_index_get(cdx_dev->intr_handle, msi_id);
}

int
rte_raw_cdx_exerciser_trigger_msi(int dev_id, int msi_id, uint64_t msi_addr, uint32_t msi_data)
{
	struct rte_rawdev *dev;
	struct rte_cdx_device *cdx_dev;
	volatile uint32_t *addr;
	uint32_t addr_type, pattern_type, func_id;

	if (!rte_rawdev_pmd_is_valid_dev(dev_id))
		return -ENODEV;

	dev = &rte_rawdevs[dev_id];
	cdx_dev = RTE_DEV_TO_CDX_DEV(dev->device);
	if (!cdx_dev) {
		CDX_EXERCISER_LOG(ERR, "Invalid CDX device, raw device index %d", dev_id);
		return -EINVAL;
	}

	if (msi_id >= rte_intr_nb_intr_get(cdx_dev->intr_handle)) {
		CDX_EXERCISER_LOG(ERR, "Invalid IRQ No: %d for device %s\n", msi_id, cdx_dev->device.name);
		return -EINVAL;
	}

	if (!cdx_dev->mem_resource[1].len) {
		CDX_EXERCISER_LOG(ERR, "Invalid resource address, device %s", cdx_dev->device.name);
		return -EINVAL;
	}

	addr = cdx_dev->mem_resource[1].addr;

	decode_device_id(cdx_dev, &func_id);
	write32_cdm(addr, CDM_GLOBAL_START, 0x0);
	write32_cdm(addr, CDM_SOFT_RSTN, 0x1);
	write32_cdm(addr, CDM_HOST_CTRL_REG_DST2, 0x0);
	/*Write MSI address as start address*/
	write32_cdm(addr, CDM_MSGST_HOST_START_ADDR_0_DST2, (msi_addr & 0xFFFFFFFF));
	write32_cdm(addr, CDM_MSGST_HOST_START_ADDR_1_DST2, (msi_addr >> 32));
	write32_cdm(addr, CDM_HOST_CTRL_REG_DST2, 0x1);
	/*Initialize CMD RAM*/
	/*Set length as 16 bit which is the width of data and update function ID*/
	write32_cdm(addr, MSGST_CTRL0, (func_id << MSG_ST_FUNC_ID_SHIFT) | MSI_DATA_LENGTH);
	write32_cdm(addr, MSGST_CTRL1, (CSI_DST << CSI_DST_SHIFT) | (1 << WC_LINE_CACHE_SIZE));
	addr_type = 0;//0-generated , 1-from command
	write32_cdm(addr, MSGST_CTRL2,
		    (1 << CLIENT_ID_SHIFT) | (1 << DATA_WIDTH_SHIFT) | (addr_type << TYPE_OF_ADDRESS_SHIFT));
	/* Write event ID as data so that same is written into the GIC translator register.
	 * Write pattern as zero so that event ID written in MSGST_CTRL7 will be written into GIC translator register.
	 */
	pattern_type = 0;
	write32_cdm(addr, MSGST_CTRL3, (pattern_type << PATTERN_SHIFT));
	/*Set event ID as MSI data*/
	write32_cdm(addr, MSGST_CTRL7, msi_data);
	write32_cdm(addr, CDM_MSGST_CTRL_REG, MSG_STORE_START);
	/*Start the msg store engine*/
	write32_cdm(addr, CDM_GLOBAL_START, 0x1);

	return 0;
}

static int
cdx_exerciser_probe(struct rte_cdx_driver *cdx_driver,
		   struct rte_cdx_device *cdx_dev)
{
	struct rte_rawdev *rawdev;
	int num_msi;

	CDX_EXERCISER_LOG(INFO, "Probing %s device", cdx_dev->device.name);

	/* Allocate device structure. */
	rawdev = rte_rawdev_pmd_allocate(cdx_dev->device.name, 0, rte_socket_id());
	if (rawdev == NULL) {
		CDX_EXERCISER_LOG(ERR, "Unable to allocate rawdev for device %s", cdx_dev->device.name);
		return -EINVAL;
	}

	rawdev->dev_ops = &cdx_exerciser_ops;
	rawdev->device = &cdx_dev->device;
	rawdev->driver_name = cdx_driver->driver.name;

	if (init_csi_exerciser(cdx_dev) < 0) {
		CDX_EXERCISER_LOG(ERR, "CSI exerciser initialization failed for device %s",
				  cdx_dev->device.name);
		if (rte_rawdev_pmd_release(rawdev))
			CDX_EXERCISER_LOG(ERR, "Failed to destroy cdx rawdev for device %s",
				          cdx_dev->device.name);
			return -EINVAL;
	}

	if (rte_intr_type_get(cdx_dev->intr_handle) == RTE_INTR_HANDLE_VFIO_MSIX) {
		/* Enable interrupts */
		num_msi = rte_intr_nb_intr_get(cdx_dev->intr_handle);
		rte_intr_efd_enable(cdx_dev->intr_handle, num_msi);
		rte_cdx_vfio_intr_enable(cdx_dev->intr_handle);
	}

	return 0;
}

static int
cdx_exerciser_remove(struct rte_cdx_device *cdx_dev)
{
	struct rte_rawdev *rawdev = NULL;
	int ret;

	CDX_EXERCISER_LOG(INFO,"Closing CDX test device %s", cdx_dev->device.name);

	rawdev = rte_rawdev_pmd_get_named_dev(cdx_dev->device.name);
	if (rawdev == NULL) {
		CDX_EXERCISER_LOG(ERR, "Invalid device name (%s)", cdx_dev->device.name);
		ret = -EINVAL;
		return ret;
	}

	/* Disable interrupts */
	if (rte_intr_type_get(cdx_dev->intr_handle) == RTE_INTR_HANDLE_VFIO_MSIX) {
		rte_cdx_vfio_intr_disable(cdx_dev->intr_handle);
		rte_intr_efd_disable(cdx_dev->intr_handle);
	}

	ret = rte_rawdev_pmd_release(rawdev);
	if (ret)
		CDX_EXERCISER_LOG(ERR, "Failed to destroy cdx rawdev for device %s",
			          cdx_dev->device.name);

	return 0;
}

static struct rte_cdx_driver cdx_exerciser_drv = {
		.id_table = cdx_exerciser_match_id_tbl,
		.probe = cdx_exerciser_probe,
		.remove = cdx_exerciser_remove,
		.drv_flags = RTE_CDX_DRV_NEED_MAPPING
};

RTE_PMD_REGISTER_CDX(cdx_exerciser_driver, cdx_exerciser_drv);
RTE_LOG_REGISTER_DEFAULT(cdx_exerciser_logtype, INFO);
