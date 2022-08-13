/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, Advanced Micro Devices, Inc.
 */

#ifndef _CDX_CDMA_H_
#define _CDX_CDMA_H_

#define CDMA_MAX_VHANS		1
#define CDMA_NUM_DESC		1

/*CDMA registers*/
#define CDMA_CR		0x00
#define CDMA_SR		0x04
#define CDMA_SA		0x18
#define CDMA_SA_MSB	0x1c
#define CDMA_DA		0x20
#define CDMA_DA_MSB	0x24
#define CDMA_BTT	0x28

/* Maximum supported DMA */
#define MAX_DMA_LEN	67108863

#define cdma_write32(a, v) (*(volatile uint32_t *)(a) = (v))
#define cdma_read32(a) (*(volatile uint32_t *)(a))

#define lower_32_bits(x) ((uint32_t)(uint64_t)(x))
#define upper_32_bits(x) ((uint32_t)((uint64_t)(x) >> 32))

#define GITS_TRANSLATOR_ADDR		0xe2050000
#define GITS_TRANSLATOR_OFFSET		0x40
#define GITS_TRANSLATOR_MAP_SIZE	0x1000

/** General Macro to define a particular bit position*/
#define BIT_POS(x)			((uint64_t)1 << ((x)))
/** Set a bit in the variable */
#define SET_BIT_AT_POS(var, pos)	((var) |= (pos))
/** Reset the bit in the variable */
#define RESET_BIT_AT_POS(var, pos)	((var) &= ~(pos))
/** Check the bit is set in the variable */
#define IS_BIT_SET_AT_POS(var, pos)	(((var) & (pos)) ? 1 : 0)

/* Bits for CDMA_CR */
#define CDMA_RESET			BIT_POS(2)

/* Bits for CDMA_SR */
#define CDMA_IDLE			BIT_POS(1)
#define CDMA_DMA_INT_ERR		BIT_POS(4)
#define CDMA_DMA_SLV_ERR		BIT_POS(5)
#define CDMA_DMA_DEC_ERR		BIT_POS(6)

/* Represents the pending job */
struct cdma_pending_job_t {
	/* Source address */
	rte_iova_t src;
	/* Destination address */
	rte_iova_t dst;
	/* Length for DMA */
	uint32_t length;
	/* Set when job is valid */
	int job_valid;
};

/** Represents a CDMA virtual queue */
struct cdma_virt_queue_t {
	/* Virtual queue ID */
	uint16_t vq_id;
	/* Pending job */
	struct cdma_pending_job_t pending_job;
	/* Statistics associated with the queue */
	struct rte_dma_stats stats;
};

/* CDMA device structure */
struct cdma_dev_t {
	/* CDX device associated with device */
	struct rte_cdx_device *cdx_dev;
	/** VQ's of this device */
	struct cdma_virt_queue_t *vqs;
	/* Virtual MMIO address */
	void *addr;
	/* Length of mapped memory */
	uint64_t len;
	/* Number of MSI's supported on this device */
	uint8_t num_msi;
	/* Associated dma device */
	struct rte_dma_dev *dmadev;
};

#endif /* _CDX_CDMA_H_ */
