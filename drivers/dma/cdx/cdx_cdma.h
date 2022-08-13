/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, Advanced Micro Devices, Inc.
 */

#ifndef _CDX_CDMA_H_
#define _CDX_CDMA_H_

/* CDMA device structure */
struct cdma_dev_t {
	/* CDX device associated with device */
	struct rte_cdx_device *cdx_dev;
	/* Virtual MMIO address */
	void *addr;
	/* Length of mapped memory */
	uint64_t len;
	/* Associated dma device */
	struct rte_dma_dev *dmadev;
};

#endif /* _CDX_CDMA_H_ */
