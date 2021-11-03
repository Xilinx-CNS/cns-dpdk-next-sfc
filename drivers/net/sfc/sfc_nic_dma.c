/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2021 Xilinx, Inc.
 */

#include "sfc_nic_dma.h"

#ifdef RTE_PMD_NET_SFC_NIC_DMA_MAP

int
sfc_nic_dma_map(const struct sfc_nic_dma_info *ndmi, rte_iova_t trgt_addr,
		size_t len, rte_iova_t *nic_addr)
{
	unsigned int i;

	for (i = 0; i < ndmi->nb_regions; i++) {
		const struct sfc_nic_dma_region *region = &ndmi->regions[i];

		if (region->trgt_base <= trgt_addr &&
		    trgt_addr + len <= region->trgt_end) {
			*nic_addr = region->nic_base + (trgt_addr - region->trgt_base);
			return 0;
		}
	}

	return ENOENT;
}

int
sfc_nic_dma_add_region(struct sfc_nic_dma_info *ndmi, rte_iova_t nic_base,
		       rte_iova_t trgt_base, size_t map_len)
{
	struct sfc_nic_dma_region *region;

	if (ndmi->nb_regions == SFC_NIC_DMA_REGIONS_MAX)
		return ENOMEM;

	region = &ndmi->regions[ndmi->nb_regions];
	region->nic_base = nic_base;
	region->trgt_base = trgt_base;
	region->trgt_end = trgt_base + map_len;

	ndmi->nb_regions++;
	return 0;
}

#endif  /* RTE_PMD_NET_SFC_NIC_DMA_MAP */
