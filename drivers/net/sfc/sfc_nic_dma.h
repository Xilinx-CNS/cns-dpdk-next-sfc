/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2021 Xilinx, Inc.
 */

#ifndef _SFC_NIC_DMA_H
#define _SFC_NIC_DMA_H

#include "rte_common.h"

#ifdef RTE_PMD_NET_SFC_NIC_DMA_MAP

#define SFC_NIC_DMA_REGIONS_MAX 2

struct sfc_nic_dma_region {
	rte_iova_t			nic_base;
	rte_iova_t			trgt_base;
	rte_iova_t			trgt_end;
};

/* Driver cache for NIC DMA regions. */
struct sfc_nic_dma_info {
	struct sfc_nic_dma_region		regions[SFC_NIC_DMA_REGIONS_MAX];
	unsigned int				nb_regions;
};

int sfc_nic_dma_map(const struct sfc_nic_dma_info *ndmi, rte_iova_t trgt_addr,
		    size_t len, rte_iova_t *nic_addr);

int sfc_nic_dma_add_region(struct sfc_nic_dma_info *ndmi, rte_iova_t nic_base,
			   rte_iova_t trgt_base, size_t map_len);

#endif  /* RTE_PMD_NET_SFC_NIC_DMA_MAP */

#endif  /* _SFC_NIC_DMA_H */
