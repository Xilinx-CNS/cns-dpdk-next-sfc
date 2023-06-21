/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#ifndef _RTE_BUS_CDX_H_
#define _RTE_BUS_CDX_H_

/**
 * @file
 * CDX device & driver interface
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct rte_cdx_device;

/**
 * Map the CDX device resources in user space virtual memory address
 *
 * Note that driver should not call this function when flag
 * RTE_CDX_DRV_NEED_MAPPING is set, as EAL will do that for
 * you when it's on.
 *
 * @param dev
 *   A pointer to a rte_cdx_device structure describing the device
 *   to use
 *
 * @return
 *   0 on success, negative on error and positive if no driver
 *   is found for the device.
 */
int rte_cdx_map_device(struct rte_cdx_device *dev);

/**
 * Unmap this device
 *
 * @param dev
 *   A pointer to a rte_cdx_device structure describing the device
 *   to use
 */
void rte_cdx_unmap_device(struct rte_cdx_device *dev);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_BUS_CDX_H_ */
