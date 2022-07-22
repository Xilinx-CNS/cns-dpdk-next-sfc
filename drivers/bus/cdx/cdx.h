/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022-2023, Advanced Micro Devices, Inc.
 */

#ifndef _CDX_H_
#define _CDX_H_

#include <stdbool.h>
#include <stdio.h>

#include "rte_bus_cdx.h"

extern struct rte_cdx_bus rte_cdx_bus;

/**
 * Map a particular resource from a file.
 *
 * @param requested_addr
 *      The starting address for the new mapping range.
 * @param fd
 *      The file descriptor.
 * @param offset
 *      The offset for the mapping range.
 * @param size
 *      The size for the mapping range.
 * @param additional_flags
 *      The additional rte_mem_map() flags for the mapping range.
 * @return
 *   - On success, the function returns a pointer to the mapped area.
 *   - On error, NULL is returned.
 */
void *cdx_map_resource(void *requested_addr, int fd, off_t offset,
		size_t size, int additional_flags);

/**
 * Unmap a particular resource.
 *
 * @param requested_addr
 *      The address for the unmapping range.
 * @param size
 *      The size for the unmapping range.
 */
void cdx_unmap_resource(void *requested_addr, size_t size);

/*
 * Helper function to map CDX resources right after hugepages in virtual memory
 */
void *cdx_find_max_end_va(void);

/* map/unmap VFIO resource */
int cdx_vfio_map_resource(struct rte_cdx_device *dev);
int cdx_vfio_unmap_resource(struct rte_cdx_device *dev);

#endif /* _CDX_H_ */
