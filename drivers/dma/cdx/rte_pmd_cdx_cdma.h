/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Xilinx Inc.
 */

#ifndef _RTE_PMD_CDX_CDMA_H_
#define _RTE_PMD_CDX_CDMA_H_

/** Get the number of MSI supproted by the device.
 *
 * @param[in] dev_id
 *    Device ID
 *
 * @return
 *    Number of MSI supported
 */
__rte_experimental
int rte_dma_cdx_cdma_num_msi(int dev_id);

/** Get the eventfd for the MSI vector ID.
 *
 * @param[in] dev_id
 *    Device ID
 * @param[in] msi_id
 *    MSI vector ID
 *
 * @return
 *    Number of interrupts supported
 */
__rte_experimental
int rte_dma_cdx_cdma_get_efd(int dev_id, int msi_id);

/** Trigger the MSI event.
 *
 * @param[in] dev_id
 *    Device ID
 * @param[in] msi_id (also equivalent to GIC eventID)
 *    MSI vector ID
 *
 * @return
 *    0 - success
 *    !=0 failure
 */
__rte_experimental
int rte_dma_cdx_cdma_trigger_fake_msi(int dev_id, int msi_id);

#endif /* _RTE_PMD_CDX_CDMA_H_ */
