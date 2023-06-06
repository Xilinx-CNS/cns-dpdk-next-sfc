/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Advanced Micro Devices, Inc.
 */

#ifndef _RTE_PMD_CDX_EXERCISER_H_
#define _RTE_PMD_CDX_EXERCISER_H_

/** Test the Msg store interface.
 *
 * @param[in] dev_id
 *    Device ID
 *
 * @return
 *    0 - success
 *    !=0 failure
 */
__rte_experimental
int rte_raw_cdx_exerciser_test_msg_store(int dev_id);

/** Test the Msg load interface.
 *
 * @param[in] dev_id
 *    Device ID
 *
 * @return
 *    0 - success
 *    !=0 failure
 */
__rte_experimental
int rte_raw_cdx_exerciser_test_msg_load(int dev_id);

/** Get the number of MSI supproted by the device.
 *
 * @param[in] dev_id
 *    Device ID
 *
 * @return
 *    Number of MSI supported
 */
__rte_experimental
int rte_raw_cdx_exerciser_num_msi(int dev_id);

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
int rte_raw_cdx_exerciser_get_efd(int dev_id, int msi_id);

/** Trigger the MSI event.
 *
 * @param[in] dev_id
 *    Device ID
 * @param[in] msi_id (also equivalent to GIC eventID)
 *    MSI vector ID
 * @param[in] msi_addr (also equivalent to GIC translator address)
 *    MSI address
 * @param[in] msi_data
 *    MSI data
 *
 * @return
 *    0 - success
 *    !=0 failure
 */
__rte_experimental
int rte_raw_cdx_exerciser_trigger_msi(int dev_id, int msi_id,
		uint64_t msi_addr, uint32_t msi_data);

#endif /* _RTE_PMD_CDX_EXERCISER_H_ */
