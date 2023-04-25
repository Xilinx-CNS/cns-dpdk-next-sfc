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

#endif /* _RTE_PMD_CDX_EXERCISER_H_ */
