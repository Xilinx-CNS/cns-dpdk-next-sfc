/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, Advanced Micro Devices, Inc.
 */

#ifndef __CDX_CDMA_LOGS_H__
#define __CDX_CDMA_LOGS_H__

#ifdef __cplusplus
extern "C" {
#endif

extern int cdma_logtype;

#define CDMA_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, cdma_logtype, "cdma: " \
		fmt "\n", ## args)

#define CDMA_DEBUG(fmt, args...) \
	rte_log(RTE_LOG_DEBUG, cdma_logtype, "cdma: %s(): " \
		fmt "\n", __func__, ## args)

#define CDMA_FUNC_TRACE() CDMA_DEBUG(">>")

#define CDMA_INFO(fmt, args...) \
	CDMA_LOG(INFO, fmt, ## args)
#define CDMA_ERR(fmt, args...) \
	CDMA_LOG(ERR, fmt, ## args)
#define CDMA_WARN(fmt, args...) \
	CDMA_LOG(WARNING, fmt, ## args)

/* DP Logs, toggled out at compile time if level lower than current level */
#define CDMA_DP_LOG(level, fmt, args...) \
	RTE_LOG_DP(level, PMD, "cdma: " fmt "\n", ## args)

#define CDMA_DP_DEBUG(fmt, args...) \
	CDMA_DP_LOG(DEBUG, fmt, ## args)
#define CDMA_DP_INFO(fmt, args...) \
	CDMA_DP_LOG(INFO, fmt, ## args)
#define CDMA_DP_WARN(fmt, args...) \
	CDMA_DP_LOG(WARNING, fmt, ## args)

#ifdef __cplusplus
}
#endif

#endif /* __CDX_CDMA_LOGS_H__ */
