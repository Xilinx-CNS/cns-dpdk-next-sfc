/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022-2023, Advanced Micro Devices, Inc.
 */

#ifndef _CDX_LOGS_H_
#define _CDX_LOGS_H_

extern int cdx_logtype_bus;

#define CDX_BUS_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, cdx_logtype_bus, "fslmc: " fmt "\n", \
		##args)

/* Debug logs are with Function names */
#define CDX_BUS_DEBUG(fmt, args...) \
	rte_log(RTE_LOG_DEBUG, cdx_logtype_bus, "fslmc: %s(): " fmt "\n", \
		__func__, ##args)

#define CDX_BUS_INFO(fmt, args...) \
	CDX_BUS_LOG(INFO, fmt, ## args)
#define CDX_BUS_ERR(fmt, args...) \
	CDX_BUS_LOG(ERR, fmt, ## args)
#define CDX_BUS_WARN(fmt, args...) \
	CDX_BUS_LOG(WARNING, fmt, ## args)

/* DP Logs, toggled out at compile time if level lower than current level */
#define CDX_BUS_DP_LOG(level, fmt, args...) \
	RTE_LOG_DP(level, PMD, fmt, ## args)

#define CDX_BUS_DP_DEBUG(fmt, args...) \
	CDX_BUS_DP_LOG(DEBUG, fmt, ## args)
#define CDX_BUS_DP_INFO(fmt, args...) \
	CDX_BUS_DP_LOG(INFO, fmt, ## args)
#define CDX_BUS_DP_WARN(fmt, args...) \
	CDX_BUS_DP_LOG(WARNING, fmt, ## args)

#endif /* _CDX_LOGS_H_ */
