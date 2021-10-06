/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2020-2021 Xilinx, Inc.
 */

#ifndef _SFC_VDPA_LOG_H_
#define _SFC_VDPA_LOG_H_

/** Generic driver log type */
extern uint32_t sfc_vdpa_logtype_driver;

/** Common log type name prefix */
#define SFC_VDPA_LOGTYPE_PREFIX	"pmd.vdpa.sfc."

/** Log PMD generic message, add a prefix and a line break */
#define SFC_VDPA_GENERIC_LOG(level, ...) \
	rte_log(RTE_LOG_ ## level, sfc_vdpa_logtype_driver,		\
		RTE_FMT("PMD: " RTE_FMT_HEAD(__VA_ARGS__ ,) "\n",	\
			RTE_FMT_TAIL(__VA_ARGS__ ,)))

/** Name prefix for the per-device log type used to report basic information */
#define SFC_VDPA_LOGTYPE_MAIN_STR	SFC_VDPA_LOGTYPE_PREFIX "main"

/** Device MCDI log type name prefix */
#define SFC_VDPA_LOGTYPE_MCDI_STR	SFC_VDPA_LOGTYPE_PREFIX "mcdi"

#define SFC_VDPA_LOG_PREFIX_MAX	32

/* Log PMD message, automatically add prefix and \n */
#define SFC_VDPA_LOG(sva, level, type, ...) \
	rte_log(level, type,					\
		RTE_FMT("%s" RTE_FMT_HEAD(__VA_ARGS__ ,) "\n",	\
			sva->log_prefix,			\
			RTE_FMT_TAIL(__VA_ARGS__ ,)))

#define sfc_vdpa_err(sva, ...) \
	do {							\
		const struct sfc_vdpa_adapter *_sva = (sva);	\
								\
		SFC_VDPA_LOG(_sva, RTE_LOG_ERR,			\
			_sva->logtype_main, __VA_ARGS__);	\
	} while (0)

#define sfc_vdpa_warn(sva, ...) \
	do {							\
		const struct sfc_vdpa_adapter *_sva = (sva);	\
								\
		SFC_VDPA_LOG(_sva, RTE_LOG_WARNING,		\
			_sva->logtype_main, __VA_ARGS__);	\
	} while (0)

#define sfc_vdpa_notice(sva, ...) \
	do {							\
		const struct sfc_vdpa_adapter *_sva = (sva);	\
								\
		SFC_VDPA_LOG(_sva, RTE_LOG_NOTICE,		\
			_sva->logtype_main, __VA_ARGS__);	\
	} while (0)

#define sfc_vdpa_info(sva, ...) \
	do {							\
		const struct sfc_vdpa_adapter *_sva = (sva);	\
								\
		SFC_VDPA_LOG(_sva, RTE_LOG_INFO,		\
			_sva->logtype_main, __VA_ARGS__);	\
	} while (0)

#define sfc_vdpa_log_init(sva, ...) \
	do {							\
		const struct sfc_vdpa_adapter *_sva = (sva);	\
								\
		SFC_VDPA_LOG(_sva, RTE_LOG_INFO,		\
			_sva->logtype_main,			\
			RTE_FMT("%s(): "			\
				RTE_FMT_HEAD(__VA_ARGS__ ,),	\
				__func__,			\
				RTE_FMT_TAIL(__VA_ARGS__ ,)));	\
	} while (0)

#endif /* _SFC_VDPA_LOG_H_ */
