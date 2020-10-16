/* SPDX-License-Identifier: BSD-3-Clause
*
 * Copyright(c) 2020 Xilinx, Inc.
 *
 * This software was jointly developed between OKTET Labs (under contract
 * for Solarflare) and Solarflare Communications, Inc.
 */

#ifndef _SFC_ADAPTER_STATE_H
#define _SFC_ADAPTER_STATE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * +---------------+
 * | UNINITIALIZED |<-----------+
 * +---------------+		|
 *	|.eth_dev_init		|.eth_dev_uninit
 *	V			|
 * +---------------+------------+
 * |  INITIALIZED  |
 * +---------------+<-----------<---------------+
 *	|.dev_configure		|		|
 *	V			|failed		|
 * +---------------+------------+		|
 * |  CONFIGURING  |				|
 * +---------------+----+			|
 *	|success	|			|
 *	|		|		+---------------+
 *	|		|		|    CLOSING    |
 *	|		|		+---------------+
 *	|		|			^
 *	V		|.dev_configure		|
 * +---------------+----+			|.dev_close
 * |  CONFIGURED   |----------------------------+
 * +---------------+<-----------+
 *	|.dev_start		|
 *	V			|
 * +---------------+		|
 * |   STARTING    |------------^
 * +---------------+ failed	|
 *	|success		|
 *	|		+---------------+
 *	|		|   STOPPING    |
 *	|		+---------------+
 *	|			^
 *	V			|.dev_stop
 * +---------------+------------+
 * |    STARTED    |
 * +---------------+
 */
enum sfc_adapter_state {
	SFC_ADAPTER_UNINITIALIZED = 0,
	SFC_ADAPTER_INITIALIZED,
	SFC_ADAPTER_CONFIGURING,
	SFC_ADAPTER_CONFIGURED,
	SFC_ADAPTER_CLOSING,
	SFC_ADAPTER_STARTING,
	SFC_ADAPTER_STARTED,
	SFC_ADAPTER_STOPPING,

	SFC_ADAPTER_NSTATES
};

#ifdef __cplusplus
}
#endif

#endif  /* _SFC_ADAPTER_STATE_H */
