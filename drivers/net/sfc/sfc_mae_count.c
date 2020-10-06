/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2020 Xilinx, Inc.
 */

#include <rte_common.h>

#include "efx.h"

#include "sfc_ev.h"
#include "sfc.h"
#include "sfc_rx.h"
#include "sfc_mae_count.h"

int
sfc_mae_count_rxq_attach(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;
	unsigned int n_elements;
	unsigned int cache_size;
	/* The mempool is internal and private area is not required */
	const uint16_t priv_size = 0;
	/*
	 * Elements count is 1 less than the number of descriptors to avoid
	 * head and tail element collisions.
	 */
	const uint16_t data_room_size = RTE_PKTMBUF_HEADROOM +
		SFC_MAE_COUNT_STREAM_PACKET_SIZE;
	int rc;

	sfc_log_init(sa, "entry");

	if (!sas->cnt_rxq_supported)
		return 0;

	/*
	 * At least one element in the ring is always unused to distinguish
	 * between empty and full ring cases.
	 */
	n_elements = SFC_CNT_RXQ_RX_DESC_COUNT - 1;

	/*
	 * The cache must have sufficient space to put received buckets
	 * before they're reused on refill.
	 */
	cache_size = rte_align32pow2(SFC_CNT_RXQ_REFILL_LEVEL +
				     SFC_MAE_COUNT_RX_BURST - 1);

	if (snprintf(name, sizeof(name), "cnt_rxq-pool-%u", sas->port_id) >=
	    (int)sizeof(name))
		return ENAMETOOLONG;

	/*
	 * It could be single-producer single-consumer ring mempool which
	 * requires minimal barriers. However, cache size and refill/burst
	 * policy are aligned, therefore it does not matter which
	 * mempool backend is chosen since backend is unused in fact.
	 */
	mp = rte_pktmbuf_pool_create(name, n_elements, cache_size,
				     priv_size, data_room_size, sa->socket_id);
	if (mp == NULL) {
		rc = rte_errno;
		goto fail_mp_create;
	}

	sa->cnt_rxq.rxq_index = sfc_cnt_rxq_sw_index(sas);
	sa->cnt_rxq.mp = mp;
	sa->cnt_rxq.state |= SFC_CNT_RXQ_ATTACHED;

	return 0;

fail_mp_create:
	sfc_log_init(sa, "failed %d", rc);

	return rc;
}

void
sfc_mae_count_rxq_detach(struct sfc_adapter *sa)
{
	sfc_log_init(sa, "entry");

	if ((sa->cnt_rxq.state & SFC_CNT_RXQ_ATTACHED) == 0)
		return;

	rte_mempool_free(sa->cnt_rxq.mp);
	sa->cnt_rxq.mp = NULL;
	sa->cnt_rxq.state &= ~SFC_CNT_RXQ_ATTACHED;
}

int
sfc_mae_count_rxq_init(struct sfc_adapter *sa)
{
	struct rte_eth_rxconf rxconf = {
		.rx_free_thresh = SFC_CNT_RXQ_REFILL_LEVEL,
		.rx_drop_en = 1,
	};
	uint16_t nb_rx_desc = SFC_CNT_RXQ_RX_DESC_COUNT;
	int rc;

	sfc_log_init(sa, "entry");

	if ((sa->cnt_rxq.state & SFC_CNT_RXQ_ATTACHED) == 0)
		return 0;

	nb_rx_desc = RTE_MIN(nb_rx_desc, sa->rxq_max_entries);
	nb_rx_desc = RTE_MAX(nb_rx_desc, sa->rxq_min_entries);

	rc = sfc_rx_qinit_info(sa, sa->cnt_rxq.rxq_index);
	if (rc != 0)
		goto fail_cnt_rxq_init_info;

	rc = sfc_rx_qinit(sa, sa->cnt_rxq.rxq_index, nb_rx_desc,
			  sa->socket_id, &rxconf, sa->cnt_rxq.mp);
	if (rc != 0)
		goto fail_cnt_rxq_init;

	sa->cnt_rxq.state |= SFC_CNT_RXQ_INITIALIZED;

	return 0;

fail_cnt_rxq_init:
fail_cnt_rxq_init_info:
	sfc_log_init(sa, "failed %d", rc);

	return rc;
}

void
sfc_mae_count_rxq_fini(struct sfc_adapter *sa)
{
	sfc_log_init(sa, "entry");

	if ((sa->cnt_rxq.state & SFC_CNT_RXQ_INITIALIZED) == 0)
		return;

	sfc_rx_qfini(sa, sa->cnt_rxq.rxq_index);
}
