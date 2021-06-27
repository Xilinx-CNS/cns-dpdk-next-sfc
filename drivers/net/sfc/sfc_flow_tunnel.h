/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2021 Xilinx, Inc.
 */

#ifndef _SFC_FLOW_TUNNEL_H
#define _SFC_FLOW_TUNNEL_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "efx.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Flow Tunnel (FT) SW entry ID */
typedef uint8_t sfc_ft_id_t;

#define SFC_FT_TUNNEL_MARK_BITS	(sizeof(sfc_ft_id_t) * CHAR_BIT)
#define SFC_FT_USER_MARK_BITS	(sizeof(uint32_t) * CHAR_BIT - \
				 SFC_FT_TUNNEL_MARK_BITS)
#define SFC_FT_USER_MARK_MASK	RTE_LEN2MASK(SFC_FT_USER_MARK_BITS, uint32_t)
#define SFC_FT_TUNNEL_MARK_MASK	(UINT32_MAX & ~SFC_FT_USER_MARK_MASK)

#define SFC_FT_GET_TUNNEL_MARK(_mark) \
	((_mark) >> SFC_FT_USER_MARK_BITS)

#define SFC_FT_TUNNEL_MARK_INVALID	(0)

#define SFC_FT_TUNNEL_MARK_TO_ID(_tunnel_mark) \
	((_tunnel_mark) - 1)

#define SFC_FT_GET_USER_MARK(_mark) \
	((_mark) & SFC_FT_USER_MARK_MASK)

#define SFC_FT_MAX_NTUNNELS	((1U << SFC_FT_TUNNEL_MARK_BITS) - 1)

/** Expected (maximum) number of pattern items in a VNRX rule */
#define SFC_FT_VNRX_NB_ITEMS	(1 /* ETH */ + 1 /* IPV4 or IPV6 */ + \
				 1 /* UDP */)

/** Bounce buffer needed to refine item ETH in a VNRX rule pattern */
struct sfc_flow_tunnel_bounce {
	struct rte_flow_item		flow_pattern[SFC_FT_VNRX_NB_ITEMS + 1];
	struct rte_flow_item_eth	flow_item_eth_spec;
	struct rte_flow_item_eth	flow_item_eth_mask;
};

struct sfc_flow_tunnel_mae_rule {
	efx_mae_match_spec_t		*outer_spec;
	efx_tunnel_protocol_t		encap_type;
	efx_mae_rule_id_t		outer_rule;
	unsigned int			refcnt;
};

struct sfc_flow_tunnel {
	struct sfc_flow_tunnel_bounce	vnrx_rule_bounce_buf;

	bool				vnrx_rule_is_set;
	struct sfc_flow_tunnel_mae_rule	mae_rule;
	unsigned int			refcnt;
	sfc_ft_id_t			id;
};

struct sfc_adapter;

struct sfc_flow_tunnel *sfc_flow_tunnel_pick(struct sfc_adapter *sa,
					     uint32_t ft_mark);

bool sfc_flow_tunnel_is_supported(struct sfc_adapter *sa);

int sfc_flow_tunnel_detect_vnrx_rule(struct sfc_adapter *sa,
				     const struct rte_flow_attr *attr,
				     const struct rte_flow_item *ptrn,
				     const struct rte_flow_action *actions,
				     struct rte_flow_attr *refined_attr,
				     const struct rte_flow_item **refined_ptrn,
				     struct rte_flow *flow,
				     struct rte_flow_error *error);

int sfc_flow_tunnel_mae_rule_attach(struct sfc_adapter *sa,
				    efx_tunnel_protocol_t encap_type,
				    efx_mae_match_spec_t *outer_spec,
				    efx_mae_match_spec_t *action_spec,
				    uint32_t ft_mark);

void sfc_flow_tunnel_mae_rule_cleanup(struct sfc_adapter *sa, uint32_t ft_mark);

int sfc_flow_tunnel_mae_rule_enable(struct sfc_adapter *sa, uint32_t ft_mark);

void sfc_flow_tunnel_mae_rule_disable(struct sfc_adapter *sa, uint32_t ft_mark);

#ifdef __cplusplus
}
#endif
#endif /* _SFC_FLOW_TUNNEL_H */
