/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2021 Xilinx, Inc.
 */

#include <stdbool.h>
#include <stdint.h>

#include "sfc.h"
#include "sfc_flow.h"
#include "sfc_flow_tunnel.h"
#include "sfc_mae.h"

bool
sfc_flow_tunnel_is_supported(struct sfc_adapter *sa)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(sa->nic);
	struct sfc_mae *mae = &sa->mae;

	return (encp->enc_filter_action_mark_max == UINT32_MAX &&
		mae->status == SFC_MAE_STATUS_SUPPORTED);
}

struct sfc_flow_tunnel *
sfc_flow_tunnel_pick(struct sfc_adapter *sa, uint32_t ft_mark)
{
	uint32_t tunnel_mark = SFC_FT_GET_TUNNEL_MARK(ft_mark);

	if (tunnel_mark != SFC_FT_TUNNEL_MARK_INVALID) {
		sfc_ft_id_t ft_id = SFC_FT_TUNNEL_MARK_TO_ID(tunnel_mark);
		struct sfc_flow_tunnel *ft = &sa->flow_tunnels[ft_id];

		ft->id = ft_id;

		return ft;
	}

	return NULL;
}

static int
sfc_flow_tunnel_vnrx_rule_refine_pattern(struct sfc_adapter *sa,
					 struct sfc_flow_tunnel *ft,
					 const struct rte_flow_item *pattern,
					 const struct rte_flow_item **new_ptrn)
{
	struct sfc_flow_tunnel_bounce *bounce = &ft->vnrx_rule_bounce_buf;
	struct rte_flow_item *item;
	unsigned int nb_items = 0;

	for (; pattern->type != RTE_FLOW_ITEM_TYPE_END; ++pattern) {
		if (pattern->type == RTE_FLOW_ITEM_TYPE_VOID)
			continue;

		if (nb_items == SFC_FT_VNRX_NB_ITEMS) {
			sfc_err(sa, "tunnel offload: too many pattern items in VNRX rule");
			return EINVAL;
		}

		item = &bounce->flow_pattern[nb_items];
		memset(item, 0, sizeof(*item));
		item->type = pattern->type;

		if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
			memcpy(&bounce->flow_item_eth_spec, pattern->spec,
			       sizeof(bounce->flow_item_eth_spec));
			memcpy(&bounce->flow_item_eth_mask, pattern->mask,
			       sizeof(bounce->flow_item_eth_mask));

			/*
			 * In this particular implementation, VNRX rule is
			 * expected to match on MAC addresses, EtherType,
			 * L3 DST, L4 protocol (UDP) and UDP DST (VXLAN).
			 *
			 * The resulting filter will be unsupported by the
			 * HW unless match on the MAC addresses is skipped.
			 */
			memset(&bounce->flow_item_eth_mask.dst, 0,
			       sizeof(bounce->flow_item_eth_mask.dst));
			memset(&bounce->flow_item_eth_mask.src, 0,
			       sizeof(bounce->flow_item_eth_mask.src));

			/* Filter backend doesn't support this field. */
			bounce->flow_item_eth_mask.has_vlan = 0;

			item->spec = &bounce->flow_item_eth_spec;
			item->mask = &bounce->flow_item_eth_mask;
		} else {
			item->spec = pattern->spec;
			item->mask = pattern->mask;
		}

		++nb_items;
	}

	item = &bounce->flow_pattern[nb_items];
	memset(item, 0, sizeof(*item));
	item->type = RTE_FLOW_ITEM_TYPE_END;

	*new_ptrn = bounce->flow_pattern;

	return 0;
}

int
sfc_flow_tunnel_detect_vnrx_rule(struct sfc_adapter *sa,
				 const struct rte_flow_attr *attr,
				 const struct rte_flow_item *ptrn,
				 const struct rte_flow_action *actions,
				 struct rte_flow_attr *refined_attr,
				 const struct rte_flow_item **refined_ptrn,
				 struct rte_flow *flow,
				 struct rte_flow_error *error)
{
	const struct rte_flow_action_mark *action_mark;
	const struct rte_flow_action_jump *action_jump;
	struct sfc_flow_spec *spec = &flow->spec;
	unsigned int nb_actions_mark = 0;
	struct sfc_flow_tunnel *ft;
	uint32_t ft_mark = 0;
	bool jump = B_FALSE;
	int rc = 0;

	/*
	 * In a VNRX rule, one may have an action MARK containing
	 * a tunnel ID (high bits), which is opaque to the caller,
	 * and, optionally, another action MARK with a user value.
	 *
	 * The two mark values will be combined into a single one.
	 * On receive, the user value will be extracted correctly.
	 */
	const uint32_t exp_mark_masks[] = {
		SFC_FT_TUNNEL_MARK_MASK,
		SFC_FT_USER_MARK_MASK,
	};

	if (attr == NULL) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ATTR, NULL,
				   "NULL attribute");
		return -rte_errno;
	}

	if (ptrn == NULL) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ITEM_NUM, NULL,
				   "NULL pattern");
		return -rte_errno;
	}

	*refined_attr = *attr;
	*refined_ptrn = ptrn;

	if (!sfc_flow_tunnel_is_supported(sa) || attr->transfer == 0) {
		/*
		 * Tunnel-related actions (if present) will be turned
		 * down later, that is, on normal action parsing path.
		 */
		return 0;
	}

	if (actions == NULL) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ACTION_NUM, NULL,
				   "NULL actions");
		return -rte_errno;
	}

	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; ++actions) {
		if (actions->conf == NULL)
			continue;

		switch (actions->type) {
		case RTE_FLOW_ACTION_TYPE_MARK:
			action_mark = actions->conf;

			if (nb_actions_mark == RTE_DIM(exp_mark_masks) ||
			    (action_mark->id &
			     ~exp_mark_masks[nb_actions_mark]) != 0) {
				rc = EINVAL;
			} else {
				ft_mark |= action_mark->id;
				++nb_actions_mark;
			}
			break;

		case RTE_FLOW_ACTION_TYPE_JUMP:
			action_jump = actions->conf;
			if (jump || action_jump->group != 0)
				rc = EINVAL;
			else
				jump = B_TRUE;
			break;

		default:
			rc = ENOTSUP;
			break;
		}
	}

	ft = sfc_flow_tunnel_pick(sa, ft_mark);
	if (ft != NULL && jump) {
		sfc_dbg(sa, "tunnel offload: VNRX rule is detected: doing pre-parsing");

		if (rc != 0) {
			/* The loop above might have detected wrong actions. */
			sfc_err(sa, "tunnel offload: VNRX rule is inconsistent: %s",
				strerror(rc));
			goto fail;
		}

		if (ft->refcnt == 0) {
			sfc_err(sa, "tunnel offload: tunnel=%u doesn't exist",
				ft->id);
			rc = ENOENT;
			goto fail;
		}

		if (ft->vnrx_rule_is_set) {
			sfc_err(sa, "tunnel offload: VNRX rule in tunnel=%u already exists",
				ft->id);
			rc = EEXIST;
			goto fail;
		}

		rc = sfc_flow_tunnel_vnrx_rule_refine_pattern(sa, ft, ptrn,
							      refined_ptrn);
		if (rc != 0)
			goto fail;

		refined_attr->transfer = 0;

		spec->ft_mark = ft_mark;
	} else {
		/*
		 * Tunnel-related actions (if present) will be turned
		 * down later, that is, on normal action parsing path.
		 */
		sfc_dbg(sa, "tunnel offload: non-VNRX rule: pre-parsing is skipped");
	}

	return 0;

fail:
	return rte_flow_error_set(error, rc,
				  RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				  "tunnel offload: VNRX rule detection failed");
}
