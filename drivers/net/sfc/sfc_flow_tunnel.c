/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2021 Xilinx, Inc.
 */

#include <stdbool.h>
#include <stdint.h>

#include <rte_flow.h>

#include "efx.h"

#include "sfc.h"
#include "sfc_dp.h"
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

int
sfc_flow_tunnel_mae_rule_attach(struct sfc_adapter *sa,
				efx_tunnel_protocol_t encap_type,
				efx_mae_match_spec_t *outer_spec,
				efx_mae_match_spec_t *action_spec,
				uint32_t ft_mark)
{
	struct sfc_flow_tunnel_mae_rule *ft_mae_rule;
	struct sfc_flow_tunnel *ft;
	const char *or_status;
	int rc;

	ft = sfc_flow_tunnel_pick(sa, ft_mark);
	if (ft == NULL) {
		sfc_err(sa, "tunnel offload: MAE: invalid tunnel");
		return EINVAL;
	}

	/*
	 * Do this here for correct comparison
	 * in efx_mae_match_specs_equal().
	 */
	rc = efx_mae_outer_rule_recirc_id_set(outer_spec, ft->id + 1);
	if (rc != 0) {
		sfc_err(sa, "tunnel offload: MAE: failed to initialise RECIRC_ID in the outer rule: %s",
			strerror(rc));
		return rc;
	}

	ft_mae_rule = &ft->mae_rule;

	if (ft_mae_rule->refcnt != 0) {
		if (encap_type != ft_mae_rule->encap_type ||
		    !efx_mae_match_specs_equal(outer_spec,
					       ft_mae_rule->outer_spec)) {
			sfc_err(sa, "tunnel offload: MAE: diverging outer rule spec");
			return EINVAL;
		}


		efx_mae_match_spec_fini(sa->nic, outer_spec);
		outer_spec = ft_mae_rule->outer_spec;

		or_status = "existing";
	} else {
		ft_mae_rule->outer_rule.id = EFX_MAE_RSRC_ID_INVALID;

		or_status = "newly added";
	}

	rc = efx_mae_match_spec_recirc_id_set(action_spec, ft->id + 1);
	if (rc != 0) {
		sfc_err(sa, "tunnel offload: MAE: failed to set match on RECIRC_ID in the action rule: %s",
			strerror(rc));
		return rc;
	}

	sfc_dbg(sa, "tunnel offload: MAE: attached to %s rule in tunnel=%u",
		or_status, ft->id);

	ft_mae_rule->encap_type = encap_type;
	ft_mae_rule->outer_spec = outer_spec;

	++(ft_mae_rule->refcnt);

	return 0;
}

void
sfc_flow_tunnel_mae_rule_cleanup(struct sfc_adapter *sa, uint32_t ft_mark)
{
	struct sfc_flow_tunnel_mae_rule *ft_mae_rule;
	struct sfc_flow_tunnel *ft;

	ft = sfc_flow_tunnel_pick(sa, ft_mark);
	if (ft == NULL)
		return;

	ft_mae_rule = &ft->mae_rule;

	SFC_ASSERT(ft_mae_rule->refcnt != 0);
	--(ft_mae_rule->refcnt);

	if (ft_mae_rule->refcnt == 0) {
		SFC_ASSERT(ft_mae_rule->outer_rule.id ==
			   EFX_MAE_RSRC_ID_INVALID);

		sfc_dbg(sa, "tunnel offload: MAE: cleaned outer rule data in tunnel=%u",
			ft->id);

		efx_mae_match_spec_fini(sa->nic, ft_mae_rule->outer_spec);
		ft_mae_rule->encap_type = EFX_TUNNEL_PROTOCOL_NONE;
		ft_mae_rule->outer_spec = NULL;
	}
}

int
sfc_flow_tunnel_mae_rule_enable(struct sfc_adapter *sa, uint32_t ft_mark)
{
	struct sfc_flow_tunnel_mae_rule *ft_mae_rule;
	struct sfc_flow_tunnel *ft;
	int rc;

	ft = sfc_flow_tunnel_pick(sa, ft_mark);
	if (ft == NULL)
		return 0;

	ft_mae_rule = &ft->mae_rule;

	if (ft_mae_rule->outer_rule.id == EFX_MAE_RSRC_ID_INVALID &&
	    ft_mae_rule->outer_spec != NULL && ft->vnrx_rule_is_set) {
		rc = efx_mae_outer_rule_insert(sa->nic, ft_mae_rule->outer_spec,
					       ft_mae_rule->encap_type,
					       &ft_mae_rule->outer_rule);
		if (rc != 0) {
			sfc_err(sa, "tunnel offload: MAE: failed to enable outer rule in tunnel=%u: %s",
				ft->id, strerror(rc));
			return rc;
		}

		sfc_dbg(sa, "tunnel offload: MAE: enabled outer rule in tunnel=%u: OR_ID=0x%08x",
			ft->id, ft_mae_rule->outer_rule.id);
	}

	return 0;
}

void
sfc_flow_tunnel_mae_rule_disable(struct sfc_adapter *sa, uint32_t ft_mark)
{
	struct sfc_flow_tunnel_mae_rule *ft_mae_rule;
	struct sfc_flow_tunnel *ft;
	int rc;

	ft = sfc_flow_tunnel_pick(sa, ft_mark);
	if (ft == NULL)
		return;

	ft_mae_rule = &ft->mae_rule;

	if (ft_mae_rule->outer_rule.id != EFX_MAE_RSRC_ID_INVALID &&
	    (ft_mae_rule->refcnt == 1 || !ft->vnrx_rule_is_set)) {
		rc = efx_mae_outer_rule_remove(sa->nic,
					       &ft_mae_rule->outer_rule);
		if (rc == 0) {
			sfc_dbg(sa, "tunnel offload: MAE: disabled outer rule in tunnel=%u with OR_ID=0x%08x",
				ft->id, ft_mae_rule->outer_rule.id);
		} else {
			sfc_err(sa, "tunnel offload: MAE: failed to disable outer rule in tunnel=%u with OR_ID=0x%08x: %s",
				ft->id, ft_mae_rule->outer_rule.id,
				strerror(rc));
		}
		ft_mae_rule->outer_rule.id = EFX_MAE_RSRC_ID_INVALID;
	}
}

static int
sfc_flow_tunnel_attach(struct sfc_adapter *sa,
		       struct rte_flow_tunnel *tunnel,
		       struct sfc_flow_tunnel **ftp)
{
	struct sfc_flow_tunnel_mae_rule *ft_mae_rule;
	struct sfc_flow_tunnel *ft;
	const char *ft_status;
	int ft_id_free = -1;
	sfc_ft_id_t ft_id;
	int rc;

	/*
	 * Register "ft_id" dynfield and its validity dynflag now, when the
	 * first tunnel entry is created, rather than do it unconditionally
	 * during ethdev initialisation. This helps to avoid extra overhead
	 * possibly inflicted to mbuf processing performance by having such
	 * registration in the case when users don't utilise tunnel offload.
	 */
	rc = sfc_dp_ft_id_register();
	if (rc != 0)
		return rc;

	if (tunnel->type != RTE_FLOW_ITEM_TYPE_VXLAN) {
		sfc_err(sa, "tunnel offload: unsupported tunnel (encapsulation) type");
		return ENOTSUP;
	}

	for (ft_id = 0; ft_id < SFC_FT_MAX_NTUNNELS; ++ft_id) {
		ft = &sa->flow_tunnels[ft_id];

		if (ft->refcnt == 0) {
			if (ft_id_free == -1)
				ft_id_free = ft_id;

			continue;
		}

		if (memcmp(tunnel, &ft->rte_tunnel, sizeof(*tunnel)) == 0) {
			ft_status = "existing";
			goto attach;
		}
	}

	if (ft_id_free == -1) {
		sfc_err(sa, "tunnel offload: no free slot for the new tunnel");
		return ENOBUFS;
	}

	ft_id = ft_id_free;
	ft = &sa->flow_tunnels[ft_id];

	ft_mae_rule = &ft->mae_rule;
	ft_mae_rule->outer_rule.id = EFX_MAE_RSRC_ID_INVALID;
	ft_mae_rule->encap_type = EFX_TUNNEL_PROTOCOL_NONE;
	ft_mae_rule->outer_spec = NULL;
	ft_mae_rule->refcnt = 0;

	memcpy(&ft->rte_tunnel, tunnel, sizeof(*tunnel));

	ft->action_mark.id = SFC_FT_ID_TO_MARK(ft_id_free);
	ft->action.type = RTE_FLOW_ACTION_TYPE_MARK;
	ft->action.conf = &ft->action_mark;

	ft->item.type = RTE_FLOW_ITEM_TYPE_MARK;
	ft->item_mark_v.id = ft->action_mark.id;
	ft->item.spec = &ft->item_mark_v;
	ft->item.mask = &ft->item_mark_m;
	ft->item_mark_m.id = UINT32_MAX;

	ft->vnrx_rule_is_set = B_FALSE;

	ft->refcnt = 0;

	ft_status = "newly added";

attach:
	sfc_dbg(sa, "tunnel offload: attaching to %s tunnel=%u",
		ft_status, ft_id);

	++(ft->refcnt);
	*ftp = ft;

	return 0;
}

static int
sfc_flow_tunnel_detach(struct sfc_adapter *sa,
		       uint32_t ft_mark)
{
	struct sfc_flow_tunnel *ft;

	ft = sfc_flow_tunnel_pick(sa, ft_mark);
	if (ft == NULL) {
		sfc_err(sa, "tunnel offload: invalid tunnel");
		return EINVAL;
	}

	if (ft->refcnt == 0) {
		sfc_err(sa, "tunnel offload: tunnel=%u doesn't exist", ft->id);
		return ENOENT;
	}

	--(ft->refcnt);

	return 0;
}

int
sfc_flow_tunnel_decap_set(struct rte_eth_dev *dev,
			  struct rte_flow_tunnel *tunnel,
			  struct rte_flow_action **pmd_actions,
			  uint32_t *num_of_actions,
			  struct rte_flow_error *err)
{
	struct sfc_adapter *sa = sfc_adapter_by_eth_dev(dev);
	struct sfc_flow_tunnel *ft;
	int rc;

	if (!sfc_flow_tunnel_is_supported(sa)) {
		rc = ENOTSUP;
		goto fail;
	}

	rc = sfc_flow_tunnel_attach(sa, tunnel, &ft);
	if (rc != 0)
		goto fail;

	*pmd_actions = &ft->action;
	*num_of_actions = 1;

	return 0;

fail:
	return rte_flow_error_set(err, rc,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				  "tunnel offload: decap_set failed");
}

int
sfc_flow_tunnel_match(struct rte_eth_dev *dev,
		      struct rte_flow_tunnel *tunnel,
		      struct rte_flow_item **pmd_items,
		      uint32_t *num_of_items,
		      struct rte_flow_error *err)
{
	struct sfc_adapter *sa = sfc_adapter_by_eth_dev(dev);
	struct sfc_flow_tunnel *ft;
	int rc;

	if (!sfc_flow_tunnel_is_supported(sa)) {
		rc = ENOTSUP;
		goto fail;
	}

	rc = sfc_flow_tunnel_attach(sa, tunnel, &ft);
	if (rc != 0)
		goto fail;

	*pmd_items = &ft->item;
	*num_of_items = 1;

	return 0;

fail:
	return rte_flow_error_set(err, rc,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				  "tunnel offload: match failed");
}

int
sfc_flow_tunnel_item_release(struct rte_eth_dev *dev,
			     struct rte_flow_item *pmd_items,
			     uint32_t num_items,
			     struct rte_flow_error *err)
{
	struct sfc_adapter *sa = sfc_adapter_by_eth_dev(dev);
	const struct rte_flow_item_mark *item_mark;
	struct rte_flow_item *item = pmd_items;
	int rc;

	if (!sfc_flow_tunnel_is_supported(sa)) {
		rc = ENOTSUP;
		goto fail;
	}

	if (num_items != 1 || item == NULL || item->spec == NULL ||
	    item->type != RTE_FLOW_ITEM_TYPE_MARK) {
		sfc_err(sa, "tunnel offload: item_release: wrong input");
		rc = EINVAL;
		goto fail;
	}

	item_mark = item->spec;

	rc = sfc_flow_tunnel_detach(sa, item_mark->id);
	if (rc != 0)
		goto fail;

	return 0;

fail:
	return rte_flow_error_set(err, rc,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				  "tunnel offload: item_release failed");
}

int
sfc_flow_tunnel_action_decap_release(struct rte_eth_dev *dev,
				     struct rte_flow_action *pmd_actions,
				     uint32_t num_actions,
				     struct rte_flow_error *err)
{
	struct sfc_adapter *sa = sfc_adapter_by_eth_dev(dev);
	const struct rte_flow_action_mark *action_mark;
	struct rte_flow_action *action = pmd_actions;
	int rc;

	if (!sfc_flow_tunnel_is_supported(sa)) {
		rc = ENOTSUP;
		goto fail;
	}

	if (num_actions != 1 || action == NULL || action->conf == NULL ||
	    action->type != RTE_FLOW_ACTION_TYPE_MARK) {
		sfc_err(sa, "tunnel offload: action_decap_release: wrong input");
		rc = EINVAL;
		goto fail;
	}

	action_mark = action->conf;

	rc = sfc_flow_tunnel_detach(sa, action_mark->id);
	if (rc != 0)
		goto fail;

	return 0;

fail:
	return rte_flow_error_set(err, rc,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				  "tunnel offload: item_release failed");
}

int
sfc_flow_tunnel_get_restore_info(struct rte_eth_dev *dev,
				 struct rte_mbuf *m,
				 struct rte_flow_restore_info *info,
				 struct rte_flow_error *err)
{
	struct sfc_adapter *sa = sfc_adapter_by_eth_dev(dev);
	const struct sfc_flow_tunnel *ft;
	sfc_ft_id_t ft_id;
	int rc;

	if ((m->ol_flags & sfc_dp_ft_id_valid) == 0) {
		sfc_dbg(sa, "tunnel offload: get_restore_info: no tunnel mark in the packet");
		rc = EINVAL;
		goto fail;
	}

	ft_id = *RTE_MBUF_DYNFIELD(m, sfc_dp_ft_id_offset, sfc_ft_id_t *);
	ft = &sa->flow_tunnels[ft_id];

	if (ft->refcnt == 0) {
		sfc_err(sa, "tunnel offload: get_restore_info: tunnel=%u doesn't exist",
			ft_id);
		rc = ENOENT;
		goto fail;
	}

	memcpy(&info->tunnel, &ft->rte_tunnel, sizeof(info->tunnel));

	/*
	 * The packet still has encapsulation header; VNRX rules never
	 * strip it. Therefore, set RTE_FLOW_RESTORE_INFO_ENCAPSULATED.
	 */
	info->flags = RTE_FLOW_RESTORE_INFO_ENCAPSULATED |
		      RTE_FLOW_RESTORE_INFO_GROUP_ID |
		      RTE_FLOW_RESTORE_INFO_TUNNEL;

	info->group_id = 0;

	sfc_dbg(sa, "tunnel offload: get_restore_info: success");

	return 0;

fail:
	return rte_flow_error_set(err, rc,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				  "tunnel offload: get_restore_info failed");
}
