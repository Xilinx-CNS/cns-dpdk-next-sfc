/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

int
roc_npc_vtag_actions_get(struct roc_npc *roc_npc)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	return npc->vtag_actions;
}

int
roc_npc_vtag_actions_sub_return(struct roc_npc *roc_npc, uint32_t count)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	npc->vtag_actions -= count;
	return npc->vtag_actions;
}

int
roc_npc_mcam_free_counter(struct roc_npc *roc_npc, uint16_t ctr_id)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	return npc_mcam_free_counter(npc, ctr_id);
}

int
roc_npc_mcam_read_counter(struct roc_npc *roc_npc, uint32_t ctr_id,
			  uint64_t *count)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	return npc_mcam_read_counter(npc, ctr_id, count);
}

int
roc_npc_mcam_clear_counter(struct roc_npc *roc_npc, uint32_t ctr_id)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	return npc_mcam_clear_counter(npc, ctr_id);
}

int
roc_npc_mcam_free_entry(struct roc_npc *roc_npc, uint32_t entry)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	return npc_mcam_free_entry(npc, entry);
}

int
roc_npc_mcam_free_all_resources(struct roc_npc *roc_npc)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	return npc_flow_free_all_resources(npc);
}

int
roc_npc_mcam_alloc_entries(struct roc_npc *roc_npc, int ref_entry,
			   int *alloc_entry, int req_count, int priority,
			   int *resp_count)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	return npc_mcam_alloc_entries(npc, ref_entry, alloc_entry, req_count,
				      priority, resp_count);
}

int
roc_npc_mcam_alloc_entry(struct roc_npc *roc_npc, struct roc_npc_flow *mcam,
			 struct roc_npc_flow *ref_mcam, int prio,
			 int *resp_count)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	return npc_mcam_alloc_entry(npc, mcam, ref_mcam, prio, resp_count);
}

int
roc_npc_mcam_ena_dis_entry(struct roc_npc *roc_npc, struct roc_npc_flow *mcam,
			   bool enable)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	return npc_mcam_ena_dis_entry(npc, mcam, enable);
}

int
roc_npc_mcam_write_entry(struct roc_npc *roc_npc, struct roc_npc_flow *mcam)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	return npc_mcam_write_entry(npc, mcam);
}

int
roc_npc_get_low_priority_mcam(struct roc_npc *roc_npc)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	if (roc_model_is_cn10k())
		return (npc->mcam_entries - NPC_MCAME_RESVD_10XX - 1);
	else
		return (npc->mcam_entries - NPC_MCAME_RESVD_9XXX - 1);
}

static int
npc_mcam_tot_entries(void)
{
	/* FIXME: change to reading in AF from NPC_AF_CONST1/2
	 * MCAM_BANK_DEPTH(_EXT) * MCAM_BANKS
	 */
	if (roc_model_is_cn10k() || roc_model_is_cn98xx())
		return 16 * 1024; /* MCAM_BANKS = 4, BANK_DEPTH_EXT = 4096 */
	else
		return 4 * 1024; /* MCAM_BANKS = 4, BANK_DEPTH_EXT = 1024 */
}

const char *
roc_npc_profile_name_get(struct roc_npc *roc_npc)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	return (char *)npc->profile_name;
}

int
roc_npc_init(struct roc_npc *roc_npc)
{
	uint8_t *mem = NULL, *nix_mem = NULL, *npc_mem = NULL;
	struct nix *nix = roc_nix_to_nix_priv(roc_npc->roc_nix);
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);
	uint32_t bmap_sz;
	int rc = 0, idx;
	size_t sz;

	PLT_STATIC_ASSERT(sizeof(struct npc) <= ROC_NPC_MEM_SZ);

	memset(npc, 0, sizeof(*npc));
	npc->mbox = (&nix->dev)->mbox;
	roc_npc->channel = nix->rx_chan_base;
	roc_npc->pf_func = (&nix->dev)->pf_func;
	npc->channel = roc_npc->channel;
	npc->pf_func = roc_npc->pf_func;
	npc->flow_max_priority = roc_npc->flow_max_priority;
	npc->switch_header_type = roc_npc->switch_header_type;
	npc->flow_prealloc_size = roc_npc->flow_prealloc_size;

	if (npc->mbox == NULL)
		return NPC_ERR_PARAM;

	rc = npc_mcam_fetch_kex_cfg(npc);
	if (rc)
		goto done;

	roc_npc->kex_capability = npc_get_kex_capability(npc);
	roc_npc->rx_parse_nibble = npc->keyx_supp_nmask[NPC_MCAM_RX];

	npc->mark_actions = 0;

	npc->mcam_entries = npc_mcam_tot_entries() >> npc->keyw[NPC_MCAM_RX];

	/* Free, free_rev, live and live_rev entries */
	bmap_sz = plt_bitmap_get_memory_footprint(npc->mcam_entries);
	mem = plt_zmalloc(4 * bmap_sz * npc->flow_max_priority, 0);
	if (mem == NULL) {
		plt_err("Bmap alloc failed");
		rc = NPC_ERR_NO_MEM;
		return rc;
	}

	sz = npc->flow_max_priority * sizeof(struct npc_mcam_ents_info);
	npc->flow_entry_info = plt_zmalloc(sz, 0);
	if (npc->flow_entry_info == NULL) {
		plt_err("flow_entry_info alloc failed");
		rc = NPC_ERR_NO_MEM;
		goto done;
	}

	sz = npc->flow_max_priority * sizeof(struct plt_bitmap *);
	npc->free_entries = plt_zmalloc(sz, 0);
	if (npc->free_entries == NULL) {
		plt_err("free_entries alloc failed");
		rc = NPC_ERR_NO_MEM;
		goto done;
	}

	sz = npc->flow_max_priority * sizeof(struct plt_bitmap *);
	npc->free_entries_rev = plt_zmalloc(sz, 0);
	if (npc->free_entries_rev == NULL) {
		plt_err("free_entries_rev alloc failed");
		rc = NPC_ERR_NO_MEM;
		goto done;
	}

	sz = npc->flow_max_priority * sizeof(struct plt_bitmap *);
	npc->live_entries = plt_zmalloc(sz, 0);
	if (npc->live_entries == NULL) {
		plt_err("live_entries alloc failed");
		rc = NPC_ERR_NO_MEM;
		goto done;
	}

	sz = npc->flow_max_priority * sizeof(struct plt_bitmap *);
	npc->live_entries_rev = plt_zmalloc(sz, 0);
	if (npc->live_entries_rev == NULL) {
		plt_err("live_entries_rev alloc failed");
		rc = NPC_ERR_NO_MEM;
		goto done;
	}

	sz = npc->flow_max_priority * sizeof(struct npc_flow_list);
	npc->flow_list = plt_zmalloc(sz, 0);
	if (npc->flow_list == NULL) {
		plt_err("flow_list alloc failed");
		rc = NPC_ERR_NO_MEM;
		goto done;
	}

	npc_mem = mem;
	for (idx = 0; idx < npc->flow_max_priority; idx++) {
		TAILQ_INIT(&npc->flow_list[idx]);

		npc->free_entries[idx] =
			plt_bitmap_init(npc->mcam_entries, mem, bmap_sz);
		mem += bmap_sz;

		npc->free_entries_rev[idx] =
			plt_bitmap_init(npc->mcam_entries, mem, bmap_sz);
		mem += bmap_sz;

		npc->live_entries[idx] =
			plt_bitmap_init(npc->mcam_entries, mem, bmap_sz);
		mem += bmap_sz;

		npc->live_entries_rev[idx] =
			plt_bitmap_init(npc->mcam_entries, mem, bmap_sz);
		mem += bmap_sz;

		npc->flow_entry_info[idx].free_ent = 0;
		npc->flow_entry_info[idx].live_ent = 0;
		npc->flow_entry_info[idx].max_id = 0;
		npc->flow_entry_info[idx].min_id = ~(0);
	}

	npc->rss_grps = NPC_RSS_GRPS;

	bmap_sz = plt_bitmap_get_memory_footprint(npc->rss_grps);
	nix_mem = plt_zmalloc(bmap_sz, 0);
	if (nix_mem == NULL) {
		plt_err("Bmap alloc failed");
		rc = NPC_ERR_NO_MEM;
		goto done;
	}

	npc->rss_grp_entries = plt_bitmap_init(npc->rss_grps, nix_mem, bmap_sz);

	if (!npc->rss_grp_entries) {
		plt_err("bitmap init failed");
		rc = NPC_ERR_NO_MEM;
		goto done;
	}

	/* Group 0 will be used for RSS,
	 * 1 -7 will be used for npc_flow RSS action
	 */
	plt_bitmap_set(npc->rss_grp_entries, 0);

	return rc;

done:
	if (npc->flow_list)
		plt_free(npc->flow_list);
	if (npc->live_entries_rev)
		plt_free(npc->live_entries_rev);
	if (npc->live_entries)
		plt_free(npc->live_entries);
	if (npc->free_entries_rev)
		plt_free(npc->free_entries_rev);
	if (npc->free_entries)
		plt_free(npc->free_entries);
	if (npc->flow_entry_info)
		plt_free(npc->flow_entry_info);
	if (npc_mem)
		plt_free(npc_mem);
	return rc;
}

int
roc_npc_fini(struct roc_npc *roc_npc)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);
	int rc;

	rc = npc_flow_free_all_resources(npc);
	if (rc) {
		plt_err("Error when deleting NPC MCAM entries, counters");
		return rc;
	}

	if (npc->flow_list) {
		plt_free(npc->flow_list);
		npc->flow_list = NULL;
	}

	if (npc->live_entries_rev) {
		plt_free(npc->live_entries_rev);
		npc->live_entries_rev = NULL;
	}

	if (npc->live_entries) {
		plt_free(npc->live_entries);
		npc->live_entries = NULL;
	}

	if (npc->free_entries_rev) {
		plt_free(npc->free_entries_rev);
		npc->free_entries_rev = NULL;
	}

	if (npc->free_entries) {
		plt_free(npc->free_entries);
		npc->free_entries = NULL;
	}

	if (npc->flow_entry_info) {
		plt_free(npc->flow_entry_info);
		npc->flow_entry_info = NULL;
	}

	return 0;
}

static int
npc_parse_actions(struct npc *npc, const struct roc_npc_attr *attr,
		  const struct roc_npc_action actions[],
		  struct roc_npc_flow *flow)
{
	const struct roc_npc_action_mark *act_mark;
	const struct roc_npc_action_queue *act_q;
	const struct roc_npc_action_vf *vf_act;
	bool vlan_insert_action = false;
	int sel_act, req_act = 0;
	uint16_t pf_func, vf_id;
	int errcode = 0;
	int mark = 0;
	int rq = 0;

	/* Initialize actions */
	flow->ctr_id = NPC_COUNTER_NONE;
	pf_func = npc->pf_func;

	for (; actions->type != ROC_NPC_ACTION_TYPE_END; actions++) {
		switch (actions->type) {
		case ROC_NPC_ACTION_TYPE_VOID:
			break;
		case ROC_NPC_ACTION_TYPE_MARK:
			act_mark = (const struct roc_npc_action_mark *)
					   actions->conf;
			if (act_mark->id > (NPC_FLOW_FLAG_VAL - 2)) {
				plt_err("mark value must be < 0xfffe");
				goto err_exit;
			}
			mark = act_mark->id + 1;
			req_act |= ROC_NPC_ACTION_TYPE_MARK;
			npc->mark_actions += 1;
			break;

		case ROC_NPC_ACTION_TYPE_FLAG:
			mark = NPC_FLOW_FLAG_VAL;
			req_act |= ROC_NPC_ACTION_TYPE_FLAG;
			npc->mark_actions += 1;
			break;

		case ROC_NPC_ACTION_TYPE_COUNT:
			/* Indicates, need a counter */
			flow->ctr_id = 1;
			req_act |= ROC_NPC_ACTION_TYPE_COUNT;
			break;

		case ROC_NPC_ACTION_TYPE_DROP:
			req_act |= ROC_NPC_ACTION_TYPE_DROP;
			break;

		case ROC_NPC_ACTION_TYPE_PF:
			req_act |= ROC_NPC_ACTION_TYPE_PF;
			pf_func &= (0xfc00);
			break;

		case ROC_NPC_ACTION_TYPE_VF:
			vf_act =
				(const struct roc_npc_action_vf *)actions->conf;
			req_act |= ROC_NPC_ACTION_TYPE_VF;
			vf_id = vf_act->id & RVU_PFVF_FUNC_MASK;
			pf_func &= (0xfc00);
			pf_func = (pf_func | (vf_id + 1));
			break;

		case ROC_NPC_ACTION_TYPE_QUEUE:
			act_q = (const struct roc_npc_action_queue *)
					actions->conf;
			rq = act_q->index;
			req_act |= ROC_NPC_ACTION_TYPE_QUEUE;
			break;

		case ROC_NPC_ACTION_TYPE_RSS:
			req_act |= ROC_NPC_ACTION_TYPE_RSS;
			break;

		case ROC_NPC_ACTION_TYPE_SEC:
			/* Assumes user has already configured security
			 * session for this flow. Associated conf is
			 * opaque. When security is implemented,
			 * we need to verify that for specified security
			 * session:
			 *  action_type ==
			 *    NPC_SECURITY_ACTION_TYPE_INLINE_PROTOCOL &&
			 *  session_protocol ==
			 *    NPC_SECURITY_PROTOCOL_IPSEC
			 *
			 * RSS is not supported with inline ipsec. Get the
			 * rq from associated conf, or make
			 * ROC_NPC_ACTION_TYPE_QUEUE compulsory with this
			 * action.
			 * Currently, rq = 0 is assumed.
			 */
			req_act |= ROC_NPC_ACTION_TYPE_SEC;
			rq = 0;
			break;
		case ROC_NPC_ACTION_TYPE_VLAN_STRIP:
			req_act |= ROC_NPC_ACTION_TYPE_VLAN_STRIP;
			break;
		case ROC_NPC_ACTION_TYPE_VLAN_INSERT:
			req_act |= ROC_NPC_ACTION_TYPE_VLAN_INSERT;
			break;
		case ROC_NPC_ACTION_TYPE_VLAN_ETHTYPE_INSERT:
			req_act |= ROC_NPC_ACTION_TYPE_VLAN_ETHTYPE_INSERT;
			break;
		case ROC_NPC_ACTION_TYPE_VLAN_PCP_INSERT:
			req_act |= ROC_NPC_ACTION_TYPE_VLAN_PCP_INSERT;
			break;
		default:
			errcode = NPC_ERR_ACTION_NOTSUP;
			goto err_exit;
		}
	}

	if (req_act & (ROC_NPC_ACTION_TYPE_VLAN_INSERT |
		       ROC_NPC_ACTION_TYPE_VLAN_ETHTYPE_INSERT |
		       ROC_NPC_ACTION_TYPE_VLAN_PCP_INSERT))
		vlan_insert_action = true;

	if ((req_act & (ROC_NPC_ACTION_TYPE_VLAN_INSERT |
			ROC_NPC_ACTION_TYPE_VLAN_ETHTYPE_INSERT |
			ROC_NPC_ACTION_TYPE_VLAN_PCP_INSERT)) ==
	    ROC_NPC_ACTION_TYPE_VLAN_PCP_INSERT) {
		plt_err("PCP insert action can't be supported alone");
		errcode = NPC_ERR_ACTION_NOTSUP;
		goto err_exit;
	}

	/* Both STRIP and INSERT actions are not supported */
	if (vlan_insert_action && (req_act & ROC_NPC_ACTION_TYPE_VLAN_STRIP)) {
		errcode = NPC_ERR_ACTION_NOTSUP;
		goto err_exit;
	}

	/* Check if actions specified are compatible */
	if (attr->egress) {
		if (req_act & ROC_NPC_ACTION_TYPE_VLAN_STRIP) {
			plt_err("VLAN pop action is not supported on Egress");
			errcode = NPC_ERR_ACTION_NOTSUP;
			goto err_exit;
		}

		if (req_act & ROC_NPC_ACTION_TYPE_DROP) {
			flow->npc_action = NIX_TX_ACTIONOP_DROP;
		} else if ((req_act & ROC_NPC_ACTION_TYPE_COUNT) ||
			   vlan_insert_action) {
			flow->npc_action = NIX_TX_ACTIONOP_UCAST_DEFAULT;
		} else {
			plt_err("Unsupported action for egress");
			errcode = NPC_ERR_ACTION_NOTSUP;
			goto err_exit;
		}

		goto set_pf_func;
	} else {
		if (vlan_insert_action) {
			errcode = NPC_ERR_ACTION_NOTSUP;
			goto err_exit;
		}
	}

	/* We have already verified the attr, this is ingress.
	 * - Exactly one terminating action is supported
	 * - Exactly one of MARK or FLAG is supported
	 * - If terminating action is DROP, only count is valid.
	 */
	sel_act = req_act & NPC_ACTION_TERM;
	if ((sel_act & (sel_act - 1)) != 0) {
		errcode = NPC_ERR_ACTION_NOTSUP;
		goto err_exit;
	}

	if (req_act & ROC_NPC_ACTION_TYPE_DROP) {
		sel_act = req_act & ~ROC_NPC_ACTION_TYPE_COUNT;
		if ((sel_act & (sel_act - 1)) != 0) {
			errcode = NPC_ERR_ACTION_NOTSUP;
			goto err_exit;
		}
	}

	if ((req_act & (ROC_NPC_ACTION_TYPE_FLAG | ROC_NPC_ACTION_TYPE_MARK)) ==
	    (ROC_NPC_ACTION_TYPE_FLAG | ROC_NPC_ACTION_TYPE_MARK)) {
		errcode = NPC_ERR_ACTION_NOTSUP;
		goto err_exit;
	}

	if (req_act & ROC_NPC_ACTION_TYPE_VLAN_STRIP)
		npc->vtag_actions++;

	/* Only VLAN action is provided */
	if (req_act == ROC_NPC_ACTION_TYPE_VLAN_STRIP)
		flow->npc_action = NIX_RX_ACTIONOP_UCAST;

	/* Set NIX_RX_ACTIONOP */
	if (req_act & (ROC_NPC_ACTION_TYPE_PF | ROC_NPC_ACTION_TYPE_VF)) {
		flow->npc_action = NIX_RX_ACTIONOP_UCAST;
		if (req_act & ROC_NPC_ACTION_TYPE_QUEUE)
			flow->npc_action |= (uint64_t)rq << 20;
	} else if (req_act & ROC_NPC_ACTION_TYPE_DROP) {
		flow->npc_action = NIX_RX_ACTIONOP_DROP;
	} else if (req_act & ROC_NPC_ACTION_TYPE_QUEUE) {
		flow->npc_action = NIX_RX_ACTIONOP_UCAST;
		flow->npc_action |= (uint64_t)rq << 20;
	} else if (req_act & ROC_NPC_ACTION_TYPE_RSS) {
		flow->npc_action = NIX_RX_ACTIONOP_UCAST;
	} else if (req_act & ROC_NPC_ACTION_TYPE_SEC) {
		flow->npc_action = NIX_RX_ACTIONOP_UCAST_IPSEC;
		flow->npc_action |= (uint64_t)rq << 20;
	} else if (req_act &
		   (ROC_NPC_ACTION_TYPE_FLAG | ROC_NPC_ACTION_TYPE_MARK)) {
		flow->npc_action = NIX_RX_ACTIONOP_UCAST;
	} else if (req_act & ROC_NPC_ACTION_TYPE_COUNT) {
		/* Keep ROC_NPC_ACTION_TYPE_COUNT_ACT always at the end
		 * This is default action, when user specify only
		 * COUNT ACTION
		 */
		flow->npc_action = NIX_RX_ACTIONOP_UCAST;
	} else {
		/* Should never reach here */
		errcode = NPC_ERR_ACTION_NOTSUP;
		goto err_exit;
	}

	if (mark)
		flow->npc_action |= (uint64_t)mark << 40;

set_pf_func:
	/* Ideally AF must ensure that correct pf_func is set */
	flow->npc_action |= (uint64_t)pf_func << 4;

	return 0;

err_exit:
	return errcode;
}

typedef int (*npc_parse_stage_func_t)(struct npc_parse_state *pst);

static int
npc_parse_pattern(struct npc *npc, const struct roc_npc_item_info pattern[],
		  struct roc_npc_flow *flow, struct npc_parse_state *pst)
{
	npc_parse_stage_func_t parse_stage_funcs[] = {
		npc_parse_meta_items, npc_parse_cpt_hdr, npc_parse_higig2_hdr,
		npc_parse_la,	      npc_parse_lb,	 npc_parse_lc,
		npc_parse_ld,	      npc_parse_le,	 npc_parse_lf,
		npc_parse_lg,	      npc_parse_lh,
	};
	uint8_t layer = 0;
	int key_offset;
	int rc;

	if (pattern == NULL)
		return NPC_ERR_PARAM;

	memset(pst, 0, sizeof(*pst));
	pst->npc = npc;
	pst->flow = flow;

	/* Use integral byte offset */
	key_offset = pst->npc->keyx_len[flow->nix_intf];
	key_offset = (key_offset + 7) / 8;

	/* Location where LDATA would begin */
	pst->mcam_data = (uint8_t *)flow->mcam_data;
	pst->mcam_mask = (uint8_t *)flow->mcam_mask;

	while (pattern->type != ROC_NPC_ITEM_TYPE_END &&
	       layer < PLT_DIM(parse_stage_funcs)) {
		/* Skip place-holders */
		pattern = npc_parse_skip_void_and_any_items(pattern);

		pst->pattern = pattern;
		rc = parse_stage_funcs[layer](pst);
		if (rc != 0)
			return rc;

		layer++;

		/*
		 * Parse stage function sets pst->pattern to
		 * 1 past the last item it consumed.
		 */
		pattern = pst->pattern;

		if (pst->terminate)
			break;
	}

	/* Skip trailing place-holders */
	pattern = npc_parse_skip_void_and_any_items(pattern);

	/* Are there more items than what we can handle? */
	if (pattern->type != ROC_NPC_ITEM_TYPE_END)
		return NPC_ERR_PATTERN_NOTSUP;

	return 0;
}

static int
npc_parse_attr(struct npc *npc, const struct roc_npc_attr *attr,
	       struct roc_npc_flow *flow)
{
	if (attr == NULL)
		return NPC_ERR_PARAM;
	else if (attr->priority >= npc->flow_max_priority)
		return NPC_ERR_PARAM;
	else if ((!attr->egress && !attr->ingress) ||
		 (attr->egress && attr->ingress))
		return NPC_ERR_PARAM;

	if (attr->ingress)
		flow->nix_intf = ROC_NPC_INTF_RX;
	else
		flow->nix_intf = ROC_NPC_INTF_TX;

	flow->priority = attr->priority;
	return 0;
}

static int
npc_parse_rule(struct npc *npc, const struct roc_npc_attr *attr,
	       const struct roc_npc_item_info pattern[],
	       const struct roc_npc_action actions[], struct roc_npc_flow *flow,
	       struct npc_parse_state *pst)
{
	int err;

	/* Check attr */
	err = npc_parse_attr(npc, attr, flow);
	if (err)
		return err;

	/* Check pattern */
	err = npc_parse_pattern(npc, pattern, flow, pst);
	if (err)
		return err;

	/* Check action */
	err = npc_parse_actions(npc, attr, actions, flow);
	if (err)
		return err;
	return 0;
}

int
roc_npc_flow_parse(struct roc_npc *roc_npc, const struct roc_npc_attr *attr,
		   const struct roc_npc_item_info pattern[],
		   const struct roc_npc_action actions[],
		   struct roc_npc_flow *flow)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);
	struct npc_parse_state parse_state = {0};
	int rc;

	rc = npc_parse_rule(npc, attr, pattern, actions, flow, &parse_state);
	if (rc)
		return rc;

	parse_state.is_vf = !roc_nix_is_pf(roc_npc->roc_nix);

	return npc_program_mcam(npc, &parse_state, 0);
}

int
npc_rss_free_grp_get(struct npc *npc, uint32_t *pos)
{
	struct plt_bitmap *bmap = npc->rss_grp_entries;

	for (*pos = 0; *pos < ROC_NIX_RSS_GRPS; ++*pos) {
		if (!plt_bitmap_get(bmap, *pos))
			break;
	}
	return *pos < ROC_NIX_RSS_GRPS ? 0 : -1;
}

int
npc_rss_action_configure(struct roc_npc *roc_npc,
			 const struct roc_npc_action_rss *rss, uint8_t *alg_idx,
			 uint32_t *rss_grp, uint32_t mcam_id)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);
	struct roc_nix *roc_nix = roc_npc->roc_nix;
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	uint32_t flowkey_cfg, rss_grp_idx, i, rem;
	uint8_t key[ROC_NIX_RSS_KEY_LEN];
	const uint8_t *key_ptr;
	uint8_t flowkey_algx;
	uint16_t *reta;
	int rc;

	rc = npc_rss_free_grp_get(npc, &rss_grp_idx);
	/* RSS group :0 is not usable for flow rss action */
	if (rc < 0 || rss_grp_idx == 0)
		return -ENOSPC;

	for (i = 0; i < rss->queue_num; i++) {
		if (rss->queue[i] >= nix->nb_rx_queues) {
			plt_err("queue id > max number of queues");
			return -EINVAL;
		}
	}

	*rss_grp = rss_grp_idx;

	if (rss->key == NULL) {
		roc_nix_rss_key_default_fill(roc_nix, key);
		key_ptr = key;
	} else {
		key_ptr = rss->key;
	}

	roc_nix_rss_key_set(roc_nix, key_ptr);

	/* If queue count passed in the rss action is less than
	 * HW configured reta size, replicate rss action reta
	 * across HW reta table.
	 */
	reta = nix->reta[rss_grp_idx];

	if (rss->queue_num > nix->reta_sz) {
		plt_err("too many queues for RSS context");
		return -ENOTSUP;
	}

	for (i = 0; i < (nix->reta_sz / rss->queue_num); i++)
		memcpy(reta + i * rss->queue_num, rss->queue,
		       sizeof(uint16_t) * rss->queue_num);

	rem = nix->reta_sz % rss->queue_num;
	if (rem)
		memcpy(&reta[i * rss->queue_num], rss->queue,
		       rem * sizeof(uint16_t));

	rc = roc_nix_rss_reta_set(roc_nix, *rss_grp, reta);
	if (rc) {
		plt_err("Failed to init rss table rc = %d", rc);
		return rc;
	}

	flowkey_cfg = roc_npc->flowkey_cfg_state;

	rc = roc_nix_rss_flowkey_set(roc_nix, &flowkey_algx, flowkey_cfg,
				     *rss_grp, mcam_id);
	if (rc) {
		plt_err("Failed to set rss hash function rc = %d", rc);
		return rc;
	}

	*alg_idx = flowkey_algx;

	plt_bitmap_set(npc->rss_grp_entries, *rss_grp);

	return 0;
}

int
npc_rss_action_program(struct roc_npc *roc_npc,
		       const struct roc_npc_action actions[],
		       struct roc_npc_flow *flow)
{
	const struct roc_npc_action_rss *rss;
	uint32_t rss_grp;
	uint8_t alg_idx;
	int rc;

	for (; actions->type != ROC_NPC_ACTION_TYPE_END; actions++) {
		if (actions->type == ROC_NPC_ACTION_TYPE_RSS) {
			rss = (const struct roc_npc_action_rss *)actions->conf;
			rc = npc_rss_action_configure(roc_npc, rss, &alg_idx,
						      &rss_grp, flow->mcam_id);
			if (rc)
				return rc;

			flow->npc_action &= (~(0xfULL));
			flow->npc_action |= NIX_RX_ACTIONOP_RSS;
			flow->npc_action |=
				((uint64_t)(alg_idx & NPC_RSS_ACT_ALG_MASK)
				 << NPC_RSS_ACT_ALG_OFFSET) |
				((uint64_t)(rss_grp & NPC_RSS_ACT_GRP_MASK)
				 << NPC_RSS_ACT_GRP_OFFSET);
			break;
		}
	}
	return 0;
}

int
roc_npc_mark_actions_get(struct roc_npc *roc_npc)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	return npc->mark_actions;
}

int
roc_npc_mark_actions_sub_return(struct roc_npc *roc_npc, uint32_t count)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);

	npc->mark_actions -= count;
	return npc->mark_actions;
}

static int
npc_vtag_cfg_delete(struct roc_npc *roc_npc, struct roc_npc_flow *flow)
{
	struct roc_nix *roc_nix = roc_npc->roc_nix;
	struct nix_vtag_config *vtag_cfg;
	struct nix_vtag_config_rsp *rsp;
	struct mbox *mbox;
	struct nix *nix;
	int rc = 0;

	union {
		uint64_t reg;
		struct nix_tx_vtag_action_s act;
	} tx_vtag_action;

	nix = roc_nix_to_nix_priv(roc_nix);
	mbox = (&nix->dev)->mbox;

	tx_vtag_action.reg = flow->vtag_action;
	vtag_cfg = mbox_alloc_msg_nix_vtag_cfg(mbox);

	if (vtag_cfg == NULL)
		return -ENOSPC;

	vtag_cfg->cfg_type = VTAG_TX;
	vtag_cfg->vtag_size = NIX_VTAGSIZE_T4;
	vtag_cfg->tx.vtag0_idx = tx_vtag_action.act.vtag0_def;
	vtag_cfg->tx.free_vtag0 = true;

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc)
		return rc;

	return 0;
}

static int
npc_vtag_action_program(struct roc_npc *roc_npc,
			const struct roc_npc_action actions[],
			struct roc_npc_flow *flow)
{
	uint16_t vlan_id = 0, vlan_ethtype = ROC_ETHER_TYPE_VLAN;
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);
	struct roc_nix *roc_nix = roc_npc->roc_nix;
	struct nix_vtag_config *vtag_cfg;
	struct nix_vtag_config_rsp *rsp;
	uint64_t rx_vtag_action = 0;
	uint8_t vlan_pcp = 0;
	struct mbox *mbox;
	struct nix *nix;
	int rc;

	union {
		uint64_t reg;
		struct nix_tx_vtag_action_s act;
	} tx_vtag_action;

	nix = roc_nix_to_nix_priv(roc_nix);
	mbox = (&nix->dev)->mbox;

	flow->vtag_insert_enabled = false;

	for (; actions->type != ROC_NPC_ACTION_TYPE_END; actions++) {
		if (actions->type == ROC_NPC_ACTION_TYPE_VLAN_STRIP) {
			if (npc->vtag_actions == 1) {
				vtag_cfg = mbox_alloc_msg_nix_vtag_cfg(mbox);

				if (vtag_cfg == NULL)
					return -ENOSPC;

				vtag_cfg->cfg_type = VTAG_RX;
				vtag_cfg->rx.strip_vtag = 1;
				/* Always capture */
				vtag_cfg->rx.capture_vtag = 1;
				vtag_cfg->vtag_size = NIX_VTAGSIZE_T4;
				vtag_cfg->rx.vtag_type = 0;

				rc = mbox_process(mbox);
				if (rc)
					return rc;
			}

			rx_vtag_action |= (NIX_RX_VTAGACTION_VTAG_VALID << 15);
			rx_vtag_action |= ((uint64_t)NPC_LID_LB << 8);
			rx_vtag_action |= NIX_RX_VTAGACTION_VTAG0_RELPTR;
			flow->vtag_action = rx_vtag_action;
		} else if (actions->type == ROC_NPC_ACTION_TYPE_VLAN_INSERT) {
			const struct roc_npc_action_of_set_vlan_vid *vtag =
				(const struct roc_npc_action_of_set_vlan_vid *)
					actions->conf;
			vlan_id = plt_be_to_cpu_16(vtag->vlan_vid);
			if (vlan_id > 0xfff) {
				plt_err("Invalid vlan_id for set vlan action");
				return -EINVAL;
			}
			flow->vtag_insert_enabled = true;
		} else if (actions->type ==
			   ROC_NPC_ACTION_TYPE_VLAN_ETHTYPE_INSERT) {
			const struct roc_npc_action_of_push_vlan *ethtype =
				(const struct roc_npc_action_of_push_vlan *)
					actions->conf;
			vlan_ethtype = plt_be_to_cpu_16(ethtype->ethertype);
			if (vlan_ethtype != ROC_ETHER_TYPE_VLAN &&
			    vlan_ethtype != ROC_ETHER_TYPE_QINQ) {
				plt_err("Invalid ethtype specified for push"
					" vlan action");
				return -EINVAL;
			}
			flow->vtag_insert_enabled = true;
		} else if (actions->type ==
			   ROC_NPC_ACTION_TYPE_VLAN_PCP_INSERT) {
			const struct roc_npc_action_of_set_vlan_pcp *pcp =
				(const struct roc_npc_action_of_set_vlan_pcp *)
					actions->conf;
			vlan_pcp = pcp->vlan_pcp;
			if (vlan_pcp > 0x7) {
				plt_err("Invalid PCP value for pcp action");
				return -EINVAL;
			}
			flow->vtag_insert_enabled = true;
		}
	}

	if (flow->vtag_insert_enabled) {
		vtag_cfg = mbox_alloc_msg_nix_vtag_cfg(mbox);

		if (vtag_cfg == NULL)
			return -ENOSPC;

		vtag_cfg->cfg_type = VTAG_TX;
		vtag_cfg->vtag_size = NIX_VTAGSIZE_T4;
		vtag_cfg->tx.vtag0 =
			((vlan_ethtype << 16) | (vlan_pcp << 13) | vlan_id);

		vtag_cfg->tx.cfg_vtag0 = 1;
		rc = mbox_process_msg(mbox, (void *)&rsp);
		if (rc)
			return rc;

		if (rsp->vtag0_idx < 0) {
			plt_err("Failed to config TX VTAG action");
			return -EINVAL;
		}

		tx_vtag_action.reg = 0;
		tx_vtag_action.act.vtag0_def = rsp->vtag0_idx;
		tx_vtag_action.act.vtag0_lid = NPC_LID_LA;
		tx_vtag_action.act.vtag0_op = NIX_TX_VTAGOP_INSERT;
		tx_vtag_action.act.vtag0_relptr =
			NIX_TX_VTAGACTION_VTAG0_RELPTR;
		flow->vtag_action = tx_vtag_action.reg;
	}
	return 0;
}

struct roc_npc_flow *
roc_npc_flow_create(struct roc_npc *roc_npc, const struct roc_npc_attr *attr,
		    const struct roc_npc_item_info pattern[],
		    const struct roc_npc_action actions[], int *errcode)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);
	struct roc_npc_flow *flow, *flow_iter;
	struct npc_parse_state parse_state;
	struct npc_flow_list *list;
	int rc;

	npc->channel = roc_npc->channel;

	flow = plt_zmalloc(sizeof(*flow), 0);
	if (flow == NULL) {
		*errcode = NPC_ERR_NO_MEM;
		return NULL;
	}
	memset(flow, 0, sizeof(*flow));

	rc = npc_parse_rule(npc, attr, pattern, actions, flow, &parse_state);
	if (rc != 0) {
		*errcode = rc;
		goto err_exit;
	}

	rc = npc_vtag_action_program(roc_npc, actions, flow);
	if (rc != 0) {
		*errcode = rc;
		goto err_exit;
	}

	parse_state.is_vf = !roc_nix_is_pf(roc_npc->roc_nix);

	rc = npc_program_mcam(npc, &parse_state, 1);
	if (rc != 0) {
		*errcode = rc;
		goto err_exit;
	}

	rc = npc_rss_action_program(roc_npc, actions, flow);
	if (rc != 0) {
		*errcode = rc;
		goto set_rss_failed;
	}

	list = &npc->flow_list[flow->priority];
	/* List in ascending order of mcam entries */
	TAILQ_FOREACH(flow_iter, list, next) {
		if (flow_iter->mcam_id > flow->mcam_id) {
			TAILQ_INSERT_BEFORE(flow_iter, flow, next);
			return flow;
		}
	}

	TAILQ_INSERT_TAIL(list, flow, next);
	return flow;

set_rss_failed:
	rc = npc_mcam_free_entry(npc, flow->mcam_id);
	if (rc != 0) {
		*errcode = rc;
		plt_free(flow);
		return NULL;
	}
err_exit:
	plt_free(flow);
	return NULL;
}

int
npc_rss_group_free(struct npc *npc, struct roc_npc_flow *flow)
{
	uint32_t rss_grp;

	if ((flow->npc_action & 0xF) == NIX_RX_ACTIONOP_RSS) {
		rss_grp = (flow->npc_action >> NPC_RSS_ACT_GRP_OFFSET) &
			  NPC_RSS_ACT_GRP_MASK;
		if (rss_grp == 0 || rss_grp >= npc->rss_grps)
			return -EINVAL;

		plt_bitmap_clear(npc->rss_grp_entries, rss_grp);
	}

	return 0;
}

int
roc_npc_flow_destroy(struct roc_npc *roc_npc, struct roc_npc_flow *flow)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);
	struct plt_bitmap *bmap;
	int rc;

	rc = npc_rss_group_free(npc, flow);
	if (rc != 0) {
		plt_err("Failed to free rss action rc = %d", rc);
		return rc;
	}

	if (flow->vtag_insert_enabled) {
		rc = npc_vtag_cfg_delete(roc_npc, flow);
		if (rc != 0)
			return rc;
	}

	rc = npc_mcam_free_entry(npc, flow->mcam_id);
	if (rc != 0)
		return rc;

	TAILQ_REMOVE(&npc->flow_list[flow->priority], flow, next);

	bmap = npc->live_entries[flow->priority];
	plt_bitmap_clear(bmap, flow->mcam_id);

	plt_free(flow);
	return 0;
}

void
roc_npc_flow_dump(FILE *file, struct roc_npc *roc_npc)
{
	struct npc *npc = roc_npc_to_npc_priv(roc_npc);
	struct roc_npc_flow *flow_iter;
	struct npc_flow_list *list;
	uint32_t max_prio, i;

	max_prio = npc->flow_max_priority;

	for (i = 0; i < max_prio; i++) {
		list = &npc->flow_list[i];

		/* List in ascending order of mcam entries */
		TAILQ_FOREACH(flow_iter, list, next) {
			roc_npc_flow_mcam_dump(file, roc_npc, flow_iter);
		}
	}
}
