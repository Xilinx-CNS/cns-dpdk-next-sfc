/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2019-2020 Xilinx, Inc.
 * Copyright(c) 2019 Solarflare Communications Inc.
 *
 * This software was jointly developed between OKTET Labs (under contract
 * for Solarflare) and Solarflare Communications, Inc.
 */

#include <stdbool.h>

#include <rte_common.h>
#include <rte_vxlan.h>

#include "efx.h"

#include "sfc.h"
#include "sfc_mae_count.h"
#include "sfc_log.h"
#include "sfc_switch.h"

static int
sfc_mae_assign_entity_mport(struct sfc_adapter *sa,
			    efx_mport_sel_t *mportp)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(sa->nic);

	return efx_mae_mport_by_pcie_function(encp->enc_pf, encp->enc_vf,
					      mportp);
}

static int
sfc_mae_counter_registry_init(struct sfc_adapter *sa,
			      struct sfc_mae_counter_registry *registry)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);

	registry->pending_counter = EFX_MAE_COUNTER_ID_INVALID;

	return sfc_mae_counters_init(&registry->counters, sa->socket_id,
				     sas->port_id);
}

static void
sfc_mae_counter_registry_fini(struct sfc_adapter *sa,
			      struct sfc_mae_counter_registry *registry)
{
	if (registry->pending_counter != EFX_MAE_COUNTER_ID_INVALID) {
		(void)efx_mae_counters_free(sa->nic, 1,
					    &registry->pending_counter);
	}

	sfc_mae_counters_fini(&registry->counters);
}

int
sfc_mae_attach(struct sfc_adapter *sa)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	struct sfc_mae_switch_port_request switch_port_request = {0};
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(sa->nic);
	efx_mport_sel_t entity_mport;
	struct sfc_mae *mae = &sa->mae;
	efx_mae_limits_t limits;
	int rc;

	sfc_log_init(sa, "entry");

	mae->outer_rc_cache.class_handle.h = EFX_MAE_HANDLE_NULL;
	mae->outer_rc_cache.match_spec = NULL;

	mae->action_rc_cache.class_handle.h = EFX_MAE_HANDLE_NULL;
	mae->action_rc_cache.match_spec = NULL;

	if (!encp->enc_mae_supported) {
		mae->status = SFC_MAE_STATUS_UNSUPPORTED;
		return 0;
	}

	sfc_log_init(sa, "init MAE");
	rc = efx_mae_init(sa->nic);
	if (rc != 0)
		goto fail_mae_init;

	sfc_log_init(sa, "get MAE limits");
	rc = efx_mae_get_limits(sa->nic, &limits);
	if (rc != 0)
		goto fail_mae_get_limits;

	sfc_log_init(sa, "init MAE counter registry");
	rc = sfc_mae_counter_registry_init(sa, &mae->counter_registry);
	if (rc != 0)
		goto fail_counter_registry_init;

	sfc_log_init(sa, "assign entity MPORT");
	rc = sfc_mae_assign_entity_mport(sa, &entity_mport);
	if (rc != 0)
		goto fail_mae_assign_entity_mport;

	rc = sfc_mae_assign_switch_domain(sa, &mae->switch_domain_id);
	if (rc != 0)
		goto fail_mae_assign_switch_domain;

	sfc_log_init(sa, "assign RTE switch parameters");
	switch_port_request.type = SFC_MAE_SWITCH_PORT_INDEPENDENT;
	switch_port_request.entity_mportp = &entity_mport;
	/*
	 * As of now, the driver does not support representors, so
	 * RTE ethdev port ID is port ID of this adapter.
	 */
	switch_port_request.ethdev_port_id = sas->port_id;
	rc = sfc_mae_assign_switch_port(mae->switch_domain_id,
					&switch_port_request,
					&mae->switch_port_id);
	if (rc != 0)
		goto fail_mae_assign_switch_port;

	sfc_log_init(sa, "allocate encap. header bounce buffer");
	mae->encap_header_buf_size = limits.eml_encap_header_size_limit;
	mae->encap_header_buf = rte_malloc("sfc_mae_eh_buf",
					   mae->encap_header_buf_size, 0);
	if (mae->encap_header_buf == NULL)
		goto fail_mae_allocate_encap_header_buf;

	mae->encap_header_type_cur = EFX_TUNNEL_PROTOCOL_NONE;

	mae->status = SFC_MAE_STATUS_SUPPORTED;
	mae->nb_outer_rule_prios_max = limits.eml_max_n_outer_prios;
	mae->nb_action_rule_prios_max = limits.eml_max_n_action_prios;
	mae->encap_types_supported = limits.eml_encap_types_supported;
	TAILQ_INIT(&mae->outer_rules);
	TAILQ_INIT(&mae->encap_headers);
	TAILQ_INIT(&mae->action_sets);

	sfc_log_init(sa, "done");

	return 0;

fail_mae_allocate_encap_header_buf:
fail_mae_assign_switch_port:
fail_mae_assign_switch_domain:
fail_mae_assign_entity_mport:
	sfc_mae_counter_registry_fini(sa, &mae->counter_registry);

fail_counter_registry_init:
fail_mae_get_limits:
	efx_mae_fini(sa->nic);

fail_mae_init:
	sfc_log_init(sa, "failed %d", rc);

	return rc;
}

void
sfc_mae_detach(struct sfc_adapter *sa)
{
	struct sfc_mae *mae = &sa->mae;
	enum sfc_mae_status status_prev = mae->status;

	sfc_log_init(sa, "entry");

	mae->nb_action_rule_prios_max = 0;
	mae->status = SFC_MAE_STATUS_UNKNOWN;

	if (status_prev != SFC_MAE_STATUS_SUPPORTED)
		return;

	rte_free(mae->encap_header_buf);

	SFC_ASSERT(mae->outer_rc_cache.class_handle.h == EFX_MAE_HANDLE_NULL);
	SFC_ASSERT(mae->outer_rc_cache.match_spec == NULL);

	SFC_ASSERT(mae->action_rc_cache.class_handle.h == EFX_MAE_HANDLE_NULL);
	SFC_ASSERT(mae->action_rc_cache.match_spec == NULL);

	sfc_mae_counter_registry_fini(sa, &mae->counter_registry);

	efx_mae_fini(sa->nic);

	sfc_log_init(sa, "done");
}

static struct sfc_mae_outer_rule *
sfc_mae_outer_rule_attach(struct sfc_adapter *sa,
			  const efx_mae_match_spec_t *match_spec,
			  efx_tunnel_protocol_t encap_type)
{
	struct sfc_mae_outer_rule *rule;
	struct sfc_mae *mae = &sa->mae;

	SFC_ASSERT(sfc_adapter_is_locked(sa));

	TAILQ_FOREACH(rule, &mae->outer_rules, entries) {
		if (efx_mae_match_specs_equal(rule->match_spec, match_spec) &&
		    rule->encap_type == encap_type) {
			++(rule->refcnt);
			return rule;
		}
	}

	return NULL;
}

static int
sfc_mae_outer_rule_add(struct sfc_adapter *sa,
		       efx_mae_match_spec_t *match_spec,
		       efx_tunnel_protocol_t encap_type,
		       struct sfc_mae_outer_rule **rulep)
{
	struct sfc_mae_outer_rule *rule;
	struct sfc_mae *mae = &sa->mae;

	SFC_ASSERT(sfc_adapter_is_locked(sa));

	rule = rte_zmalloc("sfc_mae_outer_rule", sizeof(*rule), 0);
	if (rule == NULL)
		return ENOMEM;

	rule->refcnt = 1;
	rule->match_spec = match_spec;
	rule->encap_type = encap_type;
	rule->rule_class.h = EFX_MAE_HANDLE_NULL;

	rule->fw_rsrc.rule_id.id = EFX_MAE_RSRC_ID_INVALID;

	TAILQ_INSERT_TAIL(&mae->outer_rules, rule, entries);

	*rulep = rule;

	return 0;
}

static void
sfc_mae_outer_rule_del(struct sfc_adapter *sa,
		       struct sfc_mae_outer_rule *rule)
{
	struct sfc_mae_fw_rsrc *fw_rsrc = &rule->fw_rsrc;
	struct sfc_mae *mae = &sa->mae;

	SFC_ASSERT(sfc_adapter_is_locked(sa));
	SFC_ASSERT(rule->refcnt != 0);

	rule->refcnt = rule->refcnt - 1;

	if (rule->refcnt != 0)
		return;

	SFC_ASSERT(fw_rsrc->rule_id.id == EFX_MAE_RSRC_ID_INVALID);
	SFC_ASSERT(fw_rsrc->refcnt == 0);

	/*
	 * If match_spec is NULL, the specification has been
	 * tracked by outer rule class validation cache.
	 */
	if (rule->match_spec != NULL)
		efx_mae_match_spec_fini(sa->nic, rule->match_spec);

	TAILQ_REMOVE(&mae->outer_rules, rule, entries);
	rte_free(rule);
}

static int
sfc_mae_outer_rule_enable(struct sfc_adapter *sa,
			  struct sfc_mae_outer_rule *rule,
			  efx_mae_match_spec_t *match_spec_action)
{
	struct sfc_mae_fw_rsrc *fw_rsrc = &rule->fw_rsrc;
	int rc;

	SFC_ASSERT(sfc_adapter_is_locked(sa));

	if (fw_rsrc->refcnt == 0) {
		SFC_ASSERT(fw_rsrc->rule_id.id == EFX_MAE_RSRC_ID_INVALID);
		SFC_ASSERT(rule->match_spec != NULL);

		rc = efx_mae_outer_rule_insert(sa->nic, rule->match_spec,
					       rule->encap_type,
					       &fw_rsrc->rule_id);
		if (rc != 0)
			return rc;
	}

	rc = efx_mae_match_spec_outer_rule_id_set(match_spec_action,
						  &fw_rsrc->rule_id);
	if (rc != 0) {
		if (fw_rsrc->refcnt == 0) {
			(void)efx_mae_outer_rule_remove(sa->nic,
							&fw_rsrc->rule_id);
		}
		return rc;
	}

	fw_rsrc->refcnt = fw_rsrc->refcnt + 1;

	return 0;
}

static int
sfc_mae_outer_rule_disable(struct sfc_adapter *sa,
			   struct sfc_mae_outer_rule *rule)
{
	struct sfc_mae_fw_rsrc *fw_rsrc = &rule->fw_rsrc;
	int rc;

	SFC_ASSERT(sfc_adapter_is_locked(sa));
	SFC_ASSERT(fw_rsrc->rule_id.id != EFX_MAE_RSRC_ID_INVALID);
	SFC_ASSERT(fw_rsrc->refcnt != 0);

	if (fw_rsrc->refcnt == 1) {
		rc = efx_mae_outer_rule_remove(sa->nic, &fw_rsrc->rule_id);
		if (rc != 0)
			return rc;

		fw_rsrc->rule_id.id = EFX_MAE_RSRC_ID_INVALID;
	}

	fw_rsrc->refcnt = fw_rsrc->refcnt - 1;

	return 0;
}

static struct sfc_mae_encap_header *
sfc_mae_encap_header_attach(struct sfc_adapter *sa)
{
	struct sfc_mae_encap_header *encap_header;
	struct sfc_mae *mae = &sa->mae;

	SFC_ASSERT(sfc_adapter_is_locked(sa));

	TAILQ_FOREACH(encap_header, &mae->encap_headers, entries) {
		if (encap_header->header_size == mae->encap_header_size_cur &&
		    memcmp(encap_header->header_data, mae->encap_header_buf,
			   encap_header->header_size) == 0) {
			++(encap_header->refcnt);
			return encap_header;
		}
	}

	return NULL;
}

static int
sfc_mae_encap_header_add(struct sfc_adapter *sa,
			 struct sfc_mae_encap_header **encap_headerp)
{
	struct sfc_mae_encap_header *encap_header;
	struct sfc_mae *mae = &sa->mae;

	SFC_ASSERT(sfc_adapter_is_locked(sa));

	encap_header = rte_zmalloc("sfc_mae_encap_header",
				   sizeof(*encap_header), 0);
	if (encap_header == NULL)
		return ENOMEM;

	encap_header->header_size = mae->encap_header_size_cur;

	encap_header->header_data = rte_malloc("sfc_mae_eh_buf",
					       encap_header->header_size, 0);
	if (encap_header->header_data == NULL) {
		rte_free(encap_header);
		return ENOMEM;
	}

	rte_memcpy(encap_header->header_data, mae->encap_header_buf,
		   encap_header->header_size);

	encap_header->refcnt = 1;
	encap_header->encap_type = mae->encap_header_type_cur;
	encap_header->fw_rsrc.eh_id.id = EFX_MAE_RSRC_ID_INVALID;

	TAILQ_INSERT_TAIL(&mae->encap_headers, encap_header, entries);

	*encap_headerp = encap_header;

	return 0;
}

static void
sfc_mae_encap_header_del(struct sfc_adapter *sa,
		       struct sfc_mae_encap_header *encap_header)
{
	struct sfc_mae_fw_rsrc *fw_rsrc = &encap_header->fw_rsrc;
	struct sfc_mae *mae = &sa->mae;

	SFC_ASSERT(sfc_adapter_is_locked(sa));
	SFC_ASSERT(encap_header->refcnt != 0);

	encap_header->refcnt = encap_header->refcnt - 1;

	if (encap_header->refcnt != 0)
		return;

	SFC_ASSERT(fw_rsrc->eh_id.id == EFX_MAE_RSRC_ID_INVALID);
	SFC_ASSERT(fw_rsrc->refcnt == 0);

	TAILQ_REMOVE(&mae->encap_headers, encap_header, entries);
	rte_free(encap_header->header_data);
	rte_free(encap_header);
}

static int
sfc_mae_encap_header_enable(struct sfc_adapter *sa,
			    struct sfc_mae_encap_header *encap_header,
			    efx_mae_actions_t *action_set_spec)
{
	struct sfc_mae_fw_rsrc *fw_rsrc = &encap_header->fw_rsrc;
	int rc;

	SFC_ASSERT(sfc_adapter_is_locked(sa));

	if (fw_rsrc->refcnt == 0) {
		SFC_ASSERT(fw_rsrc->eh_id.id == EFX_MAE_RSRC_ID_INVALID);
		SFC_ASSERT(encap_header->header_data != NULL);
		SFC_ASSERT(encap_header->header_size != 0);

		rc = efx_mae_encap_header_alloc(sa->nic,
						encap_header->encap_type,
						encap_header->header_data,
						encap_header->header_size,
						&fw_rsrc->eh_id);
		if (rc != 0)
			return rc;
	}

	rc = efx_mae_action_set_fill_in_eh_id(action_set_spec,
					      &fw_rsrc->eh_id);
	if (rc != 0) {
		if (fw_rsrc->refcnt == 0) {
			(void)efx_mae_encap_header_free(sa->nic,
							&fw_rsrc->eh_id);
		}
		return rc;
	}

	fw_rsrc->refcnt = fw_rsrc->refcnt + 1;

	return 0;
}

static int
sfc_mae_encap_header_disable(struct sfc_adapter *sa,
			     struct sfc_mae_encap_header *encap_header)
{
	struct sfc_mae_fw_rsrc *fw_rsrc = &encap_header->fw_rsrc;
	int rc;

	SFC_ASSERT(sfc_adapter_is_locked(sa));
	SFC_ASSERT(fw_rsrc->eh_id.id != EFX_MAE_RSRC_ID_INVALID);
	SFC_ASSERT(fw_rsrc->refcnt != 0);

	if (fw_rsrc->refcnt == 1) {
		rc = efx_mae_encap_header_free(sa->nic, &fw_rsrc->eh_id);
		if (rc != 0)
			return rc;

		fw_rsrc->eh_id.id = EFX_MAE_RSRC_ID_INVALID;
	}

	fw_rsrc->refcnt = fw_rsrc->refcnt - 1;

	return 0;
}

static struct sfc_mae_action_set *
sfc_mae_action_set_attach(struct sfc_mae *mae,
			  const struct sfc_mae_encap_header *encap_header,
			  const efx_mae_actions_t *spec)
{
	struct sfc_mae_action_set *action_set;

	TAILQ_FOREACH(action_set, &mae->action_sets, entries) {
		if (action_set->encap_header == encap_header &&
		    efx_mae_action_set_specs_equal(action_set->spec, spec)) {
			++(action_set->refcnt);
			return action_set;
		}
	}

	return NULL;
}

static int
sfc_mae_action_set_add(struct sfc_mae *mae,
		       struct sfc_mae_encap_header *encap_header,
		       efx_mae_actions_t *spec,
		       struct sfc_mae_action_set **action_setp)
{
	struct sfc_mae_action_set *action_set;
	struct sfc_mae_fw_rsrc *fw_rsrc;
	int rc = ENOMEM;

	action_set = rte_zmalloc("sfc_mae_action_set", sizeof(*action_set), 0);
	if (action_set == NULL)
		return rc;

	action_set->refcnt = 1;
	action_set->encap_header = encap_header;
	action_set->spec = spec;

	fw_rsrc = &action_set->fw_rsrc;
	fw_rsrc->aset_id.id = EFX_MAE_RSRC_ID_INVALID;

	TAILQ_INSERT_TAIL(&mae->action_sets, action_set, entries);

	*action_setp = action_set;

	return 0;
}

static void
sfc_mae_action_set_del(struct sfc_adapter *sa,
		       struct sfc_mae_action_set *action_set)
{
	struct sfc_mae_fw_rsrc *fw_rsrc = &action_set->fw_rsrc;
	struct sfc_mae *mae = &sa->mae;

	if (--action_set->refcnt != 0)
		return;

	SFC_ASSERT(fw_rsrc->aset_id.id == EFX_MAE_RSRC_ID_INVALID);
	SFC_ASSERT(fw_rsrc->refcnt == 0);

	efx_mae_action_set_spec_fini(sa->nic, action_set->spec);
	TAILQ_REMOVE(&mae->action_sets, action_set, entries);
	rte_free(action_set);

	if (action_set->encap_header != NULL)
		sfc_mae_encap_header_del(sa, action_set->encap_header);
}

static int
sfc_mae_action_set_enable(struct sfc_adapter *sa,
			  struct sfc_mae_action_set *action_set)
{
	struct sfc_mae_encap_header *eh = action_set->encap_header;
	struct sfc_mae_fw_rsrc *fw_rsrc = &action_set->fw_rsrc;
	unsigned int refcnt = fw_rsrc->refcnt;
	int rc;

	if (refcnt++ == 0) {
		SFC_ASSERT(fw_rsrc->aset_id.id == EFX_MAE_RSRC_ID_INVALID);
		SFC_ASSERT(action_set->spec != NULL);

		if (eh != NULL) {
			rc = sfc_mae_encap_header_enable(sa, eh,
							 action_set->spec);
			if (rc != 0)
				return rc;
		}

		rc = efx_mae_action_set_alloc(sa->nic, action_set->spec,
					      &fw_rsrc->aset_id);
		if (rc != 0) {
			if (eh != NULL)
				(void)sfc_mae_encap_header_disable(sa, eh);

			return rc;
		}
	}

	fw_rsrc->refcnt = refcnt;

	return 0;
}

static int
sfc_mae_action_set_disable(struct sfc_adapter *sa,
			   struct sfc_mae_action_set *action_set)
{
	struct sfc_mae_fw_rsrc *fw_rsrc = &action_set->fw_rsrc;
	unsigned int refcnt = fw_rsrc->refcnt;
	int rc;

	SFC_ASSERT(fw_rsrc->aset_id.id != EFX_MAE_RSRC_ID_INVALID);

	if (--refcnt == 0) {
		struct sfc_mae_encap_header *eh = action_set->encap_header;

		rc = efx_mae_action_set_free(sa->nic, &fw_rsrc->aset_id);
		if (rc != 0)
			return rc;

		fw_rsrc->aset_id.id = EFX_MAE_RSRC_ID_INVALID;

		if (eh != NULL) {
			rc = sfc_mae_encap_header_disable(sa, eh);
			if (rc != 0)
				return rc;
		}
	}

	fw_rsrc->refcnt = refcnt;

	return 0;
}

static int
sfc_mae_counter_remove(struct sfc_adapter *sa, uint32_t mae_counter_id)
{
	int rc;
	uint32_t id_to_free;

	if (mae_counter_id == EFX_MAE_COUNTER_ID_INVALID)
		return 0;

	rc = sfc_mae_counter_del(&sa->mae.counter_registry.counters,
				 mae_counter_id, &id_to_free);
	if (rc != 0)
		return rc;

	if (id_to_free != EFX_MAE_COUNTER_ID_INVALID)
		(void)efx_mae_counters_free(sa->nic, 1, &id_to_free);

	return 0;
}

void
sfc_mae_flow_cleanup(struct sfc_adapter *sa,
		     struct rte_flow *flow)
{
	struct sfc_flow_spec *spec;
	struct sfc_flow_spec_mae *spec_mae;

	if (flow == NULL)
		return;

	spec = &flow->spec;

	if (spec == NULL)
		return;

	spec_mae = &spec->mae;

	SFC_ASSERT(spec_mae->rule_id.id == EFX_MAE_RSRC_ID_INVALID);

	if (spec_mae->outer_rule != NULL)
		sfc_mae_outer_rule_del(sa, spec_mae->outer_rule);

	if (spec_mae->action_set != NULL)
		sfc_mae_action_set_del(sa, spec_mae->action_set);

	if (spec_mae->match_spec != NULL)
		efx_mae_match_spec_fini(sa->nic, spec_mae->match_spec);

	sfc_mae_counter_remove(sa, spec_mae->counter_id);
}

static int
sfc_mae_set_ethertypes(struct sfc_mae_parse_ctx *ctx)
{
	struct sfc_mae_pattern_data *pdata = &ctx->pattern_data;
	const efx_mae_field_id_t *fremap = ctx->field_ids_remap;
	const efx_mae_field_id_t field_ids[] = {
		EFX_MAE_FIELD_VLAN0_PROTO_BE,
		EFX_MAE_FIELD_VLAN1_PROTO_BE,
	};
	const struct sfc_mae_ethertype *et;
	unsigned int i;
	int rc;

	/*
	 * In accordance with RTE flow API convention, the innermost L2
	 * item's "type" ("inner_type") is a L3 EtherType. If there is
	 * no L3 item, it's 0x0000/0x0000.
	 */
	et = &pdata->ethertypes[pdata->nb_vlan_tags];
	rc = efx_mae_match_spec_field_set(ctx->match_spec,
					  fremap[EFX_MAE_FIELD_ETHER_TYPE_BE],
					  sizeof(et->value),
					  (const uint8_t *)&et->value,
					  sizeof(et->mask),
					  (const uint8_t *)&et->mask);
	if (rc != 0)
		return rc;

	/*
	 * sfc_mae_rule_parse_item_vlan() has already made sure
	 * that pdata->nb_vlan_tags does not exceed this figure.
	 */
	RTE_BUILD_BUG_ON(SFC_MAE_MATCH_VLAN_MAX_NTAGS != 2);

	for (i = 0; i < pdata->nb_vlan_tags; ++i) {
		et = &pdata->ethertypes[i];

		rc = efx_mae_match_spec_field_set(ctx->match_spec,
						  fremap[field_ids[i]],
						  sizeof(et->value),
						  (const uint8_t *)&et->value,
						  sizeof(et->mask),
						  (const uint8_t *)&et->mask);
		if (rc != 0)
			return rc;
	}

	return 0;
}

static int
sfc_mae_rule_process_pattern_data(struct sfc_mae_parse_ctx *ctx,
				  struct rte_flow_error *error)
{
	const efx_mae_field_id_t *fremap = ctx->field_ids_remap;
	struct sfc_mae_pattern_data *pdata = &ctx->pattern_data;
	struct sfc_mae_ethertype *ethertypes = pdata->ethertypes;
	const rte_be16_t supported_tpids[] = {
		/* VLAN standard TPID (always the first element) */
		RTE_BE16(RTE_ETHER_TYPE_VLAN),

		/* Double-tagging TPIDs */
		RTE_BE16(RTE_ETHER_TYPE_QINQ),
		RTE_BE16(RTE_ETHER_TYPE_QINQ1),
		RTE_BE16(RTE_ETHER_TYPE_QINQ2),
		RTE_BE16(RTE_ETHER_TYPE_QINQ3),
	};
	unsigned int nb_supported_tpids = RTE_DIM(supported_tpids);
	unsigned int ethertype_idx;
	const uint8_t *valuep;
	const uint8_t *maskp;
	int rc;

	if (pdata->innermost_ethertype_restriction.mask != 0 &&
	    pdata->nb_vlan_tags < SFC_MAE_MATCH_VLAN_MAX_NTAGS) {
		/*
		 * If a single item VLAN is followed by a L3 item, value
		 * of "type" in item ETH can't be a double-tagging TPID.
		 */
		nb_supported_tpids = 1;
	}

	/*
	 * sfc_mae_rule_parse_item_vlan() has already made sure
	 * that pdata->nb_vlan_tags does not exceed this figure.
	 */
	RTE_BUILD_BUG_ON(SFC_MAE_MATCH_VLAN_MAX_NTAGS != 2);

	for (ethertype_idx = 0;
	     ethertype_idx < pdata->nb_vlan_tags; ++ethertype_idx) {
		unsigned int tpid_idx;

		/* Exact match is supported only. */
		if (ethertypes[ethertype_idx].mask != RTE_BE16(0xffff)) {
			rc = EINVAL;
			goto fail;
		}

		for (tpid_idx = pdata->nb_vlan_tags - ethertype_idx - 1;
		     tpid_idx < nb_supported_tpids; ++tpid_idx) {
			if (ethertypes[ethertype_idx].value ==
			    supported_tpids[tpid_idx])
				break;
		}

		if (tpid_idx == nb_supported_tpids) {
			rc = EINVAL;
			goto fail;
		}

		nb_supported_tpids = 1;
	}

	if (pdata->innermost_ethertype_restriction.mask == RTE_BE16(0xffff)) {
		struct sfc_mae_ethertype *et = &ethertypes[ethertype_idx];

		if (et->mask == 0) {
			et->mask = RTE_BE16(0xffff);
			et->value =
			    pdata->innermost_ethertype_restriction.value;
		} else if (et->mask != RTE_BE16(0xffff) ||
			   et->value !=
			   pdata->innermost_ethertype_restriction.value) {
			rc = EINVAL;
			goto fail;
		}
	}

	/*
	 * Now, when the number of VLAN tags is known, set fields
	 * ETHER_TYPE, VLAN0_PROTO and VLAN1_PROTO so that the first
	 * one is either a valid L3 EtherType (or 0x0000/0x0000),
	 * and the last two are valid TPIDs (or 0x0000/0x0000).
	 */
	rc = sfc_mae_set_ethertypes(ctx);
	if (rc != 0)
		goto fail;

	if (pdata->l3_next_proto_restriction_mask == 0xff) {
		if (pdata->l3_next_proto_mask == 0) {
			pdata->l3_next_proto_mask = 0xff;
			pdata->l3_next_proto_value =
			    pdata->l3_next_proto_restriction_value;
		} else if (pdata->l3_next_proto_mask != 0xff ||
			   pdata->l3_next_proto_value !=
			   pdata->l3_next_proto_restriction_value) {
			rc = EINVAL;
			goto fail;
		}
	}

	valuep = (const uint8_t *)&pdata->l3_next_proto_value;
	maskp = (const uint8_t *)&pdata->l3_next_proto_mask;
	rc = efx_mae_match_spec_field_set(ctx->match_spec,
					  fremap[EFX_MAE_FIELD_IP_PROTO],
					  sizeof(pdata->l3_next_proto_value),
					  valuep,
					  sizeof(pdata->l3_next_proto_mask),
					  maskp);
	if (rc != 0)
		goto fail;

	return 0;

fail:
	return rte_flow_error_set(error, rc, RTE_FLOW_ERROR_TYPE_ITEM, NULL,
				  "Failed to process pattern data");
}

static int
sfc_mae_rule_parse_item_port_id(const struct rte_flow_item *item,
				struct sfc_flow_parse_ctx *ctx,
				struct rte_flow_error *error)
{
	struct sfc_mae_parse_ctx *ctx_mae = ctx->mae;
	const struct rte_flow_item_port_id supp_mask = {
		.id = 0xffffffff,
	};
	const void *def_mask = &rte_flow_item_port_id_mask;
	const struct rte_flow_item_port_id *spec = NULL;
	const struct rte_flow_item_port_id *mask = NULL;
	efx_mport_sel_t mport_sel;
	int rc;

	if (ctx_mae->match_mport_set) {
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Can't handle multiple traffic source items");
	}

	rc = sfc_flow_parse_init(item,
				 (const void **)&spec, (const void **)&mask,
				 (const void *)&supp_mask, def_mask,
				 sizeof(struct rte_flow_item_port_id), error);
	if (rc != 0)
		return rc;

	if (mask->id != supp_mask.id) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Bad mask in the PORT_ID pattern item");
	}

	/* If "spec" is not set, could be any port ID */
	if (spec == NULL)
		return 0;

	if (spec->id > UINT16_MAX) {
		return rte_flow_error_set(error, EOVERFLOW,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "The port ID is too large");
	}

	rc = sfc_mae_switch_port_by_ethdev(ctx_mae->sa->mae.switch_domain_id,
					   spec->id, &mport_sel);
	if (rc != 0) {
		return rte_flow_error_set(error, rc,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Can't find RTE ethdev by the port ID");
	}

	rc = efx_mae_match_spec_mport_set(ctx_mae->match_spec,
					  &mport_sel, NULL);
	if (rc != 0) {
		return rte_flow_error_set(error, rc,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Failed to set MPORT for the port ID");
	}

	ctx_mae->match_mport_set = B_TRUE;

	return 0;
}

static int
sfc_mae_rule_parse_item_phy_port(const struct rte_flow_item *item,
				 struct sfc_flow_parse_ctx *ctx,
				 struct rte_flow_error *error)
{
	struct sfc_mae_parse_ctx *ctx_mae = ctx->mae;
	const struct rte_flow_item_phy_port supp_mask = {
		.index = 0xffffffff,
	};
	const void *def_mask = &rte_flow_item_phy_port_mask;
	const struct rte_flow_item_phy_port *spec = NULL;
	const struct rte_flow_item_phy_port *mask = NULL;
	efx_mport_sel_t mport_v;
	int rc;

	if (ctx_mae->match_mport_set) {
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Can't handle multiple traffic source items");
	}

	rc = sfc_flow_parse_init(item,
				 (const void **)&spec, (const void **)&mask,
				 (const void *)&supp_mask, def_mask,
				 sizeof(struct rte_flow_item_phy_port), error);
	if (rc != 0)
		return rc;

	if (mask->index != supp_mask.index) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Bad mask in the PHY_PORT pattern item");
	}

	/* If "spec" is not set, could be any physical port */
	if (spec == NULL)
		return 0;

	rc = efx_mae_mport_by_phy_port(spec->index, &mport_v);
	if (rc != 0) {
		return rte_flow_error_set(error, rc,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Failed to convert the PHY_PORT index");
	}

	rc = efx_mae_match_spec_mport_set(ctx_mae->match_spec, &mport_v, NULL);
	if (rc != 0) {
		return rte_flow_error_set(error, rc,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Failed to set MPORT for the PHY_PORT");
	}

	ctx_mae->match_mport_set = B_TRUE;

	return 0;
}

static int
sfc_mae_rule_parse_item_pf(__rte_unused const struct rte_flow_item *item,
			   struct sfc_flow_parse_ctx *ctx,
			   struct rte_flow_error *error)
{
	struct sfc_mae_parse_ctx *ctx_mae = ctx->mae;
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(ctx_mae->sa->nic);
	efx_mport_sel_t mport_v;
	int rc;

	if (ctx_mae->match_mport_set) {
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Can't handle multiple traffic source items");
	}

	rc = efx_mae_mport_by_pcie_function(encp->enc_pf, EFX_PCI_VF_INVALID,
					    &mport_v);
	if (rc != 0) {
		return rte_flow_error_set(error, rc,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Failed to convert the PF ID");
	}

	rc = efx_mae_match_spec_mport_set(ctx_mae->match_spec, &mport_v, NULL);
	if (rc != 0) {
		return rte_flow_error_set(error, rc,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Failed to set MPORT for the PF");
	}

	ctx_mae->match_mport_set = B_TRUE;

	return 0;
}

static int
sfc_mae_rule_parse_item_vf(const struct rte_flow_item *item,
			   struct sfc_flow_parse_ctx *ctx,
			   struct rte_flow_error *error)
{
	struct sfc_mae_parse_ctx *ctx_mae = ctx->mae;
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(ctx_mae->sa->nic);
	const struct rte_flow_item_vf supp_mask = {
		.id = 0xffffffff,
	};
	const void *def_mask = &rte_flow_item_vf_mask;
	const struct rte_flow_item_vf *spec = NULL;
	const struct rte_flow_item_vf *mask = NULL;
	efx_mport_sel_t mport_v;
	int rc;

	if (ctx_mae->match_mport_set) {
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Can't handle multiple traffic source items");
	}

	rc = sfc_flow_parse_init(item,
				 (const void **)&spec, (const void **)&mask,
				 (const void *)&supp_mask, def_mask,
				 sizeof(struct rte_flow_item_vf), error);
	if (rc != 0)
		return rc;

	if (mask->id != supp_mask.id) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Bad mask in the VF pattern item");
	}

	/*
	 * If "spec" is not set, the item requests any VF related to the
	 * PF of the current DPDK port (but not the PF itself).
	 * Reject this match criterion as unsupported.
	 */
	if (spec == NULL) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Bad spec in the VF pattern item");
	}

	rc = efx_mae_mport_by_pcie_function(encp->enc_pf, spec->id, &mport_v);
	if (rc != 0) {
		return rte_flow_error_set(error, rc,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Failed to convert the PF + VF IDs");
	}

	rc = efx_mae_match_spec_mport_set(ctx_mae->match_spec, &mport_v, NULL);
	if (rc != 0) {
		return rte_flow_error_set(error, rc,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Failed to set MPORT for the PF + VF");
	}

	ctx_mae->match_mport_set = B_TRUE;

	return 0;
}

/*
 * Having this field ID in a field locator means that this
 * locator cannot be used to actually set the field at the
 * time when the corresponding item gets encountered. Such
 * fields get stashed in the parsing context instead. This
 * is required to resolve dependencies between the stashed
 * fields. See sfc_mae_rule_process_pattern_data().
 */
#define SFC_MAE_FIELD_HANDLING_DEFERRED	EFX_MAE_FIELD_NIDS

struct sfc_mae_field_locator {
	efx_mae_field_id_t		field_id;
	size_t				size;
	/* Field offset in the corresponding rte_flow_item_ struct */
	size_t				ofst;
};

static void
sfc_mae_item_build_supp_mask(const struct sfc_mae_field_locator *field_locators,
			     unsigned int nb_field_locators, void *mask_ptr,
			     size_t mask_size)
{
	unsigned int i;

	memset(mask_ptr, 0, mask_size);

	for (i = 0; i < nb_field_locators; ++i) {
		const struct sfc_mae_field_locator *fl = &field_locators[i];

		SFC_ASSERT(fl->ofst + fl->size <= mask_size);
		memset(RTE_PTR_ADD(mask_ptr, fl->ofst), 0xff, fl->size);
	}
}

static int
sfc_mae_parse_item(const struct sfc_mae_field_locator *field_locators,
		   unsigned int nb_field_locators, const uint8_t *spec,
		   const uint8_t *mask, struct sfc_mae_parse_ctx *ctx,
		   struct rte_flow_error *error)
{
	const efx_mae_field_id_t *fremap = ctx->field_ids_remap;
	unsigned int i;
	int rc = 0;

	for (i = 0; i < nb_field_locators; ++i) {
		const struct sfc_mae_field_locator *fl = &field_locators[i];

		if (fl->field_id == SFC_MAE_FIELD_HANDLING_DEFERRED)
			continue;

		rc = efx_mae_match_spec_field_set(ctx->match_spec,
						  fremap[fl->field_id],
						  fl->size, spec + fl->ofst,
						  fl->size, mask + fl->ofst);
		if (rc != 0)
			break;
	}

	if (rc != 0) {
		rc = rte_flow_error_set(error, rc, RTE_FLOW_ERROR_TYPE_ITEM,
				NULL, "Failed to process item fields");
	}

	return rc;
}

static const struct sfc_mae_field_locator flocs_eth[] = {
	{
		/*
		 * This locator is used only for building supported fields mask.
		 * The field is handled by sfc_mae_rule_process_pattern_data().
		 */
		SFC_MAE_FIELD_HANDLING_DEFERRED,
		RTE_SIZEOF_FIELD(struct rte_flow_item_eth, type),
		offsetof(struct rte_flow_item_eth, type),
	},
	{
		EFX_MAE_FIELD_ETH_DADDR_BE,
		RTE_SIZEOF_FIELD(struct rte_flow_item_eth, dst),
		offsetof(struct rte_flow_item_eth, dst),
	},
	{
		EFX_MAE_FIELD_ETH_SADDR_BE,
		RTE_SIZEOF_FIELD(struct rte_flow_item_eth, src),
		offsetof(struct rte_flow_item_eth, src),
	},
};

static int
sfc_mae_rule_parse_item_eth(const struct rte_flow_item *item,
			    struct sfc_flow_parse_ctx *ctx,
			    struct rte_flow_error *error)
{
	struct sfc_mae_parse_ctx *ctx_mae = ctx->mae;
	struct rte_flow_item_eth supp_mask;
	const uint8_t *spec = NULL;
	const uint8_t *mask = NULL;
	int rc;

	sfc_mae_item_build_supp_mask(flocs_eth, RTE_DIM(flocs_eth),
				     &supp_mask, sizeof(supp_mask));

	rc = sfc_flow_parse_init(item,
				 (const void **)&spec, (const void **)&mask,
				 (const void *)&supp_mask,
				 &rte_flow_item_eth_mask,
				 sizeof(struct rte_flow_item_eth), error);
	if (rc != 0)
		return rc;

	if (spec != NULL) {
		struct sfc_mae_pattern_data *pdata = &ctx_mae->pattern_data;
		struct sfc_mae_ethertype *ethertypes = pdata->ethertypes;
		const struct rte_flow_item_eth *item_spec;
		const struct rte_flow_item_eth *item_mask;

		item_spec = (const struct rte_flow_item_eth *)spec;
		item_mask = (const struct rte_flow_item_eth *)mask;

		ethertypes[0].value = item_spec->type;
		ethertypes[0].mask = item_mask->type;
	} else {
		/*
		 * The specification is empty. This is wrong in the case
		 * when there are more network patterns in line. Other
		 * than that, any Ethernet can match. All of that is
		 * checked at the end of parsing.
		 */
		return 0;
	}

	return sfc_mae_parse_item(flocs_eth, RTE_DIM(flocs_eth), spec, mask,
				  ctx_mae, error);
}

static const struct sfc_mae_field_locator flocs_vlan[] = {
	/* Outermost tag */
	{
		EFX_MAE_FIELD_VLAN0_TCI_BE,
		RTE_SIZEOF_FIELD(struct rte_flow_item_vlan, tci),
		offsetof(struct rte_flow_item_vlan, tci),
	},
	{
		/*
		 * This locator is used only for building supported fields mask.
		 * The field is handled by sfc_mae_rule_process_pattern_data().
		 */
		SFC_MAE_FIELD_HANDLING_DEFERRED,
		RTE_SIZEOF_FIELD(struct rte_flow_item_vlan, inner_type),
		offsetof(struct rte_flow_item_vlan, inner_type),
	},

	/* Innermost tag */
	{
		EFX_MAE_FIELD_VLAN1_TCI_BE,
		RTE_SIZEOF_FIELD(struct rte_flow_item_vlan, tci),
		offsetof(struct rte_flow_item_vlan, tci),
	},
	{
		/*
		 * This locator is used only for building supported fields mask.
		 * The field is handled by sfc_mae_rule_process_pattern_data().
		 */
		SFC_MAE_FIELD_HANDLING_DEFERRED,
		RTE_SIZEOF_FIELD(struct rte_flow_item_vlan, inner_type),
		offsetof(struct rte_flow_item_vlan, inner_type),
	},
};

static int
sfc_mae_rule_parse_item_vlan(const struct rte_flow_item *item,
			     struct sfc_flow_parse_ctx *ctx,
			     struct rte_flow_error *error)
{
	struct sfc_mae_parse_ctx *ctx_mae = ctx->mae;
	struct sfc_mae_pattern_data *pdata = &ctx_mae->pattern_data;
	const struct sfc_mae_field_locator *flocs;
	struct rte_flow_item_vlan supp_mask;
	const uint8_t *spec = NULL;
	const uint8_t *mask = NULL;
	unsigned int nb_flocs;
	int rc;

	RTE_BUILD_BUG_ON(SFC_MAE_MATCH_VLAN_MAX_NTAGS != 2);

	if (pdata->nb_vlan_tags == SFC_MAE_MATCH_VLAN_MAX_NTAGS) {
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Can't match that many VLAN tags");
	}

	nb_flocs = RTE_DIM(flocs_vlan) / SFC_MAE_MATCH_VLAN_MAX_NTAGS;
	flocs = flocs_vlan + pdata->nb_vlan_tags * nb_flocs;

	/* If parsing fails, this can remain incremented. */
	++pdata->nb_vlan_tags;

	sfc_mae_item_build_supp_mask(flocs, nb_flocs,
				     &supp_mask, sizeof(supp_mask));

	rc = sfc_flow_parse_init(item,
				 (const void **)&spec, (const void **)&mask,
				 (const void *)&supp_mask,
				 &rte_flow_item_vlan_mask,
				 sizeof(struct rte_flow_item_vlan), error);
	if (rc != 0)
		return rc;

	if (spec != NULL) {
		struct sfc_mae_ethertype *ethertypes = pdata->ethertypes;
		const struct rte_flow_item_vlan *item_spec;
		const struct rte_flow_item_vlan *item_mask;

		item_spec = (const struct rte_flow_item_vlan *)spec;
		item_mask = (const struct rte_flow_item_vlan *)mask;

		ethertypes[pdata->nb_vlan_tags].value = item_spec->inner_type;
		ethertypes[pdata->nb_vlan_tags].mask = item_mask->inner_type;
	} else {
		/*
		 * The specification is empty. This is wrong in the case
		 * when there are more network patterns in line. Other
		 * than that, any Ethernet can match. All of that is
		 * checked at the end of parsing.
		 */
		return 0;
	}

	return sfc_mae_parse_item(flocs, nb_flocs, spec, mask, ctx_mae, error);
}

static const struct sfc_mae_field_locator flocs_ipv4[] = {
	{
		EFX_MAE_FIELD_SRC_IP4_BE,
		RTE_SIZEOF_FIELD(struct rte_flow_item_ipv4, hdr.src_addr),
		offsetof(struct rte_flow_item_ipv4, hdr.src_addr),
	},
	{
		EFX_MAE_FIELD_DST_IP4_BE,
		RTE_SIZEOF_FIELD(struct rte_flow_item_ipv4, hdr.dst_addr),
		offsetof(struct rte_flow_item_ipv4, hdr.dst_addr),
	},
	{
		/*
		 * This locator is used only for building supported fields mask.
		 * The field is handled by sfc_mae_rule_process_pattern_data().
		 */
		SFC_MAE_FIELD_HANDLING_DEFERRED,
		RTE_SIZEOF_FIELD(struct rte_flow_item_ipv4, hdr.next_proto_id),
		offsetof(struct rte_flow_item_ipv4, hdr.next_proto_id),
	},
	{
		EFX_MAE_FIELD_IP_TOS,
		RTE_SIZEOF_FIELD(struct rte_flow_item_ipv4,
				 hdr.type_of_service),
		offsetof(struct rte_flow_item_ipv4, hdr.type_of_service),
	},
	{
		EFX_MAE_FIELD_IP_TTL,
		RTE_SIZEOF_FIELD(struct rte_flow_item_ipv4, hdr.time_to_live),
		offsetof(struct rte_flow_item_ipv4, hdr.time_to_live),
	},
};

static int
sfc_mae_rule_parse_item_ipv4(const struct rte_flow_item *item,
			     struct sfc_flow_parse_ctx *ctx,
			     struct rte_flow_error *error)
{
	rte_be16_t ethertype_ipv4_be = RTE_BE16(RTE_ETHER_TYPE_IPV4);
	struct sfc_mae_parse_ctx *ctx_mae = ctx->mae;
	struct sfc_mae_pattern_data *pdata = &ctx_mae->pattern_data;
	struct rte_flow_item_ipv4 supp_mask;
	const uint8_t *spec = NULL;
	const uint8_t *mask = NULL;
	int rc;

	sfc_mae_item_build_supp_mask(flocs_ipv4, RTE_DIM(flocs_ipv4),
				     &supp_mask, sizeof(supp_mask));

	rc = sfc_flow_parse_init(item,
				 (const void **)&spec, (const void **)&mask,
				 (const void *)&supp_mask,
				 &rte_flow_item_ipv4_mask,
				 sizeof(struct rte_flow_item_ipv4), error);
	if (rc != 0)
		return rc;

	pdata->innermost_ethertype_restriction.value = ethertype_ipv4_be;
	pdata->innermost_ethertype_restriction.mask = RTE_BE16(0xffff);

	if (spec != NULL) {
		const struct rte_flow_item_ipv4 *item_spec;
		const struct rte_flow_item_ipv4 *item_mask;

		item_spec = (const struct rte_flow_item_ipv4 *)spec;
		item_mask = (const struct rte_flow_item_ipv4 *)mask;

		pdata->l3_next_proto_value = item_spec->hdr.next_proto_id;
		pdata->l3_next_proto_mask = item_mask->hdr.next_proto_id;
	} else {
		return 0;
	}

	return sfc_mae_parse_item(flocs_ipv4, RTE_DIM(flocs_ipv4), spec, mask,
				  ctx_mae, error);
}

static const struct sfc_mae_field_locator flocs_ipv6[] = {
	{
		EFX_MAE_FIELD_SRC_IP6_BE,
		RTE_SIZEOF_FIELD(struct rte_flow_item_ipv6, hdr.src_addr),
		offsetof(struct rte_flow_item_ipv6, hdr.src_addr),
	},
	{
		EFX_MAE_FIELD_DST_IP6_BE,
		RTE_SIZEOF_FIELD(struct rte_flow_item_ipv6, hdr.dst_addr),
		offsetof(struct rte_flow_item_ipv6, hdr.dst_addr),
	},
	{
		/*
		 * This locator is used only for building supported fields mask.
		 * The field is handled by sfc_mae_rule_process_pattern_data().
		 */
		SFC_MAE_FIELD_HANDLING_DEFERRED,
		RTE_SIZEOF_FIELD(struct rte_flow_item_ipv6, hdr.proto),
		offsetof(struct rte_flow_item_ipv6, hdr.proto),
	},
	{
		EFX_MAE_FIELD_IP_TTL,
		RTE_SIZEOF_FIELD(struct rte_flow_item_ipv6, hdr.hop_limits),
		offsetof(struct rte_flow_item_ipv6, hdr.hop_limits),
	},
};

static int
sfc_mae_rule_parse_item_ipv6(const struct rte_flow_item *item,
			     struct sfc_flow_parse_ctx *ctx,
			     struct rte_flow_error *error)
{
	rte_be16_t ethertype_ipv6_be = RTE_BE16(RTE_ETHER_TYPE_IPV6);
	struct sfc_mae_parse_ctx *ctx_mae = ctx->mae;
	const efx_mae_field_id_t *fremap = ctx_mae->field_ids_remap;
	struct sfc_mae_pattern_data *pdata = &ctx_mae->pattern_data;
	struct rte_flow_item_ipv6 supp_mask;
	const uint8_t *spec = NULL;
	const uint8_t *mask = NULL;
	rte_be32_t vtc_flow_be;
	uint32_t vtc_flow;
	uint8_t tc_value;
	uint8_t tc_mask;
	int rc;

	sfc_mae_item_build_supp_mask(flocs_ipv6, RTE_DIM(flocs_ipv6),
				     &supp_mask, sizeof(supp_mask));

	vtc_flow_be = RTE_BE32(RTE_IPV6_HDR_TC_MASK);
	memcpy(&supp_mask, &vtc_flow_be, sizeof(vtc_flow_be));

	rc = sfc_flow_parse_init(item,
				 (const void **)&spec, (const void **)&mask,
				 (const void *)&supp_mask,
				 &rte_flow_item_ipv6_mask,
				 sizeof(struct rte_flow_item_ipv6), error);
	if (rc != 0)
		return rc;

	pdata->innermost_ethertype_restriction.value = ethertype_ipv6_be;
	pdata->innermost_ethertype_restriction.mask = RTE_BE16(0xffff);

	if (spec != NULL) {
		const struct rte_flow_item_ipv6 *item_spec;
		const struct rte_flow_item_ipv6 *item_mask;

		item_spec = (const struct rte_flow_item_ipv6 *)spec;
		item_mask = (const struct rte_flow_item_ipv6 *)mask;

		pdata->l3_next_proto_value = item_spec->hdr.proto;
		pdata->l3_next_proto_mask = item_mask->hdr.proto;
	} else {
		return 0;
	}

	rc = sfc_mae_parse_item(flocs_ipv6, RTE_DIM(flocs_ipv6), spec, mask,
				ctx_mae, error);
	if (rc != 0)
		return rc;

	memcpy(&vtc_flow_be, spec, sizeof(vtc_flow_be));
	vtc_flow = rte_be_to_cpu_32(vtc_flow_be);
	tc_value = (vtc_flow & RTE_IPV6_HDR_TC_MASK) >> RTE_IPV6_HDR_TC_SHIFT;

	memcpy(&vtc_flow_be, mask, sizeof(vtc_flow_be));
	vtc_flow = rte_be_to_cpu_32(vtc_flow_be);
	tc_mask = (vtc_flow & RTE_IPV6_HDR_TC_MASK) >> RTE_IPV6_HDR_TC_SHIFT;

	rc = efx_mae_match_spec_field_set(ctx_mae->match_spec,
					  fremap[EFX_MAE_FIELD_IP_TOS],
					  sizeof(tc_value), &tc_value,
					  sizeof(tc_mask), &tc_mask);
	if (rc != 0) {
		return rte_flow_error_set(error, rc, RTE_FLOW_ERROR_TYPE_ITEM,
				NULL, "Failed to process item fields");
	}

	return 0;
}

static const struct sfc_mae_field_locator flocs_tcp[] = {
	{
		EFX_MAE_FIELD_L4_SPORT_BE,
		RTE_SIZEOF_FIELD(struct rte_flow_item_tcp, hdr.src_port),
		offsetof(struct rte_flow_item_tcp, hdr.src_port),
	},
	{
		EFX_MAE_FIELD_L4_DPORT_BE,
		RTE_SIZEOF_FIELD(struct rte_flow_item_tcp, hdr.dst_port),
		offsetof(struct rte_flow_item_tcp, hdr.dst_port),
	},
	{
		EFX_MAE_FIELD_TCP_FLAGS_BE,
		/*
		 * The values have been picked intentionally since the
		 * target MAE field is oversize (16 bit). This mapping
		 * relies on the fact that the MAE field is big-endian.
		 */
		RTE_SIZEOF_FIELD(struct rte_flow_item_tcp, hdr.data_off) +
		RTE_SIZEOF_FIELD(struct rte_flow_item_tcp, hdr.tcp_flags),
		offsetof(struct rte_flow_item_tcp, hdr.data_off),
	},
};

static int
sfc_mae_rule_parse_item_tcp(const struct rte_flow_item *item,
			    struct sfc_flow_parse_ctx *ctx,
			    struct rte_flow_error *error)
{
	struct sfc_mae_parse_ctx *ctx_mae = ctx->mae;
	struct sfc_mae_pattern_data *pdata = &ctx_mae->pattern_data;
	struct rte_flow_item_tcp supp_mask;
	const uint8_t *spec = NULL;
	const uint8_t *mask = NULL;
	int rc;

	/*
	 * When encountered among outermost items, item TCP is invalid.
	 * Check which match specification is being constructed now.
	 */
	if (ctx_mae->match_spec != ctx_mae->match_spec_action) {
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "TCP in outer frame is invalid");
	}

	sfc_mae_item_build_supp_mask(flocs_tcp, RTE_DIM(flocs_tcp),
				     &supp_mask, sizeof(supp_mask));

	rc = sfc_flow_parse_init(item,
				 (const void **)&spec, (const void **)&mask,
				 (const void *)&supp_mask,
				 &rte_flow_item_tcp_mask,
				 sizeof(struct rte_flow_item_tcp), error);
	if (rc != 0)
		return rc;

	pdata->l3_next_proto_restriction_value = IPPROTO_TCP;
	pdata->l3_next_proto_restriction_mask = 0xff;

	if (spec == NULL)
		return 0;

	return sfc_mae_parse_item(flocs_tcp, RTE_DIM(flocs_tcp), spec, mask,
				  ctx_mae, error);
}

static const struct sfc_mae_field_locator flocs_udp[] = {
	{
		EFX_MAE_FIELD_L4_SPORT_BE,
		RTE_SIZEOF_FIELD(struct rte_flow_item_udp, hdr.src_port),
		offsetof(struct rte_flow_item_udp, hdr.src_port),
	},
	{
		EFX_MAE_FIELD_L4_DPORT_BE,
		RTE_SIZEOF_FIELD(struct rte_flow_item_udp, hdr.dst_port),
		offsetof(struct rte_flow_item_udp, hdr.dst_port),
	},
};

static int
sfc_mae_rule_parse_item_udp(const struct rte_flow_item *item,
			    struct sfc_flow_parse_ctx *ctx,
			    struct rte_flow_error *error)
{
	struct sfc_mae_parse_ctx *ctx_mae = ctx->mae;
	struct sfc_mae_pattern_data *pdata = &ctx_mae->pattern_data;
	struct rte_flow_item_udp supp_mask;
	const uint8_t *spec = NULL;
	const uint8_t *mask = NULL;
	int rc;

	sfc_mae_item_build_supp_mask(flocs_udp, RTE_DIM(flocs_udp),
				     &supp_mask, sizeof(supp_mask));

	rc = sfc_flow_parse_init(item,
				 (const void **)&spec, (const void **)&mask,
				 (const void *)&supp_mask,
				 &rte_flow_item_udp_mask,
				 sizeof(struct rte_flow_item_udp), error);
	if (rc != 0)
		return rc;

	pdata->l3_next_proto_restriction_value = IPPROTO_UDP;
	pdata->l3_next_proto_restriction_mask = 0xff;

	if (spec == NULL)
		return 0;

	return sfc_mae_parse_item(flocs_udp, RTE_DIM(flocs_udp), spec, mask,
				  ctx_mae, error);
}

static const struct sfc_mae_field_locator flocs_tunnel[] = {
	{
		EFX_MAE_FIELD_ENC_VNET_ID_BE,
		/*
		 * Virtual network ID is located at the second 32-bit word
		 * in VXLAN, Geneve and NVGRE headers. The ID itself is
		 * 24-bit in all cases, and extra 8 bits are reserved.
		 *
		 * MAE field for virtual network ID is a 32-bit one.
		 */
		sizeof(uint32_t),
		sizeof(uint32_t),
	},
};

/*
 * An auxiliary registry which allows using non-encap. field IDs
 * directly when building a match specification of type ACTION.
 *
 * See sfc_mae_rule_parse_pattern() and sfc_mae_rule_parse_item_tunnel().
 */
static const efx_mae_field_id_t field_ids_no_remap[] = {
#define FIELD_ID_NO_REMAP(_field) \
	[EFX_MAE_FIELD_##_field] = EFX_MAE_FIELD_##_field

	FIELD_ID_NO_REMAP(ETHER_TYPE_BE),
	FIELD_ID_NO_REMAP(ETH_SADDR_BE),
	FIELD_ID_NO_REMAP(ETH_DADDR_BE),
	FIELD_ID_NO_REMAP(VLAN0_TCI_BE),
	FIELD_ID_NO_REMAP(VLAN0_PROTO_BE),
	FIELD_ID_NO_REMAP(VLAN1_TCI_BE),
	FIELD_ID_NO_REMAP(VLAN1_PROTO_BE),
	FIELD_ID_NO_REMAP(SRC_IP4_BE),
	FIELD_ID_NO_REMAP(DST_IP4_BE),
	FIELD_ID_NO_REMAP(IP_PROTO),
	FIELD_ID_NO_REMAP(IP_TOS),
	FIELD_ID_NO_REMAP(IP_TTL),
	FIELD_ID_NO_REMAP(SRC_IP6_BE),
	FIELD_ID_NO_REMAP(DST_IP6_BE),
	FIELD_ID_NO_REMAP(L4_SPORT_BE),
	FIELD_ID_NO_REMAP(L4_DPORT_BE),
	FIELD_ID_NO_REMAP(TCP_FLAGS_BE),

	/*
	 * This field, despite it has "ENC" in its name,
	 * goes to a specification of type ACTION.
	 */
	FIELD_ID_NO_REMAP(ENC_VNET_ID_BE),

#undef FIELD_ID_NO_REMAP
};

/*
 * An auxiliary registry which allows using "ENC" field IDs
 * when building a match specification of type OUTER.
 *
 * See sfc_mae_rule_encap_parse_init().
 */
static const efx_mae_field_id_t field_ids_remap_to_encap[] = {
#define FIELD_ID_REMAP_TO_ENCAP(_field) \
	[EFX_MAE_FIELD_##_field] = EFX_MAE_FIELD_ENC_##_field

	FIELD_ID_REMAP_TO_ENCAP(ETHER_TYPE_BE),
	FIELD_ID_REMAP_TO_ENCAP(ETH_SADDR_BE),
	FIELD_ID_REMAP_TO_ENCAP(ETH_DADDR_BE),
	FIELD_ID_REMAP_TO_ENCAP(VLAN0_TCI_BE),
	FIELD_ID_REMAP_TO_ENCAP(VLAN0_PROTO_BE),
	FIELD_ID_REMAP_TO_ENCAP(VLAN1_TCI_BE),
	FIELD_ID_REMAP_TO_ENCAP(VLAN1_PROTO_BE),
	FIELD_ID_REMAP_TO_ENCAP(SRC_IP4_BE),
	FIELD_ID_REMAP_TO_ENCAP(DST_IP4_BE),
	FIELD_ID_REMAP_TO_ENCAP(IP_PROTO),
	FIELD_ID_REMAP_TO_ENCAP(IP_TOS),
	FIELD_ID_REMAP_TO_ENCAP(IP_TTL),
	FIELD_ID_REMAP_TO_ENCAP(SRC_IP6_BE),
	FIELD_ID_REMAP_TO_ENCAP(DST_IP6_BE),
	FIELD_ID_REMAP_TO_ENCAP(L4_SPORT_BE),
	FIELD_ID_REMAP_TO_ENCAP(L4_DPORT_BE),

#undef FIELD_ID_REMAP_TO_ENCAP
};

static int
sfc_mae_rule_parse_item_tunnel(const struct rte_flow_item *item,
			       struct sfc_flow_parse_ctx *ctx,
			       struct rte_flow_error *error)
{
	struct sfc_mae_parse_ctx *ctx_mae = ctx->mae;
	uint8_t supp_mask[sizeof(uint64_t)];
	const uint8_t *spec = NULL;
	const uint8_t *mask = NULL;
	const void *def_mask;
	int rc;

	/*
	 * We're about to start processing inner frame items.
	 * Process pattern data that has been deferred so far
	 * and reset pattern data storage.
	 */
	rc = sfc_mae_rule_process_pattern_data(ctx_mae, error);
	if (rc != 0)
		return rc;

	memset(&ctx_mae->pattern_data, 0, sizeof(ctx_mae->pattern_data));

	sfc_mae_item_build_supp_mask(flocs_tunnel, RTE_DIM(flocs_tunnel),
				     &supp_mask, sizeof(supp_mask));

	/*
	 * This tunnel item was preliminarily detected by
	 * sfc_mae_rule_encap_parse_init(). Default mask
	 * was also picked by that helper. Use it here.
	 */
	def_mask = ctx_mae->tunnel_def_mask;

	rc = sfc_flow_parse_init(item,
				 (const void **)&spec, (const void **)&mask,
				 (const void *)&supp_mask, def_mask,
				 sizeof(def_mask), error);
	if (rc != 0)
		return rc;

	/*
	 * This item and later ones comprise a
	 * match specification of type ACTION.
	 */
	ctx_mae->match_spec = ctx_mae->match_spec_action;

	/* This item and later ones use non-encap. EFX MAE field IDs. */
	ctx_mae->field_ids_remap = field_ids_no_remap;

	if (spec == NULL)
		return 0;

	return sfc_mae_parse_item(flocs_tunnel, RTE_DIM(flocs_tunnel), spec,
				  mask, ctx_mae, error);
}

static const struct sfc_flow_item sfc_flow_items[] = {
	{
		.type = RTE_FLOW_ITEM_TYPE_PORT_ID,
		/*
		 * In terms of RTE flow, this item is a META one,
		 * and its position in the pattern is don't care.
		 */
		.prev_layer = SFC_FLOW_ITEM_ANY_LAYER,
		.layer = SFC_FLOW_ITEM_ANY_LAYER,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_port_id,
	},
	{
		.type = RTE_FLOW_ITEM_TYPE_PHY_PORT,
		/*
		 * In terms of RTE flow, this item is a META one,
		 * and its position in the pattern is don't care.
		 */
		.prev_layer = SFC_FLOW_ITEM_ANY_LAYER,
		.layer = SFC_FLOW_ITEM_ANY_LAYER,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_phy_port,
	},
	{
		.type = RTE_FLOW_ITEM_TYPE_PF,
		/*
		 * In terms of RTE flow, this item is a META one,
		 * and its position in the pattern is don't care.
		 */
		.prev_layer = SFC_FLOW_ITEM_ANY_LAYER,
		.layer = SFC_FLOW_ITEM_ANY_LAYER,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_pf,
	},
	{
		.type = RTE_FLOW_ITEM_TYPE_VF,
		/*
		 * In terms of RTE flow, this item is a META one,
		 * and its position in the pattern is don't care.
		 */
		.prev_layer = SFC_FLOW_ITEM_ANY_LAYER,
		.layer = SFC_FLOW_ITEM_ANY_LAYER,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_vf,
	},
	{
		.type = RTE_FLOW_ITEM_TYPE_ETH,
		.prev_layer = SFC_FLOW_ITEM_START_LAYER,
		.layer = SFC_FLOW_ITEM_L2,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_eth,
	},
	{
		.type = RTE_FLOW_ITEM_TYPE_VLAN,
		.prev_layer = SFC_FLOW_ITEM_L2,
		.layer = SFC_FLOW_ITEM_L2,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_vlan,
	},
	{
		.type = RTE_FLOW_ITEM_TYPE_IPV4,
		.prev_layer = SFC_FLOW_ITEM_L2,
		.layer = SFC_FLOW_ITEM_L3,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_ipv4,
	},
	{
		.type = RTE_FLOW_ITEM_TYPE_IPV6,
		.prev_layer = SFC_FLOW_ITEM_L2,
		.layer = SFC_FLOW_ITEM_L3,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_ipv6,
	},
	{
		.type = RTE_FLOW_ITEM_TYPE_TCP,
		.prev_layer = SFC_FLOW_ITEM_L3,
		.layer = SFC_FLOW_ITEM_L4,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_tcp,
	},
	{
		.type = RTE_FLOW_ITEM_TYPE_UDP,
		.prev_layer = SFC_FLOW_ITEM_L3,
		.layer = SFC_FLOW_ITEM_L4,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_udp,
	},
	{
		.type = RTE_FLOW_ITEM_TYPE_VXLAN,
		.prev_layer = SFC_FLOW_ITEM_L4,
		.layer = SFC_FLOW_ITEM_START_LAYER,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_tunnel,
	},
	{
		.type = RTE_FLOW_ITEM_TYPE_GENEVE,
		.prev_layer = SFC_FLOW_ITEM_L4,
		.layer = SFC_FLOW_ITEM_START_LAYER,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_tunnel,
	},
	{
		.type = RTE_FLOW_ITEM_TYPE_NVGRE,
		.prev_layer = SFC_FLOW_ITEM_L3,
		.layer = SFC_FLOW_ITEM_START_LAYER,
		.ctx_type = SFC_FLOW_PARSE_CTX_MAE,
		.parse = sfc_mae_rule_parse_item_tunnel,
	},
};

static int
sfc_mae_rule_process_outer(struct sfc_adapter *sa,
			   struct sfc_mae_parse_ctx *ctx,
			   struct sfc_mae_outer_rule **rulep,
			   struct rte_flow_error *error)
{
	struct sfc_mae_outer_rule *rule;
	int rc;

	if (ctx->encap_type == EFX_TUNNEL_PROTOCOL_NONE) {
		*rulep = NULL;
		return 0;
	}

	SFC_ASSERT(ctx->match_spec_outer != NULL);

	if (!efx_mae_match_spec_is_valid(sa->nic, ctx->match_spec_outer)) {
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, NULL,
					  "Inconsistent pattern (outer)");
	}

	*rulep = sfc_mae_outer_rule_attach(sa, ctx->match_spec_outer,
					   ctx->encap_type);
	if (*rulep != NULL) {
		efx_mae_match_spec_fini(sa->nic, ctx->match_spec_outer);
	} else {
		rc = sfc_mae_outer_rule_add(sa, ctx->match_spec_outer,
					    ctx->encap_type, rulep);
		if (rc != 0) {
			return rte_flow_error_set(error, rc,
					RTE_FLOW_ERROR_TYPE_ITEM, NULL,
					"Failed to process the pattern");
		}
	}

	/*
	 * Depending on whether we reuse an existing outer rule or create a
	 * new one (see above), outer rule ID is either a valid value or
	 * EFX_MAE_RSRC_ID_INVALID. Set it in the action rule match
	 * specification (and the full mask, too) in order to have correct
	 * class comparisons of the new rule with existing ones.
	 * Also, action rule match specification will be validated shortly,
	 * and having the full mask set for outer rule ID indicates that we
	 * will use this field, and support for this field has to be checked.
	 */
	rule = *rulep;
	rc = efx_mae_match_spec_outer_rule_id_set(ctx->match_spec_action,
						  &rule->fw_rsrc.rule_id);
	if (rc != 0) {
		sfc_mae_outer_rule_del(sa, *rulep);
		*rulep = NULL;

		return rte_flow_error_set(error, rc,
					  RTE_FLOW_ERROR_TYPE_ITEM, NULL,
					  "Failed to process the pattern");
	}

	return 0;
}

static int
sfc_mae_rule_encap_parse_init(struct sfc_adapter *sa,
			      const struct rte_flow_item pattern[],
			      struct sfc_mae_parse_ctx *ctx,
			      struct rte_flow_error *error)
{
	struct sfc_mae *mae = &sa->mae;
	int rc;

	if (pattern == NULL) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ITEM_NUM, NULL,
				   "NULL pattern");
		return -rte_errno;
	}

	for (;;) {
		switch (pattern->type) {
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			ctx->encap_type = EFX_TUNNEL_PROTOCOL_VXLAN;
			ctx->tunnel_def_mask = &rte_flow_item_vxlan_mask;
			RTE_BUILD_BUG_ON(sizeof(ctx->tunnel_def_mask) !=
					 sizeof(rte_flow_item_vxlan_mask));
			break;
		case RTE_FLOW_ITEM_TYPE_GENEVE:
			ctx->encap_type = EFX_TUNNEL_PROTOCOL_GENEVE;
			ctx->tunnel_def_mask = &rte_flow_item_geneve_mask;
			RTE_BUILD_BUG_ON(sizeof(ctx->tunnel_def_mask) !=
					 sizeof(rte_flow_item_geneve_mask));
			break;
		case RTE_FLOW_ITEM_TYPE_NVGRE:
			ctx->encap_type = EFX_TUNNEL_PROTOCOL_NVGRE;
			ctx->tunnel_def_mask = &rte_flow_item_nvgre_mask;
			RTE_BUILD_BUG_ON(sizeof(ctx->tunnel_def_mask) !=
					 sizeof(rte_flow_item_nvgre_mask));
			break;
		case RTE_FLOW_ITEM_TYPE_END:
			break;
		default:
			++pattern;
			continue;
		};

		break;
	}

	if (pattern->type == RTE_FLOW_ITEM_TYPE_END)
		return 0;

	if ((mae->encap_types_supported & (1U << ctx->encap_type)) == 0) {
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  pattern, "Unsupported tunnel item");
	}

	if (ctx->priority >= mae->nb_outer_rule_prios_max) {
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY,
					  NULL, "Unsupported priority level");
	}

	rc = efx_mae_match_spec_init(sa->nic, EFX_MAE_RULE_OUTER, ctx->priority,
				     &ctx->match_spec_outer);
	if (rc != 0) {
		return rte_flow_error_set(error, rc,
			RTE_FLOW_ERROR_TYPE_ITEM, pattern,
			"Failed to initialise outer rule match specification");
	}

	/* Outermost items comprise a match specification of type OUTER. */
	ctx->match_spec = ctx->match_spec_outer;

	/* Outermost items use "ENC" EFX MAE field IDs. */
	ctx->field_ids_remap = field_ids_remap_to_encap;

	return 0;
}

static void
sfc_mae_rule_encap_parse_fini(struct sfc_adapter *sa,
			      struct sfc_mae_parse_ctx *ctx)
{
	if (ctx->encap_type == EFX_TUNNEL_PROTOCOL_NONE)
		return;

	efx_mae_match_spec_fini(sa->nic, ctx->match_spec_outer);
}

int
sfc_mae_rule_parse_pattern(struct sfc_adapter *sa,
			   const struct rte_flow_item pattern[],
			   struct sfc_flow_spec_mae *spec,
			   struct rte_flow_error *error)
{
	struct sfc_mae_parse_ctx ctx_mae;
	struct sfc_flow_parse_ctx ctx;
	int rc;

	memset(&ctx_mae, 0, sizeof(ctx_mae));
	ctx_mae.priority = spec->priority;
	ctx_mae.sa = sa;

	rc = efx_mae_match_spec_init(sa->nic, EFX_MAE_RULE_ACTION,
				     spec->priority,
				     &ctx_mae.match_spec_action);
	if (rc != 0) {
		rc = rte_flow_error_set(error, rc,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			"Failed to initialise action rule match specification");
		goto fail_init_match_spec_action;
	}

	/*
	 * As a preliminary setting, assume that there is no encapsulation
	 * in the pattern. That is, pattern items are about to comprise a
	 * match specification of type ACTION and use non-encap. field IDs.
	 *
	 * sfc_mae_rule_encap_parse_init() below may override this.
	 */
	ctx_mae.encap_type = EFX_TUNNEL_PROTOCOL_NONE;
	ctx_mae.match_spec = ctx_mae.match_spec_action;
	ctx_mae.field_ids_remap = field_ids_no_remap;

	ctx.type = SFC_FLOW_PARSE_CTX_MAE;
	ctx.mae = &ctx_mae;

	rc = sfc_mae_rule_encap_parse_init(sa, pattern, &ctx_mae, error);
	if (rc != 0)
		goto fail_encap_parse_init;

	rc = sfc_flow_parse_pattern(sfc_flow_items, RTE_DIM(sfc_flow_items),
				    pattern, &ctx, error);
	if (rc != 0)
		goto fail_parse_pattern;

	rc = sfc_mae_rule_process_pattern_data(&ctx_mae, error);
	if (rc != 0)
		goto fail_process_pattern_data;

	rc = sfc_mae_rule_process_outer(sa, &ctx_mae, &spec->outer_rule, error);
	if (rc != 0)
		goto fail_process_outer;

	if (!efx_mae_match_spec_is_valid(sa->nic, ctx_mae.match_spec_action)) {
		rc = rte_flow_error_set(error, ENOTSUP,
					RTE_FLOW_ERROR_TYPE_ITEM, NULL,
					"Inconsistent pattern");
		goto fail_validate_match_spec_action;
	}

	spec->match_spec = ctx_mae.match_spec_action;

	return 0;

fail_validate_match_spec_action:
fail_process_outer:
fail_process_pattern_data:
fail_parse_pattern:
	sfc_mae_rule_encap_parse_fini(sa, &ctx_mae);

fail_encap_parse_init:
	efx_mae_match_spec_fini(sa->nic, ctx_mae.match_spec_action);

fail_init_match_spec_action:
	return rc;
}

/*
 * An action supported by MAE may correspond to a bundle of RTE flow actions,
 * in example, VLAN_PUSH = OF_PUSH_VLAN + OF_VLAN_SET_VID + OF_VLAN_SET_PCP.
 * That is, related RTE flow actions need to be tracked as parts of a whole
 * so that they can be combined into a single action and submitted to MAE
 * representation of a given rule's action set.
 *
 * Each RTE flow action provided by an application gets classified as
 * one belonging to some bundle type. If an action is not supposed to
 * belong to any bundle, or if this action is END, it is described as
 * one belonging to a dummy bundle of type EMPTY.
 *
 * A currently tracked bundle will be submitted if a repeating
 * action or an action of different bundle type follows.
 */

enum sfc_mae_actions_bundle_type {
	SFC_MAE_ACTIONS_BUNDLE_EMPTY = 0,
	SFC_MAE_ACTIONS_BUNDLE_VLAN_PUSH,
};

struct sfc_mae_actions_bundle {
	enum sfc_mae_actions_bundle_type	type;

	/* Indicates actions already tracked by the current bundle */
	uint64_t				actions_mask;

	/* Parameters used by SFC_MAE_ACTIONS_BUNDLE_VLAN_PUSH */
	rte_be16_t				vlan_push_tpid;
	rte_be16_t				vlan_push_tci;
};

/*
 * Combine configuration of RTE flow actions tracked by the bundle into a
 * single action and submit the result to MAE action set specification.
 * Do nothing in the case of dummy action bundle.
 */
static int
sfc_mae_actions_bundle_submit(const struct sfc_mae_actions_bundle *bundle,
			      efx_mae_actions_t *spec)
{
	int rc = 0;

	switch (bundle->type) {
	case SFC_MAE_ACTIONS_BUNDLE_EMPTY:
		break;
	case SFC_MAE_ACTIONS_BUNDLE_VLAN_PUSH:
		rc = efx_mae_action_set_populate_vlan_push(
			    spec, bundle->vlan_push_tpid, bundle->vlan_push_tci);
		break;
	default:
		SFC_ASSERT(B_FALSE);
		break;
	}

	return rc;
}

/*
 * Given the type of the next RTE flow action in the line, decide
 * whether a new bundle is about to start, and, if this is the case,
 * submit and reset the current bundle.
 */
static int
sfc_mae_actions_bundle_sync(const struct rte_flow_action *action,
			    struct sfc_mae_actions_bundle *bundle,
			    efx_mae_actions_t *spec,
			    struct rte_flow_error *error)
{
	enum sfc_mae_actions_bundle_type bundle_type_new;
	int rc;

	switch (action->type) {
	case RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN:
	case RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID:
	case RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP:
		bundle_type_new = SFC_MAE_ACTIONS_BUNDLE_VLAN_PUSH;
		break;
	default:
		/*
		 * Self-sufficient actions, including END, are handled in this
		 * case. No checks for unsupported actions are needed here
		 * because parsing doesn't occur at this point.
		 */
		bundle_type_new = SFC_MAE_ACTIONS_BUNDLE_EMPTY;
		break;
	}

	if (bundle_type_new != bundle->type ||
	    (bundle->actions_mask & (1ULL << action->type)) != 0) {
		rc = sfc_mae_actions_bundle_submit(bundle, spec);
		if (rc != 0)
			goto fail_submit;

		memset(bundle, 0, sizeof(*bundle));
	}

	bundle->type = bundle_type_new;

	return 0;

fail_submit:
	return rte_flow_error_set(error, rc,
			RTE_FLOW_ERROR_TYPE_ACTION, NULL,
			"Failed to request the (group of) action(s)");
}

static void
sfc_mae_rule_parse_action_of_push_vlan(
			    const struct rte_flow_action_of_push_vlan *conf,
			    struct sfc_mae_actions_bundle *bundle)
{
	bundle->vlan_push_tpid = conf->ethertype;
}

static void
sfc_mae_rule_parse_action_of_set_vlan_vid(
			    const struct rte_flow_action_of_set_vlan_vid *conf,
			    struct sfc_mae_actions_bundle *bundle)
{
	bundle->vlan_push_tci |= (conf->vlan_vid &
				  rte_cpu_to_be_16(RTE_LEN2MASK(12, uint16_t)));
}

static void
sfc_mae_rule_parse_action_of_set_vlan_pcp(
			    const struct rte_flow_action_of_set_vlan_pcp *conf,
			    struct sfc_mae_actions_bundle *bundle)
{
	uint16_t vlan_tci_pcp = (uint16_t)(conf->vlan_pcp &
					   RTE_LEN2MASK(3, uint8_t)) << 13;

	bundle->vlan_push_tci |= rte_cpu_to_be_16(vlan_tci_pcp);
}

#define SFC_IPV4_TTL_DEF	0x40
#define SFC_IPV6_VTC_FLOW_DEF	0x60000000
#define SFC_IPV6_HOP_LIMITS_DEF	0xff
#define SFC_VXLAN_FLAGS_DEF	0x08000000

static int
sfc_mae_rule_parse_action_vxlan_encap(
			    struct sfc_adapter *sa,
			    const struct rte_flow_action_vxlan_encap *conf,
			    efx_mae_actions_t *spec)
{
	struct sfc_mae *mae = &sa->mae;
	size_t eth_ethertype_ofst = offsetof(struct rte_ether_hdr, ether_type);
	struct rte_flow_item *pattern = conf->definition;
	uint8_t dummy_buf[sizeof(struct rte_ipv6_hdr)];
	struct rte_ipv4_hdr *ipv4 = (void *)dummy_buf;
	struct rte_ipv6_hdr *ipv6 = (void *)dummy_buf;
	uint8_t *buf = mae->encap_header_buf;
	struct rte_vxlan_hdr *vxlan = NULL;
	struct rte_udp_hdr *udp = NULL;
	unsigned int nb_vlan_tags = 0;
	size_t next_proto_ofst = 0;
	size_t ethertype_ofst = 0;
	uint8_t *next_protop;
	uint64_t exp_items;

	if (pattern == NULL)
		return EINVAL;

	mae->encap_header_type_cur = EFX_TUNNEL_PROTOCOL_VXLAN;
	mae->encap_header_size_cur = 0;

	exp_items = (1ULL << RTE_FLOW_ITEM_TYPE_ETH);

	for (; pattern->type != RTE_FLOW_ITEM_TYPE_END; ++pattern) {
		uint8_t *buf_cur = buf + mae->encap_header_size_cur;
		uint64_t exp_items_extra_vlan[] = {
			(1ULL << RTE_FLOW_ITEM_TYPE_VLAN), 0
		};
		size_t proto_header_size;
		rte_be16_t *ethertypep;

		exp_items |= (1ULL << RTE_FLOW_ITEM_TYPE_VOID);

		if ((exp_items & (1ULL << pattern->type)) == 0)
			return ENOTSUP;

		switch (pattern->type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			proto_header_size = sizeof(struct rte_ether_hdr);

			ethertype_ofst = eth_ethertype_ofst;

			exp_items = (1ULL << RTE_FLOW_ITEM_TYPE_VLAN) |
				    (1ULL << RTE_FLOW_ITEM_TYPE_IPV4) |
				    (1ULL << RTE_FLOW_ITEM_TYPE_IPV6);
			break;
		case RTE_FLOW_ITEM_TYPE_VLAN:
			proto_header_size = sizeof(struct rte_vlan_hdr);

			ethertypep = (rte_be16_t *)(buf + eth_ethertype_ofst);
			*ethertypep = RTE_BE16(RTE_ETHER_TYPE_QINQ);

			ethertypep = (rte_be16_t *)(buf + ethertype_ofst);
			*ethertypep = RTE_BE16(RTE_ETHER_TYPE_VLAN);

			ethertype_ofst =
			    mae->encap_header_size_cur +
			    offsetof(struct rte_vlan_hdr, eth_proto);

			exp_items = (1ULL << RTE_FLOW_ITEM_TYPE_IPV4) |
				    (1ULL << RTE_FLOW_ITEM_TYPE_IPV6);
			exp_items |= exp_items_extra_vlan[nb_vlan_tags];

			++nb_vlan_tags;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			proto_header_size = sizeof(struct rte_ipv4_hdr);

			ethertypep = (rte_be16_t *)(buf + ethertype_ofst);
			*ethertypep = RTE_BE16(RTE_ETHER_TYPE_IPV4);

			next_proto_ofst =
			    mae->encap_header_size_cur +
			    offsetof(struct rte_ipv4_hdr, next_proto_id);

			ipv4 = (struct rte_ipv4_hdr *)buf_cur;

			exp_items = (1ULL << RTE_FLOW_ITEM_TYPE_UDP);
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			proto_header_size = sizeof(struct rte_ipv6_hdr);

			ethertypep = (rte_be16_t *)(buf + ethertype_ofst);
			*ethertypep = RTE_BE16(RTE_ETHER_TYPE_IPV6);

			next_proto_ofst = mae->encap_header_size_cur +
					  offsetof(struct rte_ipv6_hdr, proto);

			ipv6 = (struct rte_ipv6_hdr *)buf_cur;

			exp_items = (1ULL << RTE_FLOW_ITEM_TYPE_UDP);
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			proto_header_size = sizeof(struct rte_udp_hdr);

			next_protop = buf + next_proto_ofst;
			*next_protop = IPPROTO_UDP;

			udp = (struct rte_udp_hdr *)buf_cur;

			exp_items = (1ULL << RTE_FLOW_ITEM_TYPE_VXLAN);
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			proto_header_size = sizeof(struct rte_vxlan_hdr);

			vxlan = (struct rte_vxlan_hdr *)buf_cur;

			udp->dst_port = RTE_BE16(RTE_VXLAN_DEFAULT_PORT);
			udp->dgram_cksum = 0;

			exp_items = 0;
			break;
		case RTE_FLOW_ITEM_TYPE_VOID:
			proto_header_size = 0;
			break;
		default:
			SFC_ASSERT(B_FALSE);
		}

		if (mae->encap_header_size_cur + proto_header_size >
		    mae->encap_header_buf_size)
			return E2BIG;

		rte_memcpy(buf_cur, pattern->spec, proto_header_size);
		mae->encap_header_size_cur += proto_header_size;
	}

	if (exp_items != 0) {
		/* Parsing item VXLAN (the last step) would reset this to 0. */
		return ENOTSUP;
	}

	/* One of the pointers (ipv4, ipv6) referes to a dummy area. */
	ipv4->version_ihl = RTE_IPV4_VHL_DEF;
	ipv4->time_to_live = SFC_IPV4_TTL_DEF;
	ipv4->hdr_checksum = 0;
	ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);

	ipv6->vtc_flow = RTE_BE32(SFC_IPV6_VTC_FLOW_DEF);
	ipv6->hop_limits = SFC_IPV6_HOP_LIMITS_DEF;

	vxlan->vx_flags = RTE_BE32(SFC_VXLAN_FLAGS_DEF);

	return efx_mae_action_set_populate_encap(spec);
}

static int
sfc_mae_rule_parse_action_mark(const struct rte_flow_action_mark *conf,
			       efx_mae_actions_t *spec)
{
	return efx_mae_action_set_populate_mark(spec, conf->id);
}

static int
sfc_mae_rule_parse_action_count(struct sfc_adapter *sa,
				const struct rte_flow_action_count *conf,
				uint32_t *counter_id,
				efx_mae_actions_t *spec)
{
	struct sfc_mae_counter_registry *counter_registry =
		&sa->mae.counter_registry;
	int pending_counter_rc = 0;
	efx_counter_t mae_id;
	int rc;

	/*
	 * Always try to allocate pending counter if it is not already present.
	 * It may or may not be consumed by counter add operation.
	 */
	if (counter_registry->pending_counter == EFX_MAE_COUNTER_ID_INVALID) {
		pending_counter_rc = efx_mae_counters_alloc(sa->nic, 1,
				&counter_registry->pending_counter);
		/* Do not fail since counter add may not need a new counter */
		if (pending_counter_rc != 0) {
			counter_registry->pending_counter =
				EFX_MAE_COUNTER_ID_INVALID;
		}
	}

	rc = sfc_mae_counter_add(&counter_registry->counters, conf->shared,
				 conf->id, counter_registry->pending_counter,
				 &mae_id.id);
	if (rc != 0)
		goto fail_counter_add;

	rc = efx_mae_action_set_populate_count(spec, &mae_id);
	if (rc != 0)
		goto fail_populate_count;

	/* Check if passed counter was consumed by the add operation */
	if (mae_id.id == counter_registry->pending_counter)
		counter_registry->pending_counter = EFX_MAE_COUNTER_ID_INVALID;

	*counter_id = mae_id.id;

	return 0;

fail_populate_count:
	sfc_mae_counter_remove(sa, mae_id.id);

fail_counter_add:
	sfc_log_init(sa, "failed %d", rc);

	return rc;
}


static int
sfc_mae_rule_parse_action_phy_port(const struct rte_flow_action_phy_port *conf,
				   efx_mae_actions_t *spec)
{
	efx_mport_sel_t mport;
	int rc;

	rc = efx_mae_mport_by_phy_port(conf->index, &mport);
	if (rc != 0)
		return rc;

	return efx_mae_action_set_populate_deliver(spec, &mport);
}

static int
sfc_mae_rule_parse_action_pf_vf(struct sfc_adapter *sa,
				const struct rte_flow_action_vf *vf_conf,
				efx_mae_actions_t *spec)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(sa->nic);
	efx_mport_sel_t mport;
	uint32_t vf;
	int rc;

	if (vf_conf == NULL)
		vf = EFX_PCI_VF_INVALID;
	else if (vf_conf->original != 0)
		vf = encp->enc_vf;
	else
		vf = vf_conf->id;

	rc = efx_mae_mport_by_pcie_function(encp->enc_pf, vf, &mport);
	if (rc != 0)
		return rc;

	return efx_mae_action_set_populate_deliver(spec, &mport);
}

static int
sfc_mae_rule_parse_action_port_id(struct sfc_adapter *sa,
				  const struct rte_flow_action_port_id *conf,
				  efx_mae_actions_t *spec)
{
	struct sfc_adapter_shared * const sas = sfc_sa2shared(sa);
	struct sfc_mae *mae = &sa->mae;
	efx_mport_sel_t mport;
	uint16_t port_id;
	int rc;

	port_id = (conf->original != 0) ? sas->port_id : conf->id;

	rc = sfc_mae_switch_port_by_ethdev(mae->switch_domain_id,
					   port_id, &mport);
	if (rc != 0)
		return rc;

	return efx_mae_action_set_populate_deliver(spec, &mport);
}

static int
sfc_mae_rule_parse_action(struct sfc_adapter *sa,
			  const struct rte_flow_action *action,
			  struct sfc_mae_actions_bundle *bundle,
			  efx_mae_actions_t *spec,
			  uint32_t *counter_id,
			  struct rte_flow_error *error)
{
	int rc = 0;

	switch (action->type) {
	case RTE_FLOW_ACTION_TYPE_OF_POP_VLAN:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_OF_POP_VLAN,
				       bundle->actions_mask);
		rc = efx_mae_action_set_populate_vlan_pop(spec);
		break;
	case RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN,
				       bundle->actions_mask);
		sfc_mae_rule_parse_action_of_push_vlan(action->conf, bundle);
		break;
	case RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID,
				       bundle->actions_mask);
		sfc_mae_rule_parse_action_of_set_vlan_vid(action->conf, bundle);
		break;
	case RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP,
				       bundle->actions_mask);
		sfc_mae_rule_parse_action_of_set_vlan_pcp(action->conf, bundle);
		break;
	case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP,
				       bundle->actions_mask);
		rc = sfc_mae_rule_parse_action_vxlan_encap(sa, action->conf,
							   spec);
		break;
	case RTE_FLOW_ACTION_TYPE_COUNT:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_COUNT,
				       bundle->actions_mask);
		rc = sfc_mae_rule_parse_action_count(sa, action->conf,
						     counter_id, spec);
		break;
	case RTE_FLOW_ACTION_TYPE_FLAG:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_FLAG,
				       bundle->actions_mask);
		rc = efx_mae_action_set_populate_flag(spec);
		break;
	case RTE_FLOW_ACTION_TYPE_MARK:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_MARK,
				       bundle->actions_mask);
		rc = sfc_mae_rule_parse_action_mark(action->conf, spec);
		break;
	case RTE_FLOW_ACTION_TYPE_PHY_PORT:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_PHY_PORT,
				       bundle->actions_mask);
		rc = sfc_mae_rule_parse_action_phy_port(action->conf, spec);
		break;
	case RTE_FLOW_ACTION_TYPE_PF:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_PF,
				       bundle->actions_mask);
		rc = sfc_mae_rule_parse_action_pf_vf(sa, NULL, spec);
		break;
	case RTE_FLOW_ACTION_TYPE_VF:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_VF,
				       bundle->actions_mask);
		rc = sfc_mae_rule_parse_action_pf_vf(sa, action->conf, spec);
		break;
	case RTE_FLOW_ACTION_TYPE_PORT_ID:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_PORT_ID,
				       bundle->actions_mask);
		rc = sfc_mae_rule_parse_action_port_id(sa, action->conf, spec);
		break;
	case RTE_FLOW_ACTION_TYPE_DROP:
		SFC_BUILD_SET_OVERFLOW(RTE_FLOW_ACTION_TYPE_DROP,
				       bundle->actions_mask);
		rc = efx_mae_action_set_populate_drop(spec);
		break;
	default:
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ACTION, NULL,
				"Unsupported action");
	}

	if (rc != 0) {
		rc = rte_flow_error_set(error, rc, RTE_FLOW_ERROR_TYPE_ACTION,
				NULL, "Failed to request the action");
	} else {
		bundle->actions_mask |= (1ULL << action->type);
	}

	return rc;
}

static int
sfc_mae_process_encap_header(struct sfc_adapter *sa,
			     struct sfc_mae_encap_header **encap_headerp)
{
	struct sfc_mae *mae = &sa->mae;
	int rc = 0;

	if (mae->encap_header_type_cur == EFX_TUNNEL_PROTOCOL_NONE) {
		encap_headerp = NULL;
		return 0;
	}

	*encap_headerp = sfc_mae_encap_header_attach(sa);
	if (*encap_headerp != NULL)
		goto out;

	rc = sfc_mae_encap_header_add(sa, encap_headerp);

out:
	/* Invalidate the bounce buffer. */
	mae->encap_header_type_cur = EFX_TUNNEL_PROTOCOL_NONE;

	return rc;
}

int
sfc_mae_rule_parse_actions(struct sfc_adapter *sa,
			   const struct rte_flow_action actions[],
			   struct sfc_flow_spec_mae *spec_mae,
			   struct rte_flow_error *error)
{
	struct sfc_mae_encap_header *encap_header = NULL;
	struct sfc_mae_actions_bundle bundle = {0};
	const struct rte_flow_action *action;
	efx_mae_actions_t *spec;
	struct sfc_mae *mae = &sa->mae;
	int rc;

	spec_mae->counter_id = EFX_MAE_COUNTER_ID_INVALID;

	if (actions == NULL) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION_NUM, NULL,
				"NULL actions");
	}

	rc = efx_mae_action_set_spec_init(sa->nic, &spec);
	if (rc != 0)
		goto fail_action_set_spec_init;

	for (action = actions;
	     action->type != RTE_FLOW_ACTION_TYPE_END; ++action) {
		rc = sfc_mae_actions_bundle_sync(action, &bundle, spec, error);
		if (rc != 0)
			goto fail_rule_parse_action;

		rc = sfc_mae_rule_parse_action(sa, action, &bundle, spec,
					       &spec_mae->counter_id, error);
		if (rc != 0)
			goto fail_rule_parse_action;
	}

	rc = sfc_mae_actions_bundle_sync(action, &bundle, spec, error);
	if (rc != 0)
		goto fail_rule_parse_action;

	rc = sfc_mae_process_encap_header(sa, &encap_header);
	if (rc != 0)
		goto fail_process_encap_header;

	spec_mae->action_set = sfc_mae_action_set_attach(mae, encap_header,
							 spec);
	if (spec_mae->action_set != NULL) {
		if (encap_header != NULL)
			sfc_mae_encap_header_del(sa, encap_header);

		efx_mae_action_set_spec_fini(sa->nic, spec);
		return 0;
	}

	rc = sfc_mae_action_set_add(mae, encap_header, spec,
				    &spec_mae->action_set);
	if (rc != 0)
		goto fail_action_set_add;

	return 0;

fail_action_set_add:
	if (encap_header != NULL)
		sfc_mae_encap_header_del(sa, encap_header);

fail_process_encap_header:
fail_rule_parse_action:
	sfc_mae_counter_remove(sa, spec_mae->counter_id);
	efx_mae_action_set_spec_fini(sa->nic, spec);

fail_action_set_spec_init:
	if (rc > 0) {
		rc = rte_flow_error_set(error, rc,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
			NULL, "Failed to process the action");
	}
	return rc;
}

static bool
sfc_mae_rules_class_cmp(struct sfc_adapter *sa,
			const efx_mae_match_spec_t *left,
			const efx_mae_match_spec_t *right)
{
	bool have_same_class;
	int rc;

	rc = efx_mae_match_specs_class_cmp(sa->nic, left, right,
					   &have_same_class);

	return (rc == 0) ? have_same_class : false;
}

void
sfc_mae_validation_cache_drop(struct sfc_adapter *sa,
			      struct sfc_mae_rc_cache *rc_cache)
{
	efx_mae_match_spec_t *spec = rc_cache->match_spec;
	efx_mae_rc_handle_t handle = rc_cache->class_handle;

	if (spec == NULL) {
		SFC_ASSERT(handle.h == EFX_MAE_HANDLE_NULL);
		return;
	}

	SFC_ASSERT(handle.h != EFX_MAE_HANDLE_NULL);

	(void)efx_mae_rule_class_unregister(sa->nic, spec, &handle);

	rc_cache->class_handle.h = EFX_MAE_HANDLE_NULL;
	efx_mae_match_spec_fini(sa->nic, spec);
	rc_cache->match_spec = NULL;
}

static int
sfc_mae_rule_class_verify_with_fw(struct sfc_adapter *sa,
				  struct sfc_mae_rc_cache *rc_cache,
				  efx_mae_match_spec_t **match_specp)
{
	efx_mae_rc_handle_t handle;
	int rc;

	sfc_mae_validation_cache_drop(sa, rc_cache);

	rc = efx_mae_rule_class_register(sa->nic, *match_specp, &handle);
	if (rc != 0)
		return rc;

	/*
	 * Typically, a flow create call for the same rule will follow.
	 * Cache the validation result so that is can be picked
	 * and remembered by the said flow create call.
	 */
	rc_cache->match_spec = *match_specp;
	rc_cache->class_handle = handle;

	/*
	 * The match specification is owned by the validation cache now.
	 * There is no need to finalise it on the flow cleanup.
	 */
	*match_specp = NULL;

	return 0;
}

static int
sfc_mae_outer_rule_class_verify(struct sfc_adapter *sa,
				struct sfc_mae_outer_rule *rule)
{
	struct sfc_mae_fw_rsrc *fw_rsrc = &rule->fw_rsrc;
	struct sfc_mae_outer_rule *entry;
	struct sfc_mae *mae = &sa->mae;

	if (fw_rsrc->rule_id.id != EFX_MAE_RSRC_ID_INVALID) {
		/* Class of an active rule is wittingly valid. */
		return 0;
	}

	TAILQ_FOREACH_REVERSE(entry, &mae->outer_rules,
			      sfc_mae_outer_rules, entries) {
		const efx_mae_match_spec_t *left = entry->match_spec;
		const efx_mae_match_spec_t *right = rule->match_spec;

		if (entry == rule)
			continue;

		if (sfc_mae_rules_class_cmp(sa, left, right))
			return 0;
	}

	return sfc_mae_rule_class_verify_with_fw(sa, &mae->outer_rc_cache,
						 &rule->match_spec);
}

static int
sfc_mae_action_rule_class_verify(struct sfc_adapter *sa,
				 struct sfc_flow_spec_mae *spec)
{
	struct sfc_mae *mae = &sa->mae;
	const struct rte_flow *entry;

	TAILQ_FOREACH_REVERSE(entry, &sa->flow_list, sfc_flow_list, entries) {
		const struct sfc_flow_spec *entry_spec = &entry->spec;
		const struct sfc_flow_spec_mae *es_mae = &entry_spec->mae;
		const efx_mae_match_spec_t *left = es_mae->match_spec;
		const efx_mae_match_spec_t *right = spec->match_spec;

		switch (entry_spec->type) {
		case SFC_FLOW_SPEC_FILTER:
			/* Ignore VNIC-level flows */
			break;
		case SFC_FLOW_SPEC_MAE:
			if (sfc_mae_rules_class_cmp(sa, left, right))
				return 0;
			break;
		default:
			SFC_ASSERT(false);
		}
	}

	return sfc_mae_rule_class_verify_with_fw(sa, &mae->action_rc_cache,
						 &spec->match_spec);
}

/**
 * Confirm that a given flow can be accepted by the FW.
 *
 * @param sa
 *   Software adapter context
 * @param flow
 *   Flow to be verified
 * @return
 *   Zero on success and non-zero in the case of error.
 *   A special value of EAGAIN indicates that the adapter is
 *   not in started state. This state is compulsory because
 *   it only makes sense to compare the rule class of the flow
 *   being validated with classes of the active rules.
 *   Such classes are wittingly supported by the FW.
 */
int
sfc_mae_flow_verify(struct sfc_adapter *sa,
		    struct rte_flow *flow)
{
	struct sfc_flow_spec *spec = &flow->spec;
	struct sfc_flow_spec_mae *spec_mae = &spec->mae;
	struct sfc_mae_outer_rule *outer_rule = spec_mae->outer_rule;
	int rc;

	SFC_ASSERT(sfc_adapter_is_locked(sa));

	if (sa->state != SFC_ADAPTER_STARTED)
		return EAGAIN;

	if (outer_rule != NULL) {
		rc = sfc_mae_outer_rule_class_verify(sa, outer_rule);
		if (rc != 0)
			return rc;
	}

	return sfc_mae_action_rule_class_verify(sa, spec_mae);
}

int
sfc_mae_flow_insert(struct sfc_adapter *sa,
		    struct rte_flow *flow)
{
	struct sfc_mae *mae = &sa->mae;
	struct sfc_flow_spec *spec = &flow->spec;
	struct sfc_flow_spec_mae *spec_mae = &spec->mae;
	struct sfc_mae_outer_rule *outer_rule = spec_mae->outer_rule;
	struct sfc_mae_action_set *action_set = spec_mae->action_set;
	struct sfc_mae_fw_rsrc *fw_rsrc = &action_set->fw_rsrc;
	int rc;

	SFC_ASSERT(spec_mae->rule_id.id == EFX_MAE_RSRC_ID_INVALID);
	SFC_ASSERT(action_set != NULL);

	if (outer_rule != NULL) {
		rc = sfc_mae_outer_rule_enable(sa, outer_rule,
					       spec_mae->match_spec);
		if (rc != 0)
			goto fail_outer_rule_enable;
	}

	rc = sfc_mae_action_set_enable(sa, action_set);
	if (rc != 0)
		goto fail_action_set_enable;

	if (spec_mae->counter_id != EFX_MAE_COUNTER_ID_INVALID) {
		rc = sfc_mae_count_start(sa);
		if (rc != 0)
			goto fail_mae_count_start;
	}

	rc = efx_mae_action_rule_insert(sa->nic, spec_mae->match_spec,
					NULL, &fw_rsrc->aset_id,
					&spec_mae->rule_id);
	if (rc != 0)
		goto fail_action_rule_insert;

	/*
	 * Suppose, an application validated the same flow before inserting
	 * it. This validation might have involved explicit rule class
	 * registration. Rule insertion, in turn, makes the FW conduct the
	 * very same class registration procedure implicitly. With these
	 * considerations in mind, it's safe to drop the cache here. Keeping
	 * the cache between flow validation and flow insertion operations
	 * ensures FW support availability for the flow, and once the flow
	 * has been inserted, keeping the explicit class is unneeded.
	 *
	 * If the cache in fact keeps track of some other flow validation
	 * result, it's even more so supposed to be dropped here.
	 */
	sfc_mae_validation_cache_drop(sa, &mae->outer_rc_cache);
	sfc_mae_validation_cache_drop(sa, &mae->action_rc_cache);

	return 0;

fail_action_rule_insert:
fail_mae_count_start:
	(void)sfc_mae_action_set_disable(sa, action_set);

fail_action_set_enable:
	if (outer_rule != NULL)
		(void)sfc_mae_outer_rule_disable(sa, outer_rule);

fail_outer_rule_enable:
	return rc;
}

int
sfc_mae_flow_remove(struct sfc_adapter *sa,
		    struct rte_flow *flow)
{
	struct sfc_flow_spec *spec = &flow->spec;
	struct sfc_flow_spec_mae *spec_mae = &spec->mae;
	struct sfc_mae_action_set *action_set = spec_mae->action_set;
	struct sfc_mae_outer_rule *outer_rule = spec_mae->outer_rule;
	int rc;

	SFC_ASSERT(spec_mae->rule_id.id != EFX_MAE_RSRC_ID_INVALID);
	SFC_ASSERT(action_set != NULL);

	rc = efx_mae_action_rule_remove(sa->nic, &spec_mae->rule_id);
	if (rc != 0)
		return rc;

	spec_mae->rule_id.id = EFX_MAE_RSRC_ID_INVALID;

	rc = sfc_mae_action_set_disable(sa, action_set);
	if (rc != 0) {
		sfc_err(sa, "failed to disable the action set (rc = %d)", rc);
		/* Despite the error, proceed with outer rule removal. */
	}

	if (outer_rule != NULL)
		return sfc_mae_outer_rule_disable(sa, outer_rule);

	return 0;
}

static int
sfc_mae_query_counter(struct sfc_adapter *sa,
		      struct sfc_flow_spec_mae *spec,
		      const struct rte_flow_action *action,
		      struct rte_flow_query_count *data,
		      struct rte_flow_error *error)
{
	const struct rte_flow_action_count *conf = action->conf;
	int rc;

	if (spec->counter_id == EFX_MAE_COUNTER_ID_INVALID) {
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ACTION, action,
			"Queried flow rule does not have count actions");
	}

	rc = sfc_mae_counter_get(&sa->mae.counter_registry.counters,
				 spec->counter_id, conf, data);
	if (rc != 0) {
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ACTION, action,
			"Queried flow rule counter action is invalid");
	}

	return 0;
}

int
sfc_mae_flow_query(struct rte_eth_dev *dev,
		   struct rte_flow *flow,
		   const struct rte_flow_action *action,
		   void *data,
		   struct rte_flow_error *error)
{
	struct sfc_adapter *sa = sfc_adapter_by_eth_dev(dev);
	struct sfc_flow_spec *spec = &flow->spec;
	struct sfc_flow_spec_mae *spec_mae = &spec->mae;

	if (action->type != RTE_FLOW_ACTION_TYPE_COUNT) {
		return rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_ACTION, NULL,
			"Query for action of this type is not supported");
	}

	return sfc_mae_query_counter(sa, spec_mae, action, data, error);
}
