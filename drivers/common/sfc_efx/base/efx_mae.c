/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2019 Xilinx, Inc. All rights reserved.
 * All rights reserved.
 */

#include "efx.h"
#include "efx_impl.h"


#if EFSYS_OPT_MAE

static	__checkReturn			efx_rc_t
efx_mae_get_capabilities(
	__in				efx_nic_t *enp)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload, MC_CMD_MAE_GET_CAPABILITIES_IN_LEN,
			     MC_CMD_MAE_GET_CAPABILITIES_OUT_LEN);
	struct efx_mae_s *maep = enp->en_maep;
	efx_rc_t rc;

	req.emr_cmd = MC_CMD_MAE_GET_CAPABILITIES;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_MAE_GET_CAPABILITIES_IN_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_MAE_GET_CAPABILITIES_OUT_LEN;

	efx_mcdi_execute(enp, &req);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail1;
	}

	if (req.emr_out_length_used < MC_CMD_MAE_GET_CAPABILITIES_OUT_LEN) {
		rc = EMSGSIZE;
		goto fail2;
	}

	maep->em_max_n_action_prios =
	    MCDI_OUT_DWORD(req, MAE_GET_CAPABILITIES_OUT_ACTION_PRIOS);

	maep->em_max_nfields =
	    MCDI_OUT_DWORD(req, MAE_GET_CAPABILITIES_OUT_MATCH_FIELD_COUNT);

	return (0);

fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

static	__checkReturn			efx_rc_t
efx_mae_get_action_rule_caps(
	__in				efx_nic_t *enp,
	__in				unsigned int field_ncaps,
	__out_ecount(field_ncaps)	efx_mae_field_cap_t *field_caps)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload, MC_CMD_MAE_GET_ACTION_RULE_CAPS_IN_LEN,
			     MC_CMD_MAE_GET_ACTION_RULE_CAPS_OUT_LENMAX_MCDI2);
	unsigned int i;
	efx_rc_t rc;

	if (MC_CMD_MAE_GET_ACTION_RULE_CAPS_OUT_LEN(field_ncaps) >
	    MC_CMD_MAE_GET_ACTION_RULE_CAPS_OUT_LENMAX_MCDI2) {
		rc = EINVAL;
		goto fail1;
	}

	req.emr_cmd = MC_CMD_MAE_GET_ACTION_RULE_CAPS;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_MAE_GET_ACTION_RULE_CAPS_IN_LEN;
	req.emr_out_buf = payload;
	req.emr_out_length =
	    MC_CMD_MAE_GET_ACTION_RULE_CAPS_OUT_LEN(field_ncaps);

	efx_mcdi_execute(enp, &req);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail2;
	}

	if (req.emr_out_length_used <
	    MC_CMD_MAE_GET_ACTION_RULE_CAPS_OUT_LEN(field_ncaps)) {
		rc = EMSGSIZE;
		goto fail3;
	}

	for (i = 0; i < field_ncaps; ++i) {
		uint32_t f;

		field_caps[i].emfc_support =
		    MCDI_OUT_INDEXED_DWORD_FIELD(req,
				    MAE_GET_ACTION_RULE_CAPS_OUT_FIELD_FLAGS, i,
				    MAE_FIELD_FLAGS_SUPPORT_STATUS);

		f = MCDI_OUT_INDEXED_DWORD_FIELD(req,
				    MAE_GET_ACTION_RULE_CAPS_OUT_FIELD_FLAGS, i,
				    MAE_FIELD_FLAGS_MATCH_AFFECTS_CLASS);
		field_caps[i].emfc_match_affects_class =
		    (f != 0) ? B_TRUE : B_FALSE;

		f = MCDI_OUT_INDEXED_DWORD_FIELD(req,
				    MAE_GET_ACTION_RULE_CAPS_OUT_FIELD_FLAGS, i,
				    MAE_FIELD_FLAGS_MASK_AFFECTS_CLASS);
		field_caps[i].emfc_mask_affects_class =
		    (f != 0) ? B_TRUE : B_FALSE;
	}

	return (0);

fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

	__checkReturn			efx_rc_t
efx_mae_init(
	__in				efx_nic_t *enp)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(enp);
	efx_mae_field_cap_t *ar_field_caps;
	size_t ar_field_caps_size;
	efx_mae_t *maep;
	efx_rc_t rc;

	if (encp->enc_mae_supported == B_FALSE) {
		rc = ENOTSUP;
		goto fail1;
	}

	EFSYS_KMEM_ALLOC(enp->en_esip, sizeof (*maep), maep);
	if (maep == NULL) {
		rc = ENOMEM;
		goto fail2;
	}

	enp->en_maep = maep;

	rc = efx_mae_get_capabilities(enp);
	if (rc != 0)
		goto fail3;

	ar_field_caps_size = maep->em_max_nfields * sizeof (*ar_field_caps);
	EFSYS_KMEM_ALLOC(enp->en_esip, ar_field_caps_size, ar_field_caps);
	if (ar_field_caps == NULL) {
		rc = ENOMEM;
		goto fail4;
	}

	maep->em_action_rule_field_caps_size = ar_field_caps_size;
	maep->em_action_rule_field_caps = ar_field_caps;

	rc = efx_mae_get_action_rule_caps(enp, maep->em_max_nfields,
					  ar_field_caps);
	if (rc != 0)
		goto fail5;

	return (0);

fail5:
	EFSYS_PROBE(fail5);
	EFSYS_KMEM_FREE(enp->en_esip, ar_field_caps_size, ar_field_caps);
fail4:
	EFSYS_PROBE(fail4);
fail3:
	EFSYS_PROBE(fail3);
	EFSYS_KMEM_FREE(enp->en_esip, sizeof (struct efx_mae_s), enp->en_maep);
	enp->en_maep = NULL;
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

					void
efx_mae_fini(
	__in				efx_nic_t *enp)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(enp);
	efx_mae_t *maep = enp->en_maep;

	if (encp->enc_mae_supported == B_FALSE)
		return;

	EFSYS_KMEM_FREE(enp->en_esip, maep->em_action_rule_field_caps_size,
			maep->em_action_rule_field_caps);
	EFSYS_KMEM_FREE(enp->en_esip, sizeof (*maep), maep);
	enp->en_maep = NULL;
}

	__checkReturn			efx_rc_t
efx_mae_get_limits(
	__in				efx_nic_t *enp,
	__out				efx_mae_limits_t *emlp)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(enp);
	struct efx_mae_s *maep = enp->en_maep;
	efx_rc_t rc;

	if (encp->enc_mae_supported == B_FALSE) {
		rc = ENOTSUP;
		goto fail1;
	}

	emlp->eml_max_n_action_prios = maep->em_max_n_action_prios;

	return (0);

fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}
	__checkReturn			efx_rc_t
efx_mae_match_spec_init(
	__in				efx_nic_t *enp,
	__in				efx_mae_rule_type_t type,
	__in				uint32_t prio,
	__out				efx_mae_match_spec_t **specp)
{
	efx_mae_match_spec_t *spec;
	efx_rc_t rc;

	switch (type) {
	case EFX_MAE_RULE_ACTION:
		break;
	default:
		rc = ENOTSUP;
		goto fail1;
	}

	EFSYS_KMEM_ALLOC(enp->en_esip, sizeof (*spec), spec);
	if (spec == NULL) {
		rc = ENOMEM;
		goto fail2;
	}

	spec->emms_type = type;
	spec->emms_prio = prio;

	*specp = spec;

	return (0);

fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

					void
efx_mae_match_spec_fini(
	__in				efx_nic_t *enp,
	__in				efx_mae_match_spec_t *spec)
{
	EFSYS_KMEM_FREE(enp->en_esip, sizeof (*spec), spec);
}

#define	EFX_MASK_BIT_IS_SET(_mask, _mask_page_nbits, _bit)		\
	    ((_mask)[(_bit) / (_mask_page_nbits)] &			\
		    (1ULL << ((_bit) & ((_mask_page_nbits) - 1))))

static inline				boolean_t
efx_mask_is_prefix(
	__in				size_t mask_nbytes,
	__in_bcount(mask_nbytes)	const uint8_t *maskp)
{
	boolean_t prev_bit_is_set = B_TRUE;
	unsigned int i;

	for (i = 0; i < 8 * mask_nbytes; ++i) {
		boolean_t bit_is_set = EFX_MASK_BIT_IS_SET(maskp, 8, i);

		if (!prev_bit_is_set && bit_is_set)
			return B_FALSE;

		prev_bit_is_set = bit_is_set;
	}

	return B_TRUE;
}

static inline				boolean_t
efx_mask_is_all_ones(
	__in				size_t mask_nbytes,
	__in_bcount(mask_nbytes)	const uint8_t *maskp)
{
	unsigned int i;
	uint8_t t = ~0;

	for (i = 0; i < mask_nbytes; ++i)
		t &= maskp[i];

	return (t == (uint8_t)(~0));
}

static inline				boolean_t
efx_mask_is_all_zeros(
	__in				size_t mask_nbytes,
	__in_bcount(mask_nbytes)	const uint8_t *maskp)
{
	unsigned int i;
	uint8_t t = 0;

	for (i = 0; i < mask_nbytes; ++i)
		t |= maskp[i];

	return (t == 0);
}

/* Named identifiers which are valid indices to efx_mae_field_cap_t */
typedef enum efx_mae_field_cap_id_e {
	EFX_MAE_FIELD_CAP_NIDS
} efx_mae_field_cap_id_t;

typedef enum efx_mae_field_endianness_e {
	EFX_MAE_FIELD_LE = 0,
	EFX_MAE_FIELD_BE,

	EFX_MAE_FIELD_ENDIANNESS_NTYPES
} efx_mae_field_endianness_t;

/*
 * The following structure is a means to describe an MAE field.
 * The information in it is meant to be used internally by
 * APIs for addressing a given field in a mask-value pairs
 * structure and for validation purposes.
 */
typedef struct efx_mae_mv_desc_s {
	efx_mae_field_cap_id_t		emmd_field_cap_id;

	size_t				emmd_value_size;
	size_t				emmd_value_offset;
	size_t				emmd_mask_size;
	size_t				emmd_mask_offset;

	efx_mae_field_endianness_t	emmd_endianness;
} efx_mae_mv_desc_t;

/* Indices to this array are provided by efx_mae_field_id_t */
static const efx_mae_mv_desc_t __efx_mae_action_rule_mv_desc_set[] = {
};

	__checkReturn			boolean_t
efx_mae_match_spec_is_valid(
	__in				efx_nic_t *enp,
	__in				const efx_mae_match_spec_t *spec)
{
	efx_mae_t *maep = enp->en_maep;
	const efx_mae_field_cap_t *field_caps = maep->em_action_rule_field_caps;
	unsigned int field_ncaps = maep->em_max_nfields;
	const efx_mae_mv_desc_t *desc_setp;
	boolean_t is_valid = B_TRUE;
	efx_mae_field_id_t field_id;

	if (field_caps == NULL)
		return (B_FALSE);

	switch (spec->emms_type) {
	case EFX_MAE_RULE_ACTION:
		desc_setp = __efx_mae_action_rule_mv_desc_set;
		break;
	default:
		return (B_FALSE);
	}

	for (field_id = 0; field_id < EFX_MAE_FIELD_NIDS; ++field_id) {
		const efx_mae_mv_desc_t *descp = &desc_setp[field_id];
		efx_mae_field_cap_id_t field_cap_id = descp->emmd_field_cap_id;
		const uint8_t *m_buf = spec->emms_mask_value_pairs.action +
				       descp->emmd_mask_offset;
		size_t m_size = descp->emmd_mask_size;

		if (field_cap_id >= field_ncaps)
			break;

		switch (field_caps[field_cap_id].emfc_support) {
		case MAE_FIELD_SUPPORTED_MATCH_MASK:
			is_valid = B_TRUE;
			break;
		case MAE_FIELD_SUPPORTED_MATCH_PREFIX:
			is_valid = efx_mask_is_prefix(m_size, m_buf);
			break;
		case MAE_FIELD_SUPPORTED_MATCH_OPTIONAL:
			is_valid = (efx_mask_is_all_ones(m_size, m_buf) ||
				    efx_mask_is_all_zeros(m_size, m_buf));
			break;
		case MAE_FIELD_SUPPORTED_MATCH_ALWAYS:
			is_valid = efx_mask_is_all_ones(m_size, m_buf);
			break;
		case MAE_FIELD_SUPPORTED_MATCH_NEVER:
		case MAE_FIELD_UNSUPPORTED:
		default:
			is_valid = efx_mask_is_all_zeros(m_size, m_buf);
			break;
		}

		if (is_valid == B_FALSE)
			break;
	}

	return (is_valid);
}

	__checkReturn			efx_rc_t
efx_mae_match_specs_class_cmp(
	__in				efx_nic_t *enp,
	__in				const efx_mae_match_spec_t *left,
	__in				const efx_mae_match_spec_t *right,
	__out				boolean_t *have_same_classp)
{
	efx_mae_t *maep = enp->en_maep;
	const efx_mae_field_cap_t *field_caps = maep->em_action_rule_field_caps;
	unsigned int field_ncaps = maep->em_max_nfields;
	const efx_mae_mv_desc_t *desc_setp;
	boolean_t have_same_class = B_TRUE;
	efx_mae_field_id_t field_id;
	const uint8_t *mvpl;
	const uint8_t *mvpr;
	efx_rc_t rc;

	if (field_caps == NULL) {
		rc = EAGAIN;
		goto fail1;
	}

	switch (left->emms_type) {
	case EFX_MAE_RULE_ACTION:
		desc_setp = __efx_mae_action_rule_mv_desc_set;
		mvpl = left->emms_mask_value_pairs.action;
		mvpr = right->emms_mask_value_pairs.action;
		break;
	default:
		rc = ENOTSUP;
		goto fail2;
	}

	if (left->emms_type != right->emms_type ||
	    left->emms_prio != right->emms_prio) {
		/*
		 * Rules of different types can never map to the same class.
		 *
		 * The FW can support some set of match criteria for one
		 * priority and not support the very same set for
		 * another priority. Thus, two rules which have
		 * different priorities can never map to
		 * the same class.
		 */
		*have_same_classp = B_FALSE;
		return (0);
	}

	for (field_id = 0; field_id < EFX_MAE_FIELD_NIDS; ++field_id) {
		const efx_mae_mv_desc_t *descp = &desc_setp[field_id];
		efx_mae_field_cap_id_t field_cap_id = descp->emmd_field_cap_id;

		if (field_cap_id >= field_ncaps)
			break;

		if (field_caps[field_cap_id].emfc_mask_affects_class) {
			const uint8_t *lmaskp = mvpl + descp->emmd_mask_offset;
			const uint8_t *rmaskp = mvpr + descp->emmd_mask_offset;
			size_t mask_size = descp->emmd_mask_size;

			if (memcmp(lmaskp, rmaskp, mask_size) != 0) {
				have_same_class = B_FALSE;
				break;
			}
		}

		if (field_caps[field_cap_id].emfc_match_affects_class) {
			const uint8_t *lvalp = mvpl + descp->emmd_value_offset;
			const uint8_t *rvalp = mvpr + descp->emmd_value_offset;
			size_t value_size = descp->emmd_value_size;

			if (memcmp(lvalp, rvalp, value_size) != 0) {
				have_same_class = B_FALSE;
				break;
			}
		}
	}

	*have_same_classp = have_same_class;

	return (0);

fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

/* FIXME: Remove this helper once MCDI symbol names get shorter. */
#define	MCDI_ID(_part1, _part2)						\
	_part1 ## _ ## _part2

static	__checkReturn			efx_rc_t
efx_mae_action_rule_class_register(
	__in				efx_nic_t *enp,
	__in				const efx_mae_match_spec_t *spec,
	__out				efx_mae_rc_handle_t *handlep)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload,
	    MC_CMD_MAE_ACTION_RULE_CLASS_REGISTER_IN_LENMAX_MCDI2,
	    MC_CMD_MAE_ACTION_RULE_CLASS_REGISTER_OUT_LEN);
	efx_mae_rc_handle_t handle;
	efx_rc_t rc;

	EFX_STATIC_ASSERT(sizeof (handlep->h) ==
		    MC_CMD_MAE_ACTION_RULE_CLASS_REGISTER_OUT_ARC_HANDLE_LEN);
	EFX_STATIC_ASSERT(EFX_MAE_HANDLE_NULL ==
	    MCDI_ID(MC_CMD_MAE_ACTION_RULE_CLASS_REGISTER_OUT,
		    ACTION_RULE_CLASS_HANDLE_NULL));

	req.emr_cmd = MC_CMD_MAE_ACTION_RULE_CLASS_REGISTER;
	req.emr_in_buf = payload;
	req.emr_in_length =
	    MC_CMD_MAE_ACTION_RULE_CLASS_REGISTER_IN_LENMAX_MCDI2;
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_MAE_ACTION_RULE_CLASS_REGISTER_OUT_LEN;

	MCDI_IN_SET_DWORD(req, MAE_ACTION_RULE_CLASS_REGISTER_IN_PRIO,
	    spec->emms_prio);

	memcpy(payload + MC_CMD_MAE_ACTION_RULE_CLASS_REGISTER_IN_FIELDS_OFST,
	    spec->emms_mask_value_pairs.action, MAE_FIELD_MASK_VALUE_PAIRS_LEN);

	efx_mcdi_execute(enp, &req);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail1;
	}

	if (req.emr_out_length_used <
	    MC_CMD_MAE_ACTION_RULE_CLASS_REGISTER_OUT_LEN) {
		rc = EMSGSIZE;
		goto fail2;
	}

	handle.h = MCDI_OUT_DWORD(req,
			    MAE_ACTION_RULE_CLASS_REGISTER_OUT_ARC_HANDLE);
	if (handle.h == EFX_MAE_HANDLE_NULL) {
		rc = ENOENT;
		goto fail3;
	}

	handlep->h = handle.h;

	return (0);

fail3:
	EFSYS_PROBE(fail3);
fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

	__checkReturn			efx_rc_t
efx_mae_rule_class_register(
	__in				efx_nic_t *enp,
	__in				const efx_mae_match_spec_t *spec,
	__out				efx_mae_rc_handle_t *handlep)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(enp);
	efx_rc_t rc;

	if (encp->enc_mae_supported == B_FALSE) {
		rc = ENOTSUP;
		goto fail1;
	}

	switch (spec->emms_type) {
	case EFX_MAE_RULE_ACTION:
		rc = efx_mae_action_rule_class_register(enp, spec, handlep);
		break;

	default:
		rc = ENOTSUP;
		break;
	}

	if (rc != 0)
		goto fail2;

	return (0);

fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

static	__checkReturn			efx_rc_t
efx_mae_action_rule_class_unregister(
	__in				efx_nic_t *enp,
	__in				efx_mae_rc_handle_t *handlep)
{
	efx_mcdi_req_t req;
	EFX_MCDI_DECLARE_BUF(payload,
	    MC_CMD_MAE_ACTION_RULE_CLASS_UNREGISTER_IN_LEN(1),
	    MC_CMD_MAE_ACTION_RULE_CLASS_UNREGISTER_OUT_LEN(1));
	efx_rc_t rc;

	req.emr_cmd = MC_CMD_MAE_ACTION_RULE_CLASS_UNREGISTER;
	req.emr_in_buf = payload;
	req.emr_in_length = MC_CMD_MAE_ACTION_RULE_CLASS_UNREGISTER_IN_LEN(1);
	req.emr_out_buf = payload;
	req.emr_out_length = MC_CMD_MAE_ACTION_RULE_CLASS_UNREGISTER_OUT_LEN(1);

	MCDI_IN_SET_DWORD(req, MAE_ACTION_RULE_CLASS_UNREGISTER_IN_ARC_HANDLE,
			  handlep->h);
	efx_mcdi_execute(enp, &req);

	if (req.emr_rc != 0) {
		rc = req.emr_rc;
		goto fail1;
	}

	if (MCDI_OUT_DWORD(req,
			   MCDI_ID(MAE_ACTION_RULE_CLASS_UNREGISTER_OUT,
				   UNREGISTERED_ARC_HANDLE)) != handlep->h) {
		/* Firmware failed to unregister the action rule class. */
		rc = EAGAIN;
		goto fail2;
	}

	return (0);

fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

#undef MCDI_ID

	__checkReturn			efx_rc_t
efx_mae_rule_class_unregister(
	__in				efx_nic_t *enp,
	__in				const efx_mae_match_spec_t *spec,
	__in				efx_mae_rc_handle_t *handlep)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(enp);
	efx_rc_t rc;

	if (encp->enc_mae_supported == B_FALSE) {
		rc = ENOTSUP;
		goto fail1;
	}

	switch (spec->emms_type) {
	case EFX_MAE_RULE_ACTION:
		rc = efx_mae_action_rule_class_unregister(enp, handlep);
		break;

	default:
		rc = ENOTSUP;
		break;
	}

	if (rc != 0)
		goto fail2;

	return (0);

fail2:
	EFSYS_PROBE(fail2);
fail1:
	EFSYS_PROBE1(fail1, efx_rc_t, rc);
	return (rc);
}

#endif /* EFSYS_OPT_MAE */
