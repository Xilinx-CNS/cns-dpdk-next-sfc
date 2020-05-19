/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2019 Solarflare Communications Inc.
 * All rights reserved.
 *
 * This software was jointly developed between OKTET Labs (under contract
 * for Solarflare) and Solarflare Communications, Inc.
 */

#ifndef _SFC_MAE_H
#define _SFC_MAE_H

#include <stdbool.h>

#include <rte_spinlock.h>

#include "efx.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Options for MAE switch port type */
enum sfc_mae_switch_port_type {
	/**
	 * The switch port is operated by a self-sufficient RTE ethdev
	 * and thus refers to its underlying PCIe function
	 */
	SFC_MAE_SWITCH_PORT_INDEPENDENT = 0,
};

/**
 * Switch port registry entry.
 *
 * Drivers aware of RTE switch domains also have to maintain RTE switch
 * port IDs for RTE ethdev instances they operate. These IDs are supposed
 * to stand for physical interconnect entities, in example, PCIe functions.
 *
 * In terms of MAE, a physical interconnect entity can be referred to using
 * an MPORT selector, that is, a 32-bit value. RTE switch port IDs, in turn,
 * are 16-bit values, so indirect mapping has to be maintained:
 *
 * +--------------------+          +---------------------------------------+
 * | RTE switch port ID |  ------  |         MAE switch port entry         |
 * +--------------------+          |         ---------------------         |
 *                                 |                                       |
 *                                 | Entity (PCIe function) MPORT selector |
 *                                 |                   +                   |
 *                                 |  Port type (independent/representor)  |
 *                                 +---------------------------------------+
 *
 * This mapping comprises a port type to ensure that RTE switch port ID
 * of a represented entity and that of its representor are different in
 * the case when the entity gets plugged into DPDK and not into a guest.
 *
 * Entry data also comprises RTE ethdev's own MPORT. This value
 * coincides with the entity MPORT in the case of independent ports.
 * In the case of representors, this ID is not a selector and refers
 * to an allocatable object (that is, it's likely to change on RTE
 * ethdev replug). Flow API backend must use this value rather
 * than entity_mport to support flow rule action PORT_ID.
 */
struct sfc_mae_switch_port {
	TAILQ_ENTRY(sfc_mae_switch_port)	switch_domain_ports;

	/** RTE ethdev MPORT */
	efx_mport_sel_t				ethdev_mport;
	/** RTE ethdev port ID */
	uint16_t				ethdev_port_id;

	/** Entity (PCIe function) MPORT selector */
	efx_mport_sel_t				entity_mport;
	/** Port type (independent/representor) */
	enum sfc_mae_switch_port_type		type;
	/** RTE switch port ID */
	uint16_t				id;
};

TAILQ_HEAD(sfc_mae_switch_ports, sfc_mae_switch_port);

/**
 * Switch domain registry entry.
 *
 * Even if an RTE ethdev instance gets unplugged, the corresponding
 * entry in the switch port registry will not be removed because the
 * entity (PCIe function) MPORT is static and cannot change. If this
 * RTE ethdev gets plugged back, the entry will be reused, and
 * RTE switch port ID will be the same.
 */
struct sfc_mae_switch_domain {
	TAILQ_ENTRY(sfc_mae_switch_domain)	entries;

	/** HW switch ID */
	struct sfc_hw_switch_id			*hw_switch_id;
	/** The number of ports in the switch port registry */
	unsigned int				nb_ports;
	/** Switch port registry */
	struct sfc_mae_switch_ports		ports;
	/** RTE switch domain ID allocated for a group of devices */
	uint16_t				id;
};

TAILQ_HEAD(sfc_mae_switch_domains, sfc_mae_switch_domain);

/**
 * MAE representation of RTE switch infrastructure.
 *
 * It is possible that an RTE flow API client tries to insert a rule
 * referencing an RTE ethdev deployed on top of a different physical
 * device (it may belong to the same vendor or not). This particular
 * driver/engine cannot support this and has to turn down such rules.
 *
 * Technically, it's HW switch identifier which, if queried for each
 * RTE ethdev instance, indicates relationship between the instances.
 * In the meantime, RTE flow API clients also need to somehow figure
 * out relationship between RTE ethdev instances in advance.
 *
 * The concept of RTE switch domains resolves this issue. The driver
 * maintains a static list of switch domains which is easy to browse,
 * and each RTE ethdev fills RTE switch parameters in device
 * information structure which is made available to clients.
 *
 * Even if all RTE ethdev instances belonging to a switch domain get
 * unplugged, the corresponding entry in the switch domain registry
 * will not be removed because the corresponding HW switch exists
 * regardless of its ports being plugged to DPDK or kept aside.
 * If a port gets plugged back to DPDK, the corresponding
 * RTE ethdev will indicate the same RTE switch domain ID.
 */
struct sfc_mae_switch {
	/** A lock to protect the whole structure */
	rte_spinlock_t			lock;
	/** Switch domain registry */
	struct sfc_mae_switch_domains	domains;
};

/** FW-allocatable resource context */
struct sfc_mae_fw_rsrc {
	unsigned int			refcnt;
	RTE_STD_C11
	union {
		efx_mae_aset_id_t	aset_id;
	};
};

/** Action set registry entry */
struct sfc_mae_action_set {
	TAILQ_ENTRY(sfc_mae_action_set)	entries;
	unsigned int			refcnt;
	efx_mae_actions_t		*spec;
	struct sfc_mae_fw_rsrc		fw_rsrc;
};

TAILQ_HEAD(sfc_mae_action_sets, sfc_mae_action_set);

/** Options for MAE support status */
enum sfc_mae_status {
	SFC_MAE_STATUS_UNKNOWN = 0,
	SFC_MAE_STATUS_UNSUPPORTED,
	SFC_MAE_STATUS_SUPPORTED
};

/** Rule class registration cache */
struct sfc_mae_rc_cache {
	/**
	 * The last EFX match specification for which class registration
	 * has been conducted successfully
	 */
	efx_mae_match_spec_t		*match_spec;
	/** Handle of the last class registered with the FW */
	efx_mae_rc_handle_t		class_handle;
};

struct sfc_mae {
	/** Switch domain entry */
	struct sfc_mae_switch_domain	*switch_domain;
	/** Switch port entry */
	struct sfc_mae_switch_port	*switch_port;
	/** NIC support for MAE status */
	enum sfc_mae_status		status;
	/** Priority level limit for MAE action rules */
	unsigned int			nb_action_rule_prios_max;
	/** Action rule class registration cache */
	struct sfc_mae_rc_cache		action_rc_cache;
	/** Action set registry */
	struct sfc_mae_action_sets	action_sets;
};

struct sfc_adapter;
struct sfc_flow_spec;

struct sfc_mae_parse_ctx {
	struct sfc_adapter		*sa;
	efx_mae_match_spec_t		*match_spec_action;
	bool				match_mport_set;
};

int sfc_mae_attach(struct sfc_adapter *sa);
void sfc_mae_detach(struct sfc_adapter *sa);
sfc_flow_cleanup_cb_t sfc_mae_flow_cleanup;
int sfc_mae_rule_parse_pattern(struct sfc_adapter *sa,
			       const struct rte_flow_item pattern[],
			       struct sfc_flow_spec_mae *spec,
			       struct rte_flow_error *error);
void sfc_mae_validation_cache_drop(struct sfc_adapter *sa,
				   struct sfc_mae_rc_cache *rc_cache);
int sfc_mae_rule_parse_actions(struct sfc_adapter *sa,
			       const struct rte_flow_action actions[],
			       struct sfc_mae_action_set **action_setp,
			       struct rte_flow_error *error);
sfc_flow_verify_cb_t sfc_mae_flow_verify;
sfc_flow_insert_cb_t sfc_mae_flow_insert;
sfc_flow_remove_cb_t sfc_mae_flow_remove;

#ifdef __cplusplus
}
#endif
#endif /* _SFC_MAE_H */
