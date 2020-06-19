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
 * an mport selector, that is, a 32-bit mport ID value. RTE switch port IDs,
 * in turn, are 16-bit values, so indirect mapping has to be maintained:

 * +--------------------+          +---------------------------------------+
 * | RTE switch port ID |  ------  |         MAE switch port entry         |
 * +--------------------+          |         ---------------------         |
 *                                 |                                       |
 *                                 | Entity (PCIe function) mport selector |
 *                                 |                   +                   |
 *                                 |  Port type (independent/representor)  |
 *                                 +---------------------------------------+
 *
 * This mapping comprises a port type to ensure that RTE switch port ID
 * of a represented entity and that of its representor are different in
 * the case when the entity gets plugged into DPDK and not into a guest.
 *
 * Entry data also comprises RTE ethdev's own mport ID. This value
 * coincides with the entity mport ID in the case of independent ports.
 * In the case of representors, this ID is not a selector and refers
 * to an allocatable object (that is, it's likely to change on RTE
 * ethdev replug). Flow API backend must use this value rather
 * than entity_mport_id to support flow rule action PORT_ID.
 */
struct sfc_mae_switch_port {
	TAILQ_ENTRY(sfc_mae_switch_port)	switch_domain_ports;

	/** RTE ethdev mport ID */
	efx_mport_id_t				ethdev_mport_id;
	/** RTE ethdev port ID */
	uint16_t				ethdev_port_id;

	/** Entity (PCIe function) mport selector */
	efx_mport_id_t				entity_mport_id;
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
 * entity (PCIe function) m-port selector is static and cannot
 * change. If this RTE ethdev gets plugged back, the entry
 * will be reused, and RTE switch port ID will be the same.
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
	unsigned int		refcnt;
	efx_mae_aset_id_t	id;
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

struct sfc_mae {
	/** Switch domain entry */
	struct sfc_mae_switch_domain	*switch_domain;
	/** Switch port entry */
	struct sfc_mae_switch_port	*switch_port;
	/** NIC support for MAE status */
	enum sfc_mae_status		status;
	/** Priority level limit for MAE action rules */
	unsigned int			nb_action_rule_prios_max;
	/**
	 * The last EFX match specification for which class registration
	 * has been conducted successfully
	 */
	efx_mae_match_spec_t		*match_spec_cache;
	/** Handle of the last class registered with the FW */
	efx_mae_rc_handle_t		rule_class_cache;
	/** Action set registry */
	struct sfc_mae_action_sets	action_sets;
};

struct sfc_adapter;
struct sfc_flow_spec;

/** This implementation supports double-tagging */
#define SFC_MAE_MATCH_VLAN_MAX_NTAGS	(2)

/** It is possible to keep track of one item ETH and two items VLAN */
#define SFC_MAE_L2_MAX_NITEMS		(SFC_MAE_MATCH_VLAN_MAX_NTAGS + 1)

/** Auxiliary entry format to keep track of L2 "type" ("inner_type") */
struct sfc_mae_ethertype {
	rte_be16_t	value;
	rte_be16_t	mask;
};

struct sfc_mae_pattern_data {
	/**
	 * Keeps track of "type" ("inner_type") mask and value for each
	 * parsed L2 item in a pattern. These values/masks get filled
	 * in MAE match specification at the end of parsing. Also, this
	 * information is used to conduct consistency checks:
	 *
	 * - If an item ETH is followed by a single item VLAN,
	 *   the former must have "type" set to one of supported
	 *   TPID values (0x8100, 0x88a8, 0x9100, 0x9200, 0x9300).
	 *
	 * - If an item ETH is followed by two items VLAN, the
	 *   item ETH must have "type" set to one of supported TPID
	 *   values (0x88a8, 0x9100, 0x9200, 0x9300), and the outermost
	 *   VLAN item must have "inner_type" set to TPID value 0x8100.
	 *
	 * - If a L2 item is followed by a L3 one, the former must
	 *   indicate "type" ("inner_type") which corresponds to
	 *   the protocol used in the L3 item, or 0x0000/0x0000.
	 *
	 * In turn, mapping between RTE convention (above requirements) and
	 * MAE fields is non-trivial. The following scheme indicates
	 * which item EtherTypes go to which MAE fields in the case
	 * of single tag:
	 *
	 * ETH	(0x8100)	--> VLAN0_PROTO_BE
	 * VLAN	(L3 EtherType)	--> ETHER_TYPE_BE
	 *
	 * Similarly, in the case of double tagging:
	 *
	 * ETH	(0x88a8)	--> VLAN0_PROTO_BE
	 * VLAN	(0x8100)	--> VLAN1_PROTO_BE
	 * VLAN	(L3 EtherType)	--> ETHER_TYPE_BE
	 */
	struct sfc_mae_ethertype	ethertypes[SFC_MAE_L2_MAX_NITEMS];
	unsigned int			nb_vlan_tags;

	/**
	 * L3 requirement for the innermost L2 item's "type" ("inner_type").
	 * This contains one of:
	 * - 0x0800/0xffff: IPV4
	 * - 0x86dd/0xffff: IPV6
	 * - 0x0000/0x0000: no L3 item
	 */
	struct sfc_mae_ethertype	innermost_ethertype_restriction;

	/**
	 * The following two fields keep track of L3 "proto" mask and value.
	 * The corresponding fields get filled in MAE match specification
	 * at the end of parsing. Also, the information is used by a
	 * post-check to enforce consistency requirements:
	 *
	 * - If a L3 item is followed by an item TCP, the former has
	 *   its "proto" set to either 0x06/0xff or 0x00/0x00.
	 *
	 * - If a L3 item is followed by an item UDP, the former has
	 *   its "proto" set to either 0x11/0xff or 0x00/0x00.
	 */
	uint8_t				l3_next_proto_value;
	uint8_t				l3_next_proto_mask;

	/*
	 * L4 requirement for L3 item's "proto".
	 * This contains one of:
	 * - 0x06/0xff: TCP
	 * - 0x11/0xff: UDP
	 * - 0x00/0x00: no L4 item
	 */
	uint8_t				l3_next_proto_restriction_value;
	uint8_t				l3_next_proto_restriction_mask;
};

struct sfc_mae_parse_ctx {
	efx_mae_match_spec_t		*match_spec_action;
	bool				match_mport_set;
	struct sfc_mae_switch_domain	*switch_domain;
	struct sfc_mae_pattern_data	pattern_data;
	uint32_t			pf;
};

int sfc_mae_attach(struct sfc_adapter *sa);
void sfc_mae_detach(struct sfc_adapter *sa);
sfc_flow_cleanup_cb_t sfc_mae_flow_cleanup;
int sfc_mae_rule_parse_pattern(struct sfc_adapter *sa,
			       const struct rte_flow_item pattern[],
			       struct sfc_flow_spec_mae *spec,
			       struct rte_flow_error *error);
void sfc_mae_validation_cache_drop(struct sfc_adapter *sa,
				   efx_mae_rc_handle_t *retained_classp);
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
