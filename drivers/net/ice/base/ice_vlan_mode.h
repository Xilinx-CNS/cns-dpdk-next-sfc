/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2021 Intel Corporation
 */

#ifndef _ICE_VLAN_MODE_H_
#define _ICE_VLAN_MODE_H_

#include "ice_osdep.h"
#include "ice_status.h"

struct ice_hw;

bool ice_is_dvm_ena(struct ice_hw *hw);
void ice_cache_vlan_mode(struct ice_hw *hw);
enum ice_status ice_set_vlan_mode(struct ice_hw *hw);

#endif /* _ICE_VLAN_MODE_H */
