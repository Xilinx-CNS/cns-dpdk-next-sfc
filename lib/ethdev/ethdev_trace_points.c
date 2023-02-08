/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#include <rte_trace_point_register.h>

#include <ethdev_trace.h>
#include <rte_ethdev_trace_fp.h>

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_configure,
	lib.ethdev.configure)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_rxq_setup,
	lib.ethdev.rxq.setup)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_txq_setup,
	lib.ethdev.txq.setup)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_start,
	lib.ethdev.start)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_stop,
	lib.ethdev.stop)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_close,
	lib.ethdev.close)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_rx_burst,
	lib.ethdev.rx.burst)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_tx_burst,
	lib.ethdev.tx.burst)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_call_rx_callbacks,
	lib.ethdev.call_rx_callbacks)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_call_tx_callbacks,
	lib.ethdev.call_tx_callbacks)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_iterator_init,
	lib.ethdev.iterator_init)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_iterator_next,
	lib.ethdev.iterator_next)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_iterator_cleanup,
	lib.ethdev.iterator_cleanup)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_find_next,
	lib.ethdev.find_next)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_find_next_of,
	lib.ethdev.find_next_of)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_find_next_sibling,
	lib.ethdev.find_next_sibling)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_is_valid_port,
	lib.ethdev.is_valid_port)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_find_next_owned_by,
	lib.ethdev.find_next_owned_by)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_owner_new,
	lib.ethdev.owner_new)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_owner_set,
	lib.ethdev.owner_set)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_owner_unset,
	lib.ethdev.owner_unset)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_owner_delete,
	lib.ethdev.owner_delete)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_owner_get,
	lib.ethdev.owner_get)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_socket_id,
	lib.ethdev.socket_id)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_get_sec_ctx,
	lib.ethdev.get_sec_ctx)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_count_avail,
	lib.ethdev.count_avail)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_count_total,
	lib.ethdev.count_total)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_get_name_by_port,
	lib.ethdev.get_name_by_port)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_get_port_by_name,
	lib.ethdev.get_port_by_name)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_rx_queue_start,
	lib.ethdev.rx_queue_start)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_rx_queue_stop,
	lib.ethdev.rx_queue_stop)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_tx_queue_start,
	lib.ethdev.tx_queue_start)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_tx_queue_stop,
	lib.ethdev.tx_queue_stop)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_speed_bitflag,
	lib.ethdev.speed_bitflag)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_rx_offload_name,
	lib.ethdev.rx_offload_name)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_tx_offload_name,
	lib.ethdev.tx_offload_name)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_capability_name,
	lib.ethdev.capability_name)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_set_link_up,
	lib.ethdev.set_link_up)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_set_link_down,
	lib.ethdev.set_link_down)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_reset,
	lib.ethdev.reset)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_is_removed,
	lib.ethdev.is_removed)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_rx_hairpin_queue_setup,
	lib.ethdev.rx_hairpin_queue_setup)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_tx_hairpin_queue_setup,
	lib.ethdev.tx_hairpin_queue_setup)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_hairpin_bind,
	lib.ethdev.hairpin_bind)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_hairpin_unbind,
	lib.ethdev.hairpin_unbind)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_hairpin_get_peer_ports,
	lib.ethdev.hairpin_get_peer_ports)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_tx_buffer_drop_callback,
	lib.ethdev.tx_buffer_drop_callback)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_tx_buffer_count_callback,
	lib.ethdev.tx_buffer_count_callback)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_tx_buffer_set_err_callback,
	lib.ethdev.tx_buffer_set_err_callback)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_tx_buffer_init,
	lib.ethdev.tx_buffer_init)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_tx_done_cleanup,
	lib.ethdev.tx_done_cleanup)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_promiscuous_enable,
	lib.ethdev.promiscuous_enable)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_promiscuous_disable,
	lib.ethdev.promiscuous_disable)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_promiscuous_get,
	lib.ethdev.promiscuous_get)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_allmulticast_enable,
	lib.ethdev.allmulticast_enable)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_allmulticast_disable,
	lib.ethdev.allmulticast_disable)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_allmulticast_get,
	lib.ethdev.allmulticast_get)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_link_get,
	lib.ethdev.link_get)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_link_get_nowait,
	lib.ethdev.link_get_nowait)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_link_speed_to_str,
	lib.ethdev.link_speed_to_str)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_link_to_str,
	lib.ethdev.link_to_str)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_stats_get,
	lib.ethdev.stats_get)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_stats_reset,
	lib.ethdev.stats_reset)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_xstats_get_id_by_name,
	lib.ethdev.xstats_get_id_by_name)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_xstats_get_names_by_id,
	lib.ethdev.xstats_get_names_by_id)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_xstats_get_names,
	lib.ethdev.xstats_get_names)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_xstats_get_by_id,
	lib.ethdev.xstats_get_by_id)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_xstats_get,
	lib.ethdev.xstats_get)

RTE_TRACE_POINT_REGISTER(rte_eth_trace_xstats_reset,
	lib.ethdev.xstats_reset)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_set_tx_queue_stats_mapping,
	lib.ethdev.set_tx_queue_stats_mapping)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_set_rx_queue_stats_mapping,
	lib.ethdev.set_rx_queue_stats_mapping)

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_fw_version_get,
	lib.ethdev.fw_version_get)
