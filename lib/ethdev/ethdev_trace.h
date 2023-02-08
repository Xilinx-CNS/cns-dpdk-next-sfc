/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#ifndef _RTE_ETHDEV_TRACE_H_
#define _RTE_ETHDEV_TRACE_H_

/**
 * @file
 *
 * API for ethdev trace support
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <dev_driver.h>
#include <rte_trace_point.h>

#include "rte_ethdev.h"

RTE_TRACE_POINT(
	rte_ethdev_trace_configure,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t nb_rx_q,
		uint16_t nb_tx_q, const struct rte_eth_conf *dev_conf, int rc),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(nb_rx_q);
	rte_trace_point_emit_u16(nb_tx_q);
	rte_trace_point_emit_u32(dev_conf->link_speeds);
	rte_trace_point_emit_u32(dev_conf->rxmode.mq_mode);
	rte_trace_point_emit_u32(dev_conf->rxmode.mtu);
	rte_trace_point_emit_u64(dev_conf->rxmode.offloads);
	rte_trace_point_emit_u32(dev_conf->txmode.mq_mode);
	rte_trace_point_emit_u64(dev_conf->txmode.offloads);
	rte_trace_point_emit_u32(dev_conf->lpbk_mode);
	rte_trace_point_emit_int(rc);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rxq_setup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id,
		uint16_t nb_rx_desc, void *mp,
		const struct rte_eth_rxconf *rx_conf, int rc),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_u16(nb_rx_desc);
	rte_trace_point_emit_ptr(mp);
	rte_trace_point_emit_u8(rx_conf->rx_thresh.pthresh);
	rte_trace_point_emit_u8(rx_conf->rx_thresh.hthresh);
	rte_trace_point_emit_u8(rx_conf->rx_thresh.wthresh);
	rte_trace_point_emit_u8(rx_conf->rx_drop_en);
	rte_trace_point_emit_u8(rx_conf->rx_deferred_start);
	rte_trace_point_emit_u64(rx_conf->offloads);
	rte_trace_point_emit_int(rc);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_txq_setup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id,
		uint16_t nb_tx_desc, const struct rte_eth_txconf *tx_conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_u16(nb_tx_desc);
	rte_trace_point_emit_u8(tx_conf->tx_thresh.pthresh);
	rte_trace_point_emit_u8(tx_conf->tx_thresh.hthresh);
	rte_trace_point_emit_u8(tx_conf->tx_thresh.wthresh);
	rte_trace_point_emit_u8(tx_conf->tx_deferred_start);
	rte_trace_point_emit_u16(tx_conf->tx_free_thresh);
	rte_trace_point_emit_u64(tx_conf->offloads);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_start,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_stop,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_close,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_iterator_init,
	RTE_TRACE_POINT_ARGS(const char *devargs),
	rte_trace_point_emit_string(devargs);
)

RTE_TRACE_POINT(
	rte_eth_trace_iterator_next,
	RTE_TRACE_POINT_ARGS(const struct rte_dev_iterator *iter, uint16_t id),
	rte_trace_point_emit_string(iter->bus_str);
	rte_trace_point_emit_string(iter->cls_str);
	rte_trace_point_emit_u16(id);
)

RTE_TRACE_POINT(
	rte_eth_trace_iterator_cleanup,
	RTE_TRACE_POINT_ARGS(const struct rte_dev_iterator *iter),
	rte_trace_point_emit_string(iter->bus_str);
	rte_trace_point_emit_string(iter->cls_str);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_new,
	RTE_TRACE_POINT_ARGS(uint64_t owner_id),
	rte_trace_point_emit_u64(owner_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_set,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		const struct rte_eth_dev_owner *owner, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(owner->id);
	rte_trace_point_emit_string(owner->name);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_unset,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint64_t owner_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(owner_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_delete,
	RTE_TRACE_POINT_ARGS(uint64_t owner_id, int ret),
	rte_trace_point_emit_u64(owner_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_socket_id,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int socket_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(socket_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_queue_start,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_queue_stop,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_tx_queue_start,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_tx_queue_stop,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_speed_bitflag,
	RTE_TRACE_POINT_ARGS(uint32_t speed, int duplex, uint32_t ret),
	rte_trace_point_emit_u32(speed);
	rte_trace_point_emit_int(duplex);
	rte_trace_point_emit_u32(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_offload_name,
	RTE_TRACE_POINT_ARGS(uint64_t offload, const char *name),
	rte_trace_point_emit_u64(offload);
	rte_trace_point_emit_string(name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_tx_offload_name,
	RTE_TRACE_POINT_ARGS(uint64_t offload, const char *name),
	rte_trace_point_emit_u64(offload);
	rte_trace_point_emit_string(name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_capability_name,
	RTE_TRACE_POINT_ARGS(uint64_t capability, const char *name),
	rte_trace_point_emit_u64(capability);
	rte_trace_point_emit_string(name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_link_up,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_link_down,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_reset,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_rx_hairpin_queue_setup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id,
		uint16_t nb_rx_desc, const struct rte_eth_hairpin_conf *conf,
		int ret),
	uint16_t peer_count = conf->peer_count;
	uint8_t tx_explicit = conf->tx_explicit;
	uint8_t manual_bind = conf->manual_bind;
	uint8_t use_locked_device_memory = conf->use_locked_device_memory;
	uint8_t use_rte_memory = conf->use_rte_memory;
	uint8_t force_memory = conf->force_memory;

	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_u16(nb_rx_desc);
	rte_trace_point_emit_u16(peer_count);
	rte_trace_point_emit_u8(tx_explicit);
	rte_trace_point_emit_u8(manual_bind);
	rte_trace_point_emit_u8(use_locked_device_memory);
	rte_trace_point_emit_u8(use_rte_memory);
	rte_trace_point_emit_u8(force_memory);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_hairpin_queue_setup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id,
		uint16_t nb_tx_desc, const struct rte_eth_hairpin_conf *conf,
		int ret),
	uint16_t peer_count = conf->peer_count;
	uint8_t tx_explicit = conf->tx_explicit;
	uint8_t manual_bind = conf->manual_bind;
	uint8_t use_locked_device_memory = conf->use_locked_device_memory;
	uint8_t use_rte_memory = conf->use_rte_memory;
	uint8_t force_memory = conf->force_memory;

	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_u16(nb_tx_desc);
	rte_trace_point_emit_u16(peer_count);
	rte_trace_point_emit_u8(tx_explicit);
	rte_trace_point_emit_u8(manual_bind);
	rte_trace_point_emit_u8(use_locked_device_memory);
	rte_trace_point_emit_u8(use_rte_memory);
	rte_trace_point_emit_u8(force_memory);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_hairpin_bind,
	RTE_TRACE_POINT_ARGS(uint16_t tx_port, uint16_t rx_port, int ret),
	rte_trace_point_emit_u16(tx_port);
	rte_trace_point_emit_u16(rx_port);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_hairpin_unbind,
	RTE_TRACE_POINT_ARGS(uint16_t tx_port, uint16_t rx_port, int ret),
	rte_trace_point_emit_u16(tx_port);
	rte_trace_point_emit_u16(rx_port);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_buffer_set_err_callback,
	RTE_TRACE_POINT_ARGS(const struct rte_eth_dev_tx_buffer *buffer),
	rte_trace_point_emit_ptr(buffer->error_callback);
	rte_trace_point_emit_ptr(buffer->error_userdata);
)

RTE_TRACE_POINT(
	rte_eth_trace_promiscuous_enable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int promiscuous, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(promiscuous);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_promiscuous_disable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int promiscuous, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(promiscuous);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_allmulticast_enable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int all_multicast, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(all_multicast);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_allmulticast_disable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int all_multicast, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(all_multicast);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_rx_queue_stats_mapping,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id,
		uint8_t stat_idx, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_u8(stat_idx);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_tx_queue_stats_mapping,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id,
		uint8_t stat_idx, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_u8(stat_idx);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_fw_version_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const char *fw_version,
		size_t fw_size, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(fw_version);
	rte_trace_point_emit_size_t(fw_size);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_find_next,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_find_next_of,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const struct rte_device *parent),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(parent->name);
	rte_trace_point_emit_string(parent->bus_info);
	rte_trace_point_emit_int(parent->numa_node);
)

RTE_TRACE_POINT(
	rte_eth_trace_find_next_sibling,
	RTE_TRACE_POINT_ARGS(uint16_t port_id_start, uint16_t ref_port_id,
		uint16_t ret),
	rte_trace_point_emit_u16(port_id_start);
	rte_trace_point_emit_u16(ref_port_id);
	rte_trace_point_emit_u16(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_is_valid_port,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int is_valid),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(is_valid);
)

RTE_TRACE_POINT(
	rte_eth_trace_find_next_owned_by,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint64_t owner_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(owner_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		const struct rte_eth_dev_owner *owner),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(owner->id);
	rte_trace_point_emit_string(owner->name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_sec_ctx,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const void *ctx),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(ctx);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_count_avail,
	RTE_TRACE_POINT_ARGS(uint16_t count),
	rte_trace_point_emit_u16(count);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_count_total,
	RTE_TRACE_POINT_ARGS(uint16_t count),
	rte_trace_point_emit_u16(count);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_name_by_port,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const char *name),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_port_by_name,
	RTE_TRACE_POINT_ARGS(const char *name, uint16_t port_id),
	rte_trace_point_emit_string(name);
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_is_removed,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_hairpin_get_peer_ports,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const uint16_t *peer_ports,
		size_t len, uint32_t direction, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(peer_ports);
	rte_trace_point_emit_size_t(len);
	rte_trace_point_emit_u32(direction);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_buffer_init,
	RTE_TRACE_POINT_ARGS(const struct rte_eth_dev_tx_buffer *buffer,
		uint16_t size, int ret),
	rte_trace_point_emit_ptr(buffer);
	rte_trace_point_emit_u16(size);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_done_cleanup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		uint32_t free_cnt, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_u32(free_cnt);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_promiscuous_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int promiscuous),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(promiscuous);
)

RTE_TRACE_POINT(
	rte_eth_trace_allmulticast_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int all_multicast),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(all_multicast);
)

RTE_TRACE_POINT(
	rte_eth_trace_link_get_nowait,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const struct rte_eth_link *link),
	uint8_t link_duplex = link->link_duplex;
	uint8_t link_autoneg = link->link_autoneg;
	uint8_t link_status = link->link_status;

	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(link->link_speed);
	rte_trace_point_emit_u8(link_duplex);
	rte_trace_point_emit_u8(link_autoneg);
	rte_trace_point_emit_u8(link_status);
)

RTE_TRACE_POINT(
	rte_eth_trace_link_to_str,
	RTE_TRACE_POINT_ARGS(size_t len, const struct rte_eth_link *link,
		char *str, int ret),
	uint8_t link_duplex = link->link_duplex;
	uint8_t link_autoneg = link->link_autoneg;
	uint8_t link_status = link->link_status;

	rte_trace_point_emit_size_t(len);
	rte_trace_point_emit_u32(link->link_speed);
	rte_trace_point_emit_u8(link_duplex);
	rte_trace_point_emit_u8(link_autoneg);
	rte_trace_point_emit_u8(link_status);
	rte_trace_point_emit_string(str);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_stats_reset,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_xstats_get_id_by_name,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const char *xstat_name,
		uint64_t id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(xstat_name);
	rte_trace_point_emit_u64(id);
)

RTE_TRACE_POINT(
	rte_eth_trace_xstats_get_names_by_id,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		const struct rte_eth_xstat_name *xstats_names, uint64_t ids),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(xstats_names->name);
	rte_trace_point_emit_u64(ids);
)

RTE_TRACE_POINT(
	rte_eth_trace_xstats_get_names,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int i,
		struct rte_eth_xstat_name xstats_names,
		unsigned int size, int cnt_used_entries),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(i);
	rte_trace_point_emit_string(xstats_names.name);
	rte_trace_point_emit_u32(size);
	rte_trace_point_emit_int(cnt_used_entries);
)

RTE_TRACE_POINT(
	rte_eth_trace_xstats_get_by_id,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const uint64_t *ids,
		const uint64_t *values, unsigned int size),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(ids);
	rte_trace_point_emit_ptr(values);
	rte_trace_point_emit_u32(size);
)

RTE_TRACE_POINT(
	rte_eth_trace_xstats_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_xstat xstats),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(xstats.id);
	rte_trace_point_emit_u64(xstats.value);
)

RTE_TRACE_POINT(
	rte_eth_trace_xstats_reset,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

/* Fast path trace points */

/* Called in loop in examples/qos_sched and examples/distributor */
RTE_TRACE_POINT_FP(
	rte_eth_trace_stats_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		const struct rte_eth_stats *stats, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(stats->rx_nombuf);
	rte_trace_point_emit_u64(stats->ipackets);
	rte_trace_point_emit_u64(stats->opackets);
	rte_trace_point_emit_u64(stats->ibytes);
	rte_trace_point_emit_u64(stats->obytes);
	rte_trace_point_emit_u64(stats->imissed);
	rte_trace_point_emit_u64(stats->ierrors);
	rte_trace_point_emit_u64(stats->oerrors);
	rte_trace_point_emit_int(ret);
)

/* Called in loop in examples/ip_pipeline */
RTE_TRACE_POINT_FP(
	rte_eth_trace_link_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const struct rte_eth_link *link),
	uint8_t link_duplex = link->link_duplex;
	uint8_t link_autoneg = link->link_autoneg;
	uint8_t link_status = link->link_status;

	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(link->link_speed);
	rte_trace_point_emit_u8(link_duplex);
	rte_trace_point_emit_u8(link_autoneg);
	rte_trace_point_emit_u8(link_status);
)

/* Called in loop in examples/ip_pipeline */
RTE_TRACE_POINT_FP(
	rte_eth_trace_link_speed_to_str,
	RTE_TRACE_POINT_ARGS(uint32_t link_speed, const char *ret),
	rte_trace_point_emit_u32(link_speed);
	rte_trace_point_emit_string(ret);
)

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ETHDEV_TRACE_H_ */
