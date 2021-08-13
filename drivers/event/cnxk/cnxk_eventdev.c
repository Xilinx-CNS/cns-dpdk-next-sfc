/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cnxk_eventdev.h"

void
cnxk_sso_info_get(struct cnxk_sso_evdev *dev,
		  struct rte_event_dev_info *dev_info)
{

	dev_info->min_dequeue_timeout_ns = dev->min_dequeue_timeout_ns;
	dev_info->max_dequeue_timeout_ns = dev->max_dequeue_timeout_ns;
	dev_info->max_event_queues = dev->max_event_queues;
	dev_info->max_event_queue_flows = (1ULL << 20);
	dev_info->max_event_queue_priority_levels = 8;
	dev_info->max_event_priority_levels = 1;
	dev_info->max_event_ports = dev->max_event_ports;
	dev_info->max_event_port_dequeue_depth = 1;
	dev_info->max_event_port_enqueue_depth = 1;
	dev_info->max_num_events = dev->max_num_events;
	dev_info->event_dev_cap = RTE_EVENT_DEV_CAP_QUEUE_QOS |
				  RTE_EVENT_DEV_CAP_DISTRIBUTED_SCHED |
				  RTE_EVENT_DEV_CAP_QUEUE_ALL_TYPES |
				  RTE_EVENT_DEV_CAP_RUNTIME_PORT_LINK |
				  RTE_EVENT_DEV_CAP_MULTIPLE_QUEUE_PORT |
				  RTE_EVENT_DEV_CAP_NONSEQ_MODE |
				  RTE_EVENT_DEV_CAP_CARRY_FLOW_ID;
}

int
cnxk_sso_xaq_allocate(struct cnxk_sso_evdev *dev)
{
	char pool_name[RTE_MEMZONE_NAMESIZE];
	uint32_t xaq_cnt, npa_aura_id;
	const struct rte_memzone *mz;
	struct npa_aura_s *aura;
	static int reconfig_cnt;
	int rc;

	if (dev->xaq_pool) {
		rc = roc_sso_hwgrp_release_xaq(&dev->sso, dev->nb_event_queues);
		if (rc < 0) {
			plt_err("Failed to release XAQ %d", rc);
			return rc;
		}
		rte_mempool_free(dev->xaq_pool);
		dev->xaq_pool = NULL;
	}

	/*
	 * Allocate memory for Add work backpressure.
	 */
	mz = rte_memzone_lookup(CNXK_SSO_FC_NAME);
	if (mz == NULL)
		mz = rte_memzone_reserve_aligned(CNXK_SSO_FC_NAME,
						 sizeof(struct npa_aura_s) +
							 RTE_CACHE_LINE_SIZE,
						 0, 0, RTE_CACHE_LINE_SIZE);
	if (mz == NULL) {
		plt_err("Failed to allocate mem for fcmem");
		return -ENOMEM;
	}

	dev->fc_iova = mz->iova;
	dev->fc_mem = mz->addr;

	aura = (struct npa_aura_s *)((uintptr_t)dev->fc_mem +
				     RTE_CACHE_LINE_SIZE);
	memset(aura, 0, sizeof(struct npa_aura_s));

	aura->fc_ena = 1;
	aura->fc_addr = dev->fc_iova;
	aura->fc_hyst_bits = 0; /* Store count on all updates */

	/* Taken from HRM 14.3.3(4) */
	xaq_cnt = dev->nb_event_queues * CNXK_SSO_XAQ_CACHE_CNT;
	if (dev->xae_cnt)
		xaq_cnt += dev->xae_cnt / dev->sso.xae_waes;
	else if (dev->adptr_xae_cnt)
		xaq_cnt += (dev->adptr_xae_cnt / dev->sso.xae_waes) +
			   (CNXK_SSO_XAQ_SLACK * dev->nb_event_queues);
	else
		xaq_cnt += (dev->sso.iue / dev->sso.xae_waes) +
			   (CNXK_SSO_XAQ_SLACK * dev->nb_event_queues);

	plt_sso_dbg("Configuring %d xaq buffers", xaq_cnt);
	/* Setup XAQ based on number of nb queues. */
	snprintf(pool_name, 30, "cnxk_xaq_buf_pool_%d", reconfig_cnt);
	dev->xaq_pool = (void *)rte_mempool_create_empty(
		pool_name, xaq_cnt, dev->sso.xaq_buf_size, 0, 0,
		rte_socket_id(), 0);

	if (dev->xaq_pool == NULL) {
		plt_err("Unable to create empty mempool.");
		rte_memzone_free(mz);
		return -ENOMEM;
	}

	rc = rte_mempool_set_ops_byname(dev->xaq_pool,
					rte_mbuf_platform_mempool_ops(), aura);
	if (rc != 0) {
		plt_err("Unable to set xaqpool ops.");
		goto alloc_fail;
	}

	rc = rte_mempool_populate_default(dev->xaq_pool);
	if (rc < 0) {
		plt_err("Unable to set populate xaqpool.");
		goto alloc_fail;
	}
	reconfig_cnt++;
	/* When SW does addwork (enqueue) check if there is space in XAQ by
	 * comparing fc_addr above against the xaq_lmt calculated below.
	 * There should be a minimum headroom (CNXK_SSO_XAQ_SLACK / 2) for SSO
	 * to request XAQ to cache them even before enqueue is called.
	 */
	dev->xaq_lmt =
		xaq_cnt - (CNXK_SSO_XAQ_SLACK / 2 * dev->nb_event_queues);
	dev->nb_xaq_cfg = xaq_cnt;

	npa_aura_id = roc_npa_aura_handle_to_aura(dev->xaq_pool->pool_id);
	return roc_sso_hwgrp_alloc_xaq(&dev->sso, npa_aura_id,
				       dev->nb_event_queues);
alloc_fail:
	rte_mempool_free(dev->xaq_pool);
	rte_memzone_free(mz);
	return rc;
}

int
cnxk_sso_xae_reconfigure(struct rte_eventdev *event_dev)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	int rc = 0;

	if (event_dev->data->dev_started)
		event_dev->dev_ops->dev_stop(event_dev);

	rc = roc_sso_hwgrp_release_xaq(&dev->sso, dev->nb_event_queues);
	if (rc < 0) {
		plt_err("Failed to release XAQ %d", rc);
		return rc;
	}

	rte_mempool_free(dev->xaq_pool);
	dev->xaq_pool = NULL;
	rc = cnxk_sso_xaq_allocate(dev);
	if (rc < 0) {
		plt_err("Failed to alloc XAQ %d", rc);
		return rc;
	}

	rte_mb();
	if (event_dev->data->dev_started)
		event_dev->dev_ops->dev_start(event_dev);

	return 0;
}

int
cnxk_setup_event_ports(const struct rte_eventdev *event_dev,
		       cnxk_sso_init_hws_mem_t init_hws_fn,
		       cnxk_sso_hws_setup_t setup_hws_fn)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	int i;

	for (i = 0; i < dev->nb_event_ports; i++) {
		struct cnxk_sso_hws_cookie *ws_cookie;
		void *ws;

		/* Free memory prior to re-allocation if needed */
		if (event_dev->data->ports[i] != NULL)
			ws = event_dev->data->ports[i];
		else
			ws = init_hws_fn(dev, i);
		if (ws == NULL)
			goto hws_fini;
		ws_cookie = cnxk_sso_hws_get_cookie(ws);
		ws_cookie->event_dev = event_dev;
		ws_cookie->configured = 1;
		event_dev->data->ports[i] = ws;
		cnxk_sso_port_setup((struct rte_eventdev *)(uintptr_t)event_dev,
				    i, setup_hws_fn);
	}

	return 0;
hws_fini:
	for (i = i - 1; i >= 0; i--) {
		event_dev->data->ports[i] = NULL;
		rte_free(cnxk_sso_hws_get_cookie(event_dev->data->ports[i]));
	}
	return -ENOMEM;
}

void
cnxk_sso_restore_links(const struct rte_eventdev *event_dev,
		       cnxk_sso_link_t link_fn)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	uint16_t *links_map, hwgrp[CNXK_SSO_MAX_HWGRP];
	int i, j;

	for (i = 0; i < dev->nb_event_ports; i++) {
		uint16_t nb_hwgrp = 0;

		links_map = event_dev->data->links_map;
		/* Point links_map to this port specific area */
		links_map += (i * RTE_EVENT_MAX_QUEUES_PER_DEV);

		for (j = 0; j < dev->nb_event_queues; j++) {
			if (links_map[j] == 0xdead)
				continue;
			hwgrp[nb_hwgrp] = j;
			nb_hwgrp++;
		}

		link_fn(dev, event_dev->data->ports[i], hwgrp, nb_hwgrp);
	}
}

int
cnxk_sso_dev_validate(const struct rte_eventdev *event_dev)
{
	struct rte_event_dev_config *conf = &event_dev->data->dev_conf;
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	uint32_t deq_tmo_ns;
	int rc;

	deq_tmo_ns = conf->dequeue_timeout_ns;

	if (deq_tmo_ns == 0)
		deq_tmo_ns = dev->min_dequeue_timeout_ns;
	if (deq_tmo_ns < dev->min_dequeue_timeout_ns ||
	    deq_tmo_ns > dev->max_dequeue_timeout_ns) {
		plt_err("Unsupported dequeue timeout requested");
		return -EINVAL;
	}

	if (conf->event_dev_cfg & RTE_EVENT_DEV_CFG_PER_DEQUEUE_TIMEOUT)
		dev->is_timeout_deq = 1;

	dev->deq_tmo_ns = deq_tmo_ns;

	if (!conf->nb_event_queues || !conf->nb_event_ports ||
	    conf->nb_event_ports > dev->max_event_ports ||
	    conf->nb_event_queues > dev->max_event_queues) {
		plt_err("Unsupported event queues/ports requested");
		return -EINVAL;
	}

	if (conf->nb_event_port_dequeue_depth > 1) {
		plt_err("Unsupported event port deq depth requested");
		return -EINVAL;
	}

	if (conf->nb_event_port_enqueue_depth > 1) {
		plt_err("Unsupported event port enq depth requested");
		return -EINVAL;
	}

	if (dev->xaq_pool) {
		rc = roc_sso_hwgrp_release_xaq(&dev->sso, dev->nb_event_queues);
		if (rc < 0) {
			plt_err("Failed to release XAQ %d", rc);
			return rc;
		}
		rte_mempool_free(dev->xaq_pool);
		dev->xaq_pool = NULL;
	}

	dev->nb_event_queues = conf->nb_event_queues;
	dev->nb_event_ports = conf->nb_event_ports;

	return 0;
}

void
cnxk_sso_queue_def_conf(struct rte_eventdev *event_dev, uint8_t queue_id,
			struct rte_event_queue_conf *queue_conf)
{
	RTE_SET_USED(event_dev);
	RTE_SET_USED(queue_id);

	queue_conf->nb_atomic_flows = (1ULL << 20);
	queue_conf->nb_atomic_order_sequences = (1ULL << 20);
	queue_conf->event_queue_cfg = RTE_EVENT_QUEUE_CFG_ALL_TYPES;
	queue_conf->priority = RTE_EVENT_DEV_PRIORITY_NORMAL;
}

int
cnxk_sso_queue_setup(struct rte_eventdev *event_dev, uint8_t queue_id,
		     const struct rte_event_queue_conf *queue_conf)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);

	plt_sso_dbg("Queue=%d prio=%d", queue_id, queue_conf->priority);
	/* Normalize <0-255> to <0-7> */
	return roc_sso_hwgrp_set_priority(&dev->sso, queue_id, 0xFF, 0xFF,
					  queue_conf->priority / 32);
}

void
cnxk_sso_queue_release(struct rte_eventdev *event_dev, uint8_t queue_id)
{
	RTE_SET_USED(event_dev);
	RTE_SET_USED(queue_id);
}

void
cnxk_sso_port_def_conf(struct rte_eventdev *event_dev, uint8_t port_id,
		       struct rte_event_port_conf *port_conf)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);

	RTE_SET_USED(port_id);
	port_conf->new_event_threshold = dev->max_num_events;
	port_conf->dequeue_depth = 1;
	port_conf->enqueue_depth = 1;
}

int
cnxk_sso_port_setup(struct rte_eventdev *event_dev, uint8_t port_id,
		    cnxk_sso_hws_setup_t hws_setup_fn)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	uintptr_t grps_base[CNXK_SSO_MAX_HWGRP] = {0};
	uint16_t q;

	plt_sso_dbg("Port=%d", port_id);
	if (event_dev->data->ports[port_id] == NULL) {
		plt_err("Invalid port Id %d", port_id);
		return -EINVAL;
	}

	for (q = 0; q < dev->nb_event_queues; q++) {
		grps_base[q] = roc_sso_hwgrp_base_get(&dev->sso, q);
		if (grps_base[q] == 0) {
			plt_err("Failed to get grp[%d] base addr", q);
			return -EINVAL;
		}
	}

	hws_setup_fn(dev, event_dev->data->ports[port_id], grps_base);
	plt_sso_dbg("Port=%d ws=%p", port_id, event_dev->data->ports[port_id]);
	rte_mb();

	return 0;
}

int
cnxk_sso_timeout_ticks(struct rte_eventdev *event_dev, uint64_t ns,
		       uint64_t *tmo_ticks)
{
	RTE_SET_USED(event_dev);
	*tmo_ticks = NSEC2TICK(ns, rte_get_timer_hz());

	return 0;
}

void
cnxk_sso_dump(struct rte_eventdev *event_dev, FILE *f)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);

	roc_sso_dump(&dev->sso, dev->sso.nb_hws, dev->sso.nb_hwgrp, f);
}

static void
cnxk_handle_event(void *arg, struct rte_event event)
{
	struct rte_eventdev *event_dev = arg;

	if (event_dev->dev_ops->dev_stop_flush != NULL)
		event_dev->dev_ops->dev_stop_flush(
			event_dev->data->dev_id, event,
			event_dev->data->dev_stop_flush_arg);
}

static void
cnxk_sso_cleanup(struct rte_eventdev *event_dev, cnxk_sso_hws_reset_t reset_fn,
		 cnxk_sso_hws_flush_t flush_fn, uint8_t enable)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	uintptr_t hwgrp_base;
	uint16_t i;
	void *ws;

	for (i = 0; i < dev->nb_event_ports; i++) {
		ws = event_dev->data->ports[i];
		reset_fn(dev, ws);
	}

	rte_mb();
	ws = event_dev->data->ports[0];

	for (i = 0; i < dev->nb_event_queues; i++) {
		/* Consume all the events through HWS0 */
		hwgrp_base = roc_sso_hwgrp_base_get(&dev->sso, i);
		flush_fn(ws, i, hwgrp_base, cnxk_handle_event, event_dev);
		/* Enable/Disable SSO GGRP */
		plt_write64(enable, hwgrp_base + SSO_LF_GGRP_QCTL);
	}
}

int
cnxk_sso_start(struct rte_eventdev *event_dev, cnxk_sso_hws_reset_t reset_fn,
	       cnxk_sso_hws_flush_t flush_fn)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	struct roc_sso_hwgrp_qos qos[dev->qos_queue_cnt];
	int i, rc;

	plt_sso_dbg();
	for (i = 0; i < dev->qos_queue_cnt; i++) {
		qos->hwgrp = dev->qos_parse_data[i].queue;
		qos->iaq_prcnt = dev->qos_parse_data[i].iaq_prcnt;
		qos->taq_prcnt = dev->qos_parse_data[i].taq_prcnt;
		qos->xaq_prcnt = dev->qos_parse_data[i].xaq_prcnt;
	}
	rc = roc_sso_hwgrp_qos_config(&dev->sso, qos, dev->qos_queue_cnt,
				      dev->xae_cnt);
	if (rc < 0) {
		plt_sso_dbg("failed to configure HWGRP QoS rc = %d", rc);
		return -EINVAL;
	}
	cnxk_sso_cleanup(event_dev, reset_fn, flush_fn, true);
	rte_mb();

	return 0;
}

void
cnxk_sso_stop(struct rte_eventdev *event_dev, cnxk_sso_hws_reset_t reset_fn,
	      cnxk_sso_hws_flush_t flush_fn)
{
	plt_sso_dbg();
	cnxk_sso_cleanup(event_dev, reset_fn, flush_fn, false);
	rte_mb();
}

int
cnxk_sso_close(struct rte_eventdev *event_dev, cnxk_sso_unlink_t unlink_fn)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);
	uint16_t all_queues[CNXK_SSO_MAX_HWGRP];
	uint16_t i;
	void *ws;

	if (!dev->configured)
		return 0;

	for (i = 0; i < dev->nb_event_queues; i++)
		all_queues[i] = i;

	for (i = 0; i < dev->nb_event_ports; i++) {
		ws = event_dev->data->ports[i];
		unlink_fn(dev, ws, all_queues, dev->nb_event_queues);
		rte_free(cnxk_sso_hws_get_cookie(ws));
		event_dev->data->ports[i] = NULL;
	}

	roc_sso_rsrc_fini(&dev->sso);
	rte_mempool_free(dev->xaq_pool);
	rte_memzone_free(rte_memzone_lookup(CNXK_SSO_FC_NAME));

	dev->fc_iova = 0;
	dev->fc_mem = NULL;
	dev->xaq_pool = NULL;
	dev->configured = false;
	dev->is_timeout_deq = 0;
	dev->nb_event_ports = 0;
	dev->max_num_events = -1;
	dev->nb_event_queues = 0;
	dev->min_dequeue_timeout_ns = USEC2NSEC(1);
	dev->max_dequeue_timeout_ns = USEC2NSEC(0x3FF);

	return 0;
}

static void
parse_queue_param(char *value, void *opaque)
{
	struct cnxk_sso_qos queue_qos = {0};
	uint8_t *val = (uint8_t *)&queue_qos;
	struct cnxk_sso_evdev *dev = opaque;
	char *tok = strtok(value, "-");
	struct cnxk_sso_qos *old_ptr;

	if (!strlen(value))
		return;

	while (tok != NULL) {
		*val = atoi(tok);
		tok = strtok(NULL, "-");
		val++;
	}

	if (val != (&queue_qos.iaq_prcnt + 1)) {
		plt_err("Invalid QoS parameter expected [Qx-XAQ-TAQ-IAQ]");
		return;
	}

	dev->qos_queue_cnt++;
	old_ptr = dev->qos_parse_data;
	dev->qos_parse_data = rte_realloc(
		dev->qos_parse_data,
		sizeof(struct cnxk_sso_qos) * dev->qos_queue_cnt, 0);
	if (dev->qos_parse_data == NULL) {
		dev->qos_parse_data = old_ptr;
		dev->qos_queue_cnt--;
		return;
	}
	dev->qos_parse_data[dev->qos_queue_cnt - 1] = queue_qos;
}

static void
parse_qos_list(const char *value, void *opaque)
{
	char *s = strdup(value);
	char *start = NULL;
	char *end = NULL;
	char *f = s;

	while (*s) {
		if (*s == '[')
			start = s;
		else if (*s == ']')
			end = s;

		if (start && start < end) {
			*end = 0;
			parse_queue_param(start + 1, opaque);
			s = end;
			start = end;
		}
		s++;
	}

	free(f);
}

static int
parse_sso_kvargs_dict(const char *key, const char *value, void *opaque)
{
	RTE_SET_USED(key);

	/* Dict format [Qx-XAQ-TAQ-IAQ][Qz-XAQ-TAQ-IAQ] use '-' cause ','
	 * isn't allowed. Everything is expressed in percentages, 0 represents
	 * default.
	 */
	parse_qos_list(value, opaque);

	return 0;
}

static void
cnxk_sso_parse_devargs(struct cnxk_sso_evdev *dev, struct rte_devargs *devargs)
{
	struct rte_kvargs *kvlist;
	uint8_t single_ws = 0;

	if (devargs == NULL)
		return;
	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (kvlist == NULL)
		return;

	rte_kvargs_process(kvlist, CNXK_SSO_XAE_CNT, &parse_kvargs_value,
			   &dev->xae_cnt);
	rte_kvargs_process(kvlist, CNXK_SSO_GGRP_QOS, &parse_sso_kvargs_dict,
			   dev);
	rte_kvargs_process(kvlist, CNXK_SSO_FORCE_BP, &parse_kvargs_value,
			   &dev->force_ena_bp);
	rte_kvargs_process(kvlist, CN9K_SSO_SINGLE_WS, &parse_kvargs_value,
			   &single_ws);
	rte_kvargs_process(kvlist, CN10K_SSO_GW_MODE, &parse_kvargs_value,
			   &dev->gw_mode);
	dev->dual_ws = !single_ws;
	rte_kvargs_free(kvlist);
}

int
cnxk_sso_init(struct rte_eventdev *event_dev)
{
	const struct rte_memzone *mz = NULL;
	struct rte_pci_device *pci_dev;
	struct cnxk_sso_evdev *dev;
	int rc;

	mz = rte_memzone_reserve(CNXK_SSO_MZ_NAME, sizeof(uint64_t),
				 SOCKET_ID_ANY, 0);
	if (mz == NULL) {
		plt_err("Failed to create eventdev memzone");
		return -ENOMEM;
	}

	dev = cnxk_sso_pmd_priv(event_dev);
	pci_dev = container_of(event_dev->dev, struct rte_pci_device, device);
	dev->sso.pci_dev = pci_dev;

	*(uint64_t *)mz->addr = (uint64_t)dev;
	cnxk_sso_parse_devargs(dev, pci_dev->device.devargs);

	/* Initialize the base cnxk_dev object */
	rc = roc_sso_dev_init(&dev->sso);
	if (rc < 0) {
		plt_err("Failed to initialize RoC SSO rc=%d", rc);
		goto error;
	}

	dev->is_timeout_deq = 0;
	dev->min_dequeue_timeout_ns = USEC2NSEC(1);
	dev->max_dequeue_timeout_ns = USEC2NSEC(0x3FF);
	dev->max_num_events = -1;
	dev->nb_event_queues = 0;
	dev->nb_event_ports = 0;

	cnxk_tim_init(&dev->sso);

	return 0;

error:
	rte_memzone_free(mz);
	return rc;
}

int
cnxk_sso_fini(struct rte_eventdev *event_dev)
{
	struct cnxk_sso_evdev *dev = cnxk_sso_pmd_priv(event_dev);

	/* For secondary processes, nothing to be done */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	cnxk_tim_fini();
	roc_sso_rsrc_fini(&dev->sso);
	roc_sso_dev_fini(&dev->sso);

	return 0;
}

int
cnxk_sso_remove(struct rte_pci_device *pci_dev)
{
	return rte_event_pmd_pci_remove(pci_dev, cnxk_sso_fini);
}
