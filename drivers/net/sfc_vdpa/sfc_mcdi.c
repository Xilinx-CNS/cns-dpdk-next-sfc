/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2016-2018 Solarflare Communications Inc.
 * All rights reserved.
 *
 * This software was jointly developed between OKTET Labs (under contract
 * for Solarflare) and Solarflare Communications, Inc.
 */

#include <rte_cycles.h>

#include "efx.h"
#include "efx_mcdi.h"
#include "efx_regs_mcdi.h"


#include "sfc_vdpa.h"

#define SFC_MCDI_POLL_INTERVAL_MIN_US	10		/* 10us in 1us units */
#define SFC_MCDI_POLL_INTERVAL_MAX_US	(US_PER_S / 10)	/* 100ms in 1us units */
#define SFC_MCDI_WATCHDOG_INTERVAL_US	(10 * US_PER_S)	/* 10s in 1us units */

static void
sfc_vdpa_mcdi_timeout(struct sfc_vdpa_adapter *sva)
{
	sfc_warn(sva, "MC TIMEOUT");

	sfc_panic(sva, "MCDI timeout handling is not implemented\n");
}

static void
sfc_vdpa_mcdi_poll(struct sfc_vdpa_adapter *sva)
{
	efx_nic_t *enp;
	unsigned int delay_total;
	unsigned int delay_us;
	boolean_t aborted __rte_unused;

	delay_total = 0;
	delay_us = SFC_MCDI_POLL_INTERVAL_MIN_US;
	enp = sva->nic;

	do {
		boolean_t poll_completed;

		poll_completed = efx_mcdi_request_poll(enp);
		if (poll_completed)
			return;

		if (delay_total > SFC_MCDI_WATCHDOG_INTERVAL_US) {
			aborted = efx_mcdi_request_abort(enp);
			SFC_ASSERT(aborted);
			sfc_vdpa_mcdi_timeout(sva);
			return;
		}

		rte_delay_us(delay_us);

		delay_total += delay_us;

		/* Exponentially back off the poll frequency */
		RTE_BUILD_BUG_ON(SFC_MCDI_POLL_INTERVAL_MAX_US > UINT_MAX / 2);
		delay_us *= 2;
		if (delay_us > SFC_MCDI_POLL_INTERVAL_MAX_US)
			delay_us = SFC_MCDI_POLL_INTERVAL_MAX_US;

	} while (1);
}

static void
sfc_vdpa_mcdi_execute(void *arg, efx_mcdi_req_t *emrp)
{
	struct sfc_vdpa_adapter *sva = (struct sfc_vdpa_adapter *)arg;
	struct sfc_vdpa_mcdi *mcdi = &sva->mcdi;

	rte_spinlock_lock(&mcdi->lock);

	SFC_ASSERT(mcdi->state == SFC_MCDI_INITIALIZED);

	efx_mcdi_request_start(sva->nic, emrp, B_FALSE);
	sfc_vdpa_mcdi_poll(sva);

	rte_spinlock_unlock(&mcdi->lock);
}

static void
sfc_vdpa_mcdi_ev_cpl(void *arg)
{
	struct sfc_vdpa_adapter *sva = (struct sfc_vdpa_adapter *)arg;
	struct sfc_vdpa_mcdi *mcdi __rte_unused;

	mcdi = &sva->mcdi;
	SFC_ASSERT(mcdi->state == SFC_MCDI_INITIALIZED);

	/* MCDI is polled, completions are not expected */
	SFC_ASSERT(0);
}

static void
sfc_vdpa_mcdi_exception(void *arg, efx_mcdi_exception_t eme)
{
	struct sfc_vdpa_adapter *sva = (struct sfc_vdpa_adapter *)arg;

	sfc_warn(sva, "MC %s",
	    (eme == EFX_MCDI_EXCEPTION_MC_REBOOT) ? "REBOOT" :
	    (eme == EFX_MCDI_EXCEPTION_MC_BADASSERT) ? "BADASSERT" : "UNKNOWN");
	// TODO
	//sfc_schedule_restart(sva);
}

#define SFC_MCDI_LOG_BUF_SIZE	128

static size_t
sfc_mcdi_do_log(const struct sfc_vdpa_adapter *sva,
		char *buffer, void *data, size_t data_size,
		size_t pfxsize, size_t position)
{
	uint32_t *words = data;
	/* Space separator plus 2 characters per byte */
	const size_t word_str_space = 1 + 2 * sizeof(*words);
	size_t i;

	for (i = 0; i < data_size; i += sizeof(*words)) {
		if (position + word_str_space >=
		    SFC_MCDI_LOG_BUF_SIZE) {
			/* Flush at SFC_MCDI_LOG_BUF_SIZE with backslash
			 * at the end which is required by netlogdecode.
			 */
			buffer[position] = '\0';
			sfc_log_mcdi(sva, "%s \\", buffer);
			/* Preserve prefix for the next log message */
			position = pfxsize;
		}
		position += snprintf(buffer + position,
				     SFC_MCDI_LOG_BUF_SIZE - position,
				     " %08x", *words);
		words++;
	}
	return position;
}

static void
sfc_mcdi_logger(void *arg, efx_log_msg_t type,
		void *header, size_t header_size,
		void *data, size_t data_size)
{
	struct sfc_vdpa_adapter *sva = (struct sfc_vdpa_adapter *)arg;
	char buffer[SFC_MCDI_LOG_BUF_SIZE];
	size_t pfxsize;
	size_t start;

	/*
	 * Unlike the other cases, MCDI logging implies more onerous work
	 * needed to produce a message. If the dynamic log level prevents
	 * the end result from being printed, the CPU time will be wasted.
	 *
	 * To avoid wasting time, the actual level is examined in advance.
	 */
	if (rte_log_get_level(sva->mcdi.logtype) < (int)SFC_LOG_LEVEL_MCDI)
		return;

	/* The format including prefix added by sfc_log_mcdi() is the format
	 * consumed by the Solarflare netlogdecode tool.
	 */
	pfxsize = snprintf(buffer, sizeof(buffer), "MCDI RPC %s:",
			   type == EFX_LOG_MCDI_REQUEST ? "REQ" :
			   type == EFX_LOG_MCDI_RESPONSE ? "RESP" : "???");
	start = sfc_mcdi_do_log(sva, buffer, header, header_size,
				pfxsize, pfxsize);
	start = sfc_mcdi_do_log(sva, buffer, data, data_size, pfxsize, start);
	if (start != pfxsize) {
		buffer[start] = '\0';
		sfc_log_mcdi(sva, "%s", buffer);
	}
}


int
sfc_vdpa_mcdi_init(struct sfc_vdpa_adapter *sva)
{
	struct sfc_vdpa_mcdi *mcdi;
	size_t max_msg_size;
	efx_mcdi_transport_t *emtp;
	int rc;

	sfc_log_init(sva, "entry");

	mcdi = &sva->mcdi;

	SFC_ASSERT(mcdi->state == SFC_MCDI_UNINITIALIZED);

	rte_spinlock_init(&mcdi->lock);

	mcdi->state = SFC_MCDI_INITIALIZED;

	max_msg_size = sizeof(uint32_t) + MCDI_CTL_SDU_LEN_MAX_V2;
	rc = sfc_dma_alloc(sva, "mcdi", 0, max_msg_size, &mcdi->mem);
	if (rc != 0)
		goto fail_dma_alloc;

	mcdi->logtype = sfc_vdpa_register_logtype(sva, SFC_LOGTYPE_MCDI_STR,
					     RTE_LOG_NOTICE);

	emtp = &mcdi->transport;
	emtp->emt_context = sva;
	emtp->emt_dma_mem = &mcdi->mem;
	emtp->emt_execute = sfc_vdpa_mcdi_execute;
	emtp->emt_ev_cpl = sfc_vdpa_mcdi_ev_cpl;
	emtp->emt_exception = sfc_vdpa_mcdi_exception;
	emtp->emt_logger = sfc_mcdi_logger;
	emtp->emt_ev_proxy_response = NULL;

	sfc_log_init(sva, "init MCDI");
	rc = efx_mcdi_init(sva->nic, emtp);
	if (rc != 0)
		goto fail_mcdi_init;

	return 0;

fail_mcdi_init:
	memset(emtp, 0, sizeof(*emtp));
	sfc_dma_free(sva, &mcdi->mem);

fail_dma_alloc:
	mcdi->state = SFC_MCDI_UNINITIALIZED;
	return rc;
}

void
sfc_vdpa_mcdi_fini(struct sfc_vdpa_adapter *sva)
{
	struct sfc_vdpa_mcdi *mcdi;
	efx_mcdi_transport_t *emtp;

	sfc_log_init(sva, "entry");

	mcdi = &sva->mcdi;
	emtp = &mcdi->transport;

	rte_spinlock_lock(&mcdi->lock);

	SFC_ASSERT(mcdi->state == SFC_MCDI_INITIALIZED);
	mcdi->state = SFC_MCDI_UNINITIALIZED;

	sfc_log_init(sva, "fini MCDI");
	efx_mcdi_fini(sva->nic);
	memset(emtp, 0, sizeof(*emtp));

	rte_spinlock_unlock(&mcdi->lock);

	sfc_dma_free(sva, &mcdi->mem);
}

