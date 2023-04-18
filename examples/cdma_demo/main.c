/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, Advanced Micro Devices, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include <rte_dmadev.h>
#include <rte_dmadev_pmd.h>
#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_pmd_cdx_cdma.h>

#define RTE_LOGTYPE_CDMA_DEMO RTE_LOGTYPE_USER1

#define DMA_SIZE 256

struct intr_args_t {
	volatile int eventfd;
	volatile int sync;
	volatile int success;
};

/* Continue DMA for first device */
bool continuous;

/* Termination signalling */
static volatile bool force_quit;

/* Termination signal handler */
static void handle_sigterm(__rte_unused int value)
{
	force_quit = 1;
}

/* display usage */
static void
cdma_demo_usage(const char *prgname)
{
	printf("%s [EAL options] -- [-C]\n"
	       "  -C/--continuous: continue DMA on first device until quit (Ctrl+C) at 1 second interval.\n"
	       "                   By default this is disabled.\n",
	       prgname);
}

static struct option lgopts[] = {
	{ "continuous", 0, 0, 'C' },
	{ NULL,  0, 0, 0 }
};

/* Parse the argument given in the command line of the application */
static int
cdma_parse_args(int argc, char **argv)
{
	char *prgname = argv[0];
	int opt, option_index;

	while ((opt = getopt_long(argc, argv, "Ch", lgopts,
			&option_index)) != EOF) {
		switch (opt) {
		case 'C':
			continuous = 1;
			break;
		default:
			printf("opt: %d\n", opt);
			cdma_demo_usage(prgname);
			return -1;
		}
	}

	return 0;
}

/* Create thread for handling interrupt */
static void *
wait_on_event(void *args)
{
	struct intr_args_t *intr_args = (struct intr_args_t *)(args);
	struct epoll_event epoll_ev;
	int eventfd, epoll_fd, ret = 1;
	int timeout = 1000, n;
	int num_retries = 10;

	epoll_fd = epoll_create(1);
	eventfd = intr_args->eventfd;

	epoll_ev.events = EPOLLIN | EPOLLPRI | EPOLLET;
	epoll_ev.data.fd = eventfd;

	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, eventfd, &epoll_ev);
	if (ret < 0) {
		RTE_LOG(ERR, CDMA_DEMO, "epoll_ctl failed\n");
		return NULL;
	}

	memset(&epoll_ev, 0, sizeof(struct epoll_event));
	intr_args->sync = 1;

retry:
	n = epoll_wait(epoll_fd, &epoll_ev, 1, timeout);
	/* In case of interrupt retry */
	if (n <= 0) {
		num_retries--;
		if (num_retries == 0) {
			RTE_LOG(ERR, CDMA_DEMO, "epoll_wait failed\n");
			return NULL;
		}
		goto retry;
	}

	if (epoll_ev.data.fd == eventfd && epoll_ev.events & EPOLLIN) {
		uint64_t val = 0;

		eventfd_read(eventfd, &val);
		intr_args->success = 1;
	}

	return NULL;
}

int
main(int argc, char **argv)
{
	uint8_t *src = NULL, *dest = NULL;
	uint64_t retry_count, i;
	uint8_t num_devs, dev_id;
	struct intr_args_t *intr_args = NULL;
	struct sigaction signal_handler;
	pthread_t tid;
	int ret, completed = 0;
	int num_msi, msi_id;
	uint16_t vchan = 0;
	struct rte_dma_conf conf = { .nb_vchans = 1};
	struct rte_dma_vchan_conf qconf = {
			.direction = RTE_DMA_DIR_MEM_TO_MEM,
			.nb_desc = 1,
	};

	memset(&signal_handler, 0, sizeof(signal_handler));
	signal_handler.sa_handler = &handle_sigterm;
	if (sigaction(SIGINT, &signal_handler, NULL) == -1 ||
			sigaction(SIGTERM, &signal_handler, NULL) == -1)
		rte_exit(EXIT_FAILURE, "SIGNAL\n");

	/* Init EAL. */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = cdma_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid CDMA demo arguments\n");

	src = rte_malloc(NULL, DMA_SIZE, RTE_CACHE_LINE_SIZE);
	if (!src) {
		RTE_LOG(ERR, CDMA_DEMO, "Src memory allocation failed\n");
		ret = -ENOMEM;
		goto fail;
	}

	dest = rte_malloc(NULL, DMA_SIZE, RTE_CACHE_LINE_SIZE);
	if (!dest) {
		RTE_LOG(ERR, CDMA_DEMO, "Dest memory allocation failed\n");
		ret = -ENOMEM;
		goto fail;
	}

	intr_args = malloc(sizeof(struct intr_args_t));
	if (!intr_args) {
		RTE_LOG(ERR, CDMA_DEMO, "intr_args memory allocation failed\n");
		ret = -ENOMEM;
		goto fail;
	}

	num_devs = rte_dma_count_avail();
	if (num_devs == 0) {
		RTE_LOG(ERR, CDMA_DEMO, "No CDMA devices found\n");
		ret = 1;
		goto fail;
	}

	RTE_LOG(INFO, CDMA_DEMO, "=================================================\n");
	for (dev_id = 0; dev_id < num_devs; dev_id++) {
		if (rte_dma_configure(dev_id, &conf) != 0) {
			RTE_LOG(ERR, CDMA_DEMO,
				"Error with rte_dma_configure()\n");
			goto fail;
		}

		if (rte_dma_vchan_setup(dev_id, vchan, &qconf) < 0) {
			RTE_LOG(ERR, CDMA_DEMO,
				"Error with queue configuration\n");
			goto fail;
		}

		if (rte_dma_start(dev_id) != 0) {
			RTE_LOG(ERR, CDMA_DEMO,
				"Error with rte_dma_start() for dev_id: %d\n", dev_id);
			goto fail;
		}

		if (continuous == 1 && dev_id == 0)
			RTE_LOG(ERR, CDMA_DEMO,
				"doing continuous DMA on cdma dev 0.\n"
				"\tPress Ctrl + C to stop\n");
dma_again:
		completed = 0;
		retry_count = 100000;

		for (i = 0; i < DMA_SIZE; i++) {
			src[i] = i;
			dest[i] = 0;
		}

		ret = rte_dma_copy(dev_id, vchan, (rte_iova_t)src,
				(rte_iova_t)dest, DMA_SIZE,
				RTE_DMA_OP_FLAG_SUBMIT);
		if (ret < 0) {
			RTE_LOG(ERR, CDMA_DEMO, "rte_dma_copy failed\n");
			goto fail;
		}

		while (retry_count != 0 && completed == 0) {
			completed = rte_dma_completed(dev_id, vchan,
					1, NULL, NULL);
			retry_count--;
		}

		if (completed == 0) {
			RTE_LOG(ERR, CDMA_DEMO, "DMA incomplete\n");
			ret = -1;
			goto fail;
		}

		for (i = 0; i < DMA_SIZE; i++) {
			if (dest[i] != src[i]) {
				RTE_LOG(ERR, CDMA_DEMO, "Data mismatch after DMA\n");
				ret = -1;
				goto fail;
			}
		}

		if ((continuous == 1) && (force_quit == 0) &&
		    (dev_id == 0)) {
			/* 1 second delay so we can run other commands in between */
			sleep(1);
			goto dma_again;
		}

		RTE_LOG(INFO, CDMA_DEMO, "CDMA DMA TEST PASSED for devid: %d\n", dev_id);

		/* Test MSI */
		num_msi = rte_dma_cdx_cdma_num_msi(dev_id);

		for (msi_id = 0; msi_id < num_msi; msi_id++) {
			intr_args->eventfd = rte_dma_cdx_cdma_get_efd(dev_id, msi_id);
			intr_args->sync = 0;
			intr_args->success = 0;

			ret = pthread_create(&tid, NULL, wait_on_event, intr_args);
			if (ret != 0) {
				RTE_LOG(ERR, CDMA_DEMO,
					"pthread_create failed with ret: %d\n", ret);
				goto fail;
			}

			/* Wait until device is ready to epoll */
			while (intr_args->sync != 1)
				;

			ret = rte_dma_cdx_cdma_trigger_fake_msi(dev_id, msi_id);
			if (ret != 0) {
				RTE_LOG(ERR, CDMA_DEMO,
					"trigger event failed with ret: %d\n", ret);
				goto fail;
			}

			pthread_join(tid, NULL);

			if (intr_args->success == 0) {
				RTE_LOG(ERR, CDMA_DEMO,
					"IRQ test failed for dev_id: %d, irq_id: %d\n",
					dev_id, msi_id);
				goto fail;
			}
		}
		if (num_msi)
			RTE_LOG(INFO, CDMA_DEMO,
				"CDMA MSI TEST PASSED for devid %d with %d MSI\n",
				dev_id, num_msi);
		else
			RTE_LOG(INFO, CDMA_DEMO,
				"CDMA MSI NOT APPLICABLE for devid: %d\n", dev_id);

		ret = rte_dma_stop(dev_id);
		if (ret)
			RTE_LOG(ERR, CDMA_DEMO,
				"Error with rte_dma_stop() for devid: %d\n", dev_id);
	}

	RTE_LOG(INFO, CDMA_DEMO, "----CDMA TEST PASSED----\n");
	RTE_LOG(INFO, CDMA_DEMO, "=================================================\n");

	rte_free(src);
	rte_free(dest);
	if (intr_args)
		free(intr_args);

	return 0;

fail:
	if (src)
		rte_free(src);
	if (dest)
		rte_free(dest);
	if (intr_args)
		free(intr_args);

	RTE_LOG(INFO, CDMA_DEMO, "----CDMA TEST FAILED----\n");
	RTE_LOG(INFO, CDMA_DEMO, "=================================================\n");

	return ret;
}
