/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_dev.h>
#include <rte_rawdev.h>
#include <rte_common.h>
#include <rte_pmd_cdx_exerciser.h>

#define MAX_IDENTIFIER_SIZE	128
#define BUF_SIZE		1024

extern int get_msi_data(char *dev_name, uint32_t msi_vector,
		 uint64_t *msi_addr, uint32_t *msi_data);

struct intr_args_t {
	volatile int eventfd;
	volatile int sync;
	volatile int success;
};

/*update with command line argument to test MSI*/
int is_msi;

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
		fprintf(stderr, "epoll_ctl failed\n");
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
				fprintf(stderr, "epoll_wait failed\n");
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

static struct option lgopts[] = {
        { "msi", 0, 0, 'm' },
        { NULL,  0, 0, 0 }
};

/* Parse the argument given in the command line of the application */
static int
parse_cmdline_args(int argc, char **argv)
{
        int opt, option_index;

        while ((opt = getopt_long(argc, argv, "m", lgopts,
                        &option_index)) != EOF) {
		switch (opt) {
                case 'm':
                        is_msi = 1;
                        break;
                default:
			return -EINVAL;
                }
        }

        return 0;
}

int
main(int argc, char** argv)
{
	int ret, i;
	int raw_dev_id;
	struct rte_rawdev *raw_dev;
	char identifier[MAX_IDENTIFIER_SIZE];
	struct intr_args_t *intr_args = NULL;
	int msi_id, num_msi;
	pthread_t tid;
	uint64_t msi_addr;
	uint32_t msi_data;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot init EAL\n");

        argc -= ret;
        argv += ret;
        /* parse application arguments (after the EAL ones) */
        ret = parse_cmdline_args(argc, argv);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Invalid CDX test arguments\n");

	for (i = 0; i < RTE_RAWDEV_MAX_DEVS; i++) {
		if (!rte_rawdevs[i].driver_name ||
			strcmp(rte_rawdevs[i].driver_name, "cdx_exerciser_driver"))
			continue;

		raw_dev_id = i;
		raw_dev = &rte_rawdevs[raw_dev_id];

		/*
		* Unplug and replug the devices.
		* This is not required in usual cases, it is called here to demonstrate
		* rte_cdx_map_device/rte_cdx_upmap_device APIs which are internally
		* called from unplug (rte_cdx_remove) and plug(rte_dev_probe)
		* respectively.
		*
		* As we will rediscover these devices and device probe will again be
		* called.
		*/

		sprintf(identifier, "cdx:%s", raw_dev->name);
		fprintf(stderr,"Removing device: %s\n", raw_dev->name);
		ret = rte_dev_remove(raw_dev->device);
		if (ret < 0) {
			fprintf(stderr,"Failed to detach device %s\n", raw_dev->name);
			goto fail;
		}

		fprintf(stderr,"Probing device with identifier: %s\n", identifier);
		ret = rte_dev_probe(identifier);
		if (ret < 0) {
			fprintf(stderr,"Failed to attach device %s\n", raw_dev->name);
			goto fail;
		}
		/*Trigger self test - MMIO is tested*/
		if (rte_rawdev_selftest(raw_dev_id))
			fprintf(stderr,"Self test failed for device index: %d, device %s\n",
				raw_dev_id, raw_dev->name);
		else
			fprintf(stderr,"Self test passed for device %s\n", raw_dev->name);

		/*Test msg store*/
		if (rte_raw_cdx_exerciser_test_msg_store(raw_dev_id) != 0)
			fprintf(stderr, "Msg store test failed with for device %s, status: %d\n",
				raw_dev->name, ret);
		else
			fprintf(stderr,"Msg store test passed for device %s \n", raw_dev->name);

		/*Test msg load*/
		if (rte_raw_cdx_exerciser_test_msg_load(raw_dev_id) != 0)
			fprintf(stderr, "Msg load test failed with for device %s, status: %d\n",
				raw_dev->name, ret);
		else
			fprintf(stderr,"Msg load test passed for device %s \n", raw_dev->name);

		/*Test MSI*/
		if (is_msi) {
			intr_args = malloc(sizeof(struct intr_args_t));
			if (!intr_args) {
				fprintf(stderr, "intr_args memory allocation failed\n");
				ret = -ENOMEM;
				goto fail;
			}
			num_msi = rte_raw_cdx_exerciser_num_msi(raw_dev_id);
			for (msi_id = 0; msi_id < num_msi; msi_id++) {
				ret = get_msi_data(raw_dev->name, msi_id, &msi_addr, &msi_data);
				if (ret < 0) {
					/*With the absence of EFTEST FW, this can fail. So assigning fixed MSI IOVA
					 * base address knowing that MSI IOVA address is
					 * fixed in SMMU driver(#define MSI_IOVA_BASE 0x8000000)
					 */
					msi_addr = 0x8000040;
				}
				intr_args->eventfd = rte_raw_cdx_exerciser_get_efd(raw_dev_id, msi_id);
				intr_args->sync = 0;
				intr_args->success = 0;

				ret = pthread_create(&tid, NULL, wait_on_event, intr_args);
				if (ret != 0) {
					fprintf(stderr,
							"pthread_create failed with ret: %d\n", ret);
					goto fail;
				}

				/* Wait until device is ready to epoll */
				while (intr_args->sync != 1)
					;
				ret = rte_raw_cdx_exerciser_trigger_msi(raw_dev_id, msi_id, msi_addr, msi_id);
				if (ret != 0) {
					fprintf(stderr,
						"trigger event failed with ret: %d\n", ret);
					goto fail;
				}

				pthread_join(tid, NULL);

				if (intr_args->success == 0) {
					fprintf(stderr,
						"MSI test failed for device: %s, irq_id: %d\n",
						raw_dev->name, msi_id);
					goto fail;
				}
			}

			if (num_msi)
				fprintf(stderr,
					"MSI test passed for device %s with %d MSI\n",
					raw_dev->name, num_msi);
			else
				fprintf(stderr,
					"MSI test not applicable for device %s\n", raw_dev->name);
		}
	}
fail:
	if (intr_args)
		free(intr_args);

	ret = rte_eal_cleanup();
	if (ret)
		fprintf(stderr, "Error from rte_eal_cleanup(), %d\n", ret);

	return ret;
}
