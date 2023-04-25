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

#include <rte_eal.h>
#include <rte_dev.h>
#include <rte_rawdev.h>
#include <rte_common.h>
#include <rte_pmd_cdx_exerciser.h>

#define MAX_IDENTIFIER_SIZE	128

int
main(int argc, char** argv)
{
	int ret, i;
	int raw_dev_id;
	struct rte_rawdev *raw_dev;
	char identifier[MAX_IDENTIFIER_SIZE];

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot init EAL\n");


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

	}

fail:
	ret = rte_eal_cleanup();
	if (ret)
		fprintf(stderr, "Error from rte_eal_cleanup(), %d\n", ret);

	return ret;
}
