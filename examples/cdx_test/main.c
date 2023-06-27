/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <stdio.h>

#include <rte_eal.h>
#include <rte_dev.h>
#include <bus_cdx_driver.h>

#define NUM_WORDS_TO_PRINT	0x28
#define MAX_CDX_TEST_DEVICES	8
#define MAX_IDENTIFIER_SIZE	128

static struct rte_cdx_device *g_cdx_dev[MAX_CDX_TEST_DEVICES];
static int num_cdx_devices;

int
main(int argc, char** argv)
{
	volatile uint32_t *addr;
	int curr_cdx_devices;
	int ret, i, j, k;
	int pr_len;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot init EAL\n");
	/*
	 * Unplug and replug the devices.
	 * This is not required in usual cases, it is called here to demonstrate
	 * rte_cdx_map_device/rte_cdx_upmap_device APIs which are internally
	 * called from unplug (rte_cdx_remove) and plug(rte_dev_probe)
	 * respectively.
	 *
	 * As we will rediscover these devices and device probe will again be
	 * called set num_cdx_devices to 0, again for demonstration purpose only.
	 */
	curr_cdx_devices = num_cdx_devices;
	num_cdx_devices = 0;
	for (i = 0; i < curr_cdx_devices; i++) {
		char identifier[MAX_IDENTIFIER_SIZE];
		char dev_name[RTE_DEV_NAME_MAX_LEN];

		sprintf(dev_name, "%s", g_cdx_dev[i]->device.name);
		sprintf(identifier, "cdx:%s", dev_name);

		printf("Removing device: %s\n", dev_name);
		ret = rte_dev_remove(&g_cdx_dev[i]->device);
		if (ret < 0) {
			printf("Failed to detach device %s\n", dev_name);
			return ret;
		}

		printf("Probing device with identifier: %s\n", identifier);
		ret = rte_dev_probe(identifier);
		if (ret < 0) {
			printf("Failed to detach device %s\n", dev_name);
			return ret;
		}
	}

	/* Access the MMIO regions of all the CDX devices */
	for (i = 0; i < num_cdx_devices; i++) {
		printf("\nCDX device: %s\n", g_cdx_dev[i]->device.name);
		printf("================================\n");
		for (j = 0; j < RTE_CDX_MAX_RESOURCE; j++) {
			if (!g_cdx_dev[i]->mem_resource[j].len)
				continue;
			printf("Resource %d (total len: %ld)\n", j,
			       g_cdx_dev[i]->mem_resource[j].len);
			printf("--------------------------------");

			addr = g_cdx_dev[i]->mem_resource[j].addr;
			pr_len = g_cdx_dev[i]->mem_resource[j].len < NUM_WORDS_TO_PRINT ?
				g_cdx_dev[i]->mem_resource[j].len : NUM_WORDS_TO_PRINT;

			for (k = 0; k < pr_len ; k++) {
				if (k % 4 == 0)
					printf("\n %lx:\t", k * sizeof(addr[0]));
				printf("%08x ", addr[k]);
			}
			printf("\n");
		}
	}

	ret = rte_eal_cleanup();
	if (ret)
		fprintf(stderr, "Error from rte_eal_cleanup(), %d\n", ret);

	return ret;
}

static int
cdx_test_probe(struct rte_cdx_driver *cdx_drv __rte_unused,
		struct rte_cdx_device *cdx_dev)
{
	if (num_cdx_devices < MAX_CDX_TEST_DEVICES)
		g_cdx_dev[num_cdx_devices++] = cdx_dev;

	return 0;
}

static int
cdx_test_remove(struct rte_cdx_device *cdx_dev __rte_unused)
{
	return 0;
}

static const struct rte_cdx_id cdx_test_id_map[] = {
	{ RTE_CDX_DEVICE(RTE_CDX_ANY_ID, RTE_CDX_ANY_ID) },
};

static struct rte_cdx_driver rte_cdx_test_pmd = {
	.probe = cdx_test_probe,
	.remove = cdx_test_remove,
	.id_table = cdx_test_id_map,
	.drv_flags = RTE_CDX_DRV_NEED_MAPPING
};

RTE_PMD_REGISTER_CDX(cdx_test_driver, rte_cdx_test_pmd);
RTE_PMD_REGISTER_KMOD_DEP(cdx_test_driver, "vfio-cdx");
