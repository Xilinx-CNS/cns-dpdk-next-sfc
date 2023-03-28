/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <assert.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <stdlib.h>
#include <stdint.h>
#include <glob.h>
#include <string.h>

#include "mcdi_lib.h"

int main (int argc, char **argv)
{
	int bus_id, dev_id, fd, ret, i;
	uint32_t mcdi_buf[32];
	uint32_t opcode = strtoul(argv[3], NULL, 0); /* dump core if no parameters */
	uint32_t payload_len = (argc - 4) * 4;
	uint32_t total_len = payload_len + 8;
	uint8_t *p = (uint8_t*)mcdi_buf;
	uint8_t csum = 0;


	if (argc < 5) {
		printf("Usage: ./mcdi_app <bus id> <device id> <opcode> <payload>\n");
		return -EINVAL;
	}

	bus_id = strtoul(argv[1], NULL, 0);
	dev_id = strtoul(argv[2], NULL, 0);

	fd = mcdi_create_device_ep(bus_id, dev_id);
	if (fd < 0) {
		fprintf(stderr, "Bus %d, Device %d is not found, error code: %d\n", bus_id, dev_id, fd);
		return fd;
	}

	//TODO, encode mcdi message
	/*Construct mcdi message*/
	mcdi_buf[0] = 0x7f | 1 << 7; /* V2 extn */
	mcdi_buf[1] = opcode | (payload_len << 16) | (2 << 28);
	for (i = 4; i < argc; i++)
		mcdi_buf[i] = strtoul(argv[i], NULL, 0);
	for (i = 0; i < total_len; i++)
		csum += p[i];
	mcdi_buf[0] |= (~csum & 0xff) << 24;

	ret = write(fd, mcdi_buf, total_len);
	if (ret < 0) {
		fprintf(stderr, "Write failed on device bus: %d, dev: %d\n", bus_id, dev_id);
		goto out;
	}
	memset(mcdi_buf, 0, sizeof(mcdi_buf));
	//TODO, implement timeout using select()
	ret = read(fd, mcdi_buf, sizeof(mcdi_buf));
	if (ret < 0) {
		fprintf(stderr, "Read failed on bus: %d, dev: %d\n", bus_id, dev_id);
		goto out;
	} else if (ret == 0) {
		fprintf(stderr, "Read timed out on device bus: %d, dev: %d\n", bus_id, dev_id);
		ret = -ETIMEDOUT ;
	} else {
		printf("Response lenth : %d\n", ret);
		for (i = 0; i < ((ret + 3) & ~3) / 4; i++)
				printf(" %08X ", mcdi_buf[i]);
		printf("\n");
	}
out:
	mcdi_destroy_device_ep(fd);
	return ret;
}
