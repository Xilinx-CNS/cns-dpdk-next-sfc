/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "mcdi_lib.h"

#define BUF_SIZE 256

static void print_hex(const void *buf, int bufsize, const char *fmt, ...)
{
	const uint8_t *p = buf;
	int i;

	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	for (i = 0; i < bufsize; i++)
		printf("%02x", p[i]);
	printf("\n");
}

static char *fctime(time_t t)
{
	char *str = ctime(&t);
	*strchr(str, '\n') = '\0';

	return str;
}

#define PRINT(var, _name, _fmt, ...)					\
		printf(#_name " = " _fmt "\n", var._name, ##__VA_ARGS__)
#define PRINT_HEX(var, _name)							\
		print_hex(var._name, sizeof(var._name), #_name " = ")

int main(int argc, char **argv)
{
	int bus_id, dev_id, fd, ret, i;
	uint32_t mcdi_buf[BUF_SIZE] = {0};
	int buf_size = sizeof(mcdi_buf);
	uint8_t *p = (uint8_t *)mcdi_buf;
	mc_cmd_get_version_ext_enc_t ver_enc;
	mc_cmd_get_version_v5_dec_t ver_dec;
	char cmd[BUF_SIZE];

	if (argc < 4) {
		printf("Usage: ./mcdi_app <bus id> <device id> <command>\n");
		return -EINVAL;
	}

	bus_id = strtoul(argv[1], NULL, 0);
	dev_id = strtoul(argv[2], NULL, 0);
	strcpy(cmd, argv[3]);

	fd = mcdi_create_device_ep(bus_id, dev_id);
	if (fd < 0) {
		fprintf(stderr, "Bus %d, Device %d is not found, error code: %d\n",
			bus_id, dev_id, fd);
		return fd;
	}

	if (!strcmp(cmd, "get_version"))
		buf_size = mc_cmd_get_version_ext_enc(mcdi_buf, buf_size, &ver_enc);
	else {
		fprintf(stderr, "Invalid command %s\n", cmd);
		ret = -EINVAL;
		goto out;
	}

	ret = write(fd, mcdi_buf, buf_size);
	if (ret < 0) {
		fprintf(stderr, "Write failed on device bus: %d, dev: %d\n", bus_id, dev_id);
		goto out;
	}
	memset(mcdi_buf, 0, sizeof(mcdi_buf));
	/*TODO, implement timeout using select()*/
	ret = read(fd, mcdi_buf, sizeof(mcdi_buf));
	if (ret < 0) {
		fprintf(stderr, "Read failed on bus: %d, dev: %d\n", bus_id, dev_id);
		goto out;
	} else if (ret == 0) {
		fprintf(stderr, "Read timed out on device bus: %d, dev: %d\n", bus_id, dev_id);
		ret = -ETIMEDOUT;
	} else {
		printf("Response length : %d\n", ret);
		for (i = 0; i < ret ; i++) {
			if (i % 4 == 0)
				printf(" ");
			printf("%02X", p[i]);
		}
		printf("\n");

		if (!strcmp(cmd, "get_version")) {
			if (mc_cmd_get_version_v5_dec(mcdi_buf, ret, &ver_dec)) {
				printf("Decode error for command: %s, error: %d\n", cmd, ret);
				goto out;
			} else {
				PRINT(ver_dec, mc_cmd_get_version_out_firmware, "%u (%s)",
						fctime(ver_dec.mc_cmd_get_version_out_firmware));
				PRINT(ver_dec, pcol, "%x");
				PRINT(ver_dec, supported_funcs[0], "%08x %08x %08x %08x",
						ver_dec.supported_funcs[1],
						ver_dec.supported_funcs[2],
						ver_dec.supported_funcs[3]);
				PRINT(ver_dec, version, "%lx");
				PRINT(ver_dec, extra, "%.16s");
				PRINT(ver_dec, flags, "%x");
				PRINT_HEX(ver_dec, mcfw_build_id);
				PRINT(ver_dec, mcfw_security_level, "%x");
				PRINT(ver_dec, mcfw_build_name, "%.64s");
				PRINT(ver_dec, sucfw_version[0], "%u.%u.%u.%u",
						ver_dec.sucfw_version[1],
						ver_dec.sucfw_version[2],
						ver_dec.sucfw_version[3]);
				PRINT(ver_dec, sucfw_build_date, "%lu (%s)",
					fctime(ver_dec.sucfw_build_date));
				PRINT(ver_dec, sucfw_chip_id, "%x");
				PRINT(ver_dec, cmcfw_version[0], "%u.%u.%u.%u",
						ver_dec.cmcfw_version[1],
						ver_dec.cmcfw_version[2],
						ver_dec.cmcfw_version[3]);
				PRINT(ver_dec, cmcfw_build_date, "%lu (%s)",
					fctime(ver_dec.cmcfw_build_date));
				PRINT(ver_dec, fpga_version[0], "%u.%u.%u",
						ver_dec.fpga_version[1],
						ver_dec.fpga_version[2]);
				PRINT(ver_dec, fpga_extra, "%.16s");
				PRINT(ver_dec, board_name, "%.16s");
				PRINT(ver_dec, board_revision, "%x");
				PRINT(ver_dec, board_serial, "%.64s");
				PRINT(ver_dec, datapath_hw_version[0], "%u.%u.%u",
						ver_dec.datapath_hw_version[1],
						ver_dec.datapath_hw_version[2]);
				PRINT(ver_dec, datapath_fw_version[0], "%u.%u.%u",
						ver_dec.datapath_fw_version[1],
						ver_dec.datapath_fw_version[2]);
				PRINT(ver_dec, soc_boot_version[0], "%u.%u.%u.%u",
						ver_dec.soc_boot_version[1],
						ver_dec.soc_boot_version[2],
						ver_dec.soc_boot_version[3]);
				PRINT(ver_dec, soc_uboot_version[0], "%u.%u.%u.%u",
						ver_dec.soc_uboot_version[1],
						ver_dec.soc_uboot_version[2],
						ver_dec.soc_uboot_version[3]);
				PRINT(ver_dec, soc_main_rootfs_version[0], "%u.%u.%u.%u",
						ver_dec.soc_main_rootfs_version[1],
						ver_dec.soc_main_rootfs_version[2],
						ver_dec.soc_main_rootfs_version[3]);
				PRINT(ver_dec, soc_recovery_buildroot_version[0], "%u.%u.%u.%u",
						ver_dec.soc_recovery_buildroot_version[1],
						ver_dec.soc_recovery_buildroot_version[2],
						ver_dec.soc_recovery_buildroot_version[3]);
				PRINT(ver_dec, board_version[0], "%u.%u.%u.%u",
						ver_dec.board_version[1],
						ver_dec.board_version[2],
						ver_dec.board_version[3]);
				PRINT(ver_dec, bundle_version[0], "%u.%u.%u.%u",
						ver_dec.bundle_version[1],
						ver_dec.bundle_version[2],
						ver_dec.bundle_version[3]);
			}
		}
	}
out:
	mcdi_destroy_device_ep(fd);
	return ret;
}
