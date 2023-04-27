/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <stdarg.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/sysmacros.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <glob.h>
#include <dirent.h>

#define BUF_SIZE 32
#define PATH_BUF_MAX    1024 /* size of path buffers */
#define RPMSG_CREATE_EPT_IOCTL  _IOW(0xb5, 0x1, struct rpmsg_endpoint_info)
#define RPMSG_DESTROY_EPT_IOCTL _IO(0xb5, 0x2)
#define CDX_DEV_EPT_NAME        "cdx_dev:%02x:%02x.0"

#define ARGS_SNPRINTF(buf_, bufsize_, fmt_)                             \
({                                                                    \
	va_list ap__;                                                       \
	int rc__;                                                           \
	va_start(ap__, (fmt_));                                             \
	rc__ = vsnprintf((buf_), (bufsize_), (fmt_), ap__);                 \
	va_end(ap__);                                                       \
	rc__;                                                               \
})
#define ARGS_SNPRINTF_CHECK(buf_, bufsize_, fmt_)                       \
({                                                                    \
	int rc__;                                                           \
	rc__  = ARGS_SNPRINTF((buf_), (bufsize_), (fmt_));                  \
	assert(rc__ < (bufsize_));                                          \
	rc__;                                                               \
})


struct rpmsg_endpoint_info {
	char name[BUF_SIZE];
	uint32_t src;
	uint32_t dst;
};

static int sysfs_read(const char *fn, char *buf, int maxlen)
{
	int fd;
	int rc;

	fd = open(fn, O_RDONLY);
	if (fd < 0)
		return -errno;

	rc = read(fd, buf, maxlen);
	close(fd);

	return rc;
}

__attribute__((format(printf, 2, 3)))
static int sysfs_read_int(int *result, const char *fmt, ...)
{
	char fn[PATH_BUF_MAX];
	char buf[BUF_SIZE];
	int rc;

	ARGS_SNPRINTF_CHECK(fn, PATH_BUF_MAX, fmt);
	rc = sysfs_read(fn, buf, sizeof(buf));
	if (rc < 0)
		goto err;

	/* CDX bus/RPMsg use uint32_t but we want to use base detection so atoi
	 * won't do but can happily truncate the result
	 */
	*result = (int)strtol(buf, NULL, 0);
	return 0;

err:
	*result = 0;
	return rc;
}

__attribute__((format(printf, 3, 4)))
static int sysfs_read_str(char *buf, int bufsize, const char *fmt, ...)
{
	char fn[PATH_BUF_MAX];
	int rc;
	int i;

	ARGS_SNPRINTF_CHECK(fn, PATH_BUF_MAX, fmt);
	buf[0] = '\0';
	rc = sysfs_read(fn, buf, bufsize);
	for (i = 0; buf[i]; i++) {
		if (buf[i] == '\n') {
			buf[i] = '\0';
			break;
		}
	}
	return rc;
}

static int get_ep_dst(int bus, int dev)
{
	DIR *dp;
	struct dirent *ep;
	const char *base = "/sys/bus/rpmsg/devices/";
	char dev_str[PATH_BUF_MAX];
	int dev_dst, ret;

	sprintf(dev_str, CDX_DEV_EPT_NAME, bus, dev);

	dp = opendir(base);
	if (dp != NULL) {
		while ((ep = readdir(dp)) != NULL) {
			if (strstr(ep->d_name, dev_str))
				break;
		}
		(void)closedir(dp);
	} else {
		fprintf(stderr, "Couldn't open the directory %s\n", base);
		return -ENOENT;
	}

	ret = sysfs_read_int(&dev_dst, "%s/%s/dst", base, ep->d_name);
	if (ret) {
		fprintf(stderr, "Couldn't read the dst address %s\n", ep->d_name);
		return ret;
	}

	return dev_dst;
}

int main(int argc, char **argv)
{
	struct rpmsg_endpoint_info ept;
	int ret = 0, fd, status = 0;
	size_t i;
	uint16_t op;
	uint16_t bus_id, dev_id;
	glob_t gl;
	char *rc = NULL, *token1, *token2, buf[BUF_SIZE];
	const char pattern[] =
			"/sys/bus/rpmsg/devices/virtio0.cdx_dev:*";

	if (argc < 2) {
		fprintf(stderr, "Usage: ./mcdi_init <operation, 1:create, 0:destroy>\n");
		return -EINVAL;
	}
	op = strtoul(argv[1], NULL, 0);

	/*Create end points*/
	if (op == 1) {
		fd = open("/dev/rpmsg_ctrl0", O_RDWR);
		if (fd < 0) {
			fprintf(stderr, "Failed to open rpmsg control device\n");
			return fd;
		}

		glob(pattern, 0, NULL, &gl);
		for (i = 0; i < gl.gl_pathc; i++) {
			rc = realpath(gl.gl_pathv[i], NULL);
			sysfs_read_str(buf, sizeof(buf), "%s/name", rc);
			/*first token is cdx_dev and ignored*/
			token1 = strtok(buf, ":");
			token1 = strtok(NULL, ":");
			token2 = strtok(NULL, ".");
			bus_id = token1 ? strtoul(token1, NULL, 0) : 0;
			dev_id = token2 ? strtoul(token2, NULL, 0) : 0;

			ept.dst = get_ep_dst(bus_id, dev_id);
			ept.src = (bus_id << 16) | (dev_id & 0xFFFF);
			strcpy(ept.name, buf);

			ret = ioctl(fd, RPMSG_CREATE_EPT_IOCTL, &ept);
			if (ret < 0) {
				fprintf(stderr, "Failed to create endpoint with dst %d, cdx device %02x:%02x. Return value is %d\n",
					ept.dst, bus_id, dev_id, ret);
				status = ret;
			} else
				fprintf(stderr, "Created endpoint for dst address %d, cdx device %02x:%02x\n",
					ept.dst, bus_id, dev_id);
			free(rc);
		}
		close(fd);
	} else if (op == 0) {
		glob_t gl;
		const char pattern[] = "/dev/rpmsg*";
		char dev_path[PATH_BUF_MAX];
		int dev_fd;

		glob(pattern, 0, NULL, &gl);
		for (i = 0; i < (gl.gl_pathc - 1); i++) {
			sprintf(dev_path, "/dev/rpmsg%ld", i);
			dev_fd = open(dev_path, O_RDWR);
			assert(dev_fd > 0);
			ret = ioctl(dev_fd, RPMSG_DESTROY_EPT_IOCTL);
			if (ret < 0) {
				fprintf(stderr, "Failed to destroy endpoint for device %s\n",
					dev_path);
				status = ret;
			}
			close(dev_fd);
		}
		globfree(&gl);
	} else {
		fprintf(stderr, "Invalid option specified, op is %d\n", op);
		status = -EINVAL;
	}

	return status;
}
