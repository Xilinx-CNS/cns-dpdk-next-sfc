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

#define CDX_BUS_EPT_NAME		"mcdi_ipc"
#define CDX_DEV_EPT_NAME		"cdx_dev:%02x:%02x.0"
#define PATH_BUF_MAX	1024 /* size of path buffers */
#define ARGS_SNPRINTF(_buf, _bufsize, _fmt)		\
	({						\
	va_list _ap;					\
	int _rc;					\
	va_start(_ap, _fmt);				\
	_rc = vsnprintf(_buf, _bufsize, _fmt, _ap);	\
	va_end(_ap);					\
	_rc;						\
	})
#define ARGS_SNPRINTF_CHECK(_buf, _bufsize, _fmt)	\
	({						\
	int _rc;					\
	_rc = ARGS_SNPRINTF(_buf, _bufsize, _fmt);	\
	assert(_rc < _bufsize);				\
	_rc;						\
	})

static int sysfs_read(const char *fn, char *buf, int maxlen)
{
	int fd;
	int rc;

	if ((fd = open(fn, O_RDONLY)) < 0)
		return -errno;
	rc = read(fd, buf, maxlen);
	close(fd);
	return rc;
}

__attribute__((format(printf, 2, 3)))
static int sysfs_read_int(int *result, const char *fmt, ...)
{
	char fn[PATH_BUF_MAX];
	char buf[32];
	int rc;

	ARGS_SNPRINTF_CHECK(fn, PATH_BUF_MAX, fmt);
	if ((rc = sysfs_read(fn, buf, sizeof(buf))) < 0)
		goto err;
	*result = strtol(buf, NULL, 0);
	return 0;
err:
	*result = 0;
	return rc;
}

/*
 * POSIX.1 defines dirname() but its return value may be overwritten by
 * subsequent dirname call so implement own simple in-place edition that
 * works with all sysfs realpaths
 */
static char *get_dirname(char *path)
{
	char *p;

	if (path && (p = strrchr(path, '/')))
		*p = '\0';
	return path;
}

/* glob + realpath, glob must have exactly one match */
__attribute__((format(printf, 1, 2)))
static char *realpath_glob(const char *fmt, ...)
{
	char pattern[PATH_BUF_MAX];
	glob_t gl;
	char *rc;

	ARGS_SNPRINTF_CHECK(pattern, sizeof(pattern), fmt);
	glob(pattern, 0, NULL, &gl);
	if (gl.gl_pathc == 1)
		rc = realpath(gl.gl_pathv[0], NULL);
	else
		rc = NULL;
	globfree(&gl);
	return rc;
}

static char *sysfs_get_cdx_bus_path(void)
{
	const char pattern[] =
	"/sys/bus/rpmsg/drivers/cdx_controller/virtio[0-9]*." CDX_BUS_EPT_NAME ".*";

	return get_dirname(realpath_glob(pattern));
}

static char *sysfs_get_cdx_device_path(const char *cdx_bus,
				       int busnum,
				       int devnum)
{
	return realpath_glob("%s/*." CDX_DEV_EPT_NAME ".*", cdx_bus, busnum, devnum);
}

static bool is_path_prefix(const char *prefix, const char *path)
{
	int i;

	for (i = 0; prefix[i]; i++) {
		if (prefix[i] != path[i])
			return false;
	}
	/* make sure we don't match partial directory name */
	return i && (path[i] == '/' || path[i - 1] == '/');
}

static char *sysfs_get_path_by_dev(const char *dev)
{
	struct stat st;
	const char *mode;

	if (stat(dev, &st) < 0)
		return NULL;

	if (S_ISCHR(st.st_mode))
		mode = "char";
	else if (S_ISBLK(st.st_mode))
		mode = "block";
	else {
		/* unsupported mode */
		assert(st.st_mode != st.st_mode);
		return NULL;
	}

	return realpath_glob("/sys/dev/%s/%u:%u",
					    mode,
					    major(st.st_rdev),
					    minor(st.st_rdev));
}

static char *dev_get_rpmsg_path_by_dst(const char *cdx_bus, uint32_t dst)
{
	const char *pattern = "/dev/rpmsg[0-9]*";
	int dev_dst;
	glob_t gl;
	int i;
	char *found = NULL;
	char *path;

	glob(pattern, 0, NULL, &gl);
	for (i = 0; i < gl.gl_pathc && !found; i++) {
		path = sysfs_get_path_by_dev(gl.gl_pathv[i]);
		if (is_path_prefix(cdx_bus, path) &&
			sysfs_read_int(&dev_dst, "%s/dst", path) == 0 &&
			dev_dst == dst)
		found = realpath(gl.gl_pathv[i], NULL);
		free(path);
	}
	globfree(&gl);

	return found;
}

static char *get_dev_path(int busnum, int devnum)
{
	char *cdx_bus;
	char *cdx_dev;
	char *rpmsg_dev = NULL;
	int dst_addr;

	if (!(cdx_bus = sysfs_get_cdx_bus_path())) {
		fprintf(stderr, "CDX bus not found\n");
		goto out;
	}

	if (!(cdx_dev = sysfs_get_cdx_device_path(cdx_bus, busnum, devnum))) {
		fprintf(stderr,"CDX device %02x:%02x not found\n",
			   busnum,
			   devnum);
		goto free_bus_and_out;
	}
	sysfs_read_int(&dst_addr, "%s/dst", cdx_dev);

	rpmsg_dev = dev_get_rpmsg_path_by_dst(cdx_bus, dst_addr);
	free(cdx_dev);

free_bus_and_out:
	free(cdx_bus);
out:
	return rpmsg_dev;
}
/**
 * mcdi_create_device_ep - Finds and opens rpmsg device corrosponsing
 *			to given bus id and device id
 * @bus_id: Bus ID
 * @dev_id: Device ID.
 *
 * Return: fd on success and error code on failure.
 */

int mcdi_create_device_ep(uint16_t bus_id, uint16_t dev_id)
{
	char *dev_path = get_dev_path(bus_id, dev_id);
	int fd, ret = 0;

	if (!dev_path)
		return -ENODEV;

	fd = open(dev_path, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "unable to open device %s\n", dev_path);
		ret = fd;
		goto out;
	}
	fprintf(stderr,"Opened an fd on rpmsg device %s\n", dev_path);
	ret = fd;

out:
	free(dev_path);
	return ret;
}

/**
 * mcdi_destroy_device_ep - Closes the given fd
 * @fd: File descriptor
 *
 * Return: None.
 */
void mcdi_destroy_device_ep(int fd)
{
	close(fd);
}
