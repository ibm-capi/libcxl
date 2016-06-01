/*
 * Copyright 2014,2015 International Business Machines
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <misc/cxl.h>
#include "libcxl.h"

#include "libcxl_internal.h"

enum cxl_sysfs_attr {
	/* AFU */
	API_VERSION = 0,
	API_VERSION_COMPATIBLE,
	CR_CLASS,
	CR_DEVICE,
	CR_VENDOR,
	IRQS_MAX,
	IRQS_MIN,
	MMIO_SIZE,
	MODE,
	MODES_SUPPORTED,
	PREFAULT_MODE,

	/* AFU Master or Slave */
	DEV,
	PP_MMIO_LEN,
	PP_MMIO_OFF,

	/* Card */
	BASE_IMAGE,
	CAIA_VERSION,
	IMAGE_LOADED,
	PSL_REVISION,

	/* Add new attrs above this */
	CXL_ATTR_MAX
};

struct cxl_sysfs_entry {
	char *name;
	int (*scan_func)(char *attr_str, long *major, long *minor);
	int expected_num;
};

static int scan_int(char *attr_str, long *majorp, long *minorp);
static int scan_hex(char *attr_str, long *majorp, long *minorp);
static int scan_dev(char *attr_str, long *majorp, long *minorp);
static int scan_mode(char *attr_str, long *majorp, long *minorp);
static int scan_modes(char *attr_str, long *majorp, long *minorp);
static int scan_prefault_mode(char *attr_str, long *majorp, long *minorp);
static int scan_caia_version(char *attr_str, long *majorp, long *minorp);
static int scan_image(char *attr_str, long *majorp, long *minorp);

static struct cxl_sysfs_entry sysfs_entry[CXL_ATTR_MAX] = {
	[API_VERSION] = { "api_version", scan_int, 1 },
	[API_VERSION_COMPATIBLE] = { "api_version_compatible", scan_int, 1 },
	[CR_CLASS] = { "cr%ld/class", scan_hex, 1 },
	[CR_DEVICE] = { "cr%ld/device", scan_hex, 1 },
	[CR_VENDOR] = { "cr%ld/vendor", scan_hex, 1 },
	[IRQS_MAX] = { "irqs_max", scan_int, 1 },
	[IRQS_MIN] = { "irqs_min", scan_int, 1 },
	[MMIO_SIZE] = { "mmio_size", scan_int, 1 },
	[MODE] = { "mode", scan_mode, 1 },
	[MODES_SUPPORTED] = { "modes_supported", scan_modes, 1 },
	[PREFAULT_MODE] = { "prefault_mode", scan_prefault_mode, 1 },
	[DEV] = { "dev", scan_dev, 2 },
	[PP_MMIO_LEN] = { "pp_mmio_len", scan_int, 1 },
	[PP_MMIO_OFF] = { "pp_mmio_off", scan_int, 1 },
	[BASE_IMAGE] = { "base_image", scan_int, 1 },
	[CAIA_VERSION] = { "caia_version", scan_caia_version, 2 },
	[IMAGE_LOADED] = { "image_loaded", scan_image, 1 },
	[PSL_REVISION] = { "psl_revision", scan_int, 1 },
};

#define OUT_OF_RANGE(attr) ((attr) < 0 || (attr) >= CXL_ATTR_MAX || \
			    (sysfs_entry[attr].name == NULL))

static int scan_int(char *attr_str, long *majorp, long *minorp)
{
	return sscanf(attr_str, "%ld", majorp);
}

static int scan_hex(char *attr_str, long *majorp, long *minorp)
{
	return sscanf(attr_str, "0x%lx", majorp);
}

static int scan_dev(char *attr_str, long *majorp, long *minorp)
{
	return sscanf(attr_str, "%ld:%ld", majorp, minorp);
}

static int scan_caia_version(char *attr_str, long *majorp, long *minorp)
{
	return sscanf(attr_str, "%ld.%ld", majorp, minorp);
}

static int scan_mode(char *attr_str, long *majorp, long *minorp)
{
	int count;
	char buf[18];

	if ((count = sscanf(attr_str, "%17s", buf)) != 1)
		return -1;
	if (!strcmp(buf, "dedicated_process")) {
		*majorp = CXL_MODE_DEDICATED;
		count = 0;
	} else if (!strcmp(buf, "afu_directed")) {
		*majorp = CXL_MODE_DIRECTED;
		count = 0;
	}
	return (count == 0);
}

static int scan_modes(char *attr_str, long *majorp, long *minorp)
{
	long val1, val2 = 0;
	char buf1[18], buf2[18];
	int rc;

	if ((rc = sscanf(attr_str, "%17s\n%17s", buf1, buf2)) <= 0)
		return -1;
	if (rc == 2 && scan_mode(buf2, &val2, NULL) != 1)
		return -1;
	if (scan_mode(buf1, &val1, NULL) != 1)
		return -1;
	*majorp = val1|val2;
	return 1;
}

static int scan_prefault_mode(char *attr_str, long *majorp, long *minorp)
{
	int count;
	char buf[24];
	if ((count = sscanf(attr_str, "%23s", buf)) != 1)
		return -1;
	if (!strcmp(buf, "none")) {
		*majorp = CXL_PREFAULT_MODE_NONE;
		count = 0;
	} else if (!strcmp(buf, "work_element_descriptor")) {
		*majorp = CXL_PREFAULT_MODE_WED;
		count = 0;
	} else if (!strcmp(buf, "all")) {
		*majorp = CXL_PREFAULT_MODE_ALL;
		count = 0;
	}
	return (count == 0);
}

static int scan_image(char *attr_str, long *majorp, long *minorp)
{
	int count;
	char buf[8];

	if ((count = sscanf(attr_str, "%7s", buf)) != 1)
		return -1;
	if (!strcmp(buf, "factory")) {
		*majorp = CXL_IMAGE_FACTORY;
		count = 0;
	} else if (!strcmp(buf, "user")) {
		*majorp = CXL_IMAGE_USER;
		count = 0;
	}
	return (count == 0);
}

static char *sysfs_attr_name(enum cxl_sysfs_attr attr)
{
	if (OUT_OF_RANGE(attr))
		return NULL;
	return sysfs_entry[attr].name;
}

#define BUFLEN 256

static char *sysfs_get_path(char *path, char *attr_name)
{
	char *attr_path = NULL;
	char *new_path;
	struct stat sb;

	path = strdup(path);
	if (path == NULL)
		return NULL;

	/*
	 * Try to open the attribute in sysfs.  If it doesn't exist, keep
	 * following "device/" path down until we find it.
	 */
	while (stat(path, &sb) != -1) {
		if (asprintf(&attr_path, "%s/%s", path, attr_name) == -1)
			goto out;

		if (stat(attr_path, &sb) == 0) {
			free(path);
			return attr_path;
		}

		if (errno != ENOENT)
			/* Something unexpected beside it not existing */
			goto enodev;

		/* If it doesn't exist, walk down "device/" link */
		if (asprintf(&new_path, "%s/device", path) == -1)
			goto out;

		free(path);
		path = new_path;
		free(attr_path);
	}
	/* Directory doesn't exist */
enodev:
	errno = ENODEV;
out:
	if (attr_path)
		free(attr_path);
	free(path);
	return NULL;
}

static char *read_sysfs_str(char *attr_path)
{
	int fd, count;
	char buf[BUFLEN];

	fd = open(attr_path, O_RDONLY);
	free(attr_path);
	if (fd == -1)
		return NULL;
	count = read(fd, buf, BUFLEN);
	close(fd);
	if (count == -1)
		return NULL;
	buf[count - 1] = '\0';
	return strdup(buf);
}

static int scan_sysfs_str(enum cxl_sysfs_attr attr, char *attr_str,
			  long *majorp, long *minorp)
{
	int (*scan_func)(char *attr_str, long *majorp, long *minorp);

	if (OUT_OF_RANGE(attr))
		return -1;
	scan_func = sysfs_entry[attr].scan_func;
	if (scan_func == NULL)
		return -1;
	return (*scan_func)(attr_str, majorp, minorp);
}

static int read_sysfs(char *sysfs_path, enum cxl_sysfs_attr attr, long *majorp,
		      long *minorp)
{
	char *attr_name;
	char *attr_path;
	char *buf;
	int expected, ret;

	if (OUT_OF_RANGE(attr))
		return -1;
	attr_name = sysfs_attr_name(attr);
	if (attr_name == NULL)
		return -1;
	/*
	 * Hack:
	 *	For configuration record attributes, attr_name is a printf
	 *	format with one parameter, the configuration record number,
	 *	pointed to by minorp.
	 */
	switch (attr) {
	case CR_CLASS:
	case CR_DEVICE:
	case CR_VENDOR:
		if (asprintf(&buf, attr_name, *minorp) == -1)
			return -1;
		attr_path = sysfs_get_path(sysfs_path, buf);
		free(buf);
		break;
	default:
		attr_path = sysfs_get_path(sysfs_path, attr_name);
	}
	if (attr_path == NULL)
		return -1;
	if ((buf = read_sysfs_str(attr_path)) == NULL)
		return -1;
	expected = sysfs_entry[attr].expected_num;
	ret = scan_sysfs_str(attr, buf, majorp, minorp);
	free(buf);
	return (ret == expected) ? 0 : -1;
}

static int read_sysfs_afu(struct cxl_afu_h *afu, enum cxl_sysfs_attr attr,
			  long *majorp, long *minorp)
{
	if ((afu == NULL) || (afu->sysfs_path == NULL)) {
		errno = EINVAL;
		return -1;
	}
	return read_sysfs(afu->sysfs_path, attr, majorp, minorp);

}

static int read_sysfs_adapter(struct cxl_adapter_h *adapter,
			      enum cxl_sysfs_attr attr, long *majorp,
			      long *minorp)
{
	if ((adapter == NULL) || (adapter->sysfs_path == NULL)) {
		errno = EINVAL;
		return -1;
	}
	return read_sysfs(adapter->sysfs_path, attr, majorp, minorp);
}

int cxl_get_api_version(struct cxl_afu_h *afu, long *valp)
{
	return read_sysfs_afu(afu, API_VERSION, valp, NULL);
}

int cxl_get_api_version_compatible(struct cxl_afu_h *afu, long *valp)
{
	return read_sysfs_afu(afu, API_VERSION_COMPATIBLE, valp, NULL);
}

int cxl_get_cr_class(struct cxl_afu_h *afu, long cr_num, long *valp)
{
	return read_sysfs_afu(afu, CR_CLASS, valp, &cr_num);
}

int cxl_get_cr_device(struct cxl_afu_h *afu, long cr_num, long *valp)
{
	return read_sysfs_afu(afu, CR_DEVICE, valp, &cr_num);
}

int cxl_get_cr_vendor(struct cxl_afu_h *afu, long cr_num, long *valp)
{
	return read_sysfs_afu(afu, CR_VENDOR, valp, &cr_num);
}

int cxl_get_irqs_max(struct cxl_afu_h *afu, long *valp)
{
	return read_sysfs_afu(afu, IRQS_MAX, valp, NULL);
}

int cxl_get_irqs_min(struct cxl_afu_h *afu, long *valp)
{
	return read_sysfs_afu(afu, IRQS_MIN, valp, NULL);
}

int cxl_get_mmio_size(struct cxl_afu_h *afu, long *valp)
{
	return read_sysfs_afu(afu, MMIO_SIZE, valp, NULL);
}

int cxl_get_mode(struct cxl_afu_h *afu, long *valp)
{
	return read_sysfs_afu(afu, MODE, valp, NULL);
}

int cxl_get_modes_supported(struct cxl_afu_h *afu, long *valp)
{
	return read_sysfs_afu(afu, MODES_SUPPORTED, valp, NULL);
}

int cxl_get_prefault_mode(struct cxl_afu_h *afu, enum cxl_prefault_mode *valp)
{
	long value;
	int ret;

	ret = read_sysfs_afu(afu, PREFAULT_MODE, &value, NULL);
	*valp = (enum cxl_prefault_mode)value;
	return ret;
}

int cxl_get_dev(struct cxl_afu_h *afu, long *majorp, long *minorp)
{
	return read_sysfs_afu(afu, DEV, majorp, minorp);
}

int cxl_get_pp_mmio_len(struct cxl_afu_h *afu, long *valp)
{
	return read_sysfs_afu(afu, PP_MMIO_LEN, valp, NULL);
}

int cxl_get_pp_mmio_off(struct cxl_afu_h *afu, long *valp)
{
	return read_sysfs_afu(afu, PP_MMIO_OFF, valp, NULL);
}

int cxl_get_base_image(struct cxl_adapter_h *adapter, long *valp)
{
	return read_sysfs_adapter(adapter, BASE_IMAGE, valp, NULL);
}

int cxl_get_caia_version(struct cxl_adapter_h *adapter, long *majorp,
			 long *minorp)
{
	return read_sysfs_adapter(adapter, CAIA_VERSION, majorp, minorp);
}

int cxl_get_image_loaded(struct cxl_adapter_h *adapter, enum cxl_image *valp)
{
	return read_sysfs_adapter(adapter, IMAGE_LOADED, (long *)valp, NULL);
}

int cxl_get_psl_revision(struct cxl_adapter_h *adapter, long *valp)
{
	return read_sysfs_adapter(adapter, PSL_REVISION, valp, NULL);
}

static int write_sysfs_str(char *path, enum cxl_sysfs_attr attr, char *str)
{
	char *attr_name;
	char *attr_path;
	int fd, count;

	if (OUT_OF_RANGE(attr))
		return -1;
	if (path == NULL)
		return -1;
	attr_name = sysfs_attr_name(attr);
	if (attr_name == NULL)
		return -1;
	attr_path = sysfs_get_path(path, attr_name);
	if (attr_path == NULL)
		return -1;
	fd = open(attr_path, O_WRONLY);
	free(attr_path);
	if (fd == -1)
		return -1;
	count = write(fd, str, strlen(str));
	close(fd);
	if (count == -1)
		return -1;
	return 0;
}

static int write_sysfs_afu(struct cxl_afu_h *afu, enum cxl_sysfs_attr attr,
			   char* str)
{
	if ((afu == NULL) || (afu->sysfs_path == NULL)) {
		errno = EINVAL;
		return -1;
	}
	return write_sysfs_str(afu->sysfs_path, attr, str);

}

int cxl_set_irqs_max(struct cxl_afu_h *afu, long value)
{
	char *buf;
	int ret;

	if (asprintf(&buf, "%ld", value) == -1)
		return -1;
	ret = write_sysfs_afu(afu, IRQS_MAX, buf);
	free(buf);
	return ret;
}

int cxl_set_mode(struct cxl_afu_h *afu, long value)
{
	char *str;

	switch (value) {
	case CXL_MODE_DEDICATED:
		str = "dedicated_process";
		break;
	case CXL_MODE_DIRECTED:
		str = "afu_directed";
		break;
	default:
		errno = EINVAL;
		return -1;
	}
	return write_sysfs_afu(afu, MODE, str);
}

int cxl_set_prefault_mode(struct cxl_afu_h *afu, enum cxl_prefault_mode value)
{
	char *str;

	switch (value) {
	case CXL_PREFAULT_MODE_NONE:
		str = "none";
		break;
	case CXL_PREFAULT_MODE_WED:
		str = "work_element_descriptor";
		break;
	case CXL_PREFAULT_MODE_ALL:
		str = "all";
		break;
	default:
		errno = EINVAL;
		return -1;
	}
	return write_sysfs_afu(afu, PREFAULT_MODE, str);
}

/* Returns the total size of the afu_err_buff in bytes */
int cxl_errinfo_size(struct cxl_afu_h *afu, size_t *valp)
{
	/* check if we need to fetch the size of the buffer */
	if (afu->errbuff_size == -1) {
		char * path;
		struct stat st;

		path = sysfs_get_path(afu->sysfs_path, "afu_err_buff");
		if (path == NULL)
			return -1;

		/* get the file size */
		if (stat(path, &st) < 0) {
			free(path);
			return -1;
		}

		afu->errbuff_size = st.st_size;
		free(path);
	}

	*valp = afu->errbuff_size;
	return 0;
}

/* Read and copies contents to afu_err_buff to the provided buffer */
ssize_t cxl_errinfo_read(struct cxl_afu_h *afu, void *dst, off_t off,
			 size_t len)
{
	/* check if we need to open the descriptor */
	if (afu->fd_errbuff == -1) {
		char * path;

		path = sysfs_get_path(afu->sysfs_path, "afu_err_buff");
		if (path == NULL)
			return -1;

		afu->fd_errbuff = open(path, O_RDONLY | O_CLOEXEC);
		free(path);

		if (afu->fd_errbuff == -1)
			return -1;
	}

	/* seek to right offset and read contents */
	if (lseek(afu->fd_errbuff, off, SEEK_SET) < 0)
		return -1;

	return read(afu->fd_errbuff, dst, len);
}
