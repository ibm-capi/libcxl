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

#define _GNU_SOURCE /* For asprintf */
#define _DEFAULT_SOURCE
#define __STDC_FORMAT_MACROS

#include <inttypes.h>
#include <assert.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <fcntl.h>
#include <regex.h>
#include <poll.h>

#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <setjmp.h>
#include <syscall.h>

#include "libcxl.h"
#include <misc/cxl.h>

#include "libcxl_internal.h"

#undef DEBUG

#ifdef DEBUG
#define _s1(x) #x
#define _s(x) _s1(x)
#define pr_devel(...) \
	fprintf(stderr, _s(__FILE__) ":" _s(__LINE__) ": " __VA_ARGS__ );
#define pr_here() \
	pr_devel("<-- DEBUG TRACE -->\n");
#else
#define pr_devel(...) do { } while (0);
#define pr_here() do { } while (0);
#endif

#define CXL_EVENT_READ_FAIL 0xffff

static struct cxl_adapter_h * malloc_adapter(void)
{
	struct cxl_adapter_h *adapter;

	if (!(adapter = malloc(sizeof(struct cxl_adapter_h))))
		return NULL;

	memset(adapter, 0, sizeof(struct cxl_adapter_h));

	return adapter;
}

char * cxl_adapter_dev_name(struct cxl_adapter_h *adapter)
{
	return adapter->enum_ent->d_name;
}

static struct cxl_afu_h * malloc_afu(void)
{
	struct cxl_afu_h *afu;

	if (!(afu = malloc(sizeof(struct cxl_afu_h))))
		return NULL;

	memset(afu, 0, sizeof(struct cxl_afu_h));
	afu->fd = -1;
	afu->process_element = -1;
	afu->mmio_addr = NULL;
	afu->dev_name = NULL;
	afu->sysfs_path = NULL;
	afu->fd_errbuff = -1;
	afu->errbuff_size = -1;
	afu->tid = -1;

	return afu;
}

char * cxl_afu_dev_name(struct cxl_afu_h *afu)
{
	if (afu->enum_ent)
		return afu->enum_ent->d_name;
	return afu->dev_name;
}

int cxl_afu_fd(struct cxl_afu_h *afu)
{
	return afu->fd;
}


/*
 * Adapter Enumeration
 */

static int is_cxl_adapter_filename(char *name)
{
	int rc;
	regex_t preg;

	if (*name != 'c')
		return 0;

	if (regcomp(&preg, "^card[0-9]\\+$", REG_NOSUB))
		return 0;
	rc = (regexec(&preg, name, 0, NULL, 0) != REG_NOMATCH);

	regfree(&preg);
	return rc;
}

static int is_cxl_afu_filename(char *name)
{
	int rc;
	regex_t preg;

	if (*name != 'a')
		return 0;

	if (regcomp(&preg, "^afu[0-9]\\+\\.[0-9]\\+$", REG_NOSUB))
		return 0;
	rc = (regexec(&preg, name, 0, NULL, 0) != REG_NOMATCH);

	regfree(&preg);
	return rc;
}

static int cxl_sysfs_adapter(char **bufp, struct cxl_adapter_h *adapter)
{
	return asprintf(bufp, CXL_SYSFS_CLASS"/%s",
			cxl_adapter_dev_name(adapter));
}

struct cxl_adapter_h * cxl_adapter_next(struct cxl_adapter_h *adapter)
{
	if (adapter == NULL) {
		if (!(adapter = malloc_adapter()))
			return NULL;
		memset(adapter, 0, sizeof(struct cxl_adapter_h));
		if (!(adapter->enum_dir = opendir(CXL_SYSFS_CLASS))) {
			if (errno == ENOENT)
				errno = ENODEV;
			goto end;
		}
	}
	errno = 0;
	do {
		if (!(adapter->enum_ent = readdir(adapter->enum_dir)))
			goto end;
	} while (!is_cxl_adapter_filename(adapter->enum_ent->d_name));

	if (cxl_sysfs_adapter(&adapter->sysfs_path, adapter) == -1)
		goto end;

	return adapter;

end:
	cxl_adapter_free(adapter);
	return NULL;
}

void cxl_adapter_free(struct cxl_adapter_h *adapter)
{
	if (!adapter)
		return;
	if (adapter->enum_dir)
		closedir(adapter->enum_dir);
	if (adapter->sysfs_path)
		free(adapter->sysfs_path);
	free(adapter);
}

/*
 * AFU Enumeration
 */

static void _cxl_afu_free(struct cxl_afu_h *afu, int free_adapter)
{
	if (!afu)
		return;
	if (afu->enum_dir)
		closedir(afu->enum_dir);
	if (afu->sysfs_path)
		free(afu->sysfs_path);
	if (free_adapter && afu->adapter)
		cxl_adapter_free(afu->adapter);
	if (afu->mmio_addr)
		cxl_mmio_unmap(afu);
	if (afu->fd != -1)
		close(afu->fd);
	if (afu->fd_errbuff != -1)
		close(afu->fd_errbuff);
	if (afu->dev_name)
		free(afu->dev_name);
	if (afu->event_buf) {
		free(afu->event_buf);
		afu->event_buf = NULL;
	}
	free(afu);
}

void cxl_afu_free(struct cxl_afu_h *afu)
{
	_cxl_afu_free(afu, 1);
}

int cxl_afu_opened(struct cxl_afu_h *afu)
{
	if (afu == NULL) {
		errno = EINVAL;
		return -1;
	}
	return (afu->fd != -1);
}

static int cxl_sysfs_fd(char **bufp, struct cxl_afu_h *afu)
{
	struct cxl_afu_id afuid;
	char suffix = '\0';
	int fd = cxl_afu_fd(afu);

	/* fetch the afu id via ioctl to the kernel driver */
	if (ioctl(fd, CXL_IOCTL_GET_AFU_ID, &afuid) < 0) {
		struct stat sb;

		/* if the ioctl is not recognized, fallback to old method */
		if ((errno != EINVAL) || (fstat(fd, &sb) < 0) ||
		    !S_ISCHR(sb.st_mode))
			return -1;

		return asprintf(bufp, "/sys/dev/char/%i:%i", major(sb.st_rdev),
				minor(sb.st_rdev));
	}

	switch (afuid.afu_mode) {
	case CXL_MODE_DEDICATED:
		suffix = 'd';
		break;
	case CXL_MODE_DIRECTED:
		suffix = (afuid.flags & CXL_AFUID_FLAG_SLAVE) ? 's' : 'm';
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	return asprintf(bufp, "/sys/class/cxl/afu%i.%i%c", afuid.card_id,
			afuid.afu_offset, suffix);
}

static int cxl_afu_sysfs(struct cxl_afu_h *afu, char **bufp)
{
	if (afu->fd >= 0)
		return cxl_sysfs_fd(bufp, afu);

	return asprintf(bufp, CXL_SYSFS_CLASS"/%s", cxl_afu_dev_name(afu));
}

struct cxl_afu_h *
cxl_adapter_afu_next(struct cxl_adapter_h *adapter, struct cxl_afu_h *afu)
{
	char *dir_path;

	if (afu == NULL) {
		assert(adapter);
		if (!(afu = malloc_afu()))
			return NULL;
		if (cxl_sysfs_adapter(&dir_path, adapter) == -1)
			goto end;
		if (!(afu->enum_dir = opendir(dir_path)))
			goto err_free;
	}
	errno = 0;
	do {
		if (!(afu->enum_ent = readdir(afu->enum_dir)))
			goto end;
	} while (!is_cxl_afu_filename(afu->enum_ent->d_name));
	if (cxl_afu_sysfs(afu, &afu->sysfs_path) == -1)
		goto err_free;
	return afu;

err_free:
	free(dir_path);
end:
	_cxl_afu_free(afu, 0);
	return NULL;
}

struct cxl_afu_h * cxl_afu_next(struct cxl_afu_h *afu)
{
	struct cxl_adapter_h *adapter = NULL;

	if (afu)
		adapter = afu->adapter;
	else if (!(adapter = cxl_adapter_next(NULL)))
		return NULL;

	do {
		if ((afu = cxl_adapter_afu_next(adapter, afu)))
			afu->adapter = adapter;
		else
			adapter = cxl_adapter_next(adapter);
	} while (adapter && !afu);

	return afu;
}

static int sysfs_subsystem(char **bufp, const char *path)
{
	char *subsystem_path, *name, *buf;
	char subsystem_link[256];
	int len;
	int rc = -1;

	if ((asprintf(&subsystem_path, "%s/subsystem", path)) == -1)
		return -1;

	/* lstat returns sb.st_size == 0 for symlinks in /sys (WTF WHY???), so
	 * we use a static buffer since we have NFI how large to allocate */
	if ((len = readlink(subsystem_path, subsystem_link, sizeof(subsystem_link) - 1)) == -1)
		goto out;
	if (len >= sizeof(subsystem_link) - 1)
		goto out;
	subsystem_link[len] = '\0';

	name = basename(subsystem_link);
	if (!(buf = malloc(strlen(name) + 1)))
		goto out;

	strcpy(buf, name);
	*bufp = buf;
	rc = 0;

out:
	free(subsystem_path);
	return rc;
}

int cxl_afu_sysfs_pci(struct cxl_afu_h *afu, char **pathp)
{
	char *path, *new_path, *subsys;
	struct stat sb;

	if (afu == NULL || pathp == NULL) {
		errno = EINVAL;
		return -1;
	}
	if ((path = strdup(afu->sysfs_path)) == NULL)
		return -1;

	do {
		if ((asprintf(&new_path, "%s/device", path)) == -1)
			goto err;
		free(path);
		path = new_path;

		if ((sysfs_subsystem(&subsys, path)) == -1) {
			if (errno == ENOENT)
				continue;
			goto err;
		}
		if (!(strcmp(subsys, "pci"))) {
			free(subsys);
			*pathp = path;
			return 0;
		}
		free(subsys);
	} while (stat(path, &sb) != -1);

err:
	free(path);
	return -1;
}

static int major_minor_match(int dirfd, char *dev_name, int major, int minor)
{
	struct stat sb;

	if (fstatat(dirfd, dev_name, &sb, 0) == -1)
		return 0;
	if (!S_ISCHR(sb.st_mode))
		return 0;
	return major(sb.st_rdev) == major && minor(sb.st_rdev) == minor;
}

static char *find_dev_name(int major, int minor)
{
	int saved_errno;
	DIR *enum_dir;
	struct dirent *enum_ent;
	int fd;
	char *dev_name = NULL;

	if ((enum_dir = opendir(CXL_DEV_DIR)) == NULL)
		return NULL;
	fd = dirfd(enum_dir);
	saved_errno = errno;
	errno = 0;
	do {
		if (!(enum_ent = readdir(enum_dir))) {
			if (errno == 0)
				errno = saved_errno;
			goto err_exit;
		}
	} while (!major_minor_match(fd, enum_ent->d_name, major, minor));

	if ((dev_name = strdup(enum_ent->d_name)) == NULL)
		goto err_exit;
	closedir(enum_dir);
	return dev_name;

err_exit:
	closedir(enum_dir);
	return NULL;
}

int cxl_afu_get_process_element(struct cxl_afu_h *afu)
{
	int process_element;
	int rc;

	if (afu == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (afu->process_element >= 0)
		/* return cached version */
		return afu->process_element;

	rc = ioctl(afu->fd, CXL_IOCTL_GET_PROCESS_ELEMENT, &process_element);
	if (rc < 0)
		return rc;
	afu->process_element = process_element;

	return process_element;
}

/* Open Functions */

static int open_afu_dev(struct cxl_afu_h *afu, char *path)
{
	struct stat sb;
	long api_version;
	int fd;

	if ((fd = open(path, O_RDWR | O_CLOEXEC)) < 0)
		return fd;
	afu->fd = fd;
	/* Verify that this is an AFU file we just opened */
	if (fstat(fd, &sb) < 0)
		goto err;
	if (!S_ISCHR(sb.st_mode))
		goto err;
	if (!(afu->dev_name = find_dev_name(major(sb.st_rdev),
					    minor(sb.st_rdev))))
		goto err;
	if (! afu->sysfs_path)
		if (cxl_afu_sysfs(afu, &afu->sysfs_path) == -1)
			goto err;
	if (cxl_get_api_version_compatible(afu, &api_version))
		goto err;
	if (api_version > CXL_KERNEL_API_VERSION) {
		errno = EPROTO;
		goto err_close;
	}
	return 0;

err:
	errno = ENODEV;
err_close:
	if (afu->dev_name)
		free(afu->dev_name);
	close(fd);
	afu->fd = -1;
	return -1;
}

struct cxl_afu_h * cxl_afu_open_dev(char *path)
{
	struct cxl_afu_h *afu;

	if (!(afu = malloc_afu()))
		return NULL;

	if (open_afu_dev(afu, path) < 0)
		goto err;
	return afu;
err:
	cxl_afu_free(afu);
	return NULL;
}

static char *new_sysfs_path(char *sysfs_path, enum cxl_views view)
{
	char lastchar;
	char *newpath;

	switch (view) {
	case CXL_VIEW_DEDICATED:
		lastchar = 'd';
		break;
	case CXL_VIEW_MASTER:
		lastchar = 'm';
		break;
	case CXL_VIEW_SLAVE:
		lastchar = 's';
		break;
	default:
		return NULL;
	}
	switch (*(sysfs_path + strlen(sysfs_path) - 1)) {
	case 'd':
	case 'm':
	case 's':
		if ((newpath = strdup(sysfs_path)) == NULL)
			return NULL;
		*(newpath + strlen(newpath) - 1) = lastchar;
		break;
	default:
		if (asprintf(&newpath, "%s%c", sysfs_path, lastchar) == -1)
			return NULL;
	}
	return newpath;
}

struct cxl_afu_h * cxl_afu_open_h(struct cxl_afu_h *afu, enum cxl_views view)
{
	char *dev_name = NULL;
	char *dev_path = NULL;
	struct cxl_afu_h *new_afu = NULL;
	long sysfs_major, sysfs_minor;

	if (!(new_afu = malloc_afu()))
		goto err_pass;
	if (!(new_afu->sysfs_path = new_sysfs_path(afu->sysfs_path, view)))
		goto err_pass;
	if (cxl_get_dev(new_afu, &sysfs_major, &sysfs_minor) < 0)
		goto err_exit;
	if (!(dev_name = find_dev_name(sysfs_major, sysfs_minor)))
		goto err_exit;
	if (asprintf(&dev_path, CXL_DEV_DIR"/%s", dev_name) == -1)
		goto err_pass;
	if (open_afu_dev(new_afu, dev_path) < 0)
		goto err_pass;
	free(dev_name);
	free(dev_path);
	return new_afu;

err_exit:
	errno = ENODEV;
err_pass:
	if (dev_name)
		free(dev_name);
	if (dev_path)
		free(dev_path);
	if (new_afu)
		free(new_afu);
	return NULL;
}

struct cxl_afu_h * cxl_afu_fd_to_h(int fd)
{
	struct cxl_afu_h *afu;
	struct stat sb;
	long api_version;

	if (!(afu = malloc_afu()))
		return NULL;
	/* Verify that the passed in fd is an AFU fd */
	if (fstat(fd, &sb) < 0)
		goto err_exit;
	afu->fd = fd;

	if (S_ISCHR(sb.st_mode)) {
		afu->dev_name = find_dev_name(major(sb.st_rdev), minor(sb.st_rdev));
		if (!afu->dev_name)
			goto enodev;
	} else {
		/* Could be an anonymous inode - see if the get_afu_id ioctl succeeds */
		afu->dev_name = NULL;
	}

	if (cxl_afu_sysfs(afu, &afu->sysfs_path) == -1)
		goto err_exit;
	if (cxl_get_api_version_compatible(afu, &api_version))
		goto err_exit;
	if (api_version > CXL_KERNEL_API_VERSION) {
		errno = EPROTO;
		goto err_exit;
	}
	return afu;

enodev:
	errno = ENODEV;
err_exit:
	free(afu);
	return NULL;
}

int cxl_afu_attach(struct cxl_afu_h *afu, __u64 wed)
{
	struct cxl_ioctl_start_work work;

	if (afu == NULL || afu->fd < 0) {
		errno = EINVAL;
		return -1;
	}
#if defined CXL_START_WORK_TID
	afu->tid = syscall(SYS_gettid);
#endif

	memset(&work, 0, sizeof(work));
	work.work_element_descriptor = wed;

	return ioctl(afu->fd, CXL_IOCTL_START_WORK, &work);
}

int cxl_afu_attach_full(struct cxl_afu_h *afu, __u64 wed, __u16 num_interrupts,
			__u64 amr)
{
	struct cxl_ioctl_start_work work;

	if (afu == NULL || afu->fd < 0) {
		errno = EINVAL;
		return -1;
	}
#if defined CXL_START_WORK_TID
	afu->tid = syscall(SYS_gettid);
#endif

	memset(&work, 0, sizeof(work));
	work.work_element_descriptor = wed;
	work.flags = CXL_START_WORK_NUM_IRQS | CXL_START_WORK_AMR;
	work.num_interrupts = num_interrupts;
	work.amr = amr;

	return ioctl(afu->fd, CXL_IOCTL_START_WORK, &work);
}

inline
int cxl_afu_attach_work(struct cxl_afu_h *afu,
			struct cxl_ioctl_start_work *work)
{
	if (afu == NULL || afu->fd < 0 || work == NULL) {
		errno = EINVAL;
		return -1;
	}
#if defined CXL_START_WORK_TID
	afu->tid = syscall(SYS_gettid);
#endif

	return ioctl(afu->fd, CXL_IOCTL_START_WORK, work);
}

inline
struct cxl_ioctl_start_work *cxl_work_alloc(void)
{
	return calloc(1, sizeof(struct cxl_ioctl_start_work));
}

inline
int cxl_work_free(struct cxl_ioctl_start_work *work)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	free(work);
	return 0;
}

inline
int cxl_work_get_amr(struct cxl_ioctl_start_work *work, __u64 *valp)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	*valp = work->amr;
	return 0;
}

inline
int cxl_work_get_num_irqs(struct cxl_ioctl_start_work *work, __s16 *valp)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	*valp = work->num_interrupts;
	return 0;
}

inline
int cxl_work_get_wed(struct cxl_ioctl_start_work *work, __u64 *valp)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	*valp = work->work_element_descriptor;
	return 0;
}

#if defined CXL_START_WORK_TID
inline
int cxl_work_get_tid(struct cxl_ioctl_start_work *work, __u16 *valp)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	*valp = work->tid;
	return 0;
}
#endif

inline
int cxl_work_set_amr(struct cxl_ioctl_start_work *work, __u64 amr)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	work->amr = amr;
	if (amr)
		work->flags |= CXL_START_WORK_AMR;
	else
		work->flags &= ~(CXL_START_WORK_AMR);
	return 0;
}

inline
int cxl_work_set_num_irqs(struct cxl_ioctl_start_work *work, __s16 irqs)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	work->num_interrupts = irqs;
	if (irqs >= 0)
		work->flags |= CXL_START_WORK_NUM_IRQS;
	else
		work->flags &= ~(CXL_START_WORK_NUM_IRQS);
	return 0;
}

inline
int cxl_work_set_wed(struct cxl_ioctl_start_work *work, __u64 wed)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	work->work_element_descriptor = wed;
	return 0;
}

#if defined CXL_START_WORK_TID
inline
int cxl_work_enable_wait(struct cxl_ioctl_start_work *work)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	work->flags |= CXL_START_WORK_TID;
	return 0;
}

inline
int cxl_work_disable_wait(struct cxl_ioctl_start_work *work)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	work->flags &= ~(CXL_START_WORK_TID);
	return 0;
}
#endif

/*
 * Event description print helpers
 */

static int
cxl_fprint_afu_interrupt(FILE *stream, struct cxl_event_afu_interrupt *event)
{
	return fprintf(stream, "AFU Interrupt %i\n", event->irq);
}

static int
cxl_fprint_data_storage(FILE *stream, struct cxl_event_data_storage *event)
{
	return fprintf(stream, "AFU Invalid memory reference: 0x%"PRIx64"\n",
		       (uint64_t) event->addr);
}

static int
cxl_fprint_afu_error(FILE *stream, struct cxl_event_afu_error *event)
{
	return fprintf(stream, "AFU Error: 0x%"PRIx64"\n",
		       (uint64_t) event->error);
}

static int hexdump(FILE *stream, __u8 *addr, ssize_t size)
{
	unsigned i, j, c = 0;

	for (i = 0; i < size; i += 4) {
		for (j = i; j < size && j < i + 4; j++)
			c += fprintf(stream, "%.2x", addr[j]);
		c += fprintf(stream, " ");
	}
	c += fprintf(stream, "\n");
	return c;
}

int
cxl_fprint_unknown_event(FILE *stream, struct cxl_event *event)
{
	int ret;

	if (!event) {
		errno = EINVAL;
		return -1;
	}
	ret = fprintf(stream, "CXL Unknown Event %i: ", event->header.type);
	if (ret < 0)
		return ret;
	ret += hexdump(stream, (__u8 *)event, event->header.size);
	return ret;
}

/*
 * Print a description of the given event to the file stream.
 */
int
cxl_fprint_event(FILE *stream, struct cxl_event *event)
{
	if (!event) {
		errno = EINVAL;
		return -1;
	}
	switch (event->header.type) {
		case CXL_EVENT_READ_FAIL:
			fprintf(stderr, "cxl_fprint_event: CXL Read failed\n");
			errno = ENODATA;
			return -1;
		case CXL_EVENT_AFU_INTERRUPT:
			return cxl_fprint_afu_interrupt(stream, &event->irq);
		case CXL_EVENT_DATA_STORAGE:
			return cxl_fprint_data_storage(stream, &event->fault);
		case CXL_EVENT_AFU_ERROR:
			return cxl_fprint_afu_error(stream, &event->afu_error);
		default:
			return cxl_fprint_unknown_event(stream, event);
	}
}

static inline void poison(__u8 *ptr, ssize_t len)
{
	unsigned int toxin = 0xDEADBEEF;
	__u8 *end;

	for (end = ptr + len; ptr < end; ptr++)
		*ptr = (toxin >> (8 * (3 - ((uintptr_t)ptr % 4)))) & 0xff;
}

static inline int fetch_cached_event(struct cxl_afu_h *afu,
				     struct cxl_event *event)
{
	int size;

	/* Local events caches, let's send it out */
	size = afu->event_buf_first->header.size;
	memcpy(event, afu->event_buf_first, size);
	afu->event_buf_first = (struct cxl_event *)
		((char *)afu->event_buf_first + size);
	assert(afu->event_buf_first <= afu->event_buf_end);
	return 0;
}

static int event_cached(struct cxl_afu_h *afu)
{
	return afu->event_buf_first != afu->event_buf_end;
}

int cxl_event_pending(struct cxl_afu_h *afu)
{
	struct pollfd fds[1] = {{cxl_afu_fd(afu), POLLIN, 0}};

	if (afu == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (event_cached(afu))
		return 1;

	return poll(fds, 1, 0);
}

int cxl_read_event(struct cxl_afu_h *afu, struct cxl_event *event)
{
	struct cxl_event *p = NULL;
	ssize_t size;
	int	rc = 0;

	if (afu == NULL || event == NULL) {
		errno = EINVAL;
		return -1;
	}
	/* Init buffer */
	if (!afu->event_buf) {
		p = malloc(CXL_READ_MIN_SIZE);
		if (!p) {
			errno = ENOMEM;
			return -1;
		}
		afu->event_buf = p;
		afu->event_buf_first = afu->event_buf;
		afu->event_buf_end = afu->event_buf;
	}

	/* Send buffered event */
	if (event_cached(afu)) {
		rc = fetch_cached_event(afu, event);
		return rc;
	}

	if (afu->fd < 0) {
		errno = EINVAL;
		return -1;
	}

	/* Looks like we need to go read some data from the kernel */
	size = read(afu->fd, afu->event_buf, CXL_READ_MIN_SIZE);
	if (size <= 0) {
		poison((__u8 *)event, sizeof(*event));
		event->header.type = CXL_EVENT_READ_FAIL;
		event->header.size = 0;
		if (size < 0)
			return size;
		errno = ENODATA;
		return -1;
	}

	/* check for at least 1 event */
	assert(size >= afu->event_buf->header.size);

	afu->event_buf_first = afu->event_buf;
	afu->event_buf_end = (struct cxl_event *)
		((char *)afu->event_buf + size);

	return fetch_cached_event(afu, event);
}

/*
 * Read an event from the AFU when an event of type is expected. For AFU
 * interrupts, the expected AFU interrupt number may also be supplied (0 will
 * accept any AFU interrupt).
 *
 * Returns 0 if the read event was of the expected type and (if applicable)
 * AFU interrupt number. If the event did not match the type & interrupt
 * number, it returns -1.
 *
 * If the read() syscall failed for some reason (e.g. no event pending when
 * using non-blocking IO, etc) it will return -2 and errno will be set
 * appropriately.
 */
int cxl_read_expected_event(struct cxl_afu_h *afu, struct cxl_event *event,
			   __u32 type, __u16 irq)
{
	int rv;

	if ((rv = cxl_read_event(afu, event)) < 0)
		return rv;

#if 0
	printf("cxl_read_expected_event: Poisoning %li bytes from %p, event: %p, size: %li, rv: %i\n",
			size - rv, (void*)(((__u8 *)event) + rv), (void*)event, size, rv);
	hexdump(stderr, (__u8 *)event, size);
#endif

	if (event->header.type != type)
		return -1;

	if ((type == CXL_EVENT_AFU_INTERRUPT) && irq) {
		if (!(event->irq.irq == irq))
			return -1;
	}

	return 0;
}

/* Userspace MMIO functions */

int cxl_mmio_map(struct cxl_afu_h *afu, __u32 flags)
{
	void *addr;
	long size;

	if (afu == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (flags & ~(CXL_MMIO_FLAGS))
		goto err;
	if (!cxl_afu_opened(afu))
		goto err;
	if (cxl_get_mmio_size(afu, &size) < 0)
		return -1;

	afu->mmio_size = (size_t)size;
	addr = mmap(NULL, afu->mmio_size, PROT_READ|PROT_WRITE, MAP_SHARED,
		    afu->fd, 0);
	if (addr == MAP_FAILED)
		return -1;

	afu->mmio_flags = flags;
	afu->mmio_addr = addr;
	return 0;
err:
	errno = ENODEV;
	return -1;
}

int cxl_mmio_unmap(struct cxl_afu_h *afu)
{
	if (!afu || !afu->mmio_addr) {
		errno = EINVAL;
		return -1;
	}
	if (munmap(afu->mmio_addr, afu->mmio_size))
		return -1;

	afu->mmio_addr = NULL;
	return 0;
}

int cxl_mmio_ptr(struct cxl_afu_h *afu, void **mmio_ptrp)
{
	if (afu == NULL || afu->mmio_addr == NULL) {
		errno = EINVAL;
		return -1;
	}
	*mmio_ptrp = afu->mmio_addr;
	return 0;
}

static int cxl_sigbus_handler_installed;
static struct sigaction cxl_sigbus_old_action;
static __thread jmp_buf cxl_sigbus_env;
static __thread int cxl_sigbus_jmp_enabled;

static inline int cxl_mmio_try(void)
{
	int ret;

	if (!cxl_sigbus_handler_installed)
		return 0;

	ret = sigsetjmp(cxl_sigbus_env, 1);
	if (!ret)
		cxl_sigbus_jmp_enabled = 1;

	return ret;
}

static inline void cxl_mmio_success(void)
{
	cxl_sigbus_jmp_enabled = 0;
}

#ifdef __PPC64__

static inline void _cxl_mmio_write64(struct cxl_afu_h *afu, uint64_t offset, uint64_t data)
{
	__asm__ __volatile__("sync ; std%U0%X0 %1,%0"
			     : "=m"(*(__u64 *)(afu->mmio_addr + offset))
			     : "r"(data));
}

static inline uint64_t _cxl_mmio_read64(struct cxl_afu_h *afu, uint64_t offset)
{
	uint64_t d;

	__asm__ __volatile__("ld%U1%X1 %0,%1; sync"
			     : "=r"(d)
			     : "m"(*(__u64 *)(afu->mmio_addr + offset)));
	return d;
}

#else /* __PPC64__ */

static inline void _cxl_mmio_write64(struct cxl_afu_h *afu, uint64_t offset, uint64_t data)
{
	uint32_t d32;

	d32 = (data >> 32);
	__asm__ __volatile__("sync ; stw%U0%X0 %1,%0"
			     : "=m"(*(__u64 *)(afu->mmio_addr + offset))
			     : "r"(d32));
	d32 = data;
	__asm__ __volatile__("sync ; stw%U0%X0 %1,%0"
			     : "=m"(*(__u64 *)(afu->mmio_addr + offset + 4))
			     : "r"(d32));
}

static inline uint64_t _cxl_mmio_read64(struct cxl_afu_h *afu, uint64_t offset)
{
	uint64_t d;
	uint32_t d32;

	__asm__ __volatile__("lwz%U1%X1 %0,%1; sync"
			     : "=r"(d32)
			     : "m"(*(__u64 *)(afu->mmio_addr + offset)));
	d = d32;
	__asm__ __volatile__("lwz%U1%X1 %0,%1; sync"
			     : "=r"(d32)
			     : "m"(*(__u64 *)(afu->mmio_addr + offset + 4)));

	return (d << 32) | d32;
}

#endif /* __PPC64__ */

static inline void _cxl_mmio_write32(struct cxl_afu_h *afu, uint64_t offset, uint32_t data)
{
	__asm__ __volatile__("sync ; stw%U0%X0 %1,%0"
			     : "=m"(*(__u64 *)(afu->mmio_addr + offset))
			     : "r"(data));
}

static inline uint32_t _cxl_mmio_read32(struct cxl_afu_h *afu, uint64_t offset)
{
	uint32_t d;

	__asm__ __volatile__("lwz%U1%X1 %0,%1; sync"
			     : "=r"(d)
			     : "m"(*(__u64 *)(afu->mmio_addr + offset)));
	return d;
}

int cxl_mmio_write64(struct cxl_afu_h *afu, uint64_t offset, uint64_t data)
{
	if (!afu || !afu->mmio_addr)
		goto out;
	if (offset >= afu->mmio_size)
		goto out;
	if (offset & 0x7)
		goto out;

	if ((afu->mmio_flags & CXL_MMIO_ENDIAN_MASK) == CXL_MMIO_LITTLE_ENDIAN)
		data = htole64(data);
	if ((afu->mmio_flags & CXL_MMIO_ENDIAN_MASK) == CXL_MMIO_BIG_ENDIAN)
		data = htobe64(data);

	if (cxl_mmio_try())
		goto fail;
	_cxl_mmio_write64(afu, offset, data);
	cxl_mmio_success();

	return 0;

out:
	errno = EINVAL;
	return -1;
fail:
	if (!cxl_sigbus_handler_installed) {
		/* TODO: use pthread_sigqueue / sigqueue / rt_tgsigqueueinfo to
		 * pass the faulting address */
		raise(SIGBUS);
	}

	errno = EIO;
	return -1;
}

int cxl_mmio_read64(struct cxl_afu_h *afu, uint64_t offset, uint64_t *data)
{
	uint64_t d;

	if (!afu || !afu->mmio_addr)
		goto out;
	if (offset >= afu->mmio_size)
		goto out;
	if (offset & 0x7)
		goto out;

	if (cxl_mmio_try())
		goto fail;
	d = _cxl_mmio_read64(afu, offset);
	cxl_mmio_success();

	if (d == 0xffffffffffffffffull)
		goto fail;

	*data = d;
	if ((afu->mmio_flags & CXL_MMIO_ENDIAN_MASK) == CXL_MMIO_LITTLE_ENDIAN)
		*data = le64toh(d);
	if ((afu->mmio_flags & CXL_MMIO_ENDIAN_MASK) == CXL_MMIO_BIG_ENDIAN)
		*data = be64toh(d);
	return 0;

out:
	errno = EINVAL;
	return -1;

fail:
	if (!cxl_sigbus_handler_installed) {
		/* TODO: use pthread_sigqueue / sigqueue / rt_tgsigqueueinfo to
		 * pass the faulting address */
		raise(SIGBUS);
	}

	*data = 0xffffffffffffffffull;
	errno = EIO;
	return -1;
}

int cxl_mmio_write32(struct cxl_afu_h *afu, uint64_t offset, uint32_t data)
{
	if (!afu || !afu->mmio_addr)
		goto out;
	if (offset >= afu->mmio_size)
		goto out;
	if (offset & 0x3)
		goto out;

	if ((afu->mmio_flags & CXL_MMIO_ENDIAN_MASK) == CXL_MMIO_LITTLE_ENDIAN)
		data = htole32(data);
	if ((afu->mmio_flags & CXL_MMIO_ENDIAN_MASK) == CXL_MMIO_BIG_ENDIAN)
		data = htobe32(data);

	if (cxl_mmio_try())
		goto fail;
	_cxl_mmio_write32(afu, offset, data);
	cxl_mmio_success();

	return 0;

out:
	errno = EINVAL;
	return -1;
fail:
	if (!cxl_sigbus_handler_installed) {
		/* TODO: use pthread_sigqueue / sigqueue / rt_tgsigqueueinfo to
		 * pass the faulting address */
		raise(SIGBUS);
	}

	errno = EIO;
	return -1;

}

int cxl_mmio_read32(struct cxl_afu_h *afu, uint64_t offset, uint32_t *data)
{
	uint32_t d;

	if (!afu || !afu->mmio_addr)
		goto out;
	if (offset >= afu->mmio_size)
		goto out;
	if (offset & 0x3)
		goto out;

	if (cxl_mmio_try())
		goto fail;
	d = _cxl_mmio_read32(afu, offset);
	cxl_mmio_success();

	if (d == 0xffffffff)
		goto fail;

	*data = d;
	if ((afu->mmio_flags & CXL_MMIO_ENDIAN_MASK) == CXL_MMIO_LITTLE_ENDIAN)
		*data = le32toh(d);
	if ((afu->mmio_flags & CXL_MMIO_ENDIAN_MASK) == CXL_MMIO_BIG_ENDIAN)
		*data = be32toh(d);
	return 0;

out:
	errno = EINVAL;
	return -1;
fail:
	if (!cxl_sigbus_handler_installed) {
		/* TODO: use pthread_sigqueue / sigqueue / rt_tgsigqueueinfo to
		 * pass the faulting address */
		raise(SIGBUS);
	}

	*data = 0xffffffff;
	errno = EIO;
	return -1;
}

static void cxl_sigbus_action(int sig, siginfo_t *info, void *context)
{
	if (info->si_code == BUS_ADRERR && cxl_sigbus_jmp_enabled) {
		/* fprintf(stderr, "libcxl: SIGBUS handler caught bad access to %p\n", info->si_addr); */
		siglongjmp(cxl_sigbus_env, 1);
	}

	if (cxl_sigbus_old_action.sa_handler == SIG_IGN) {
		/* fprintf(stderr, "libcxl: Ignoring SIGBUS\n"); */
		return;
	}

	if (cxl_sigbus_old_action.sa_handler == SIG_DFL) {
		/* fprintf(stderr, "libcxl: Raising default SIGBUS handler\n"); */
		sigaction(SIGBUS, &cxl_sigbus_old_action, NULL);
		raise(SIGBUS);
	}

	/*
	 * Chain to any other installed SIGBUS handlers. Do this after checking
	 * valid values of sa_handler as the two are stored as a union.
	 */
	if (cxl_sigbus_old_action.sa_sigaction) {
		/* fprintf(stderr, "libcxl: Calling chained SIGBUS handler\n"); */
		cxl_sigbus_old_action.sa_sigaction(sig, info, context);
	}
}

int cxl_mmio_install_sigbus_handler(void)
{
	struct sigaction act;

	if (cxl_sigbus_handler_installed)
		return 0;
	cxl_sigbus_handler_installed = 1;

	memset(&act, 0, sizeof(struct sigaction));
	act.sa_sigaction = cxl_sigbus_action;
	act.sa_flags = SA_SIGINFO;

	return sigaction(SIGBUS, &act, &cxl_sigbus_old_action);
}

#if defined CXL_START_WORK_TID
int cxl_afu_wait_host_thread(struct cxl_afu_h *afu, volatile __u64 *uword)
{
	if (afu == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (afu->tid != syscall(SYS_gettid)) {
		errno = EPERM;
		return -1;
	}

	while (*uword == 0) {
		asm volatile ("wait");
	}
	return 0;
}
#endif
