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

#ifndef _LIBCXL_H
#define _LIBCXL_H

#include <stdint.h>
#include <stdio.h>
#include <misc/cxl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CXL_KERNEL_API_VERSION 1

#define CXL_SYSFS_CLASS "/sys/class/cxl"
#define CXL_DEV_DIR "/dev/cxl"

/*
 * Opaque types
 */
struct cxl_adapter_h;
struct cxl_afu_h;
struct cxl_ioctl_start_work;

/*
 * Adapter Enumeration
 *
 * Repeatedly call cxl_adapter_next() (or use the cxl_for_each_adapter macro)
 * to enumerate the available CXL adapters.
 *
 * cxl_adapter_next() will implicitly free used buffers if it is called on the
 * last adapter, or cxl_adapter_free() can be called explicitly.
 */
struct cxl_adapter_h * cxl_adapter_next(struct cxl_adapter_h *adapter);
char * cxl_adapter_dev_name(struct cxl_adapter_h *adapter);
void cxl_adapter_free(struct cxl_adapter_h *adapter);
#define cxl_for_each_adapter(adapter) \
	for (adapter = cxl_adapter_next(NULL); adapter; adapter = cxl_adapter_next(adapter))

/*
 * AFU Enumeration
 *
 * Repeatedly call cxl_adapter_afu_next() (or use the
 * cxl_for_each_adapter_afu macro) to enumerate AFUs on a specific CXL
 * adapter, or use cxl_afu_next() or cxl_for_each_afu to enumerate AFUs over
 * all CXL adapters in the system.
 *
 * For instance, if you just want to find any AFU attached to the system but
 * don't particularly care which one, just do:
 * struct cxl_afu_h *afu_h = cxl_afu_next(NULL);
 *
 * cxl_[adapter]_afu_next() will implicitly free used buffers if it is called
 * on the last AFU, or cxl_afu_free() can be called explicitly.
 */
struct cxl_afu_h * cxl_adapter_afu_next(struct cxl_adapter_h *adapter, struct cxl_afu_h *afu);
struct cxl_afu_h * cxl_afu_next(struct cxl_afu_h *afu);
char * cxl_afu_dev_name(struct cxl_afu_h *afu);
#define cxl_for_each_adapter_afu(adapter, afu) \
	for (afu = cxl_adapter_afu_next(adapter, NULL); afu; afu = cxl_adapter_afu_next(adapter, afu))
#define cxl_for_each_afu(afu) \
	for (afu = cxl_afu_next(NULL); afu; afu = cxl_afu_next(afu))

enum cxl_views {
	CXL_VIEW_DEDICATED = 0,
	CXL_VIEW_MASTER,
	CXL_VIEW_SLAVE
};

/*
 * Open AFU - either by path, by AFU being enumerated, or tie into an AFU file
 * descriptor that has already been opened. The AFU file descriptor will be
 * closed by cxl_afu_free() regardless of how it was opened.
 */
struct cxl_afu_h * cxl_afu_open_dev(char *path);
struct cxl_afu_h * cxl_afu_open_h(struct cxl_afu_h *afu, enum cxl_views view);
struct cxl_afu_h * cxl_afu_fd_to_h(int fd);
void cxl_afu_free(struct cxl_afu_h *afu);
int cxl_afu_opened(struct cxl_afu_h *afu);

/*
 * Attach AFU context to this process
 */
struct cxl_ioctl_start_work *cxl_work_alloc(void);
int cxl_work_free(struct cxl_ioctl_start_work *work);
int cxl_work_get_amr(struct cxl_ioctl_start_work *work, __u64 *valp);
int cxl_work_get_num_irqs(struct cxl_ioctl_start_work *work, __s16 *valp);
int cxl_work_get_wed(struct cxl_ioctl_start_work *work, __u64 *valp);
int cxl_work_get_tid(struct cxl_ioctl_start_work *work, __u16 *valp);
int cxl_work_set_amr(struct cxl_ioctl_start_work *work, __u64 amr);
int cxl_work_set_num_irqs(struct cxl_ioctl_start_work *work, __s16 num_irqs);
int cxl_work_set_wed(struct cxl_ioctl_start_work *work, __u64 wed);
int cxl_work_enable_wait(struct cxl_ioctl_start_work *work);
int cxl_work_disable_wait(struct cxl_ioctl_start_work *work);

int cxl_afu_attach(struct cxl_afu_h *afu, __u64 wed);
int cxl_afu_attach_work(struct cxl_afu_h *afu,
			struct cxl_ioctl_start_work *work);

/* Deprecated interface */
int cxl_afu_attach_full(struct cxl_afu_h *afu, __u64 wed, __u16 num_interrupts,
			__u64 amr);

/*
 * Get AFU process element
 */
int cxl_afu_get_process_element(struct cxl_afu_h *afu);

/*
 * Returns the file descriptor for the open AFU to use with event loops.
 * Returns -1 if the AFU is not open.
 */
int cxl_afu_fd(struct cxl_afu_h *afu);

/*
 * sysfs helpers
 */

/*
 * NOTE: On success, this function automatically allocates the returned
 * buffer, which must be freed by the caller (much like asprintf).
 */
int cxl_afu_sysfs_pci(struct cxl_afu_h *afu, char **pathp);

/* Flags for cxl_get/set_mode and cxl_get_modes_supported */
#define CXL_MODE_DEDICATED   0x1
#define CXL_MODE_DIRECTED    0x2
#define CXL_MODE_TIME_SLICED 0x4

/* Values for cxl_get/set_prefault_mode */
enum cxl_prefault_mode {
	CXL_PREFAULT_MODE_NONE = 0,
	CXL_PREFAULT_MODE_WED,
	CXL_PREFAULT_MODE_ALL,
};

/* Values for cxl_get_image_loaded */
enum cxl_image {
	CXL_IMAGE_FACTORY = 0,
	CXL_IMAGE_USER,
};

/*
 * Get/set attribute values.
 * Return 0 on success, -1 on error.
 */
int cxl_get_api_version(struct cxl_afu_h *afu, long *valp);
int cxl_get_api_version_compatible(struct cxl_afu_h *afu, long *valp);
int cxl_get_cr_class(struct cxl_afu_h *afu, long cr_num, long *valp);
int cxl_get_cr_device(struct cxl_afu_h *afu, long cr_num, long *valp);
int cxl_get_cr_vendor(struct cxl_afu_h *afu, long cr_num, long *valp);
int cxl_get_irqs_max(struct cxl_afu_h *afu, long *valp);
int cxl_set_irqs_max(struct cxl_afu_h *afu, long value);
int cxl_get_irqs_min(struct cxl_afu_h *afu, long *valp);
int cxl_get_mmio_size(struct cxl_afu_h *afu, long *valp);
int cxl_get_mode(struct cxl_afu_h *afu, long *valp);
int cxl_set_mode(struct cxl_afu_h *afu, long value);
int cxl_get_modes_supported(struct cxl_afu_h *afu, long *valp);
int cxl_get_prefault_mode(struct cxl_afu_h *afu, enum cxl_prefault_mode *valp);
int cxl_set_prefault_mode(struct cxl_afu_h *afu, enum cxl_prefault_mode value);
int cxl_get_pp_mmio_len(struct cxl_afu_h *afu, long *valp);
int cxl_get_pp_mmio_off(struct cxl_afu_h *afu, long *valp);
int cxl_get_base_image(struct cxl_adapter_h *adapter, long *valp);
int cxl_get_caia_version(struct cxl_adapter_h *adapter, long *majorp,
			 long *minorp);
int cxl_get_image_loaded(struct cxl_adapter_h *adapter, enum cxl_image *valp);
int cxl_get_psl_revision(struct cxl_adapter_h *adapter, long *valp);
int cxl_get_psl_timebase_synced(struct cxl_adapter_h *adapter, long *valp);

/*
 * Events
 */
int cxl_event_pending(struct cxl_afu_h *afu);
int cxl_read_event(struct cxl_afu_h *afu, struct cxl_event *event);
int cxl_read_expected_event(struct cxl_afu_h *afu, struct cxl_event *event,
			    __u32 type, __u16 irq);

/*
 * fprint wrappers to print out CXL events - useful for debugging.
 * cxl_fprint_event will select the appropriate implementation based on the
 * event type and cxl_fprint_unknown_event will print out a hex dump of the
 * raw event.
 */
int cxl_fprint_event(FILE *stream, struct cxl_event *event);
int cxl_fprint_unknown_event(FILE *stream, struct cxl_event *event);

/*
 * AFU MMIO functions
 *
 * The below assessors will byte swap based on what is passed to map.  Also a
 * full memory barrier 'sync' will proceed a write and follow a read.  More
 * relaxed assessors can be created using a pointer derived from cxl_mmio_ptr().
 */
#define CXL_MMIO_BIG_ENDIAN	0x1
#define CXL_MMIO_LITTLE_ENDIAN	0x2
#define CXL_MMIO_HOST_ENDIAN	0x3
#define CXL_MMIO_ENDIAN_MASK	0x3
#define CXL_MMIO_FLAGS		0x3
int cxl_mmio_map(struct cxl_afu_h *afu, __u32 flags);
int cxl_mmio_unmap(struct cxl_afu_h *afu);
int cxl_mmio_ptr(struct cxl_afu_h *afu, void **mmio_ptrp);
int cxl_mmio_write64(struct cxl_afu_h *afu, uint64_t offset, uint64_t data);
int cxl_mmio_read64(struct cxl_afu_h *afu, uint64_t offset, uint64_t *data);
int cxl_mmio_write32(struct cxl_afu_h *afu, uint64_t offset, uint32_t data);
int cxl_mmio_read32(struct cxl_afu_h *afu, uint64_t offset, uint32_t *data);

/*
 * Calling this function will install the libcxl SIGBUS handler. This will
 * catch bad MMIO accesses (e.g. due to hardware failures) that would otherwise
 * terminate the program and make the above mmio functions return errors
 * instead.
 *
 * Call this once per process prior to any MMIO accesses.
 */
int cxl_mmio_install_sigbus_handler(void);

/**
 * Returns the size of afu_err_buff in bytes.
 * @param afu Handle to the afu.
 * @param valp Pointer to the location where size is copied to.
 * @return In case of success '0' is returned. In case of an error or
 * the afu_err_buff doesn't exist, -1 is returned and errno is set
 * appropriately.
 */
int cxl_errinfo_size(struct cxl_afu_h *afu, size_t *valp);

/**
 * Read and copy the contents of afu_err_info buffer into the provided buffer.
 * @param afu Handle to the afu
 * @param dst Pointer to the buffer where data would be copied.
 * @param off Start offset within the afu_err_info handle.
 * @param len Number of bytes to be copied after the start offset.
 * @return The number of bytes copied from the afu_err_buff to dst. In case of
 * an error or the afu_err_buff doesn't exist, -1 is returned and errno is set
 * appropriately.
 */
ssize_t cxl_errinfo_read(struct cxl_afu_h *afu, void *dst, off_t off,
			 size_t len);

/**
 * Loop used to re-wait the current thread (which has attached the work)
 * after a spurious wake-up.
 * The loop should exit only when, after waking, the shared memory
 * has changed.
 * @param uworld Pointer to the shared memory to exit from the loop.
 * @return In case of success '0' is returned. In case of an error or
 * the afu doesn't exist, -1 is returned and errno is set
 * appropriately.
 */
int cxl_wait_host_thread(struct cxl_afu_h *afu, volatile __u64 *uword);
#ifdef __cplusplus
}
#endif

#endif
