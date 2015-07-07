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

#ifndef _LIBCXL_INTERNAL_H
#define _LIBCXL_INTERNAL_H

#include <sys/types.h>
#include <dirent.h>

struct cxl_adapter_h {
	DIR *enum_dir;
	struct dirent *enum_ent;
	char *sysfs_path;
};

struct cxl_afu_h {
	struct cxl_adapter_h *adapter; /* Only used if allocated by us */
	DIR *enum_dir;
	int process_element;
	struct dirent *enum_ent;
	struct cxl_event *event_buf;		/* Event buffer storage */
	struct cxl_event *event_buf_first;	/* First event to read */
	struct cxl_event *event_buf_end;	/* End of events */
	char *dev_name;
	char *sysfs_path;
	int fd;
	void *mmio_addr;
	__u32 mmio_flags;
	size_t mmio_size;
	int fd_errbuff; /* fd to the afu_err_buff */
	size_t errbuff_size;
};

int cxl_get_dev(struct cxl_afu_h *afu, long *majorp, long *minorp);

#endif
