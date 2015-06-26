srcdir = $(PWD)
include Makefile.vars

OBJS = libcxl.o libcxl_sysfs.o
CFLAGS += -I include

all: check_cxl_header libcxl.so libcxl.a

# Update this to test a single feature from the most recent header we require:
CHECK_CXL_HEADER_IS_UP_TO_DATE = $(shell /bin/echo -e \\\#include $(1)\\\nvoid test\(struct cxl_afu_id test\)\; | \
                 $(CC) $(CFLAGS) -Werror -x c -S - > /dev/null 2>&1 && echo y || echo n)

check_cxl_header:
ifeq ($(call CHECK_CXL_HEADER_IS_UP_TO_DATE,"<misc/cxl.h>"),n)
	$(call Q,CURL include/misc/cxl.h, curl -o include/misc/cxl.h -s http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h)
endif

libcxl.o libcxl_sysfs.o : CFLAGS += -fPIC

libcxl.so: libcxl.o libcxl_sysfs.o symver.map
	$(call Q,CC, $(CC) $(CFLAGS) -shared libcxl.o libcxl_sysfs.o -o libcxl.so, libcxl.so) -Wl,--version-script symver.map

libcxl.a: libcxl.o libcxl_sysfs.o
	$(call Q,AR, ar rcs libcxl.a libcxl.o libcxl_sysfs.o, libcxl.a)

include Makefile.rules

clean:
	rm -f *.o *.d libcxl.so libcxl.a include/misc/cxl.h

.PHONY: clean all
