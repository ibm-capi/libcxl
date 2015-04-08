srcdir = $(PWD)
include Makefile.vars

OBJS = libcxl.o libcxl_sysfs.o
CFLAGS += -I include

all: include/misc/cxl.h libcxl.so libcxl.a

CHECK_HEADER = $(shell echo \\\#include $(1) | \
                 $(CC) $(CFLAGS) -E - > /dev/null 2>&1 && echo y || echo n)

include/misc/cxl.h:
ifeq ($(call CHECK_HEADER,"<misc/cxl.h>"),n)
	$(call Q,WGET include/misc/cxl.h, wget -P include/misc -q http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h)
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
