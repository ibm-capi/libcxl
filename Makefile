srcdir = $(PWD)
include Makefile.vars

OBJS = libcxl.o libcxl_sysfs.o
CFLAGS += -I include

# change VERS_LIB if new git tag
VERS_LIB = 1.7
LIBNAME   = libcxl.so.$(VERS_LIB)
# change VERS_SONAME only if library breaks backward compatibility.
# refer to file symver.map
VERS_SONAME=1
LIBSONAME = libcxl.so.$(VERS_SONAME)
SONAMEOPT = -Wl,-soname,$(LIBSONAME)

all: check_cxl_header $(LIBSONAME) libcxl.so libcxl.a

HAS_WGET = $(shell /bin/which wget > /dev/null 2>&1 && echo y || echo n)
HAS_CURL = $(shell /bin/which curl > /dev/null 2>&1 && echo y || echo n)

# Update this to test a single feature from the most recent header we require.
#
# Note that a backward-incompatible change in make 4.3 modified the
# handling \# in a function invocation, so we define the test code in
# a separate variable to work around it and keep consistent behavior
# across all versions of make
TEST_CODE = '\#include <misc/cxl.h>\nint i = CXL_START_WORK_TID;'
CHECK_CXL_HEADER_IS_UP_TO_DATE = $(shell /bin/echo -e $(TEST_CODE) | \
                 $(CC) $(CFLAGS) -Werror -x c -S -o /dev/null - >/dev/null 2>&1 && echo y || echo n)

check_cxl_header:
ifeq (${CHECK_CXL_HEADER_IS_UP_TO_DATE},n)
	mkdir -p include/misc
ifeq (${HAS_WGET},y)
	$(call Q,WGET include/misc/cxl.h, wget -O include/misc/cxl.h -q https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h)
else ifeq (${HAS_CURL},y)
	$(call Q,CURL include/misc/cxl.h, curl -o include/misc/cxl.h -s https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h)
else
	$(error 'cxl.h is non-existant or out of date, Download from https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h and place in ${PWD}/include/misc/cxl.h')
endif
endif

libcxl.o libcxl_sysfs.o : CFLAGS += -fPIC

libcxl.so: $(LIBNAME)
	ln -sf $(LIBNAME) libcxl.so

$(LIBSONAME): $(LIBNAME)
	ln -sf $(LIBNAME) $(LIBSONAME)

$(LIBNAME): libcxl.o libcxl_sysfs.o symver.map
	$(call Q,CC, $(CC) $(CFLAGS) $(LDFLAGS) -shared libcxl.o libcxl_sysfs.o -o $(LIBNAME), $(LIBNAME)) -Wl,--version-script symver.map $(SONAMEOPT)

libcxl.a: libcxl.o libcxl_sysfs.o
	$(call Q,AR, ar rcs libcxl.a libcxl.o libcxl_sysfs.o, libcxl.a)

include Makefile.rules

clean:
	rm -f *.o *.d libcxl.so* libcxl.a include/misc/cxl.h

install: all
	mkdir -p $(DESTDIR)$(libdir)
	mkdir -p $(DESTDIR)$(includedir)
	install -m 0755 $(LIBNAME) $(DESTDIR)$(libdir)/
	cp -d libcxl.so $(LIBSONAME) $(DESTDIR)$(libdir)/
	install -m 0644 libcxl.h  $(DESTDIR)$(includedir)/

.PHONY: clean all install
