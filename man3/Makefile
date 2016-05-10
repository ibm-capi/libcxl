SRC = $(wildcard *.3)
HTML = $(SRC:.3=.3.html)
TXT = $(SRC:.3=.3.txt)

all: $(HTML) $(TXT)

clean:
	rm -f *.3.html *.3.txt

%.3.html: %.3
	man2html -r <$< >$@; [ -s $@ ]

%.3.txt: %.3
	./man2txt <$< >$@; [ -s $@ ]

cxl.3.txt: cxl.3
	./man2txt <$< | ./foldtbl >$@; [ -s $@ ]

cxl_for_each_adapter.3.html: cxl_adapter_next.3.html
	cp -f $< $@

cxl_for_each_adapter_afu.3.html: cxl_adapter_afu_next.3.html
	cp -f $< $@

cxl_for_each_afu.3.html: cxl_afu_next.3.html
	cp -f $< $@

include ../Makefile.rules

install:
	mkdir -p $(DESTDIR)$(mandir)/man3
	install -m 0644 $(SRC) $(DESTDIR)$(mandir)/man3/

.PHONY: all clean install
