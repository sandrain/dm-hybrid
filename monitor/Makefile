CC	= gcc
CFLAGS	= -Wall -O0 -g3 -W
LICENSE_CFLAGS = -D_GNU_SOURCE -D_BSD_SOURCE
ALL_CFLAGS = $(CFLAGS) $(LICENSE_CFLAGS) -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -D__DEBUG__
PROGS	= hystormon
LIBS	= -lpthread

all: $(PROGS)

%.o: %.c
	$(CC) -o $*.o -c $(ALL_CFLAGS) $<

hystormon: hystormon.o hystor_lib.o rbtree.o hash_table.h
	$(CC) $(ALL_CFLAGS) -o $@ $(filter %.o,$^) $(LIBS) -lrt

clean:
	-rm -f *.o $(PROGS)


#$(PROGS): | depend
#
#depend:
#	@$(CC) -MM $(ALL_CFLAGS) *.c 1> .depend
#
#INSTALL = install
#prefix = /usr/local
#bindir = $(prefix)/bin
#mandir = $(prefix)/man
#RPMBUILD = rpmbuild
#TAR = tar
#
#export prefix INSTALL TAR
#
#dist: btrace.spec
#	git-tar-tree HEAD btrace-1.0 > btrace-1.0.tar
#	@mkdir -p btrace-1.0
#	@cp btrace.spec btrace-1.0
#	$(TAR) rf btrace-1.0.tar btrace-1.0/btrace.spec
#	@rm -rf btrace-1.0
#	@bzip2 btrace-1.0.tar
#
#rpm: dist
#	$(RPMBUILD) -ta btrace-1.0.tar.bz2
#
#
#install: all
#	$(INSTALL) -m 755 -d $(DESTDIR)$(bindir)
#	$(INSTALL) -m 755 -d $(DESTDIR)$(mandir)/man1
#	$(INSTALL) -m 755 -d $(DESTDIR)$(mandir)/man8
#	$(INSTALL) -m 755 $(ALL) $(DESTDIR)$(bindir)
#	$(INSTALL) -m 644 doc/*.1 $(DESTDIR)$(mandir)/man1
#	$(INSTALL) -m 644 doc/*.8 $(DESTDIR)$(mandir)/man8
#
#ifneq ($(wildcard .depend),)
#include .depend
#endif
