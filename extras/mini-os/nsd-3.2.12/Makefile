#
# Makefile -- one file to make them all, nsd(8)
#
# Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
#
# See LICENSE for the license.
#

# Standard installation pathnames
SHELL = /bin/bash
srcdir = .
prefix	= /usr/local
exec_prefix = ${prefix}
sbindir	= ${exec_prefix}/sbin
mandir = ${datarootdir}/man
datarootdir = ${prefix}/share

# NSD specific pathnames
configdir = /etc/nsd
piddir = /var/run
dbdir = /var/db/nsd
pidfile = /var/run/nsd.pid
logfile = /var/log/nsd.log
zonestatsfile = /var/log/nsd.stats
dbfile = /var/db/nsd/nsd.db
difffile = /var/db/nsd/ixfr.db
xfrdfile = /var/db/nsd/xfrd.state
nsdconfigfile = /etc/nsd/nsd.conf
zonesdir = /etc/nsd
user = nsd
spriority = 45
kpriority = 74

CC		= gcc
CPPFLAGS	=  -I. -I$(srcdir)# -DHAVE_CONFIG_H contains -DHAVE_CONFIG_H
CFLAGS		= -g -O2
LDFLAGS		= 
LIBS		= 
LIBOBJS		=  ${LIBOBJDIR}strlcat$U.o ${LIBOBJDIR}strlcpy$U.o ${LIBOBJDIR}b64_pton$U.o ${LIBOBJDIR}b64_ntop$U.o
INSTALL		= $(srcdir)/install-sh -c
INSTALL_PROGRAM	= $(INSTALL)
INSTALL_DATA	= $(INSTALL) -m 644

YACC		= bison -y
LEX		= flex

COMPILE		= $(CC) $(CPPFLAGS) $(CFLAGS)
LINK		= $(CC) $(CFLAGS) $(LDFLAGS)
EDIT		= sed \
			-e 's,@prefix\@,$(prefix),g' \
			-e 's,@exec_prefix\@,$(exec_prefix),g' \
			-e 's,@sbindir\@,$(sbindir),g' \
			-e 's,@configdir\@,$(configdir),g' \
			-e 's,@zonesdir\@,$(zonesdir),g' \
			-e 's,@pidfile\@,$(pidfile),g' \
			-e 's,@logfile\@,$(logfile),g' \
			-e 's,@zonestatsfile\@,$(zonestatsfile),g' \
			-e 's,@dbfile\@,$(dbfile),g' \
			-e 's,@difffile\@,$(difffile),g' \
			-e 's,@xfrdfile\@,$(xfrdfile),g' \
			-e 's,@nsdconfigfile\@,$(nsdconfigfile),g' \
			-e 's,@shell\@,$(SHELL),g' \
			-e 's,@user\@,$(user),g' \
			-e 's,@spriority\@,$(spriority),g' \
			-e 's,@kpriority\@,$(kpriority),g' 

TARGETS 	= nsd zonec nsd-notify nsd-xfer nsdc.sh nsd-checkconf nsd-patch nsd.conf.sample \
			 nsd.8 zonec.8 nsd-notify.8 nsd-xfer.8 nsdc.8 nsd-checkconf.8 nsd-patch.8 nsd.conf.5

ALL_OBJECTS	=			\
	answer.o			\
	axfr.o				\
	buffer.o			\
	configlexer.o			\
	configparser.o			\
	dbaccess.o			\
	dbcreate.o			\
	difffile.o			\
	dname.o				\
	dns.o				\
	edns.o				\
	ipc.o				\
	iterated_hash.o			\
	namedb.o			\
	netio.o				\
	nsd-checkconf.o			\
	nsd-notify.o			\
	nsd.o				\
	nsd-patch.o			\
	nsd-xfer.o			\
	nsec3.o				\
	options.o			\
	packet.o			\
	query.o				\
	rbtree.o			\
	rdata.o				\
	region-allocator.o		\
	server.o			\
	tsig.o				\
	tsig-openssl.o			\
	util.o				\
	xfrd-disk.o			\
	xfrd-notify.o			\
	xfrd.o				\
	xfrd-tcp.o			\
	zlexer.o			\
	zonec.o				\
	zparser.o

NSD_OBJECTS	=				\
	answer.o				\
	axfr.o					\
	buffer.o				\
	configlexer.o				\
	configparser.o				\
	options.o				\
	dbaccess.o				\
	difffile.o				\
	dname.o					\
	dns.o					\
	edns.o					\
	ipc.o					\
	iterated_hash.o				\
	namedb.o				\
	netio.o					\
	nsd.o					\
	nsec3.o					\
	packet.o				\
	query.o					\
	rbtree.o				\
	rdata.o					\
	region-allocator.o			\
	server.o				\
	tsig.o					\
	tsig-openssl.o				\
	util.o					\
	xfrd-disk.o				\
	xfrd-notify.o				\
	xfrd-tcp.o				\
	xfrd.o

ZONEC_OBJECTS	=				\
	answer.o				\
	axfr.o					\
	buffer.o				\
	configlexer.o				\
	configparser.o				\
	dbaccess.o				\
	difffile.o				\
	dbcreate.o				\
	dname.o					\
	dns.o					\
	edns.o					\
	iterated_hash.o				\
	namedb.o				\
	nsec3.o					\
	options.o				\
	packet.o				\
	query.o					\
	rbtree.o				\
	rdata.o					\
	region-allocator.o			\
	tsig.o					\
	tsig-openssl.o				\
	util.o					\
	zlexer.o				\
	zonec.o					\
	zparser.o

NSD_NOTIFY_OBJECTS	=			\
	answer.o				\
	axfr.o					\
	buffer.o				\
	configlexer.o                           \
	configparser.o                          \
	dbaccess.o				\
	dname.o					\
	dns.o					\
	edns.o					\
	iterated_hash.o				\
	namedb.o				\
	nsd-notify.o				\
	nsec3.o					\
	options.o				\
	packet.o				\
	query.o					\
	rbtree.o				\
	rdata.o                                 \
	region-allocator.o			\
	tsig.o					\
	tsig-openssl.o				\
	util.o

NSD_XFER_OBJECTS	=			\
	answer.o				\
	axfr.o					\
	buffer.o				\
	configlexer.o                           \
	configparser.o                          \
	dbaccess.o				\
	dname.o					\
	dns.o					\
	edns.o					\
	iterated_hash.o				\
	namedb.o				\
	nsd-xfer.o				\
	nsec3.o					\
	options.o				\
	packet.o				\
	query.o					\
	rbtree.o				\
	rdata.o					\
	region-allocator.o			\
	tsig.o					\
	tsig-openssl.o				\
	util.o

NSD_CHECKCONF_OBJECTS	=			\
	answer.o				\
	axfr.o					\
	buffer.o                                \
	configlexer.o                           \
	configparser.o                          \
	dbaccess.o				\
	dname.o                                 \
	dns.o                                   \
	edns.o					\
	iterated_hash.o				\
	namedb.o                                \
	nsd-checkconf.o                         \
	nsec3.o					\
	options.o                               \
	packet.o				\
	query.o					\
	rbtree.o                                \
	rdata.o                                 \
	region-allocator.o                      \
	tsig.o					\
	tsig-openssl.o				\
	util.o

NSD_PATCH_OBJECTS	=			\
	answer.o				\
	axfr.o					\
	buffer.o                                \
	configlexer.o                           \
	configparser.o                          \
	dbcreate.o				\
	dbaccess.o				\
	difffile.o				\
	dname.o                                 \
	dns.o                                   \
	edns.o					\
	iterated_hash.o				\
	namedb.o				\
	nsd-patch.o				\
	nsec3.o					\
	options.o                               \
	packet.o				\
	query.o					\
	rbtree.o                                \
	rdata.o                                 \
	region-allocator.o                      \
	tsig.o					\
	tsig-openssl.o				\
	util.o

CUTEST_OBJECTS		=			\
	answer.o				\
	axfr.o					\
	buffer.o				\
	configlexer.o				\
	configparser.o				\
	options.o				\
	dbaccess.o				\
	dbcreate.o				\
	difffile.o				\
	dname.o					\
	dns.o					\
	edns.o					\
	ipc.o					\
	iterated_hash.o				\
	namedb.o				\
	netio.o					\
	nsec3.o					\
	packet.o				\
	query.o					\
	rbtree.o				\
	rdata.o					\
	region-allocator.o			\
	server.o				\
	tsig.o					\
	tsig-openssl.o				\
	util.o					\
	xfrd-disk.o				\
	xfrd-notify.o				\
	xfrd-tcp.o				\
	xfrd.o					\
	cutest_dname.o 				\
	cutest_dns.o 				\
	cutest_iterated_hash.o 			\
	cutest_run.o				\
	cutest_rbtree.o 			\
	cutest_options.o 			\
	cutest_region.o 			\
	cutest_util.o 				\
	cutest.o

all:	$(TARGETS)

$(ALL_OBJECTS):
	$(COMPILE) -c $<

nsdc.sh:	$(srcdir)/nsdc.sh.in config.h
	rm -f nsdc.sh
	$(EDIT) $(srcdir)/nsdc.sh.in > nsdc.sh
	chmod +x nsdc.sh

nsd.conf.sample:	$(srcdir)/nsd.conf.sample.in config.h
	rm -f nsd.conf.sample
	$(EDIT) $(srcdir)/nsd.conf.sample.in > nsd.conf.sample

nsd.conf.5:	$(srcdir)/nsd.conf.5.in config.h
	rm -f nsd.conf.5
	$(EDIT) $(srcdir)/nsd.conf.5.in > nsd.conf.5

nsd.8:	$(srcdir)/nsd.8.in config.h
	rm -f nsd.8
	$(EDIT) $(srcdir)/nsd.8.in > nsd.8

nsdc.8:	$(srcdir)/nsdc.8.in config.h
	rm -f nsdc.8
	$(EDIT) $(srcdir)/nsdc.8.in > nsdc.8

zonec.8:	$(srcdir)/zonec.8.in config.h
	rm -f zonec.8
	$(EDIT) $(srcdir)/zonec.8.in > zonec.8

nsd-notify.8:	$(srcdir)/nsd-notify.8.in config.h
	rm -f nsd-notify.8
	$(EDIT) $(srcdir)/nsd-notify.8.in > nsd-notify.8

nsd-xfer.8:	$(srcdir)/nsd-xfer.8.in config.h
	rm -f nsd-xfer.8
	$(EDIT) $(srcdir)/nsd-xfer.8.in > nsd-xfer.8

nsd-checkconf.8:	$(srcdir)/nsd-checkconf.8.in config.h
	rm -f nsd-checkconf.8
	$(EDIT) $(srcdir)/nsd-checkconf.8.in > nsd-checkconf.8

nsd-patch.8:	$(srcdir)/nsd-patch.8.in config.h
	rm -f nsd-patch.8
	$(EDIT) $(srcdir)/nsd-patch.8.in > nsd-patch.8

install: all
	$(INSTALL) -d $(DESTDIR)$(sbindir)
	$(INSTALL) -d $(DESTDIR)$(configdir)
	$(INSTALL) -d $(DESTDIR)$(piddir)
	$(INSTALL) -d $(DESTDIR)$(dbdir)
	$(INSTALL) -d $(DESTDIR)$(mandir)
	$(INSTALL) -d $(DESTDIR)$(mandir)/man8
	$(INSTALL) -d $(DESTDIR)$(mandir)/man5
	$(INSTALL) nsd $(DESTDIR)$(sbindir)/nsd
	$(INSTALL) zonec $(DESTDIR)$(sbindir)/zonec
	$(INSTALL) nsdc.sh $(DESTDIR)$(sbindir)/nsdc
	$(INSTALL) nsd-notify $(DESTDIR)$(sbindir)/nsd-notify
	$(INSTALL) nsd-checkconf $(DESTDIR)$(sbindir)/nsd-checkconf
	$(INSTALL) nsd-patch $(DESTDIR)$(sbindir)/nsd-patch
	$(INSTALL) nsd-xfer $(DESTDIR)$(sbindir)/nsd-xfer
	$(INSTALL_DATA) $(srcdir)/nsd.8 $(DESTDIR)$(mandir)/man8
	$(INSTALL_DATA) $(srcdir)/nsdc.8 $(DESTDIR)$(mandir)/man8
	$(INSTALL_DATA) $(srcdir)/zonec.8 $(DESTDIR)$(mandir)/man8
	$(INSTALL_DATA) $(srcdir)/nsd-notify.8 $(DESTDIR)$(mandir)/man8/nsd-notify.8
	$(INSTALL_DATA) $(srcdir)/nsd-checkconf.8 $(DESTDIR)$(mandir)/man8/nsd-checkconf.8
	$(INSTALL_DATA) $(srcdir)/nsd-patch.8 $(DESTDIR)$(mandir)/man8/nsd-patch.8
	$(INSTALL_DATA) $(srcdir)/nsd-xfer.8 $(DESTDIR)$(mandir)/man8/nsd-xfer.8
	$(INSTALL_DATA) $(srcdir)/nsd.conf.5 $(DESTDIR)$(mandir)/man5/nsd.conf.5
	$(INSTALL_DATA) nsd.conf.sample $(DESTDIR)$(nsdconfigfile).sample

uninstall:
	@echo
	rm -f -- $(DESTDIR)$(sbindir)/nsd $(DESTDIR)$(sbindir)/zonec $(DESTDIR)$(sbindir)/nsdc $(DESTDIR)$(sbindir)/nsd-notify $(DESTDIR)$(sbindir)/nsd-xfer $(DESTDIR)$(sbindir)/nsd-checkconf $(DESTDIR)$(sbindir)/nsd-patch
	rm -f -- $(DESTDIR)$(mandir)/man8/nsd.8 $(DESTDIR)$(mandir)/man8/nsdc.8 $(DESTDIR)$(mandir)/man8/zonec.8 $(DESTDIR)$(mandir)/man8/nsd-notify.8 $(DESTDIR)$(mandir)/man8/nsd-xfer.8 $(DESTDIR)$(mandir)/man5/nsd.conf.5
	rm -f -- $(DESTDIR)$(mandir)/man8/nsd-checkconf.8 $(DESTDIR)$(mandir)/man8/nsd-patch.8
	rm -f -- $(DESTDIR)$(pidfile) $(DESTDIR)$(dbfile)
	@echo
	@echo "You still need to remove $(DESTDIR)$(configdir), $(DESTDIR)$(piddir), $(DESTDIR)$(dbdir) directory by hand."

test: 

nsd:	$(NSD_OBJECTS) $(LIBOBJS)
	$(LINK) -o $@ $(NSD_OBJECTS) $(LIBOBJS) $(LIBS)

zonec:	$(ZONEC_OBJECTS) $(LIBOBJS)
	$(LINK) -o $@ $(ZONEC_OBJECTS) $(LIBOBJS) $(LIBS)

nsd-notify:	$(NSD_NOTIFY_OBJECTS) $(LIBOBJS)
	$(LINK) -o $@ $(NSD_NOTIFY_OBJECTS) $(LIBOBJS) $(LIBS)

nsd-checkconf:	$(NSD_CHECKCONF_OBJECTS) $(LIBOBJS)
	$(LINK) -o $@ $(NSD_CHECKCONF_OBJECTS) $(LIBOBJS) $(LIBS)

nsd-xfer:	$(NSD_XFER_OBJECTS) $(LIBOBJS)
	$(LINK) -o $@ $(NSD_XFER_OBJECTS) $(LIBOBJS) $(LIBS)

nsd-patch:	$(NSD_PATCH_OBJECTS) $(LIBOBJS)
	$(LINK) -o $@ $(NSD_PATCH_OBJECTS) $(LIBOBJS) $(LIBS)

cutest:	$(CUTEST_OBJECTS)
	$(LINK) -o $@ $(CUTEST_OBJECTS) $(LIBOBJS) $(LIBS)

clean:
	rm -f *.o *.so y.* *.core *.gmon tags TAGS
	rm -f $(TARGETS)

realclean: clean
	rm -f Makefile config.h config.log config.status
	rm -rf autom4te*
	rm -f zlexer.c zparser.h zparser.c zparser.stamp
	rm -f configlexer.c configparser.h configparser.c configparser.stamp

devclean: realclean
	rm -f config.h.in configure

basename.o:	$(srcdir)/compat/basename.c
	$(COMPILE) -c $(srcdir)/compat/basename.c -o $@

inet_pton.o:	$(srcdir)/compat/inet_pton.c
	$(COMPILE) -c $(srcdir)/compat/inet_pton.c -o $@

inet_ntop.o:	$(srcdir)/compat/inet_ntop.c
	$(COMPILE) -c $(srcdir)/compat/inet_ntop.c -o $@

inet_aton.o:	$(srcdir)/compat/inet_aton.c
	$(COMPILE) -c $(srcdir)/compat/inet_aton.c -o $@

b64_pton.o:	$(srcdir)/compat/b64_pton.c
	$(COMPILE) -c $(srcdir)/compat/b64_pton.c -o $@

b64_ntop.o:	$(srcdir)/compat/b64_ntop.c
	$(COMPILE) -c $(srcdir)/compat/b64_ntop.c -o $@

memcmp.o:	$(srcdir)/compat/memcmp.c
	$(COMPILE) -c $(srcdir)/compat/memcmp.c -o $@

memmove.o:	$(srcdir)/compat/memmove.c
	$(COMPILE) -c $(srcdir)/compat/memmove.c -o $@

snprintf.o:	$(srcdir)/compat/snprintf.c
	$(COMPILE) -c $(srcdir)/compat/snprintf.c -o $@

strlcat.o:	$(srcdir)/compat/strlcat.c
	$(COMPILE) -c $(srcdir)/compat/strlcat.c -o $@

strlcpy.o:	$(srcdir)/compat/strlcpy.c
	$(COMPILE) -c $(srcdir)/compat/strlcpy.c -o $@

strptime.o:	$(srcdir)/compat/strptime.c
	$(COMPILE) -c $(srcdir)/compat/strptime.c -o $@

vsnprintf.o:	$(srcdir)/compat/vsnprintf.c
	$(COMPILE) -c $(srcdir)/compat/vsnprintf.c -o $@

timegm.o:	$(srcdir)/compat/timegm.c
	$(COMPILE) -c $(srcdir)/compat/timegm.c -o $@

malloc.o:	$(srcdir)/compat/malloc.c
	$(COMPILE) -c $(srcdir)/compat/malloc.c -o $@

pselect.o:	$(srcdir)/compat/pselect.c
	$(COMPILE) -c $(srcdir)/compat/pselect.c -o $@

fake-rfc2553.o:	$(srcdir)/compat/fake-rfc2553.c
	$(COMPILE) -c $(srcdir)/compat/fake-rfc2553.c -o $@

cutest_dname.o:	$(srcdir)/tpkg/cutest/cutest_dname.c
	$(COMPILE) -c $(srcdir)/tpkg/cutest/cutest_dname.c -o $@

cutest_dns.o:	$(srcdir)/tpkg/cutest/cutest_dns.c
	$(COMPILE) -c $(srcdir)/tpkg/cutest/cutest_dns.c -o $@

cutest_iterated_hash.o:	$(srcdir)/tpkg/cutest/cutest_iterated_hash.c
	$(COMPILE) -c $(srcdir)/tpkg/cutest/cutest_iterated_hash.c -o $@

cutest_run.o:	$(srcdir)/tpkg/cutest/cutest_run.c
	$(COMPILE) -c $(srcdir)/tpkg/cutest/cutest_run.c -o $@

cutest_rbtree.o:	$(srcdir)/tpkg/cutest/cutest_rbtree.c
	$(COMPILE) -c $(srcdir)/tpkg/cutest/cutest_rbtree.c -o $@

cutest_options.o:	$(srcdir)/tpkg/cutest/cutest_options.c
	$(COMPILE) -c $(srcdir)/tpkg/cutest/cutest_options.c -o $@

cutest_region.o:	$(srcdir)/tpkg/cutest/cutest_region.c
	$(COMPILE) -c $(srcdir)/tpkg/cutest/cutest_region.c -o $@

cutest_util.o:	$(srcdir)/tpkg/cutest/cutest_util.c
	$(COMPILE) -c $(srcdir)/tpkg/cutest/cutest_util.c -o $@

cutest.o:	$(srcdir)/tpkg/cutest/cutest.c
	$(COMPILE) -c $(srcdir)/tpkg/cutest/cutest.c -o $@

zlexer.c:	$(srcdir)/zlexer.lex
	echo "#include <config.h>" > $@
	$(LEX) -i -t $(srcdir)/zlexer.lex >> $@

zparser.c zparser.h: $(srcdir)/zparser.y
	$(YACC) -d -o zparser.c $(srcdir)/zparser.y

configlexer.c:	$(srcdir)/configlexer.lex
	echo "#include \"configyyrename.h\"" > $@
	$(LEX) -i -t $(srcdir)/configlexer.lex >> $@

configparser.c configparser.h:	$(srcdir)/configparser.y
	$(YACC) -d -o configparser.c $(srcdir)/configparser.y

# autoconf rules
config.h.in:	configure.ac
	autoheader

configure:	configure.ac
	autoconf

tags: 	
	ctags *.[ch]

# dependency generation
DEPEND_TMP=depend1073.tmp
DEPEND_TMP2=depend1074.tmp
DEPEND_TARGET=Makefile
DEPEND_TARGET2=Makefile.in
depend:
	(cd $(srcdir) ; $(CC) -MM $(CPPFLAGS) *.c compat/*.c tpkg/cutest/*.c) | \
		sed -e 's? *\([^ ]*\.[ch]\)? $$(srcdir)/\1?g' | \
		sed -e 's?$$(srcdir)/config.h?config.h?' \
			-e 's?$$(srcdir)/configlexer.c?configlexer.c?' \
			-e 's?$$(srcdir)/configparser.c?configparser.c?' \
			-e 's?$$(srcdir)/configparser.h?configparser.h?' \
			-e 's?$$(srcdir)/zlexer.c?zlexer.c?' \
			-e 's?$$(srcdir)/zparser.c?zparser.c?' \
			-e 's?$$(srcdir)/zparser.h?zparser.h?' \
			> $(DEPEND_TMP)
	cp $(DEPEND_TARGET) $(DEPEND_TMP2)
	head -`egrep -n "# Dependencies" $(DEPEND_TARGET) | tail -1 | sed -e 's/:.*$$//'` $(DEPEND_TMP2) > $(DEPEND_TARGET)
	cat $(DEPEND_TMP) >> $(DEPEND_TARGET)
	@if diff $(DEPEND_TARGET) $(DEPEND_TMP2); then echo "	$(DEPEND_TARGET) unchanged"; else echo "	Updated $(DEPEND_TARGET))"; fi
	@if test -f $(DEPEND_TARGET2); then \
		cp $(DEPEND_TARGET2) $(DEPEND_TMP2); \
		head -`egrep -n "# Dependencies" $(DEPEND_TARGET2) | tail -1 | sed -e 's/:.*$$//'` $(DEPEND_TMP2) > $(DEPEND_TARGET2); \
		cat $(DEPEND_TMP) >> $(DEPEND_TARGET2); \
		if diff $(DEPEND_TARGET2) $(DEPEND_TMP2); then echo "	$(DEPEND_TARGET2) unchanged"; else echo "	Updated $(DEPEND_TARGET2))"; fi; \
	fi
	rm -f $(DEPEND_TMP) $(DEPEND_TMP2)

# Dependencies
answer.o: $(srcdir)/answer.c config.h $(srcdir)/answer.h $(srcdir)/dns.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/rbtree.h $(srcdir)/packet.h $(srcdir)/query.h $(srcdir)/nsd.h $(srcdir)/edns.h $(srcdir)/tsig.h
axfr.o: $(srcdir)/axfr.c config.h $(srcdir)/axfr.h $(srcdir)/nsd.h $(srcdir)/dns.h $(srcdir)/edns.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/query.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/rbtree.h $(srcdir)/packet.h \
 $(srcdir)/tsig.h $(srcdir)/options.h
buffer.o: $(srcdir)/buffer.c config.h $(srcdir)/buffer.h $(srcdir)/region-allocator.h $(srcdir)/util.h
configlexer.o: configlexer.c $(srcdir)/configyyrename.h config.h $(srcdir)/options.h \
 $(srcdir)/region-allocator.h $(srcdir)/rbtree.h configparser.h
configparser.o: configparser.c config.h $(srcdir)/options.h $(srcdir)/region-allocator.h \
 $(srcdir)/rbtree.h $(srcdir)/util.h $(srcdir)/configyyrename.h
dbaccess.o: $(srcdir)/dbaccess.c config.h $(srcdir)/dns.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/rbtree.h $(srcdir)/options.h
dbcreate.o: $(srcdir)/dbcreate.c config.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/dns.h $(srcdir)/rbtree.h
difffile.o: $(srcdir)/difffile.c config.h $(srcdir)/difffile.h $(srcdir)/rbtree.h $(srcdir)/region-allocator.h \
 $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h $(srcdir)/util.h $(srcdir)/dns.h $(srcdir)/options.h $(srcdir)/packet.h $(srcdir)/rdata.h
dname.o: $(srcdir)/dname.c config.h $(srcdir)/dns.h $(srcdir)/dname.h $(srcdir)/buffer.h $(srcdir)/region-allocator.h \
 $(srcdir)/util.h $(srcdir)/query.h $(srcdir)/namedb.h $(srcdir)/rbtree.h $(srcdir)/nsd.h $(srcdir)/edns.h $(srcdir)/packet.h $(srcdir)/tsig.h
dns.o: $(srcdir)/dns.c config.h $(srcdir)/dns.h $(srcdir)/zonec.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/rbtree.h zparser.h
edns.o: $(srcdir)/edns.c config.h $(srcdir)/dns.h $(srcdir)/edns.h $(srcdir)/buffer.h $(srcdir)/region-allocator.h $(srcdir)/util.h
ipc.o: $(srcdir)/ipc.c config.h $(srcdir)/ipc.h $(srcdir)/netio.h $(srcdir)/region-allocator.h $(srcdir)/buffer.h $(srcdir)/util.h \
 $(srcdir)/xfrd-tcp.h $(srcdir)/xfrd.h $(srcdir)/rbtree.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/dns.h $(srcdir)/options.h $(srcdir)/tsig.h $(srcdir)/nsd.h \
 $(srcdir)/edns.h $(srcdir)/xfrd-notify.h
iterated_hash.o: $(srcdir)/iterated_hash.c config.h $(srcdir)/iterated_hash.h
namedb.o: $(srcdir)/namedb.c config.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h $(srcdir)/region-allocator.h \
 $(srcdir)/util.h $(srcdir)/dns.h $(srcdir)/rbtree.h
netio.o: $(srcdir)/netio.c config.h $(srcdir)/netio.h $(srcdir)/region-allocator.h $(srcdir)/util.h
nsd.o: $(srcdir)/nsd.c config.h $(srcdir)/nsd.h $(srcdir)/dns.h $(srcdir)/edns.h $(srcdir)/buffer.h $(srcdir)/region-allocator.h \
 $(srcdir)/util.h $(srcdir)/options.h $(srcdir)/rbtree.h $(srcdir)/tsig.h $(srcdir)/dname.h
nsd-checkconf.o: $(srcdir)/nsd-checkconf.c config.h $(srcdir)/tsig.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/dname.h $(srcdir)/options.h $(srcdir)/rbtree.h
nsd-notify.o: $(srcdir)/nsd-notify.c config.h $(srcdir)/tsig.h $(srcdir)/buffer.h $(srcdir)/region-allocator.h \
 $(srcdir)/util.h $(srcdir)/dname.h $(srcdir)/query.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/dns.h $(srcdir)/rbtree.h \
 $(srcdir)/region-allocator.h $(srcdir)/nsd.h $(srcdir)/edns.h $(srcdir)/buffer.h $(srcdir)/packet.h $(srcdir)/tsig.h
nsd-patch.o: $(srcdir)/nsd-patch.c config.h $(srcdir)/options.h $(srcdir)/region-allocator.h $(srcdir)/rbtree.h \
 $(srcdir)/difffile.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h $(srcdir)/util.h $(srcdir)/dns.h
nsd-xfer.o: $(srcdir)/nsd-xfer.c config.h $(srcdir)/dname.h $(srcdir)/buffer.h $(srcdir)/region-allocator.h \
 $(srcdir)/util.h $(srcdir)/dns.h $(srcdir)/packet.h $(srcdir)/namedb.h $(srcdir)/rbtree.h $(srcdir)/query.h $(srcdir)/nsd.h $(srcdir)/edns.h $(srcdir)/tsig.h \
 $(srcdir)/rdata.h $(srcdir)/tsig-openssl.h $(srcdir)/zonec.h
nsec3.o: $(srcdir)/nsec3.c config.h $(srcdir)/nsec3.h $(srcdir)/iterated_hash.h $(srcdir)/namedb.h $(srcdir)/dname.h \
 $(srcdir)/buffer.h $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/dns.h $(srcdir)/rbtree.h $(srcdir)/nsd.h $(srcdir)/edns.h $(srcdir)/answer.h \
 $(srcdir)/packet.h $(srcdir)/query.h $(srcdir)/tsig.h
options.o: $(srcdir)/options.c config.h $(srcdir)/options.h $(srcdir)/region-allocator.h $(srcdir)/rbtree.h \
 $(srcdir)/query.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h $(srcdir)/util.h $(srcdir)/dns.h $(srcdir)/nsd.h $(srcdir)/edns.h $(srcdir)/packet.h \
 $(srcdir)/tsig.h $(srcdir)/difffile.h $(srcdir)/configyyrename.h configparser.h
packet.o: $(srcdir)/packet.c config.h $(srcdir)/packet.h $(srcdir)/dns.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/rbtree.h $(srcdir)/query.h $(srcdir)/nsd.h $(srcdir)/edns.h $(srcdir)/tsig.h $(srcdir)/rdata.h
query.o: $(srcdir)/query.c config.h $(srcdir)/answer.h $(srcdir)/dns.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/rbtree.h $(srcdir)/packet.h $(srcdir)/query.h $(srcdir)/nsd.h $(srcdir)/edns.h $(srcdir)/tsig.h \
 $(srcdir)/axfr.h $(srcdir)/options.h $(srcdir)/nsec3.h
rbtree.o: $(srcdir)/rbtree.c config.h $(srcdir)/rbtree.h $(srcdir)/region-allocator.h
rdata.o: $(srcdir)/rdata.c config.h $(srcdir)/rdata.h $(srcdir)/dns.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/rbtree.h $(srcdir)/zonec.h
region-allocator.o: $(srcdir)/region-allocator.c config.h $(srcdir)/region-allocator.h $(srcdir)/util.h
server.o: $(srcdir)/server.c config.h $(srcdir)/axfr.h $(srcdir)/nsd.h $(srcdir)/dns.h $(srcdir)/edns.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/query.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/rbtree.h $(srcdir)/packet.h \
 $(srcdir)/tsig.h $(srcdir)/netio.h $(srcdir)/xfrd.h $(srcdir)/options.h $(srcdir)/xfrd-tcp.h $(srcdir)/difffile.h $(srcdir)/nsec3.h $(srcdir)/ipc.h
tsig.o: $(srcdir)/tsig.c config.h $(srcdir)/tsig.h $(srcdir)/buffer.h $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/dname.h \
 $(srcdir)/tsig-openssl.h $(srcdir)/dns.h $(srcdir)/packet.h $(srcdir)/namedb.h $(srcdir)/rbtree.h $(srcdir)/query.h $(srcdir)/nsd.h $(srcdir)/edns.h
tsig-openssl.o: $(srcdir)/tsig-openssl.c config.h $(srcdir)/tsig-openssl.h $(srcdir)/region-allocator.h \
 $(srcdir)/tsig.h $(srcdir)/buffer.h $(srcdir)/util.h $(srcdir)/dname.h
util.o: $(srcdir)/util.c config.h $(srcdir)/util.h $(srcdir)/region-allocator.h $(srcdir)/dname.h $(srcdir)/buffer.h \
 $(srcdir)/namedb.h $(srcdir)/dns.h $(srcdir)/rbtree.h $(srcdir)/rdata.h
xfrd.o: $(srcdir)/xfrd.c config.h $(srcdir)/xfrd.h $(srcdir)/netio.h $(srcdir)/region-allocator.h $(srcdir)/rbtree.h \
 $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h $(srcdir)/util.h $(srcdir)/dns.h $(srcdir)/options.h $(srcdir)/tsig.h $(srcdir)/xfrd-tcp.h \
 $(srcdir)/xfrd-disk.h $(srcdir)/xfrd-notify.h $(srcdir)/nsd.h $(srcdir)/edns.h $(srcdir)/packet.h $(srcdir)/difffile.h $(srcdir)/ipc.h
xfrd-disk.o: $(srcdir)/xfrd-disk.c config.h $(srcdir)/xfrd-disk.h $(srcdir)/xfrd.h $(srcdir)/netio.h \
 $(srcdir)/region-allocator.h $(srcdir)/rbtree.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h $(srcdir)/util.h $(srcdir)/dns.h \
 $(srcdir)/options.h $(srcdir)/tsig.h $(srcdir)/nsd.h $(srcdir)/edns.h
xfrd-notify.o: $(srcdir)/xfrd-notify.c config.h $(srcdir)/xfrd-notify.h $(srcdir)/tsig.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/dname.h $(srcdir)/netio.h $(srcdir)/rbtree.h $(srcdir)/xfrd.h $(srcdir)/namedb.h $(srcdir)/dns.h \
 $(srcdir)/options.h $(srcdir)/xfrd-tcp.h $(srcdir)/packet.h
xfrd-tcp.o: $(srcdir)/xfrd-tcp.c config.h $(srcdir)/xfrd-tcp.h $(srcdir)/xfrd.h $(srcdir)/netio.h \
 $(srcdir)/region-allocator.h $(srcdir)/rbtree.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h $(srcdir)/util.h $(srcdir)/dns.h \
 $(srcdir)/options.h $(srcdir)/tsig.h $(srcdir)/packet.h
zlexer.o: zlexer.c config.h $(srcdir)/zonec.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/dns.h $(srcdir)/rbtree.h zparser.h
zonec.o: $(srcdir)/zonec.c config.h $(srcdir)/zonec.h $(srcdir)/namedb.h $(srcdir)/dname.h $(srcdir)/buffer.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/dns.h $(srcdir)/rbtree.h $(srcdir)/rdata.h zparser.h $(srcdir)/options.h \
 $(srcdir)/nsec3.h
zparser.o: zparser.c config.h $(srcdir)/dname.h $(srcdir)/buffer.h $(srcdir)/region-allocator.h $(srcdir)/util.h \
 $(srcdir)/namedb.h $(srcdir)/dns.h $(srcdir)/rbtree.h $(srcdir)/zonec.h
b64_ntop.o: $(srcdir)/compat/b64_ntop.c config.h
b64_pton.o: $(srcdir)/compat/b64_pton.c config.h
basename.o: $(srcdir)/compat/basename.c
fake-rfc2553.o: $(srcdir)/compat/fake-rfc2553.c $(srcdir)/compat/fake-rfc2553.h config.h
inet_aton.o: $(srcdir)/compat/inet_aton.c config.h
inet_ntop.o: $(srcdir)/compat/inet_ntop.c config.h
inet_pton.o: $(srcdir)/compat/inet_pton.c config.h
malloc.o: $(srcdir)/compat/malloc.c
memcmp.o: $(srcdir)/compat/memcmp.c config.h
memmove.o: $(srcdir)/compat/memmove.c config.h
pselect.o: $(srcdir)/compat/pselect.c config.h
snprintf.o: $(srcdir)/compat/snprintf.c config.h
strlcat.o: $(srcdir)/compat/strlcat.c config.h
strlcpy.o: $(srcdir)/compat/strlcpy.c config.h
strptime.o: $(srcdir)/compat/strptime.c
cutest.o: $(srcdir)/tpkg/cutest/cutest.c $(srcdir)/tpkg/cutest/cutest.h
cutest_dname.o: $(srcdir)/tpkg/cutest/cutest_dname.c config.h $(srcdir)/tpkg/cutest/cutest.h \
 $(srcdir)/region-allocator.h $(srcdir)/dname.h $(srcdir)/buffer.h $(srcdir)/region-allocator.h $(srcdir)/util.h
cutest_dns.o: $(srcdir)/tpkg/cutest/cutest_dns.c config.h $(srcdir)/tpkg/cutest/cutest.h \
 $(srcdir)/region-allocator.h $(srcdir)/dns.h
cutest_iterated_hash.o: $(srcdir)/tpkg/cutest/cutest_iterated_hash.c config.h \
 $(srcdir)/tpkg/cutest/cutest.h $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/iterated_hash.h $(srcdir)/dname.h \
 $(srcdir)/buffer.h $(srcdir)/region-allocator.h $(srcdir)/util.h
cutest_options.o: $(srcdir)/tpkg/cutest/cutest_options.c config.h \
 $(srcdir)/tpkg/cutest/cutest.h $(srcdir)/region-allocator.h $(srcdir)/options.h $(srcdir)/region-allocator.h \
 $(srcdir)/rbtree.h $(srcdir)/util.h
cutest_rbtree.o: $(srcdir)/tpkg/cutest/cutest_rbtree.c config.h \
 $(srcdir)/tpkg/cutest/cutest.h $(srcdir)/region-allocator.h $(srcdir)/rbtree.h $(srcdir)/region-allocator.h
cutest_region.o: $(srcdir)/tpkg/cutest/cutest_region.c config.h \
 $(srcdir)/tpkg/cutest/cutest.h $(srcdir)/region-allocator.h $(srcdir)/util.h $(srcdir)/rbtree.h \
 $(srcdir)/region-allocator.h
cutest_run.o: $(srcdir)/tpkg/cutest/cutest_run.c config.h $(srcdir)/tpkg/cutest/cutest.h
cutest_util.o: $(srcdir)/tpkg/cutest/cutest_util.c config.h $(srcdir)/tpkg/cutest/cutest.h \
 $(srcdir)/region-allocator.h $(srcdir)/util.h
