# vim: set sw=8 ts=8 sts=8 noet:

NULL =

lib_LTLIBRARIES = falgproto/libfalgproto-0.1.la

EXTRA_DIST = \
	autogen.sh		\
	$(top_srcdir)/.version	\
	$(NULL)

# For git-version-gen
BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version

falgproto_libfalgproto_0_1_la_SOURCES = \
	falgproto/falgproto.h			\
	falgproto/falgproto.c			\
	falgproto/falgproto-protocol-dns.c	\
	falgproto/falgproto-match-hostname.c	\
	$(NULL)

falgprotoincludedir = $(includedir)/falgproto-0.1
falgprotoinclude_HEADERS = \
	falgproto/falgproto.h	\
	$(NULL)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = \
	falgproto/falgproto-0.1.pc	\
	$(NULL)
