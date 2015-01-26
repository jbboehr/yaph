
bin_PROGRAMS = yaph

yaph_SOURCES = threads.c tcp_utils.c log.c init.c content_utils.c main.c 
yaph_LDADD   = -lpthread

EXTRA_DIST = main.c content_utils.c definitions.h \
			 functions.h globals.h includes.h \
			 init.c log.c tcp_utils.c threads.c \
			 yaph.conf yaph.h 

install-data-local:
	$(mkinstalldirs) /etc/
	$(INSTALL_DATA) $(srcdir)/yaph.conf /etc/yaph.conf

uninstall-local:
	-rm -f /etc/yaph.conf

# set the include path found by configure
AMLOCAL_CPPFLAGS = $(all_includes)

# the library search path.
yaph_LDFLAGS = $(all_libraries) 
