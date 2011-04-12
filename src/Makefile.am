libexec_PROGRAMS = cups-pk-helper-mechanism
noinst_PROGRAMS = 	\
	test-cups	\
	test-cups-pk

AM_CPPFLAGS =				\
	$(CUPS_PK_CFLAGS)		\
	$(DISABLE_DEPRECATED_CFLAGS)

AM_CFLAGS = $(WARN_CFLAGS)

cups_pk_helper_mechanism_SOURCES =	\
	cups.c				\
	cups.h				\
	cups-pk-helper-mechanism.c	\
	cups-pk-helper-mechanism.h	\
	main.c
cups_pk_helper_mechanism_LDADD =	\
	$(CUPS_PK_LIBS)			\
	$(CUPS_LIBS)

test_cups_SOURCES =	\
	cups.c		\
	cups.h		\
	test-cups.c
test_cups_LDADD =	\
	$(CUPS_PK_LIBS)	\
	$(CUPS_LIBS)

test_cups_pk_SOURCES =	\
	test-cups-pk.c
test_cups_pk_CFLAGS =	\
	$(AM_CFLAGS)	\
	$(CUPS_PK_GNOME_CFLAGS)
test_cups_pk_LDADD =		\
	$(CUPS_PK_GNOME_LIBS)	\
	$(CUPS_PK_LIBS)		\
	$(CUPS_LIBS)

cups-pk-helper-mechanism-glue.h: $(srcdir)/cups-pk-helper-mechanism.xml
	$(AM_V_GEN)dbus-binding-tool --prefix=cph_mechanism --mode=glib-server	\
			--output=cups-pk-helper-mechanism-glue.h	\
			$(srcdir)/cups-pk-helper-mechanism.xml

BUILT_SOURCES = cups-pk-helper-mechanism-glue.h

dbus_confdir = $(sysconfdir)/dbus-1/system.d
dbus_conf_DATA = org.opensuse.CupsPkHelper.Mechanism.conf

dbus_servicesdir = $(datadir)/dbus-1/system-services
dbus_services_in_files = org.opensuse.CupsPkHelper.Mechanism.service.in
dbus_services_DATA = $(dbus_services_in_files:.service.in=.service)

$(dbus_services_DATA): $(dbus_services_in_files)
	$(AM_V_GEN)sed -e "s|\@LIBEXECDIR\@|$(libexecdir)|" $< > $@

polkitdir = $(datadir)/polkit-1/actions
polkit_in_files = org.opensuse.cupspkhelper.mechanism.policy.in
polkit_DATA = $(polkit_in_files:.policy.in=.policy)

@INTLTOOL_POLICY_RULE@

EXTRA_DIST =						\
	$(dbus_services_in_files)			\
	org.opensuse.CupsPkHelper.Mechanism.conf	\
	$(polkit_in_files)				\
	cups-pk-helper-mechanism.xml

CLEANFILES = 			\
	$(BUILT_SOURCES)	\
	$(polkit_DATA)		\
	$(dbus_services_DATA)
