libexec_PROGRAMS = cups-pk-helper-mechanism
noinst_PROGRAMS = 	\
	test-cups	\
	test-cups-pk

AM_CPPFLAGS =				\
	$(DISABLE_DEPRECATED_CFLAGS)

AM_CFLAGS = $(WARN_CFLAGS)

cups_pk_helper_mechanism_SOURCES =	\
	cups.c				\
	cups.h				\
	cups-pk-helper-mechanism.c	\
	cups-pk-helper-mechanism.h	\
	main.c				\
	$(cph_iface_mechanism)
cups_pk_helper_mechanism_CFLAGS =	\
	$(AM_CFLAGS)			\
	$(CUPS_PK_CFLAGS)
cups_pk_helper_mechanism_LDADD =	\
	$(CUPS_PK_LIBS)			\
	$(CUPS_LIBS)

cph_iface_mechanism =		\
	cph-iface-mechanism.c	\
	cph-iface-mechanism.h

$(cph_iface_mechanism): $(srcdir)/cups-pk-helper-mechanism.xml
	$(AM_V_GEN)$(GDBUS_CODEGEN)					\
			--interface-prefix=org.opensuse.CupsPkHelper.	\
			--c-namespace CphIface				\
			--generate-c-code cph-iface-mechanism		\
			--c-generate-object-manager			\
			$<

BUILT_SOURCES = $(cph_iface_mechanism)

test_cups_SOURCES =	\
	cups.c		\
	cups.h		\
	test-cups.c
test_cups_CFLAGS =	\
	$(AM_CFLAGS)	\
	$(TEST_CFLAGS)
test_cups_LDADD =	\
	$(TEST_LIBS)	\
	$(CUPS_LIBS)

test_cups_pk_SOURCES =	\
	test-cups-pk.c	\
	$(cph_iface_mechanism)
test_cups_pk_CFLAGS =	\
	$(AM_CFLAGS)	\
	$(TEST_CFLAGS)
test_cups_pk_LDADD =	\
	$(TEST_LIBS)	\
	$(CUPS_LIBS)

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

-include $(top_srcdir)/git.mk
