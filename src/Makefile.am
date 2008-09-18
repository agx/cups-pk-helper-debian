INCLUDES =			\
	$(CUPS_PK_CFLAGS)


libexec_PROGRAMS = cups-pk-helper-mechanism

cups-pk-helper-glue.h: $(srcdir)/cups-pk-helper-mechanism.xml
	dbus-binding-tool --prefix=cups_pk_helper --mode=glib-server	\
			  --output=cups-pk-helper-glue.h		\
			  $(srcdir)/cups-pk-helper-mechanism.xml

cups_pk_helper_mechanism_SOURCES =	\
	cups-methods.c			\
	cups-methods.h			\
	cups-pk-helper-mechanism.c	\
	cups-pk-helper-mechanism.h	\
	main.c
cups_pk_helper_mechanism_LDADD =	\
	$(CUPS_PK_LIBS)

BUILT_SOURCES = cups-pk-helper-mechanism-glue.h


dbus_servicesdir = $(datadir)/dbus-1/system-services
dbus_confdir = $(sysconfdir)/dbus-1/system.d
polkitdir = $(datadir)/PolicyKit/policy

dbus_services_in_files = org.opensuse.cups-pk-helper.Mechanism.service.in
polkit_in_files = org.opensuse.cups-pk-helper.mechanism.policy.in

dbus_services_DATA = $(dbus_services_in_files:.service.in=.service)

$(dbus_services_DATA): $(dbus_services_in_files)
	sed -e "s|\@LIBEXECDIR\@|$(libexecdir)|" $< > $@

dbus_conf_DATA = org.opensuse.cups-pk-helper.Mechanism.conf

@INTLTOOL_POLICY_RULE@
polkit_DATA = $(polkit_in_files:.policy.in=.policy)


check:
	$(POLKIT_POLICY_FILE_VALIDATE) $(polkit_DATA)


EXTRA_DIST =						\
	$(dbus_services_in_files)			\
	org.opensuse.cups-pk-helper.Mechanism.conf	\
	$(polkit_in_files)				\
	cups-pk-helper-mechanism.xml

CLEANFILES = 			\
	$(BUILT_SOURCES)	\
	$(polkit_DATA)		\
	$(dbus_services_DATA)
