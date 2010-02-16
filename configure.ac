AC_INIT([cups-pk-helper], [0.1.0],
        [mailto:vuntz@novell.com])
AC_CONFIG_SRCDIR(src/cups-pk-helper-mechanism.c)
AM_INIT_AUTOMAKE([1.9 no-dist-gzip dist-bzip2])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_CONFIG_HEADER(config.h)

AM_MAINTAINER_MODE
GNOME_MAINTAINER_MODE_DEFINES

# Standard C stuff
AC_PROG_CC
AC_ISC_POSIX
AC_HEADER_STDC
AC_PROG_LIBTOOL
AM_PROG_CC_C_O

# Additional programs that we need
AC_PATH_PROG(GLIB_GENMARSHAL, [glib-genmarshal])
AC_PATH_PROG([POLKIT_POLICY_FILE_VALIDATE], [polkit-policy-file-validate])

# Internationalisation
IT_PROG_INTLTOOL([0.40.0])
GETTEXT_PACKAGE=cups-pk-helper
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE", [Define the gettext package to be used])
AM_GLIB_GNU_GETTEXT

# Compiler Warnings
GNOME_COMPILE_WARNINGS(maximum)

AC_ARG_ENABLE(deprecations,
              [AC_HELP_STRING([--enable-deprecations],
                              [warn about deprecated usages [default=no]])],,
              [enable_deprecations=no])

if test "x$enable_deprecations" = "xyes"; then
   DISABLE_DEPRECATED_CFLAGS=$DISABLE_DEPRECATED
   AC_SUBST(DISABLE_DEPRECATED_CFLAGS)
fi

# Dependencies
GLIB_REQUIRED=2.14.0
DBUS_REQUIRED=1.1.2
DBUS_GLIB_REQUIRED=0.74
POLKIT_REQUIRED=0.92

# pkg-config dependency checks
PKG_CHECK_MODULES(CUPS_PK, glib-2.0 >= $GLIB_REQUIRED \
			   gobject-2.0 \
			   gthread-2.0 \
			   dbus-1 >= $DBUS_REQUIRED \
			   dbus-glib-1 >= $DBUS_GLIB_REQUIRED \
			   polkit-gobject-1 >= $POLKIT_REQUIRED)
AC_SUBST(CUPS_PK_CFLAGS)
AC_SUBST(CUPS_PK_LIBS)

PKG_CHECK_MODULES(CUPS_PK_GNOME, glib-2.0 >= $GLIB_REQUIRED \
				 dbus-1 >= $DBUS_REQUIRED \
				 dbus-glib-1 >= $DBUS_GLIB_REQUIRED)
AC_SUBST(CUPS_PK_GNOME_CFLAGS)
AC_SUBST(CUPS_PK_GNOME_LIBS)

# check for cups
AC_CHECK_HEADERS(cups/cups.h cups/http.h cups/ipp.h)
CUPS_LIBS=-lcups
AC_SUBST(CUPS_LIBS)

AC_OUTPUT([
Makefile
src/Makefile
po/Makefile.in
])
