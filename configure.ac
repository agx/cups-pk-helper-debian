AC_INIT([cups-pk-helper], [0.2.6],
        [https://bugs.freedesktop.org/enter_bug.cgi?product=cups-pk-helper])
AC_CONFIG_SRCDIR(src/cups-pk-helper-mechanism.c)
AM_INIT_AUTOMAKE([1.11 no-dist-gzip dist-xz tar-ustar])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_CONFIG_HEADER(config.h)

# Standard C stuff
AC_PROG_CC

# Additional programs that we need
AC_PATH_PROG(GLIB_GENMARSHAL, [glib-genmarshal])

# Internationalisation
IT_PROG_INTLTOOL([0.40.6])
GETTEXT_PACKAGE=cups-pk-helper
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE", [Define the gettext package to be used])
AM_GLIB_GNU_GETTEXT

# Compiler Warnings
GNOME_COMPILE_WARNINGS([maximum])
GNOME_MAINTAINER_MODE_DEFINES

AC_ARG_ENABLE(deprecation_flags,
              [AC_HELP_STRING([--enable-deprecation-flags],
                              [use *_DISABLE_DEPRECATED flags @<:@default=no@:>@])],,
              [enable_deprecation_flags=no])

if test "x$enable_deprecation_flags" = "xyes"; then
   DISABLE_DEPRECATED_CFLAGS=$DISABLE_DEPRECATED
   AC_SUBST(DISABLE_DEPRECATED_CFLAGS)
fi

# Dependencies
GIO_REQUIRED=2.29.8
POLKIT_REQUIRED=0.97

# pkg-config dependency checks
PKG_CHECK_MODULES(CUPS_PK, gio-2.0 >= $GIO_REQUIRED gio-unix-2.0 >= $GIO_REQUIRED polkit-gobject-1 >= $POLKIT_REQUIRED)
AC_SUBST(CUPS_PK_CFLAGS)
AC_SUBST(CUPS_PK_LIBS)

PKG_CHECK_MODULES(TEST, gio-2.0 >= $GIO_REQUIRED gio-unix-2.0 >= $GIO_REQUIRED)
AC_SUBST(TEST_CFLAGS)
AC_SUBST(TEST_LIBS)

# check for cups
AC_CHECK_HEADERS(cups/cups.h cups/http.h cups/ipp.h)
CUPS_LIBS=-lcups
AC_SUBST(CUPS_LIBS)

AC_PATH_PROG([GDBUS_CODEGEN], [gdbus-codegen])

AC_OUTPUT([
Makefile
src/Makefile
po/Makefile.in
])

dnl ---------------------------------------------------------------------------
dnl - Show summary
dnl ---------------------------------------------------------------------------

echo "
              cups-pk-helper $VERSION
              `echo cups-pk-helper $VERSION | sed "s/./=/g"`

        prefix:                        ${prefix}
        exec_prefix:                   ${exec_prefix}
        libdir:                        ${libdir}
        bindir:                        ${bindir}
        sbindir:                       ${sbindir}
        sysconfdir:                    ${sysconfdir}
        localstatedir:                 ${localstatedir}
        datadir:                       ${datadir}
        source code location:          ${srcdir}
        compiler:                      ${CC}
        cflags:                        ${CFLAGS}
        Maintainer mode:               ${USE_MAINTAINER_MODE}
        Use *_DISABLE_DEPRECATED:      ${enable_deprecation_flags}

"
