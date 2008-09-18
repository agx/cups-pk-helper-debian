#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

PKG_NAME="CUPS PolicyKit helper"

(test -f $srcdir/configure.ac \
  && test -f $srcdir/src/cups-methods.c) || {
    echo -n "**Error**: Directory "\`$srcdir\'" does not look like the"
    echo " top-level package directory"
    exit 1
}


which gnome-autogen.sh || {
    echo "You need to install gnome-common from the GNOME SVN"
    exit 1
}

. gnome-autogen.sh
