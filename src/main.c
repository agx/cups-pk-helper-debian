/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 * vim: set et ts=8 sw=8:
 *
 * Copyright (C) 2008 Novell, Inc.
 *
 * Authors: Vincent Untz
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * The code is originally based on gnome-clock-applet-mechanism-main.c, which
 * is under the same license and with the following copyright:
 *
 * Copyright (C) 2007 David Zeuthen <david@fubar.dk>
 *
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <glib.h>
#include <glib-object.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "cups-pk-helper-mechanism.h"

#define BUS_NAME "org.opensuse.CupsPkHelper.Mechanism"

static DBusGProxy *
get_bus_proxy (DBusGConnection *connection)
{
        DBusGProxy *bus_proxy;

        bus_proxy = dbus_g_proxy_new_for_name (connection,
                                               DBUS_SERVICE_DBUS,
                                               DBUS_PATH_DBUS,
                                               DBUS_INTERFACE_DBUS);
        return bus_proxy;
}

static gboolean
acquire_name_on_proxy (DBusGProxy  *bus_proxy,
                       GError     **error)
{
        guint    result;
        gboolean res;

        g_assert (bus_proxy != NULL);

        res = dbus_g_proxy_call (bus_proxy,
                                 "RequestName",
                                 error,
                                 G_TYPE_STRING, BUS_NAME,
                                 G_TYPE_UINT, 0,
                                 G_TYPE_INVALID,
                                 G_TYPE_UINT, &result,
                                 G_TYPE_INVALID);
        if (!res ||
            result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
                return FALSE;

        return TRUE;
}

int
main (int argc, char **argv)
{
        GError          *error;
        GMainLoop       *loop;
        CphMechanism    *mechanism;
        DBusGProxy      *bus_proxy;
        DBusGConnection *connection;

        if (!g_thread_supported ())
                g_thread_init (NULL);

        dbus_g_thread_init ();
        g_type_init ();

        error = NULL;

        connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
        if (connection == NULL) {
                g_warning ("Could not connect to system bus: %s",
                           error->message);
                g_error_free (error);
                return 1;
        }

        bus_proxy = get_bus_proxy (connection);
        if (bus_proxy == NULL) {
                g_warning ("Could not construct bus_proxy objects");
                return 1;
        }

        if (!acquire_name_on_proxy (bus_proxy, &error) ) {
                if (error != NULL) {
                        g_warning ("Could not acquire name: %s",
                                   error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Could not acquire name");
                }

                return 1;
        }

        mechanism = cph_mechanism_new ();

        if (mechanism == NULL) {
                g_warning ("Could not create mechanism object");
                return 1;
        }

        loop = g_main_loop_new (NULL, FALSE);

        g_main_loop_run (loop);

        g_object_unref (mechanism);
        g_main_loop_unref (loop);

        return 0;
}
