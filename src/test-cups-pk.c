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
 */


#include <glib.h>

#include <dbus/dbus-glib.h>

#define MECHANISM_BUS "org.opensuse.CupsPkHelper.Mechanism"

static gboolean
printer_add (DBusGConnection  *bus,
             const char       *printer_name,
             const char       *printer_uri,
             const char       *ppd_file,
             const char       *info,
             const char       *location,
             GError          **error)
{
        DBusGProxy *proxy;
        gboolean    ret;
        char       *ret_error;

        proxy = dbus_g_proxy_new_for_name (bus,
                                           MECHANISM_BUS,
                                           "/",
                                           MECHANISM_BUS);

        if (!proxy)
                return FALSE;

        *error = NULL;
        ret_error = NULL;

        ret = dbus_g_proxy_call (proxy, "PrinterAdd", error,
                                 G_TYPE_STRING, printer_name,
                                 G_TYPE_STRING, printer_uri,
                                 G_TYPE_STRING, ppd_file,
                                 G_TYPE_STRING, info,
                                 G_TYPE_STRING, location,
                                 G_TYPE_INVALID,
                                 G_TYPE_STRING, &ret_error,
                                 G_TYPE_INVALID);

        if (ret) {
                if (!ret_error || ret_error[0] == '\0')
                        g_print ("Worked!\n");
                else
                        g_print ("Ouch: %s\n", ret_error);
        }

        return ret;
}

int
main (int argc, char **argv)
{
        DBusGConnection *system_bus;
        gboolean         ret;
        GError          *error;

        g_type_init ();

        error = NULL;
        system_bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
        if (system_bus == NULL) {
                g_warning ("Could not connect to system bus: %s",
                           error->message);
                g_error_free (error);
                return 1;
        }

        error = NULL;
        ret = printer_add (system_bus,
                           "MyPrinter", "smb://really/cool",
                           "HP/Business_Inkjet_2200-chp2200.ppd.gz",
                           "This is my printer", "At home",
                           &error);

        if (!ret) {
                if (error) {
                        g_print ("Error: %s\n", error->message);
                        g_error_free (error);
                } else
                        g_print ("Unknown error\n");
        }

        return 0;
}
