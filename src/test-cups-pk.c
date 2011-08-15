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

#include "cph-iface-mechanism.h"

static gboolean
printer_add (GDBusProxy  *proxy,
             const char  *printer_name,
             const char  *printer_uri,
             const char  *ppd_file,
             const char  *info,
             const char  *location,
             GError     **error)
{
        GVariant *result;
        char     *ret_error;

        *error = NULL;
        ret_error = NULL;

        result = g_dbus_proxy_call_sync (proxy,
                                         "PrinterAdd",
                                         g_variant_new ("(sssss)",
                                                        printer_name,
                                                        printer_uri,
                                                        ppd_file,
                                                        info,
                                                        location),
                                         G_DBUS_CALL_FLAGS_NONE,
                                         -1,
                                         NULL,
                                         error);

        if (result == NULL)
                return FALSE;

        g_variant_get (result, "(s)", &ret_error);
        g_variant_unref (result);

        if (!ret_error || ret_error[0] == '\0')
                g_print ("Worked!\n");
        else
                g_print ("Ouch: %s\n", ret_error);

        g_free (ret_error);

        return TRUE;
}

int
main (int argc, char **argv)
{
        CphIfaceMechanism *proxy;
        gboolean           ret;
        GError            *error;

        g_type_init ();

        error = NULL;
        proxy = cph_iface_mechanism_proxy_new_for_bus_sync (
                                G_BUS_TYPE_SYSTEM,
                                G_DBUS_PROXY_FLAGS_NONE,
                                "org.opensuse.CupsPkHelper.Mechanism",
                                "/",
                                NULL,
                                &error);
        if (proxy == NULL) {
                g_warning ("Could not get proxy: %s",
                           error->message);
                g_error_free (error);
                return 1;
        }

        error = NULL;
        ret = printer_add (G_DBUS_PROXY (proxy),
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

        g_object_unref (proxy);

        return 0;
}
