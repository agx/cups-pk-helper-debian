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
#include <gio/gio.h>

#include "cups-pk-helper-mechanism.h"

#define CPH_SERVICE     "org.opensuse.CupsPkHelper.Mechanism"
#define CPH_PATH        "/"

typedef struct
{
        CphMechanism *mechanism;
        GMainLoop    *loop;
        gboolean      name_acquired;
} cph_main;

static void
on_bus_acquired (GDBusConnection *connection,
                 const gchar     *name,
                 gpointer         user_data)
{
        cph_main *data = (cph_main *) user_data;
        GError   *error = NULL;

        if (!cph_mechanism_register (data->mechanism,
                                     connection, CPH_PATH,
                                     &error)) {
                if (error)
                        g_printerr ("Could not register mechanism object: %s\n", error->message);
                else
                        g_printerr ("Could not register mechanism object\n");

                g_error_free (error);
                g_main_loop_quit (data->loop);

                return;
        }
}

static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
        cph_main *data = (cph_main *) user_data;

        data->name_acquired = TRUE;
}

static void
on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              gpointer         user_data)
{
        cph_main *data = (cph_main *) user_data;

        if (connection == NULL)
                g_printerr ("Cannot connect to the bus\n");
        else if (!data->name_acquired)
                g_printerr ("Cannot acquire %s on the bus\n", CPH_SERVICE);

        g_main_loop_quit (data->loop);
}

int
main (int argc, char **argv)
{
        cph_main data;
        guint    owner_id;

        g_type_init ();

        memset (&data, 0, sizeof (data));

        data.mechanism = cph_mechanism_new ();

        if (data.mechanism == NULL) {
                g_printerr ("Could not create mechanism object\n");
                return 1;
        }

        data.loop = g_main_loop_new (NULL, FALSE);

        owner_id = g_bus_own_name (G_BUS_TYPE_SYSTEM,
                                   CPH_SERVICE,
                                   G_BUS_NAME_OWNER_FLAGS_NONE,
                                   on_bus_acquired,
                                   on_name_acquired,
                                   on_name_lost,
                                   &data,
                                   NULL);

        g_main_loop_run (data.loop);

        g_object_unref (data.mechanism);
        g_bus_unown_name (owner_id);
        g_main_loop_unref (data.loop);

        return 0;
}
