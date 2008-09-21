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
 * The code is originally based on gnome-clock-applet-mechanism.c, which
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
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/time.h>

#include <glib.h>
#include <glib-object.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <polkit-dbus/polkit-dbus.h>

#include "cups-pk-helper-mechanism.h"
#include "cups-pk-helper-mechanism-glue.h"
#include "cups.h"

/* exit timer */

static gboolean
do_exit (gpointer user_data)
{
        g_object_unref (CPH_MECHANISM (user_data));

        exit (0);

        return FALSE;
}

static void
reset_killtimer (CphMechanism *mechanism)
{
        static guint timer_id = 0;

        if (timer_id > 0)
                g_source_remove (timer_id);

        timer_id = g_timeout_add_seconds (30, do_exit, mechanism);
}

/* error */

GQuark
cph_mechanism_error_quark (void)
{
        static GQuark ret = 0;

        if (ret == 0)
                ret = g_quark_from_static_string ("cph_mechanism_error");

        return ret;
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
cph_mechanism_error_get_type (void)
{
        static GType etype = 0;

        if (etype == 0) {
                static const GEnumValue values[] =
                        {
                                ENUM_ENTRY (CPH_MECHANISM_ERROR_GENERAL,
                                            "GeneralError"),
                                ENUM_ENTRY (CPH_MECHANISM_ERROR_NOT_PRIVILEGED,
                                            "NotPrivileged"),
                                { 0, 0, 0 }
                        };

                g_assert (CPH_MECHANISM_NUM_ERRORS == G_N_ELEMENTS (values) - 1);

                etype = g_enum_register_static ("CphMechanismError", values);
        }

        return etype;
}

/* mechanism object */

G_DEFINE_TYPE (CphMechanism, cph_mechanism, G_TYPE_OBJECT)

#define CPH_MECHANISM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), CPH_TYPE_MECHANISM, CphMechanismPrivate))

struct CphMechanismPrivate
{
        DBusGConnection *system_bus_connection;
        PolKitContext   *pol_ctx;
        CphCups         *cups;
};

static GObject *cph_mechanism_constructor (GType                  type,
                                           guint                  n_construct_properties,
                                           GObjectConstructParam *construct_properties);
static void     cph_mechanism_finalize    (GObject *object);


static void
cph_mechanism_class_init (CphMechanismClass *klass)
{
        GObjectClass *object_class = G_OBJECT_CLASS (klass);

        object_class->constructor = cph_mechanism_constructor;
        object_class->finalize = cph_mechanism_finalize;

        g_type_class_add_private (klass, sizeof (CphMechanismPrivate));

        dbus_g_object_type_install_info (CPH_TYPE_MECHANISM,
                                         &dbus_glib_cph_mechanism_object_info);

        dbus_g_error_domain_register (CPH_MECHANISM_ERROR, NULL,
                                      CPH_MECHANISM_TYPE_ERROR);
}

static GObject *
cph_mechanism_constructor (GType                  type,
                           guint                  n_construct_properties,
                           GObjectConstructParam *construct_properties)
{
        GObject      *obj;
        CphMechanism *mechanism;

        obj = G_OBJECT_CLASS (cph_mechanism_parent_class)->constructor (
                                                type,
                                                n_construct_properties,
                                                construct_properties);

        mechanism = CPH_MECHANISM (obj);
        mechanism->priv->cups = cph_cups_new ();

        if (!mechanism->priv->cups) {
                g_object_unref (mechanism);
                return NULL;
        }

        return obj;
}

static void
cph_mechanism_init (CphMechanism *mechanism)
{
        mechanism->priv = CPH_MECHANISM_GET_PRIVATE (mechanism);

        mechanism->priv->cups = NULL;
}

static void
cph_mechanism_finalize (GObject *object)
{
        CphMechanism *mechanism;

        g_return_if_fail (object != NULL);
        g_return_if_fail (CPH_IS_MECHANISM (object));

        mechanism = CPH_MECHANISM (object);

        if (mechanism->priv->cups)
                g_object_unref (mechanism->priv->cups);
        mechanism->priv->cups = NULL;

        G_OBJECT_CLASS (cph_mechanism_parent_class)->finalize (object);
}

static gboolean
pk_io_watch_have_data (GIOChannel   *channel,
                       GIOCondition  condition,
                       gpointer      user_data)
{
        int            fd;
        PolKitContext *pk_context;

        pk_context = user_data;
        fd = g_io_channel_unix_get_fd (channel);
        polkit_context_io_func (pk_context, fd);

        return TRUE;
}

static int
pk_io_add_watch (PolKitContext *pk_context,
                 int            fd)
{
        guint       id;
        GIOChannel *channel;

        channel = g_io_channel_unix_new (fd);
        if (channel == NULL)
                return 0;

        id = g_io_add_watch (channel, G_IO_IN,
                             pk_io_watch_have_data, pk_context);

        return id;
}

static void
pk_io_remove_watch (PolKitContext *pk_context,
                    int            watch_id)
{
        g_source_remove (watch_id);
}

static gboolean
register_mechanism (CphMechanism *mechanism)
{
        GError *error;

        mechanism->priv->pol_ctx = polkit_context_new ();

        polkit_context_set_io_watch_functions (mechanism->priv->pol_ctx,
                                               pk_io_add_watch,
                                               pk_io_remove_watch);

        if (!polkit_context_init (mechanism->priv->pol_ctx, NULL)) {
                g_critical ("cannot initialize libpolkit");
                return FALSE;
        }

        error = NULL;
        mechanism->priv->system_bus_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM,
                                                                 &error);
        if (mechanism->priv->system_bus_connection == NULL) {
                if (error != NULL) {
                        g_critical ("error getting system bus: %s",
                                    error->message);
                        g_error_free (error);
                } else {
                        g_critical ("error getting system bus");
                }
                return FALSE;
        }

        dbus_g_connection_register_g_object (mechanism->priv->system_bus_connection, "/",
                                             G_OBJECT (mechanism));

        reset_killtimer (mechanism);

        return TRUE;
}


CphMechanism *
cph_mechanism_new (void)
{
        GObject *object;

        object = g_object_new (CPH_TYPE_MECHANISM, NULL);

        if (!register_mechanism (CPH_MECHANISM (object))) {
                g_object_unref (object);
                return NULL;
        }

        return CPH_MECHANISM (object);
}

static gboolean
_check_polkit_for_action (CphMechanism          *mechanism,
                          DBusGMethodInvocation *context,
                          const char            *action_method)
{
        const char *sender;
        GError *error;
        DBusError dbus_error;
        PolKitCaller *pk_caller;
        PolKitAction *pk_action;
        PolKitResult pk_result;
        char *action;

        error = NULL;

        action = g_strdup_printf ("org.opensuse.cupspkhelper.mechanism.%s",
                                  action_method);

        /* Check that caller is privileged */
        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);

        pk_caller = polkit_caller_new_from_dbus_name (
                dbus_g_connection_get_connection (mechanism->priv->system_bus_connection),
                sender,
                &dbus_error);

        if (pk_caller == NULL) {
                error = g_error_new (CPH_MECHANISM_ERROR,
                                     CPH_MECHANISM_ERROR_GENERAL,
                                     "Error getting information about "
                                     "caller: %s: %s",
                                     dbus_error.name, dbus_error.message);
                dbus_error_free (&dbus_error);
                dbus_g_method_return_error (context, error);
                g_error_free (error);
                g_free (action);

                return FALSE;
        }

        pk_action = polkit_action_new ();
        polkit_action_set_action_id (pk_action, action);
        pk_result = polkit_context_is_caller_authorized (mechanism->priv->pol_ctx,
                                                         pk_action, pk_caller,
                                                         FALSE, NULL);
        polkit_caller_unref (pk_caller);
        polkit_action_unref (pk_action);

        if (pk_result != POLKIT_RESULT_YES) {
                error = g_error_new (CPH_MECHANISM_ERROR,
                                     CPH_MECHANISM_ERROR_NOT_PRIVILEGED,
                                     "%s %s <-- (action, result)",
                                     action,
                                     polkit_result_to_string_representation (pk_result));
                dbus_error_free (&dbus_error);
                dbus_g_method_return_error (context, error);
                g_error_free (error);
                g_free (action);

                return FALSE;
        }

        g_free (action);

        return TRUE;
}

/* exported methods */

gboolean
cph_mechanism_printer_add (CphMechanism           *mechanism,
                           const char             *name,
                           const char             *uri,
                           const char             *ppd,
                           const char             *info,
                           const char             *location,
                           DBusGMethodInvocation  *context)
{
        const char *error;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_action (mechanism, context, "printeradd"))
                return FALSE;

        if (!cph_cups_printer_add (mechanism->priv->cups,
                                   name, uri, ppd, info, location))
                error = cph_cups_last_status_to_string (mechanism->priv->cups);
        else
                error = "";

        dbus_g_method_return (context, error);
        return TRUE;
}
