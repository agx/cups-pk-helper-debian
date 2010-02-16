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

#include <pwd.h>

#include "cups-pk-helper-mechanism.h"
#include "cups-pk-helper-mechanism-glue.h"
#include "cups.h"

/* exit timer */

static gboolean
do_exit (gpointer user_data)
{
        if (user_data != NULL)
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
_check_polkit_for_action_internal (CphMechanism           *mechanism,
                                   DBusGMethodInvocation  *context,
                                   const char             *action_method,
                                   GError                **error)
{
        const char *sender;
        DBusError dbus_error;
        PolKitCaller *pk_caller;
        PolKitAction *pk_action;
        PolKitResult pk_result;
        char *action;

        g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

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
                g_set_error (error,
                             CPH_MECHANISM_ERROR, CPH_MECHANISM_ERROR_GENERAL,
                             "Error getting information about caller: %s: %s",
                             dbus_error.name, dbus_error.message);
                dbus_error_free (&dbus_error);
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
                g_set_error (error,
                             CPH_MECHANISM_ERROR,
                             CPH_MECHANISM_ERROR_NOT_PRIVILEGED,
                             "%s %s <-- (action, result)",
                             action,
                             polkit_result_to_string_representation (pk_result));
                dbus_error_free (&dbus_error);
                g_free (action);

                return FALSE;
        }

        g_free (action);

        return TRUE;
}

static gboolean
_check_polkit_for_action_v (CphMechanism          *mechanism,
                            DBusGMethodInvocation *context,
                            const char            *first_action_method,
                            ...)
{
        gboolean    retval;
        GError     *error;
        va_list     var_args;
        const char *action_method;

        retval = FALSE;
        error = NULL;

        /* We check if the user is authorized for any of the specificed action
         * methods. In case of failure, we'll fail for the last one. Therefore,
         * we should choose with care the order, especially if we don't want
         * to prompt for a password too often and if we don't want to authorize
         * too many things at once. */
        va_start (var_args, first_action_method);
        action_method = first_action_method;

        while (action_method) {
                if (error != NULL) {
                        g_error_free (error);
                        error = NULL;
                }

                retval = _check_polkit_for_action_internal (mechanism, context,
                                                            action_method,
                                                            &error);
                if (retval)
                        break;

                action_method = va_arg (var_args, char *);
        }

        va_end (var_args);

        if (!retval) {
                if (!error) {
                        /* This should never happen, but let's be paranoid */
                        error = g_error_new (CPH_MECHANISM_ERROR,
                                             CPH_MECHANISM_ERROR_GENERAL,
                                             "Unknown error when checking for "
                                             "authorization");
                }

                dbus_g_method_return_error (context, error);
                g_error_free (error);
        }

        return retval;
}

static gboolean
_check_polkit_for_action (CphMechanism          *mechanism,
                          DBusGMethodInvocation *context,
                          const char            *action_method)
{
        return _check_polkit_for_action_v (mechanism, context,
                                           action_method, NULL);
}

static gboolean
_check_polkit_for_printer (CphMechanism          *mechanism,
                           DBusGMethodInvocation *context,
                           const char            *printer_name,
                           const char            *uri)
{
        gboolean is_local;

        is_local = cph_cups_is_printer_local (mechanism->priv->cups,
                                              printer_name) &&
                   (!uri || cph_cups_is_printer_uri_local (uri));

        return _check_polkit_for_action_v (mechanism, context,
                                           "printeraddremove",
                                           is_local ? "printer-local-edit"
                                                    : "printer-remote-edit",
                                           NULL);
}

static gboolean
_check_polkit_for_printer_class (CphMechanism          *mechanism,
                                 DBusGMethodInvocation *context,
                                 const char            *printer_name)
{
        if (cph_cups_is_class (mechanism->priv->cups, printer_name)) {
                return _check_polkit_for_action_v (mechanism, context,
                                                   "printeraddremove",
                                                   "class-edit", NULL);
        } else {
                return _check_polkit_for_printer (mechanism, context,
                                                  printer_name, NULL);
        }
}

static const char *
_cph_mechanism_get_action_for_name (CphMechanism *mechanism,
                                    const char   *name)
{
        if (cph_cups_is_class (mechanism->priv->cups, name))
                return "class-edit";

        if (cph_cups_is_printer_local (mechanism->priv->cups, name))
                return "printer-local-edit";

        return "printer-remote-edit";
}

char *
_cph_mechanism_get_callers_user_name (CphMechanism          *mechanism,
                                      DBusGMethodInvocation *context)
{
        unsigned long  sender_uid;
        struct passwd *password_entry;
        DBusError      dbus_error;
        gchar         *sender;
        char          *user_name = NULL;

        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        sender_uid = dbus_bus_get_unix_user (
                        dbus_g_connection_get_connection (mechanism->priv->system_bus_connection),
                        sender, &dbus_error);
        password_entry = getpwuid ((uid_t) sender_uid);

        if (password_entry != NULL)
                user_name = g_strdup (password_entry->pw_name);

        g_free (sender);

        return user_name;
}

/* helpers */

static void
_cph_mechanism_return_error (CphMechanism          *mechanism,
                             DBusGMethodInvocation *context,
                             gboolean               failed)
{
        const char *error;

        if (failed)
                error = cph_cups_last_status_to_string (mechanism->priv->cups);
        else
                error = "";

        dbus_g_method_return (context, error);
}

static void
_cph_mechanism_return_error_and_value (CphMechanism          *mechanism,
                                       DBusGMethodInvocation *context,
                                       gboolean               failed,
                                       gpointer               value)
{
        const char *error;

        if (failed)
                error = cph_cups_last_status_to_string (mechanism->priv->cups);
        else
                error = "";

        dbus_g_method_return (context, error, value);
}

/* exported methods */

gboolean
cph_mechanism_file_get (CphMechanism          *mechanism,
                        const char            *resource,
                        const char            *filename,
                        DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_action (mechanism, context, "server-settings"))
                return FALSE;

        ret = cph_cups_file_get (mechanism->priv->cups, resource, filename);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_file_put (CphMechanism          *mechanism,
                        const char            *resource,
                        const char            *filename,
                        DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_action (mechanism, context, "server-settings"))
                return FALSE;

        ret = cph_cups_file_put (mechanism->priv->cups, resource, filename);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_add (CphMechanism          *mechanism,
                           const char            *name,
                           const char            *uri,
                           const char            *ppd,
                           const char            *info,
                           const char            *location,
                           DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer (mechanism, context, name, uri))
                return FALSE;

        ret = cph_cups_printer_add (mechanism->priv->cups,
                                    name, uri, ppd, info, location);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_add_with_ppd_file (CphMechanism          *mechanism,
                                         const char            *name,
                                         const char            *uri,
                                         const char            *ppdfile,
                                         const char            *info,
                                         const char            *location,
                                         DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer (mechanism, context, name, uri))
                return FALSE;

        ret = cph_cups_printer_add_with_ppd_file (mechanism->priv->cups,
                                                  name, uri, ppdfile,
                                                  info, location);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_set_device (CphMechanism          *mechanism,
                                  const char            *name,
                                  const char            *device,
                                  DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer (mechanism, context, name, device))
                return FALSE;

        ret = cph_cups_printer_set_uri (mechanism->priv->cups,
                                        name, device);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_set_info (CphMechanism          *mechanism,
                                const char            *name,
                                const char            *info,
                                DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return FALSE;

        ret = cph_cups_printer_class_set_info (mechanism->priv->cups,
                                               name, info);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_set_location (CphMechanism          *mechanism,
                                    const char            *name,
                                    const char            *location,
                                    DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return FALSE;

        ret = cph_cups_printer_class_set_location (mechanism->priv->cups,
                                                   name, location);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_set_shared (CphMechanism          *mechanism,
                                  const char            *name,
                                  gboolean               shared,
                                  DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return FALSE;

        ret = cph_cups_printer_class_set_shared (mechanism->priv->cups,
                                                 name, shared);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_set_job_sheets (CphMechanism          *mechanism,
                                      const char            *name,
                                      const char            *start,
                                      const char            *end,
                                      DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return FALSE;

        ret = cph_cups_printer_class_set_job_sheets (mechanism->priv->cups,
                                                     name, start, end);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_set_error_policy (CphMechanism          *mechanism,
                                        const char            *name,
                                        const char            *policy,
                                        DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return FALSE;

        ret = cph_cups_printer_class_set_error_policy (mechanism->priv->cups,
                                                       name, policy);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_set_op_policy (CphMechanism          *mechanism,
                                     const char            *name,
                                     const char            *policy,
                                     DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return FALSE;

        ret = cph_cups_printer_class_set_op_policy (mechanism->priv->cups,
                                                    name, policy);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_set_users_allowed (CphMechanism           *mechanism,
                                         const char             *name,
                                         const char            **users,
                                         DBusGMethodInvocation  *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return FALSE;

        ret = cph_cups_printer_class_set_users_allowed (mechanism->priv->cups,
                                                        name, users);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_set_users_denied (CphMechanism           *mechanism,
                                        const char             *name,
                                        const char            **users,
                                        DBusGMethodInvocation  *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return FALSE;

        ret = cph_cups_printer_class_set_users_denied (mechanism->priv->cups,
                                                       name, users);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}


gboolean
cph_mechanism_printer_add_option_default (CphMechanism           *mechanism,
                                          const char             *name,
                                          const char             *option,
                                          const char            **values,
                                          DBusGMethodInvocation  *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return FALSE;

        ret = cph_cups_printer_class_set_option_default (mechanism->priv->cups,
                                                         name, option, values);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_delete_option_default (CphMechanism          *mechanism,
                                             const char            *name,
                                             const char            *option,
                                             DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return FALSE;

        ret = cph_cups_printer_class_set_option_default (mechanism->priv->cups,
                                                         name, option, NULL);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_delete (CphMechanism          *mechanism,
                              const char            *name,
                              DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer (mechanism, context, name, NULL))
                return FALSE;

        ret = cph_cups_printer_delete (mechanism->priv->cups, name);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_class_add_printer (CphMechanism          *mechanism,
                                 const char            *name,
                                 const char            *printer,
                                 DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_action_v (mechanism, context,
                                         "printeraddremove", "class-edit",
                                         NULL))
                return FALSE;

        ret = cph_cups_class_add_printer (mechanism->priv->cups,
                                          name, printer);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_class_delete_printer (CphMechanism          *mechanism,
                                    const char            *name,
                                    const char            *printer,
                                    DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_action_v (mechanism, context,
                                         "printeraddremove", "class-edit",
                                         NULL))
                return FALSE;

        ret = cph_cups_class_delete_printer (mechanism->priv->cups,
                                             name, printer);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_class_delete (CphMechanism          *mechanism,
                            const char            *name,
                            DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_action_v (mechanism, context,
                                         "printeraddremove", "class-edit",
                                         NULL))
                return FALSE;

        ret = cph_cups_class_delete (mechanism->priv->cups, name);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_set_default (CphMechanism          *mechanism,
                                   const char            *name,
                                   DBusGMethodInvocation *context)
{
        gboolean    ret;
        const char *last_action;

        reset_killtimer (mechanism);

        last_action = _cph_mechanism_get_action_for_name (mechanism, name);
        if (!_check_polkit_for_action_v (mechanism, context,
                                         "printeraddremove",
                                         /* this is not the last check because
                                          * it's likely most useful to the user
                                          * to give "printer-X-edit" powers */
                                         "printer-default",
                                         /* quite important, since it's
                                          * automatically called after adding a
                                          * printer */
                                         last_action,
                                         NULL))
                return FALSE;

        ret = cph_cups_printer_set_default (mechanism->priv->cups, name);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_set_enabled (CphMechanism          *mechanism,
                                   const char            *name,
                                   gboolean               enabled,
                                   DBusGMethodInvocation *context)
{
        gboolean    ret;
        const char *last_action;

        reset_killtimer (mechanism);

        last_action = _cph_mechanism_get_action_for_name (mechanism, name);
        if (!_check_polkit_for_action_v (mechanism, context,
                                         "printeraddremove",
                                         /* this is not the last check because
                                          * it's likely most useful to the user
                                          * to give "printer-X-edit" powers */
                                         "printer-enable",
                                         /* quite important, since it's
                                          * automatically called after adding a
                                          * printer */
                                         last_action,
                                         NULL))
                return FALSE;

        ret = cph_cups_printer_set_enabled (mechanism->priv->cups,
                                            name, enabled);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_printer_set_accept_jobs (CphMechanism          *mechanism,
                                       const char            *name,
                                       gboolean               enabled,
                                       const char            *reason,
                                       DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_printer (mechanism, context, name, NULL))
                return FALSE;

        if (reason && reason[0] == '\0')
                reason = NULL;

        ret = cph_cups_printer_set_accept_jobs (mechanism->priv->cups,
                                                name, enabled, reason);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_server_get_settings (CphMechanism          *mechanism,
                                   DBusGMethodInvocation *context)
{
        GHashTable *settings;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_action (mechanism, context, "server-settings"))
                return FALSE;

        settings = cph_cups_server_get_settings (mechanism->priv->cups);
        _cph_mechanism_return_error_and_value (mechanism, context,
                                               settings == NULL, settings);

        return TRUE;
}

gboolean
cph_mechanism_server_set_settings (CphMechanism          *mechanism,
                                   GHashTable            *settings,
                                   DBusGMethodInvocation *context)
{
        gboolean ret;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_action (mechanism, context, "server-settings"))
                return FALSE;

        ret = cph_cups_server_set_settings (mechanism->priv->cups, settings);
        _cph_mechanism_return_error (mechanism, context, !ret);

        return TRUE;
}

gboolean
cph_mechanism_job_cancel (CphMechanism          *mechanism,
                          int                    id,
                          DBusGMethodInvocation *context)
{
        CphJobStatus  job_status;
        gboolean      ret;
        char         *user_name;

        reset_killtimer (mechanism);

        user_name = _cph_mechanism_get_callers_user_name (mechanism, context);
        job_status = cph_cups_job_get_status (mechanism->priv->cups,
                                              id, user_name);

        switch (job_status) {
                case CPH_JOB_STATUS_OWNED_BY_USER: {
                        if (!_check_polkit_for_action_v (mechanism, context,
                                                         "job-not-owned-edit",
                                                         "job-edit",
                                                         NULL))
                                return FALSE;
                        break;
                }
                case CPH_JOB_STATUS_NOT_OWNED_BY_USER: {
                        if (!_check_polkit_for_action (mechanism, context,
                                                       "job-not-owned-edit"))
                                return FALSE;
                        break;
                }
                case CPH_JOB_STATUS_INVALID:
                        return FALSE;
        }

        ret = cph_cups_job_cancel (mechanism->priv->cups, id, user_name);
        _cph_mechanism_return_error (mechanism, context, !ret);

        g_free (user_name);

        return TRUE;
}

gboolean
cph_mechanism_job_restart (CphMechanism          *mechanism,
                           int                    id,
                           DBusGMethodInvocation *context)
{
        CphJobStatus  job_status;
        gboolean      ret;
        char         *user_name;

        reset_killtimer (mechanism);

        user_name = _cph_mechanism_get_callers_user_name (mechanism, context);
        job_status = cph_cups_job_get_status (mechanism->priv->cups,
                                              id, user_name);

        switch (job_status) {
                case CPH_JOB_STATUS_OWNED_BY_USER: {
                        if (!_check_polkit_for_action_v (mechanism, context,
                                                         "job-not-owned-edit",
                                                         "job-edit",
                                                         NULL))
                                return FALSE;
                        break;
                }
                case CPH_JOB_STATUS_NOT_OWNED_BY_USER: {
                        if (!_check_polkit_for_action (mechanism, context,
                                                       "job-not-owned-edit"))
                                return FALSE;
                        break;
                }
                case CPH_JOB_STATUS_INVALID:
                        return FALSE;
        }

        ret = cph_cups_job_restart (mechanism->priv->cups, id, user_name);
        _cph_mechanism_return_error (mechanism, context, !ret);

        g_free (user_name);

        return TRUE;
}

gboolean
cph_mechanism_job_set_hold_until (CphMechanism          *mechanism,
                                  int                    id,
                                  const char            *job_hold_until,
                                  DBusGMethodInvocation *context)
{
        CphJobStatus  job_status;
        gboolean      ret;
        char         *user_name;

        reset_killtimer (mechanism);

        user_name = _cph_mechanism_get_callers_user_name (mechanism, context);
        job_status = cph_cups_job_get_status (mechanism->priv->cups,
                                              id, user_name);

        switch (job_status) {
                case CPH_JOB_STATUS_OWNED_BY_USER: {
                        if (!_check_polkit_for_action_v (mechanism, context,
                                                         "job-not-owned-edit",
                                                         "job-edit",
                                                         NULL))
                                return FALSE;
                        break;
                }
                case CPH_JOB_STATUS_NOT_OWNED_BY_USER: {
                        if (!_check_polkit_for_action (mechanism, context,
                                                       "job-not-owned-edit"))
                                return FALSE;
                        break;
                }
                case CPH_JOB_STATUS_INVALID:
                        return FALSE;
        }

        ret = cph_cups_job_set_hold_until (mechanism->priv->cups, id, job_hold_until, user_name);
        _cph_mechanism_return_error (mechanism, context, !ret);

        g_free (user_name);

        return TRUE;
}

gboolean
cph_mechanism_devices_get (CphMechanism          *mechanism,
                           int                    timeout,
                           const char            *include_schemes,
                           const char            *exclude_schemes,
                           DBusGMethodInvocation *context)
{
        GHashTable *devices;

        reset_killtimer (mechanism);

        if (!_check_polkit_for_action (mechanism, context, "devices-get"))
                return FALSE;

        devices = cph_cups_devices_get (mechanism->priv->cups,
                                        timeout,
                                        include_schemes,
                                        exclude_schemes);
        _cph_mechanism_return_error_and_value (mechanism, context,
                                               devices == NULL, devices);

        return TRUE;
}
