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
#include <gio/gio.h>

#include <polkit/polkit.h>

#include <pwd.h>

#include "cups-pk-helper-mechanism.h"
#include "cph-iface-mechanism.h"
#include "cups.h"

#define CPH_SERVICE_DBUS      "org.freedesktop.DBus"
#define CPH_PATH_DBUS         "/org/freedesktop/DBus"
#define CPH_INTERFACE_DBUS    "org.freedesktop.DBus"

/* error */

static const GDBusErrorEntry cph_error_entries[] =
{
        { CPH_MECHANISM_ERROR_GENERAL,        "org.opensuse.CupsPkHelper.Mechanism.GeneralError"  },
        { CPH_MECHANISM_ERROR_NOT_PRIVILEGED, "org.opensuse.CupsPkHelper.Mechanism.NotPrivileged" }
};

GQuark
cph_mechanism_error_quark (void)
{
        static gsize ret = 0;

        if (ret == 0) {
                g_assert (CPH_MECHANISM_NUM_ERRORS == G_N_ELEMENTS (cph_error_entries));

                g_dbus_error_register_error_domain ("cph-mechanism-error",
                                                    &ret,
                                                    cph_error_entries,
                                                    G_N_ELEMENTS (cph_error_entries));
        }

        return ret;
}

/* mechanism object */

G_DEFINE_TYPE (CphMechanism, cph_mechanism, CPH_IFACE_TYPE_MECHANISM_SKELETON)

#define CPH_MECHANISM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), CPH_TYPE_MECHANISM, CphMechanismPrivate))

struct CphMechanismPrivate
{
        gboolean         exported;
        gboolean         connected;
        PolkitAuthority *pol_auth;
        CphCups         *cups;
        GDBusProxy      *dbus_proxy;
};

enum {
        CALLED,
        LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static GObject *cph_mechanism_constructor (GType                  type,
                                           guint                  n_construct_properties,
                                           GObjectConstructParam *construct_properties);
static void     cph_mechanism_dispose     (GObject *object);
static void     cph_mechanism_finalize    (GObject *object);

static void     cph_mechanism_connect_signals (CphMechanism *mechanism);

static void
cph_mechanism_class_init (CphMechanismClass *klass)
{
        GObjectClass *object_class = G_OBJECT_CLASS (klass);

        object_class->constructor = cph_mechanism_constructor;
        object_class->dispose = cph_mechanism_dispose;
        object_class->finalize = cph_mechanism_finalize;

        signals[CALLED] =
                g_signal_new ("called",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              G_STRUCT_OFFSET (CphMechanismClass, called),
                              NULL, NULL,
                              g_cclosure_marshal_VOID__VOID,
                              G_TYPE_NONE,
                              0);

        g_type_class_add_private (klass, sizeof (CphMechanismPrivate));
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

        mechanism->priv->exported = FALSE;
        mechanism->priv->connected = FALSE;
        mechanism->priv->pol_auth = NULL;
        mechanism->priv->cups = NULL;
        mechanism->priv->dbus_proxy = NULL;
}

static void
cph_mechanism_dispose (GObject *object)
{
        CphMechanism *mechanism;

        g_return_if_fail (object != NULL);
        g_return_if_fail (CPH_IS_MECHANISM (object));

        mechanism = CPH_MECHANISM (object);

        if (mechanism->priv->pol_auth != NULL)
                g_object_unref (mechanism->priv->pol_auth);
        mechanism->priv->pol_auth = NULL;

        if (mechanism->priv->cups != NULL)
                g_object_unref (mechanism->priv->cups);
        mechanism->priv->cups = NULL;

        if (mechanism->priv->dbus_proxy != NULL)
                g_object_unref (mechanism->priv->dbus_proxy);
        mechanism->priv->dbus_proxy = NULL;

        G_OBJECT_CLASS (cph_mechanism_parent_class)->dispose (object);
}

static void
cph_mechanism_finalize (GObject *object)
{
        CphMechanism *mechanism;

        g_return_if_fail (object != NULL);
        g_return_if_fail (CPH_IS_MECHANISM (object));

        mechanism = CPH_MECHANISM (object);

        if (mechanism->priv->exported)
                g_dbus_interface_skeleton_unexport (G_DBUS_INTERFACE_SKELETON (mechanism));
        mechanism->priv->exported = FALSE;

        G_OBJECT_CLASS (cph_mechanism_parent_class)->finalize (object);
}

CphMechanism *
cph_mechanism_new (void)
{
        GObject *object;

        object = g_object_new (CPH_TYPE_MECHANISM, NULL);

        return CPH_MECHANISM (object);
}

gboolean
cph_mechanism_register (CphMechanism     *mechanism,
                        GDBusConnection  *connection,
                        const char       *object_path,
                        GError          **error)
{
        gboolean ret;

        g_return_val_if_fail (CPH_IS_MECHANISM (mechanism), FALSE);
        g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

        if (mechanism->priv->exported && mechanism->priv->pol_auth != NULL)
                return TRUE;

        if (!mechanism->priv->exported) {
                ret = g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (mechanism),
                                                        connection,
                                                        object_path,
                                                        error);
                if (!ret)
                        return FALSE;

                mechanism->priv->exported = TRUE;
        }

        if (mechanism->priv->pol_auth == NULL) {
                mechanism->priv->pol_auth = polkit_authority_get_sync (NULL, error);
                if (mechanism->priv->pol_auth == NULL)
                        return FALSE;
        }

        cph_mechanism_connect_signals (mechanism);

        return TRUE;
}

/* polkit helpers */

static gboolean
_check_polkit_for_action_internal (CphMechanism           *mechanism,
                                   GDBusMethodInvocation  *context,
                                   const char             *action_method,
                                   gboolean                allow_user_interaction,
                                   GError                **error)
{
        const char *sender;
        PolkitSubject *subject;
        PolkitAuthorizationResult *pk_result;
        char *action;
        GError *local_error;

        g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

        local_error = NULL;

        action = g_strdup_printf ("org.opensuse.cupspkhelper.mechanism.%s",
                                  action_method);

        /* Check that caller is privileged */
        sender = g_dbus_method_invocation_get_sender (context);
        subject = polkit_system_bus_name_new (sender);

        pk_result = polkit_authority_check_authorization_sync (mechanism->priv->pol_auth,
                                                               subject,
                                                               action,
                                                               NULL,
                                                               allow_user_interaction ?
                                                                POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION :
                                                                POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE,
                                                               NULL,
                                                               &local_error);
        g_object_unref (subject);

        if (local_error) {
                g_propagate_error (error, local_error);
                g_free (action);

                return FALSE;
        }

        if (!polkit_authorization_result_get_is_authorized (pk_result)) {
                g_set_error (error,
                             CPH_MECHANISM_ERROR,
                             CPH_MECHANISM_ERROR_NOT_PRIVILEGED,
                             "Not Authorized for action: %s", action);
                g_free (action);
                g_object_unref (pk_result);

                return FALSE;
        }

        g_free (action);
        g_object_unref (pk_result);

        return TRUE;
}

static gboolean
_check_polkit_for_action_v (CphMechanism          *mechanism,
                            GDBusMethodInvocation *context,
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
         * methods. We only allow user interaction for the last one. Therefore,
         * callers of this function should choose with care the order,
         * especially if we don't want to prompt for a password too often and
         * if we don't want to authorize too many things at once. */
        va_start (var_args, first_action_method);
        action_method = first_action_method;

        while (action_method) {
                char *next_action_method;

                if (error != NULL) {
                        g_error_free (error);
                        error = NULL;
                }

                next_action_method = va_arg (var_args, char *);

                retval = _check_polkit_for_action_internal (mechanism, context,
                                                            action_method,
                                                            next_action_method == NULL,
                                                            &error);
                if (retval)
                        break;

                action_method = next_action_method;
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

                g_dbus_method_invocation_return_gerror (context, error);
                g_error_free (error);
        }

        return retval;
}

static gboolean
_check_polkit_for_action (CphMechanism          *mechanism,
                          GDBusMethodInvocation *context,
                          const char            *action_method)
{
        return _check_polkit_for_action_v (mechanism, context,
                                           action_method, NULL);
}

static gboolean
_check_polkit_for_printer (CphMechanism          *mechanism,
                           GDBusMethodInvocation *context,
                           const char            *printer_name,
                           const char            *uri)
{
        gboolean is_local;

        is_local = cph_cups_is_printer_local (mechanism->priv->cups,
                                              printer_name) &&
                   (!uri || cph_cups_is_printer_uri_local (uri));

        return _check_polkit_for_action_v (mechanism, context,
                                           "all-edit",
                                           "printeraddremove",
                                           is_local ? "printer-local-edit"
                                                    : "printer-remote-edit",
                                           NULL);
}

static gboolean
_check_polkit_for_printer_class (CphMechanism          *mechanism,
                                 GDBusMethodInvocation *context,
                                 const char            *printer_name)
{
        if (cph_cups_is_class (mechanism->priv->cups, printer_name)) {
                return _check_polkit_for_action_v (mechanism, context,
                                                   "all-edit",
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

static void
_cph_mechanism_ensure_dbus_proxy (CphMechanism    *mechanism,
                                  GDBusConnection *connection)
{
        GError *error = NULL;

        if (mechanism->priv->dbus_proxy != NULL)
                return;

        mechanism->priv->dbus_proxy = g_dbus_proxy_new_sync (connection,
                                                             G_DBUS_PROXY_FLAGS_NONE,
                                                             NULL,
                                                             CPH_SERVICE_DBUS,
                                                             CPH_PATH_DBUS,
                                                             CPH_INTERFACE_DBUS,
                                                             NULL,
                                                             &error);

        if (mechanism->priv->dbus_proxy == NULL) {
                if (error)
                        g_warning ("Could not get proxy to dbus service: %s", error->message);
                else
                        g_warning ("Could not get proxy to dbus service user");

                g_error_free (error);
        }
}

static gboolean
_cph_mechanism_get_sender_uid (CphMechanism          *mechanism,
                               GDBusMethodInvocation *context,
                               unsigned int          *sender_uid)
{
        GError          *error;
        GDBusConnection *connection;
        const char      *sender;
        GVariant        *result;

        *sender_uid = 0;

        connection = g_dbus_method_invocation_get_connection (context);
        _cph_mechanism_ensure_dbus_proxy (mechanism, connection);
        if (mechanism->priv->dbus_proxy == NULL)
                return FALSE;

        sender = g_dbus_method_invocation_get_sender (context);

        error = NULL;
        result = g_dbus_proxy_call_sync (mechanism->priv->dbus_proxy,
                                         "GetConnectionUnixUser",
                                         g_variant_new ("(s)", sender),
                                         G_DBUS_CALL_FLAGS_NONE,
                                         -1,
                                         NULL,
                                         &error);

        if (result == NULL) {
                if (error)
                        g_warning ("Could not get unix user: %s", error->message);
                else
                        g_warning ("Could not get unix user");

                g_error_free (error);
                return FALSE;
        }

        g_variant_get (result, "(u)", sender_uid);
        g_variant_unref (result);

        return TRUE;
}

static char *
_cph_mechanism_get_sender_user_name (CphMechanism          *mechanism,
                                     GDBusMethodInvocation *context)
{
        unsigned int   sender_uid;
        struct passwd *password_entry;
        char          *user_name = NULL;

        if (!_cph_mechanism_get_sender_uid (mechanism, context, &sender_uid))
                return NULL;

        password_entry = getpwuid ((uid_t) sender_uid);

        if (password_entry != NULL)
                user_name = g_strdup (password_entry->pw_name);

        return user_name;
}

/* helpers */

static const char *
_cph_mechanism_return_error (CphMechanism *mechanism,
                             gboolean      failed)
{
        const char *error;

        if (failed) {
                error = cph_cups_last_status_to_string (mechanism->priv->cups);
                if (!error || error[0] == '\0')
                        error = "Unknown error";
        } else
                error = "";

        return error;
}

static void
_cph_mechanism_emit_called (CphMechanism *mechanism)
{
        g_signal_emit (mechanism, signals[CALLED], 0);
}

/* exported methods */

static gboolean
cph_mechanism_file_get (CphIfaceMechanism     *object,
                        GDBusMethodInvocation *context,
                        const char            *resource,
                        const char            *filename)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        unsigned int  sender_uid;
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_cph_mechanism_get_sender_uid (mechanism, context, &sender_uid)) {
                GError *error;

                error = g_error_new (CPH_MECHANISM_ERROR,
                                     CPH_MECHANISM_ERROR_GENERAL,
                                     "Cannot determine sender UID");
                g_dbus_method_invocation_return_gerror (context, error);
                g_error_free (error);

                return TRUE;
        }

        if (!_check_polkit_for_action (mechanism, context, "server-settings"))
                return TRUE;

        ret = cph_cups_file_get (mechanism->priv->cups,
                                 resource, filename, sender_uid);

        cph_iface_mechanism_complete_file_get (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_file_put (CphIfaceMechanism     *object,
                        GDBusMethodInvocation *context,
                        const char            *resource,
                        const char            *filename)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        unsigned int  sender_uid;
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_cph_mechanism_get_sender_uid (mechanism, context, &sender_uid)) {
                GError *error;

                error = g_error_new (CPH_MECHANISM_ERROR,
                                     CPH_MECHANISM_ERROR_GENERAL,
                                     "Cannot determine sender UID");
                g_dbus_method_invocation_return_gerror (context, error);
                g_error_free (error);

                return TRUE;
        }

        if (!_check_polkit_for_action (mechanism, context, "server-settings"))
                return TRUE;

        ret = cph_cups_file_put (mechanism->priv->cups,
                                 resource, filename, sender_uid);

        cph_iface_mechanism_complete_file_put (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_server_get_settings (CphIfaceMechanism     *object,
                                   GDBusMethodInvocation *context)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;
        GVariant     *settings = NULL;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_action (mechanism, context, "server-settings"))
                return TRUE;

        ret = cph_cups_server_get_settings (mechanism->priv->cups,
                                            &settings);

        if (settings == NULL)
                settings = g_variant_new_array (G_VARIANT_TYPE_DICT_ENTRY, NULL, 0);

        cph_iface_mechanism_complete_server_get_settings (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret),
                        settings);
        return TRUE;
}

static gboolean
cph_mechanism_server_set_settings (CphIfaceMechanism     *object,
                                   GDBusMethodInvocation *context,
                                   GVariant              *settings)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_action (mechanism, context, "server-settings"))
                return TRUE;

        ret = cph_cups_server_set_settings (mechanism->priv->cups, settings);

        cph_iface_mechanism_complete_server_set_settings (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_devices_get (CphIfaceMechanism      *object,
                           GDBusMethodInvocation  *context,
                           int                     timeout,
                           int                     limit,
                           const char *const      *include_schemes,
                           const char *const      *exclude_schemes)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;
        GVariant     *devices = NULL;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_action_v (mechanism, context,
                                         "all-edit",
                                         "devices-get",
                                         NULL))
                return TRUE;

        ret = cph_cups_devices_get (mechanism->priv->cups,
                                    timeout,
                                    limit,
                                    include_schemes,
                                    exclude_schemes,
                                    &devices);

        if (devices == NULL)
                devices = g_variant_new_array (G_VARIANT_TYPE_DICT_ENTRY, NULL, 0);

        cph_iface_mechanism_complete_devices_get (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret),
                        devices);
        return TRUE;
}

static gboolean
cph_mechanism_printer_add (CphIfaceMechanism     *object,
                           GDBusMethodInvocation *context,
                           const char            *name,
                           const char            *uri,
                           const char            *ppd,
                           const char            *info,
                           const char            *location)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer (mechanism, context, name, uri))
                return TRUE;

        ret = cph_cups_printer_add (mechanism->priv->cups,
                                    name, uri, ppd, info, location);

        cph_iface_mechanism_complete_printer_add (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_add_with_ppd_file (CphIfaceMechanism     *object,
                                         GDBusMethodInvocation *context,
                                         const char            *name,
                                         const char            *uri,
                                         const char            *ppdfile,
                                         const char            *info,
                                         const char            *location)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer (mechanism, context, name, uri))
                return TRUE;

        ret = cph_cups_printer_add_with_ppd_file (mechanism->priv->cups,
                                                  name, uri, ppdfile,
                                                  info, location);

        cph_iface_mechanism_complete_printer_add_with_ppd_file (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_set_device (CphIfaceMechanism     *object,
                                  GDBusMethodInvocation *context,
                                  const char            *name,
                                  const char            *device)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer (mechanism, context, name, device))
                return TRUE;

        ret = cph_cups_printer_set_uri (mechanism->priv->cups,
                                        name, device);

        cph_iface_mechanism_complete_printer_set_device (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_set_default (CphIfaceMechanism     *object,
                                   GDBusMethodInvocation *context,
                                   const char            *name)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean     ret;
        const char  *last_action;

        _cph_mechanism_emit_called (mechanism);

        last_action = _cph_mechanism_get_action_for_name (mechanism, name);
        if (!_check_polkit_for_action_v (mechanism, context,
                                         "all-edit",
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
                return TRUE;

        ret = cph_cups_printer_set_default (mechanism->priv->cups, name);

        cph_iface_mechanism_complete_printer_set_default (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_set_enabled (CphIfaceMechanism     *object,
                                   GDBusMethodInvocation *context,
                                   const char            *name,
                                   gboolean               enabled)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean     ret;
        const char  *last_action;

        _cph_mechanism_emit_called (mechanism);

        last_action = _cph_mechanism_get_action_for_name (mechanism, name);
        if (!_check_polkit_for_action_v (mechanism, context,
                                         "all-edit",
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
                return TRUE;

        ret = cph_cups_printer_set_enabled (mechanism->priv->cups,
                                            name, enabled);

        cph_iface_mechanism_complete_printer_set_enabled (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_set_accept_jobs (CphIfaceMechanism     *object,
                                       GDBusMethodInvocation *context,
                                       const char            *name,
                                       gboolean               enabled,
                                       const char            *reason)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer (mechanism, context, name, NULL))
                return TRUE;

        if (reason && reason[0] == '\0')
                reason = NULL;

        ret = cph_cups_printer_set_accept_jobs (mechanism->priv->cups,
                                                name, enabled, reason);

        cph_iface_mechanism_complete_printer_set_accept_jobs (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_delete (CphIfaceMechanism     *object,
                              GDBusMethodInvocation *context,
                              const char            *name)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer (mechanism, context, name, NULL))
                return TRUE;

        ret = cph_cups_printer_delete (mechanism->priv->cups, name);

        cph_iface_mechanism_complete_printer_delete (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_class_rename (CphIfaceMechanism     *object,
                                    GDBusMethodInvocation *context,
                                    const char            *old_printer_name,
                                    const char            *new_printer_name)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, old_printer_name))
                return TRUE;

        ret = cph_cups_printer_class_rename (mechanism->priv->cups, old_printer_name, new_printer_name);

        cph_iface_mechanism_complete_printer_rename (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_class_add_printer (CphIfaceMechanism     *object,
                                 GDBusMethodInvocation *context,
                                 const char            *name,
                                 const char            *printer)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_action_v (mechanism, context,
                                         "all-edit",
                                         "printeraddremove",
                                         "class-edit",
                                         NULL))
                return TRUE;

        ret = cph_cups_class_add_printer (mechanism->priv->cups,
                                          name, printer);

        cph_iface_mechanism_complete_class_add_printer (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_class_delete_printer (CphIfaceMechanism     *object,
                                    GDBusMethodInvocation *context,
                                    const char            *name,
                                    const char            *printer)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_action_v (mechanism, context,
                                         "all-edit",
                                         "printeraddremove",
                                         "class-edit",
                                         NULL))
                return TRUE;

        ret = cph_cups_class_delete_printer (mechanism->priv->cups,
                                             name, printer);

        cph_iface_mechanism_complete_class_delete_printer (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_class_delete (CphIfaceMechanism     *object,
                            GDBusMethodInvocation *context,
                            const char            *name)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_action_v (mechanism, context,
                                         "all-edit",
                                         "printeraddremove",
                                         "class-edit",
                                         NULL))
                return TRUE;

        ret = cph_cups_class_delete (mechanism->priv->cups, name);

        cph_iface_mechanism_complete_class_delete (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_set_info (CphIfaceMechanism     *object,
                                GDBusMethodInvocation *context,
                                const char            *name,
                                const char            *info)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return TRUE;

        ret = cph_cups_printer_class_set_info (mechanism->priv->cups,
                                               name, info);

        cph_iface_mechanism_complete_printer_set_info (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_set_location (CphIfaceMechanism     *object,
                                    GDBusMethodInvocation *context,
                                    const char            *name,
                                    const char            *location)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return TRUE;

        ret = cph_cups_printer_class_set_location (mechanism->priv->cups,
                                                   name, location);

        cph_iface_mechanism_complete_printer_set_location (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_set_shared (CphIfaceMechanism     *object,
                                  GDBusMethodInvocation *context,
                                  const char            *name,
                                  gboolean               shared)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return TRUE;

        ret = cph_cups_printer_class_set_shared (mechanism->priv->cups,
                                                 name, shared);

        cph_iface_mechanism_complete_printer_set_shared (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_set_job_sheets (CphIfaceMechanism     *object,
                                      GDBusMethodInvocation *context,
                                      const char            *name,
                                      const char            *start,
                                      const char            *end)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return TRUE;

        ret = cph_cups_printer_class_set_job_sheets (mechanism->priv->cups,
                                                     name, start, end);

        cph_iface_mechanism_complete_printer_set_job_sheets (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_set_error_policy (CphIfaceMechanism     *object,
                                        GDBusMethodInvocation *context,
                                        const char            *name,
                                        const char            *policy)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return TRUE;

        ret = cph_cups_printer_class_set_error_policy (mechanism->priv->cups,
                                                       name, policy);

        cph_iface_mechanism_complete_printer_set_error_policy (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_set_op_policy (CphIfaceMechanism     *object,
                                     GDBusMethodInvocation *context,
                                     const char            *name,
                                     const char            *policy)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return TRUE;

        ret = cph_cups_printer_class_set_op_policy (mechanism->priv->cups,
                                                    name, policy);

        cph_iface_mechanism_complete_printer_set_op_policy (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_set_users_allowed (CphIfaceMechanism      *object,
                                         GDBusMethodInvocation  *context,
                                         const char             *name,
                                         const char *const      *users)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return TRUE;

        ret = cph_cups_printer_class_set_users_allowed (mechanism->priv->cups,
                                                        name, users);

        cph_iface_mechanism_complete_printer_set_users_allowed (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_set_users_denied (CphIfaceMechanism      *object,
                                        GDBusMethodInvocation  *context,
                                        const char             *name,
                                        const char *const      *users)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return TRUE;

        ret = cph_cups_printer_class_set_users_denied (mechanism->priv->cups,
                                                       name, users);

        cph_iface_mechanism_complete_printer_set_users_denied (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_add_option_default (CphIfaceMechanism      *object,
                                          GDBusMethodInvocation  *context,
                                          const char             *name,
                                          const char             *option,
                                          const char *const      *values)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return TRUE;

        ret = cph_cups_printer_class_set_option_default (mechanism->priv->cups,
                                                         name, option, values);

        cph_iface_mechanism_complete_printer_add_option_default (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_delete_option_default (CphIfaceMechanism     *object,
                                             GDBusMethodInvocation *context,
                                             const char            *name,
                                             const char            *option)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return TRUE;

        ret = cph_cups_printer_class_set_option_default (mechanism->priv->cups,
                                                         name, option, NULL);

        cph_iface_mechanism_complete_printer_delete_option_default (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_printer_add_option (CphIfaceMechanism      *object,
                                  GDBusMethodInvocation  *context,
                                  const char             *name,
                                  const char             *option,
                                  const char *const      *values)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        gboolean      ret;

        _cph_mechanism_emit_called (mechanism);

        if (!_check_polkit_for_printer_class (mechanism, context, name))
                return TRUE;

        ret = cph_cups_printer_class_set_option (mechanism->priv->cups,
                                                 name, option, values);

        cph_iface_mechanism_complete_printer_add_option (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));
        return TRUE;
}

static gboolean
cph_mechanism_job_cancel_purge (CphIfaceMechanism     *object,
                                GDBusMethodInvocation *context,
                                int                    id,
                                gboolean               purge)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        CphJobStatus  job_status;
        gboolean      ret;
        char         *user_name;

        _cph_mechanism_emit_called (mechanism);

        user_name = _cph_mechanism_get_sender_user_name (mechanism, context);
        job_status = cph_cups_job_get_status (mechanism->priv->cups,
                                              id, user_name);

        switch (job_status) {
                case CPH_JOB_STATUS_OWNED_BY_USER: {
                        if (!_check_polkit_for_action_v (mechanism, context,
                                                         "all-edit",
                                                         "job-not-owned-edit",
                                                         "job-edit",
                                                         NULL))
                                goto out;
                        break;
                }
                case CPH_JOB_STATUS_NOT_OWNED_BY_USER: {
                        if (!_check_polkit_for_action_v (mechanism, context,
                                                         "all-edit",
                                                         "job-not-owned-edit",
                                                         NULL))
                                goto out;
                        break;
                }
                case CPH_JOB_STATUS_INVALID: {
                        cph_iface_mechanism_complete_job_cancel_purge (
                                        object, context,
                                        _cph_mechanism_return_error (mechanism, TRUE));
                        goto out;
                }
        }

        ret = cph_cups_job_cancel (mechanism->priv->cups, id, purge, user_name);

        cph_iface_mechanism_complete_job_cancel_purge (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));

out:
        g_free (user_name);

        return TRUE;
}

static gboolean
cph_mechanism_job_cancel (CphIfaceMechanism     *object,
                          GDBusMethodInvocation *context,
                          int                    id)
{
        /* This only works because cph_iface_mechanism_complete_job_cancel and
         * cph_iface_mechanism_complete_job_cancel_purge do the same thing. */
        return cph_mechanism_job_cancel_purge (object, context, id, FALSE);
}

static gboolean
cph_mechanism_job_restart (CphIfaceMechanism     *object,
                           GDBusMethodInvocation *context,
                           int                    id)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        CphJobStatus  job_status;
        gboolean      ret;
        char         *user_name;

        _cph_mechanism_emit_called (mechanism);

        user_name = _cph_mechanism_get_sender_user_name (mechanism, context);
        job_status = cph_cups_job_get_status (mechanism->priv->cups,
                                              id, user_name);

        switch (job_status) {
                case CPH_JOB_STATUS_OWNED_BY_USER: {
                        if (!_check_polkit_for_action_v (mechanism, context,
                                                         "all-edit",
                                                         "job-not-owned-edit",
                                                         "job-edit",
                                                         NULL))
                                goto out;
                        break;
                }
                case CPH_JOB_STATUS_NOT_OWNED_BY_USER: {
                        if (!_check_polkit_for_action_v (mechanism, context,
                                                         "all-edit",
                                                         "job-not-owned-edit",
                                                         NULL))
                                goto out;
                        break;
                }
                case CPH_JOB_STATUS_INVALID: {
                        cph_iface_mechanism_complete_job_restart (
                                        object, context,
                                        _cph_mechanism_return_error (mechanism, TRUE));
                        goto out;
                }
        }

        ret = cph_cups_job_restart (mechanism->priv->cups, id, user_name);

        cph_iface_mechanism_complete_job_restart (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));

out:
        g_free (user_name);

        return TRUE;
}

static gboolean
cph_mechanism_job_set_hold_until (CphIfaceMechanism     *object,
                                  GDBusMethodInvocation *context,
                                  int                    id,
                                  const char            *job_hold_until)
{
        CphMechanism *mechanism = CPH_MECHANISM (object);
        CphJobStatus  job_status;
        gboolean      ret;
        char         *user_name;

        _cph_mechanism_emit_called (mechanism);

        user_name = _cph_mechanism_get_sender_user_name (mechanism, context);
        job_status = cph_cups_job_get_status (mechanism->priv->cups,
                                              id, user_name);

        switch (job_status) {
                case CPH_JOB_STATUS_OWNED_BY_USER: {
                        if (!_check_polkit_for_action_v (mechanism, context,
                                                         "all-edit",
                                                         "job-not-owned-edit",
                                                         "job-edit",
                                                         NULL))
                                goto out;
                        break;
                }
                case CPH_JOB_STATUS_NOT_OWNED_BY_USER: {
                        if (!_check_polkit_for_action_v (mechanism, context,
                                                         "all-edit",
                                                         "job-not-owned-edit",
                                                         NULL))
                                goto out;
                        break;
                }
                case CPH_JOB_STATUS_INVALID: {
                        cph_iface_mechanism_complete_job_set_hold_until (
                                        object, context,
                                        _cph_mechanism_return_error (mechanism, TRUE));
                        goto out;
                }
        }

        ret = cph_cups_job_set_hold_until (mechanism->priv->cups, id, job_hold_until, user_name);

        cph_iface_mechanism_complete_job_set_hold_until (
                        object, context,
                        _cph_mechanism_return_error (mechanism, !ret));

out:
        g_free (user_name);

        return TRUE;
}

/* connect methors */

static void
cph_mechanism_connect_signals (CphMechanism *mechanism)
{
        g_return_if_fail (CPH_IS_MECHANISM (mechanism));

        if (mechanism->priv->connected)
                return;

        mechanism->priv->connected = TRUE;

        g_signal_connect (mechanism,
                          "handle-class-add-printer",
                          G_CALLBACK (cph_mechanism_class_add_printer),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-class-delete",
                          G_CALLBACK (cph_mechanism_class_delete),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-class-delete-printer",
                          G_CALLBACK (cph_mechanism_class_delete_printer),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-devices-get",
                          G_CALLBACK (cph_mechanism_devices_get),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-file-get",
                          G_CALLBACK (cph_mechanism_file_get),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-file-put",
                          G_CALLBACK (cph_mechanism_file_put),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-job-cancel",
                          G_CALLBACK (cph_mechanism_job_cancel),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-job-cancel-purge",
                          G_CALLBACK (cph_mechanism_job_cancel_purge),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-job-restart",
                          G_CALLBACK (cph_mechanism_job_restart),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-job-set-hold-until",
                          G_CALLBACK (cph_mechanism_job_set_hold_until),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-add",
                          G_CALLBACK (cph_mechanism_printer_add),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-add-option",
                          G_CALLBACK (cph_mechanism_printer_add_option),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-add-option-default",
                          G_CALLBACK (cph_mechanism_printer_add_option_default),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-add-with-ppd-file",
                          G_CALLBACK (cph_mechanism_printer_add_with_ppd_file),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-delete",
                          G_CALLBACK (cph_mechanism_printer_delete),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-delete-option-default",
                          G_CALLBACK (cph_mechanism_printer_delete_option_default),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-rename",
                          G_CALLBACK (cph_mechanism_printer_class_rename),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-set-accept-jobs",
                          G_CALLBACK (cph_mechanism_printer_set_accept_jobs),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-set-default",
                          G_CALLBACK (cph_mechanism_printer_set_default),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-set-device",
                          G_CALLBACK (cph_mechanism_printer_set_device),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-set-enabled",
                          G_CALLBACK (cph_mechanism_printer_set_enabled),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-set-error-policy",
                          G_CALLBACK (cph_mechanism_printer_set_error_policy),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-set-info",
                          G_CALLBACK (cph_mechanism_printer_set_info),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-set-job-sheets",
                          G_CALLBACK (cph_mechanism_printer_set_job_sheets),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-set-location",
                          G_CALLBACK (cph_mechanism_printer_set_location),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-set-op-policy",
                          G_CALLBACK (cph_mechanism_printer_set_op_policy),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-set-shared",
                          G_CALLBACK (cph_mechanism_printer_set_shared),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-set-users-allowed",
                          G_CALLBACK (cph_mechanism_printer_set_users_allowed),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-printer-set-users-denied",
                          G_CALLBACK (cph_mechanism_printer_set_users_denied),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-server-get-settings",
                          G_CALLBACK (cph_mechanism_server_get_settings),
                          NULL);
        g_signal_connect (mechanism,
                          "handle-server-set-settings",
                          G_CALLBACK (cph_mechanism_server_set_settings),
                          NULL);
}
