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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <config.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gi18n.h>

#include <cups/cups.h>
#include <cups/http.h>
#include <cups/ipp.h>

#include "cups.h"

/*
     getPrinters
     getDests
     getClasses
     getPPDs
     getServerPPD
     getDocument
     getDevices
     getJobs
     getJobAttributes
 !   cancelJob
 !   cancelAllJobs
 !   authenticateJob
 !   setJobHoldUntil
 !   restartJob
     getFile
     putFile
~!+* addPrinter
~!+* setPrinterDevice
~!+* setPrinterInfo
~!+* setPrinterLocation
~!+* setPrinterShared
~!+* setPrinterJobSheets
~!+* setPrinterErrorPolicy
~!+* setPrinterOpPolicy
 !   setPrinterUsersAllowed
 !   setPrinterUsersDenied
~!+* addPrinterOptionDefault
~!+* deletePrinterOptionDefault
~!+* deletePrinter
     getPrinterAttributes
 !   addPrinterToClass
 !   deletePrinterFromClass
 !   deleteClass
     getDefault
~!+* setDefault
     getPPD
~!+* enablePrinter
~!+* disablePrinter
~!+* acceptJobs
~!+* rejectJobs
     printTestPage
 !   adminGetServerSettings
 !   adminSetServerSettings
     getSubscriptions
     createSubscription
     getNotifications
     cancelSubscription
     renewSubscription
     printFile
     printFiles
*/

typedef enum
{
        CPH_RESOURCE_ROOT,
        CPH_RESOURCE_ADMIN,
        CPH_RESOURCE_JOBS
} CphResource;

G_DEFINE_TYPE (CphCups, cph_cups, G_TYPE_OBJECT)

#define CPH_CUPS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), CPH_TYPE_CUPS, CphCupsPrivate))

struct CphCupsPrivate
{
        http_t       *connection;
        ipp_status_t  last_status;
};

static GObject *cph_cups_constructor (GType                  type,
                                      guint                  n_construct_properties,
                                      GObjectConstructParam *construct_properties);
static void     cph_cups_finalize    (GObject *object);


static void
cph_cups_class_init (CphCupsClass *klass)
{
        GObjectClass *object_class = G_OBJECT_CLASS (klass);

        object_class->constructor = cph_cups_constructor;
        object_class->finalize = cph_cups_finalize;

        g_type_class_add_private (klass, sizeof (CphCupsPrivate));
}

static GObject *
cph_cups_constructor (GType                  type,
                      guint                  n_construct_properties,
                      GObjectConstructParam *construct_properties)
{
        GObject *obj;
        CphCups *cups;

        obj = G_OBJECT_CLASS (cph_cups_parent_class)->constructor (
                                                type,
                                                n_construct_properties,
                                                construct_properties);

        cups = CPH_CUPS (obj);

        cups->priv->connection = httpConnectEncrypt (cupsServer (),
                                                     ippPort (),
                                                     cupsEncryption ());

        if (!cups->priv->connection) {
                g_critical ("Failed to connect to cupsd");
                g_object_unref (cups);
                return NULL;
        }

        return obj;
}

static void
cph_cups_init (CphCups *cups)
{
        cups->priv = CPH_CUPS_GET_PRIVATE (cups);

        cups->priv->connection = NULL;
        cups->priv->last_status = IPP_OK;
}

static void
cph_cups_finalize (GObject *object)
{
        CphCups *cups;

        g_return_if_fail (object != NULL);
        g_return_if_fail (CPH_IS_CUPS (object));

        cups = CPH_CUPS (object);

        if (cups->priv->connection)
                httpClose (cups->priv->connection);
        cups->priv->connection = NULL;

        G_OBJECT_CLASS (cph_cups_parent_class)->finalize (object);
}

CphCups *
cph_cups_new (void)
{
        return g_object_new (CPH_TYPE_CUPS, NULL);
}

/******************************************************
 * Validation
 ******************************************************/

static gboolean
_cph_cups_is_printer_name_valid (const char *name)
{
        int i;

        if (!name || name[0] == '\0')
                return FALSE;

        /* only printable characters, no space, no /, no # */
        for (i = 0; i < strlen (name); i++) {
                if (!g_ascii_isprint (name[i]))
                        return FALSE;
                if (g_ascii_isspace (name[i]))
                        return FALSE;
                if (name[i] == '/' || name[i] == '#')
                        return FALSE;
        }

        return TRUE;
}

/******************************************************
 * Helpers
 ******************************************************/

static void
_cph_cups_add_printer_uri (ipp_t      *request,
                           const char *name)
{
        char uri[HTTP_MAX_URI + 1];

        g_snprintf (uri, sizeof (uri),
                    "ipp://localhost/printers/%s", name);
        ippAddString (request, IPP_TAG_OPERATION, IPP_TAG_URI,
		      "printer-uri", NULL, uri);
}

static void
_cph_cups_add_class_uri (ipp_t      *request,
                         const char *name)
{
        char uri[HTTP_MAX_URI + 1];

        g_snprintf (uri, sizeof (uri),
                    "ipp://localhost/classes/%s", name);
        ippAddString (request, IPP_TAG_OPERATION, IPP_TAG_URI,
		      "printer-uri", NULL, uri);
}

static void
_cph_cups_set_error_from_reply (CphCups *cups,
                                ipp_t   *reply)
{
        if (reply)
                cups->priv->last_status = reply->request.status.status_code;
        else
                cups->priv->last_status = cupsLastError ();
}

static gboolean
_cph_cups_handle_reply (CphCups *cups,
                        ipp_t   *reply)
{
        gboolean retval;

        if (!reply || reply->request.status.status_code > IPP_OK_CONFLICT) {
                retval = FALSE;
                _cph_cups_set_error_from_reply (cups, reply);
        } else {
                retval = TRUE;
                cups->priv->last_status = IPP_OK;
        }

        if (reply)
                ippDelete (reply);

        return retval;
}

static const char *
_cph_cups_get_resource (CphResource resource)
{
        switch (resource)
        {
                case CPH_RESOURCE_ROOT:
                        return "/";
                case CPH_RESOURCE_ADMIN:
                        return "/admin/";
                case CPH_RESOURCE_JOBS:
                        return "/jobs/";
                default:
                        /* that's a fallback -- we don't use
                         * g_assert_not_reached() to avoir crashing. */
                        g_critical ("Asking for a resource with no match.");
                        return "/";
        }
}

static gboolean
_cph_cups_send_request (CphCups     *cups,
                        ipp_t       *request,
                        CphResource  resource)
{
        ipp_t      *reply;
        const char *resource_char;

        resource_char = _cph_cups_get_resource (resource);
        reply = cupsDoRequest (cups->priv->connection, request, resource_char);

        return _cph_cups_handle_reply (cups, reply);
}

static gboolean
_cph_cups_post_request (CphCups     *cups,
                        ipp_t       *request,
                        const char  *file,
                        CphResource  resource)
{
        ipp_t *reply;
        const char *resource_char;

        resource_char = _cph_cups_get_resource (resource);
        reply = cupsDoFileRequest (cups->priv->connection, request,
                                   resource_char, file);

        return _cph_cups_handle_reply (cups, reply);
}

static gboolean
_cph_cups_send_new_simple_request (CphCups     *cups,
                                   ipp_op_t     op,
                                   const char  *printer_name,
                                   CphResource  resource)
{
        ipp_t *request;

        if (!_cph_cups_is_printer_name_valid (printer_name))
                /* FIXME: set status */
                return FALSE;

        request = ippNewRequest (op);
        _cph_cups_add_printer_uri (request, printer_name);

        return _cph_cups_send_request (cups, request, resource);
}

static gboolean
_cph_cups_send_new_printer_class_request (CphCups     *cups,
                                          const char  *printer_name,
                                          ipp_tag_t    group,
                                          ipp_tag_t    type,
                                          const char  *name,
                                          const char  *value)
{
        ipp_t *request;

        request = ippNewRequest (CUPS_ADD_MODIFY_PRINTER);
        _cph_cups_add_printer_uri (request, printer_name);
        ippAddString (request, group, type, name, NULL, value);

        if (_cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN))
                return TRUE;

        /* it failed, maybe it was a class? */
        if (cups->priv->last_status != IPP_NOT_POSSIBLE)
                return FALSE;

        request = ippNewRequest (CUPS_ADD_MODIFY_CLASS);
        _cph_cups_add_class_uri (request, printer_name);
        ippAddString (request, group, type, name, NULL, value);

        return _cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN);
}

/******************************************************
 * Now, the real methods
 ******************************************************/

const char *
cph_cups_last_status_to_string (CphCups *cups)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), "");

        return ippErrorString (cups->priv->last_status);
}

gboolean
cph_cups_printer_add (CphCups    *cups,
                      const char *printer_name,
                      const char *printer_uri,
                      const char *ppd_file,
                      const char *info,
                      const char *location)
{
        ipp_t *request;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        /* FIXME check arguments are fine */

        request = ippNewRequest (CUPS_ADD_MODIFY_PRINTER);
        _cph_cups_add_printer_uri (request, printer_name);

        ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                      "printer-name", NULL, printer_name);
        ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_URI,
                      "device-uri", NULL, printer_uri);
        ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                      "ppd-name", NULL, ppd_file);

        if (info) {
                ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_TEXT,
                              "printer-info", NULL, info);
        }
        if (location) {
                ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_TEXT,
                              "printer-location", NULL, location);
        }

        return _cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN);
}

gboolean
cph_cups_printer_add_with_ppd_file (CphCups    *cups,
                                    const char *printer_name,
                                    const char *printer_uri,
                                    const char *ppd_filename,
                                    const char *info,
                                    const char *location)
{
        ipp_t *request;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        /* FIXME check arguments are fine */

        request = ippNewRequest (CUPS_ADD_MODIFY_PRINTER);
        _cph_cups_add_printer_uri (request, printer_name);

        ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                      "printer-name", NULL, printer_name);
        ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_URI,
                      "device-uri", NULL, printer_uri);

        if (info) {
                ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_TEXT,
                              "printer-info", NULL, info);
        }
        if (location) {
                ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_TEXT,
                              "printer-location", NULL, location);
        }

        return _cph_cups_post_request (cups, request, ppd_filename,
                                       CPH_RESOURCE_ADMIN);
}

gboolean
cph_cups_printer_delete (CphCups    *cups,
                         const char *printer_name)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        return _cph_cups_send_new_simple_request (cups, CUPS_DELETE_PRINTER,
                                                  printer_name,
                                                  CPH_RESOURCE_ADMIN);
}

gboolean
cph_cups_printer_set_default (CphCups    *cups,
                              const char *printer_name)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        return _cph_cups_send_new_simple_request (cups, CUPS_SET_DEFAULT,
                                                  printer_name,
                                                  CPH_RESOURCE_ADMIN);
}

gboolean
cph_cups_printer_set_enabled (CphCups    *cups,
                              const char *printer_name,
                              gboolean    enabled)
{
        ipp_op_t op;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        op = enabled ? IPP_RESUME_PRINTER : IPP_PAUSE_PRINTER;

        return _cph_cups_send_new_simple_request (cups, op, printer_name,
                                                  CPH_RESOURCE_ADMIN);
}

gboolean
cph_cups_printer_set_uri (CphCups    *cups,
                          const char *printer_name,
                          const char *printer_uri)
{
        ipp_t *request;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        /* FIXME check arguments are fine */

        request = ippNewRequest (CUPS_ADD_MODIFY_PRINTER);
        _cph_cups_add_printer_uri (request, printer_name);

        ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_URI,
                      "device-uri", NULL, printer_uri);

        return _cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN);
}

/* reason must be NULL if accept is TRUE */
gboolean
cph_cups_printer_set_accept_jobs (CphCups    *cups,
                                  const char *printer_name,
                                  gboolean    accept,
                                  const char *reason)
{
        ipp_t *request;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);
        g_return_val_if_fail (!accept || reason == NULL, FALSE);

        /* FIXME check arguments are fine */

        if (accept)
                return _cph_cups_send_new_simple_request (cups,
                                                          CUPS_ACCEPT_JOBS,
                                                          printer_name,
                                                          CPH_RESOURCE_ADMIN);

        /* !accept */
        request = ippNewRequest (CUPS_REJECT_JOBS);
        _cph_cups_add_printer_uri (request, printer_name);

        if (reason)
                ippAddString (request, IPP_TAG_OPERATION, IPP_TAG_TEXT,
                              "printer-state-message", NULL, reason);

        return _cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN);
}

/* Functions that can work on printer and class */

gboolean
cph_cups_printer_class_set_info (CphCups    *cups,
                                 const char *printer_name,
                                 const char *info)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        /* FIXME check arguments are fine */

        return _cph_cups_send_new_printer_class_request (cups, printer_name,
                                                         IPP_TAG_PRINTER,
                                                         IPP_TAG_TEXT,
                                                         "printer-info",
                                                         info);
}

gboolean
cph_cups_printer_class_set_location (CphCups    *cups,
                                     const char *printer_name,
                                     const char *location)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        /* FIXME check arguments are fine */

        return _cph_cups_send_new_printer_class_request (cups, printer_name,
                                                         IPP_TAG_PRINTER,
                                                         IPP_TAG_TEXT,
                                                         "printer-location",
                                                         location);
}

gboolean
cph_cups_printer_class_set_shared (CphCups    *cups,
                                   const char *printer_name,
                                   gboolean    shared)
{
        ipp_t *request;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        /* FIXME check arguments are fine */

        request = ippNewRequest (CUPS_ADD_MODIFY_PRINTER);
        _cph_cups_add_printer_uri (request, printer_name);
        ippAddBoolean (request, IPP_TAG_OPERATION,
                       "printer-is-shared", shared ? 1 : 0);

        if (_cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN))
                return TRUE;

        /* it failed, maybe it was a class? */
        if (cups->priv->last_status != IPP_NOT_POSSIBLE)
                return FALSE;

        request = ippNewRequest (CUPS_ADD_MODIFY_CLASS);
        _cph_cups_add_class_uri (request, printer_name);
        ippAddBoolean (request, IPP_TAG_OPERATION,
                       "printer-is-shared", shared ? 1 : 0);

        return _cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN);
}

gboolean
cph_cups_printer_class_set_job_sheets (CphCups    *cups,
                                       const char *printer_name,
                                       const char *start,
                                       const char *end)
{
        ipp_t *request;
        const char * const values[2] = { start, end };

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        /* FIXME check arguments are fine */

        request = ippNewRequest (CUPS_ADD_MODIFY_PRINTER);
        _cph_cups_add_printer_uri (request, printer_name);
        ippAddStrings (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
		       "job-sheets-default", 2, NULL, values);

        if (_cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN))
                return TRUE;

        /* it failed, maybe it was a class? */
        if (cups->priv->last_status != IPP_NOT_POSSIBLE)
                return FALSE;

        request = ippNewRequest (CUPS_ADD_MODIFY_CLASS);
        _cph_cups_add_class_uri (request, printer_name);
        ippAddStrings (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
		       "job-sheets-default", 2, NULL, values);

        return _cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN);
}

gboolean
cph_cups_printer_class_set_error_policy (CphCups    *cups,
                                         const char *printer_name,
                                         const char *policy)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        /* FIXME check arguments are fine */

        return _cph_cups_send_new_printer_class_request (cups, printer_name,
                                                         IPP_TAG_PRINTER,
                                                         IPP_TAG_NAME,
                                                         "printer-error-policy",
                                                         policy);
}

gboolean
cph_cups_printer_class_set_op_policy (CphCups    *cups,
                                      const char *printer_name,
                                      const char *policy)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        /* FIXME check arguments are fine */

        return _cph_cups_send_new_printer_class_request (cups, printer_name,
                                                         IPP_TAG_PRINTER,
                                                         IPP_TAG_NAME,
                                                         "printer-op-policy",
                                                         policy);
}

/* set first_value to NULL to delete the default */
gboolean
cph_cups_printer_class_set_option_default (CphCups    *cups,
                                           const char *printer_name,
                                           const char *option,
                                           const char *first_value,
                                           ...)
{
        char            *option_name;
        const char      *value;
        va_list          var_args;
        GSList          *values;
        int              len;
        ipp_t           *request;
        ipp_attribute_t *attr;
        gboolean         retval;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        /* FIXME check arguments are fine */

        option_name = g_strdup_printf ("%s-default", option);

        /* delete default value for option */
        if (!first_value) {
                retval = _cph_cups_send_new_printer_class_request (
                                                        cups,
                                                        printer_name,
                                                        IPP_TAG_PRINTER,
                                                        IPP_TAG_DELETEATTR,
                                                        option_name,
                                                        NULL);
                g_free (option_name);

                return retval;
        }

        /* set default vaule for option */

        values = NULL;
        len = 0;
        value = first_value;
        va_start (var_args, first_value);

        while (value) {
                /* cast to remove warning */
                values = g_slist_prepend (values, (char *) value);
                len++;
                value = va_arg (var_args, char *);
        }

        va_end (var_args);

        values = g_slist_reverse (values);

        request = ippNewRequest (CUPS_ADD_MODIFY_PRINTER);
        _cph_cups_add_printer_uri (request, printer_name);

        if (len == 1)
                ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                              option_name, NULL, first_value);
        else {
                GSList *value_l;
                int     i;

                attr = ippAddStrings (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                                      option_name, len, NULL, NULL);

                i = 0;
                for (value_l = values; value_l; value_l = value_l->next) {
                        attr->values[i].string.text = g_strdup (value_l->data);
                        i++;
                }
        }

        if (_cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN)) {
                retval = TRUE;
                goto out;
        }

        /* it failed, maybe it was a class? */
        if (cups->priv->last_status != IPP_NOT_POSSIBLE) {
                retval = FALSE;
                goto out;
        }

        request = ippNewRequest (CUPS_ADD_MODIFY_CLASS);
        _cph_cups_add_class_uri (request, printer_name);

        if (len == 1)
                ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                              option_name, NULL, first_value);
        else {
                GSList *value_l;
                int     i;

                attr = ippAddStrings (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                                      option_name, len, NULL, NULL);

                i = 0;
                for (value_l = values; value_l; value_l = value_l->next) {
                        attr->values[i].string.text = g_strdup (value_l->data);
                        i++;
                }
        }

        retval = _cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN);

out:
        g_free (option_name);
        g_slist_free (values);

        return retval;
}
