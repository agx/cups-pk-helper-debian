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

#include <cups/adminutil.h>
#include <cups/cups.h>
#include <cups/http.h>
#include <cups/ipp.h>

#include "cups.h"

#define MAX_RECONNECT_ATTEMPTS 100
#define RECONNECT_DELAY        100000

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
~!+* getFile
~!+* putFile
~!+* addPrinter
~!+* setPrinterDevice
~!+* setPrinterInfo
~!+* setPrinterLocation
~!+* setPrinterShared
~!+* setPrinterJobSheets
~!+* setPrinterErrorPolicy
~!+* setPrinterOpPolicy
~!+* setPrinterUsersAllowed
~!+* setPrinterUsersDenied
~!+* addPrinterOptionDefault
~!+* deletePrinterOptionDefault
~!+* deletePrinter
     getPrinterAttributes
~!+* addPrinterToClass
~!+* deletePrinterFromClass
~!+* deleteClass
     getDefault
~!+* setDefault
     getPPD
~!+* enablePrinter
~!+* disablePrinter
~!+* acceptJobs
~!+* rejectJobs
     printTestPage
~!+* adminGetServerSettings
~!+* adminSetServerSettings
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
        char         *internal_status;
};

static GObject *cph_cups_constructor (GType                  type,
                                      guint                  n_construct_properties,
                                      GObjectConstructParam *construct_properties);
static void     cph_cups_finalize    (GObject *object);

static void     _cph_cups_set_internal_status (CphCups    *cups,
                                               const char *status);


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
        cups->priv->internal_status = NULL;
}

gboolean
cph_cups_reconnect (CphCups *cups)
{
        int  return_value = -1;
        int  i;

        for (i = 0; i < MAX_RECONNECT_ATTEMPTS; i++) {
                return_value = httpReconnect (cups->priv->connection);
                if (return_value == 0)
                        break;
                g_usleep (RECONNECT_DELAY);
        }

        if (return_value == 0)
                return TRUE;
        else
                return FALSE;
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

        if (cups->priv->internal_status)
                g_free (cups->priv->internal_status);
        cups->priv->internal_status = NULL;

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
_cph_cups_is_string_printable (const char *str,
                               gboolean    check_for_null)
{
        int i;

        /* no NULL string */
        if (!str)
                return !check_for_null;

        /* only printable characters */
        for (i = 0; i < strlen (str); i++) {
                if (!g_ascii_isprint (str[i]))
                        return FALSE;
        }

        return TRUE;
}

#define _CPH_CUPS_IS_VALID(name, name_for_str, check_for_null)                \
static gboolean                                                               \
_cph_cups_is_##name##_valid (CphCups    *cups,                                \
                             const char *str)                                 \
{                                                                             \
        char *error;                                                          \
                                                                              \
        if (_cph_cups_is_string_printable (str, check_for_null))              \
                return TRUE;                                                  \
                                                                              \
        error = g_strdup_printf ("\"%s\" is not a valid %s.",                 \
                                 str, name_for_str);                          \
        _cph_cups_set_internal_status (cups, error);                          \
        g_free (error);                                                       \
                                                                              \
        return FALSE;                                                         \
}

static gboolean
_cph_cups_is_printer_name_valid_internal (const char *name)
{
        int i;

        /* no empty string */
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

static gboolean
_cph_cups_is_printer_name_valid (CphCups    *cups,
                                 const char *name)
{
        char *error;

        if (_cph_cups_is_printer_name_valid_internal (name))
                return TRUE;

        error = g_strdup_printf ("\"%s\" is not a valid printer name.", name);
        _cph_cups_set_internal_status (cups, error);
        g_free (error);

        return FALSE;
}

/* class is similar to printer in terms of validity checks */
static gboolean
_cph_cups_is_class_name_valid (CphCups    *cups,
                               const char *name)
{
        char *error;

        if (_cph_cups_is_printer_name_valid_internal (name))
                return TRUE;

        error = g_strdup_printf ("\"%s\" is not a valid class name.", name);
        _cph_cups_set_internal_status (cups, error);
        g_free (error);

        return FALSE;
}

/* This is some text, but we could potentially do more checks. We don't do them
 * because cups will already do them.
 *   + for the URI, we could check that the scheme is supported and that the
 *     URI is a valid URI.
 *   + for the PPD, we could check that the PPD exists in the cups database.
 *     Another reason to not do this ourselves is that it's really slow to
 *     fetch all the PPDs.
 *   + for the PPD filename, we could check that the file exists and is a
 *     regular file (no socket, block device, etc.).
 *   + for the job sheet, we could check that the value is in the
 *     job-sheets-supported attribute.
 *   + for the policies, we could check that the value is in the
 *     printer-error-policy-supported and printer-op-policy-supported
 *     attributes.
 */
_CPH_CUPS_IS_VALID (printer_uri, "printer URI", TRUE)
_CPH_CUPS_IS_VALID (ppd, "PPD", TRUE)
_CPH_CUPS_IS_VALID (ppd_filename, "PPD file", FALSE)
_CPH_CUPS_IS_VALID (job_sheet, "job sheet", FALSE)
_CPH_CUPS_IS_VALID (error_policy, "error policy", FALSE)
_CPH_CUPS_IS_VALID (op_policy, "op policy", FALSE)
_CPH_CUPS_IS_VALID (job_hold_until, "job hold until", FALSE)

/* Check for users. Those are some printable strings, which souldn't be NULL.
 * They should also not be empty, but it appears that it's possible to carry
 * an empty "DenyUser" in the cups configuration, so we should handle (by
 * ignoring them) empty usernames.
 * We could also check that the username exists on the system, but cups will do
 * it.
 */
_CPH_CUPS_IS_VALID (user, "user", TRUE)

/* Check for options & values. Those are for sure some printable strings, but
 * can we do more? Let's see:
 *   + an option seems to be, empirically, composed of alphanumerical
 *     characters, and dashes. However, this is not something we can be sure of
 *     and so we'll let cups handle that.
 *   + a value can be some text, and we don't know much more.
 */
_CPH_CUPS_IS_VALID (option, "option", TRUE)
_CPH_CUPS_IS_VALID (option_value, "value for option", FALSE)

/* This is really just some text */
_CPH_CUPS_IS_VALID (info, "description", FALSE)
_CPH_CUPS_IS_VALID (location, "location", FALSE)
_CPH_CUPS_IS_VALID (reject_jobs_reason, "reason", FALSE)

/* For put/get file: this is some text, but we could potentially do more
 * checks. We don't do them because cups will already do them.
 *   + for the resource, we could check that it starts with a /, for example.
 *   + for the filename, in the put case, we could check that the file exists
 *     and is a regular file (no socket, block device, etc.).
 */
_CPH_CUPS_IS_VALID (resource, "resource", TRUE)
_CPH_CUPS_IS_VALID (filename, "filename", TRUE)

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
_cph_cups_add_job_uri (ipp_t      *request,
                       int         job_id)
{
        char uri[HTTP_MAX_URI + 1];

        g_snprintf (uri, sizeof (uri),
                    "ipp://localhost/jobs/%d", job_id);
        ippAddString (request, IPP_TAG_OPERATION, IPP_TAG_URI,
                      "job-uri", NULL, uri);
}

static void
_cph_cups_set_internal_status (CphCups    *cups,
                               const char *status)
{
        if (cups->priv->internal_status)
                g_free (cups->priv->internal_status);

        if (status)
                cups->priv->internal_status = g_strdup (status);
        else
                cups->priv->internal_status = NULL;
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

        /* reset the internal status: we'll use the cups status */
        _cph_cups_set_internal_status (cups, NULL);

        if (!reply || reply->request.status.status_code > IPP_OK_CONFLICT) {
                retval = FALSE;
                _cph_cups_set_error_from_reply (cups, reply);
#if 0
                /* Useful when debugging: */
                g_print ("%s\n", cupsLastErrorString ());
#endif
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
        switch (resource) {
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

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;

        request = ippNewRequest (op);
        _cph_cups_add_printer_uri (request, printer_name);

        return _cph_cups_send_request (cups, request, resource);
}

static gboolean
_cph_cups_send_new_simple_class_request (CphCups     *cups,
                                         ipp_op_t     op,
                                         const char  *class_name,
                                         CphResource  resource)
{
        ipp_t *request;

        if (!_cph_cups_is_class_name_valid (cups, class_name))
                return FALSE;

        request = ippNewRequest (op);
        _cph_cups_add_class_uri (request, class_name);

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

static gboolean
_cph_cups_send_new_simple_job_request (CphCups     *cups,
                                       ipp_op_t     op,
                                       int          job_id,
                                       const char  *user_name,
                                       CphResource  resource)
{
        ipp_t *request;

        request = ippNewRequest (op);

        if (user_name != NULL)
                ippAddString (request, IPP_TAG_OPERATION, IPP_TAG_NAME,
                              "requesting-user-name", NULL, user_name);

        _cph_cups_add_job_uri (request, job_id);

        return _cph_cups_send_request (cups, request, resource);
}

static gboolean
_cph_cups_send_new_job_attributes_request (CphCups     *cups,
                                           int          job_id,
                                           const char  *name,
                                           const char  *value,
                                           const char  *user_name,
                                           CphResource  resource)
{
        cups_option_t *options = NULL;
        ipp_t         *request;
        int            num_options = 0;

        request = ippNewRequest (IPP_SET_JOB_ATTRIBUTES);
        _cph_cups_add_job_uri (request, job_id);

        if (user_name != NULL)
                ippAddString (request, IPP_TAG_OPERATION, IPP_TAG_NAME,
                              "requesting-user-name", NULL, user_name);

        num_options = cupsAddOption (name, value,
                                     num_options, &options);
        cupsEncodeOptions (request, num_options, options);

        return _cph_cups_send_request (cups, request, resource);
}

static int
_cph_cups_class_has_printer (CphCups     *cups,
                             const char  *class_name,
                             const char  *printer_name,
                             ipp_t      **reply)
{
        gboolean         retval;
        const char      *resource_char;
        ipp_t           *request;
        ipp_t           *internal_reply;
        ipp_attribute_t *printer_names;
        int              i;

        retval = -1;

        if (reply)
                *reply = NULL;

        request = ippNewRequest (IPP_GET_PRINTER_ATTRIBUTES);
        _cph_cups_add_class_uri (request, class_name);
        resource_char = _cph_cups_get_resource (CPH_RESOURCE_ROOT);
        internal_reply = cupsDoRequest (cups->priv->connection,
                                        request, resource_char);

        if (!internal_reply)
                return -1;

        printer_names = ippFindAttribute (internal_reply,
                                          "member-names", IPP_TAG_NAME);

        if (!printer_names)
                goto out;

        for (i = 0; i < printer_names->num_values; i++) {
                if (!g_ascii_strcasecmp (printer_names->values[i].string.text,
                                         printer_name)) {
                        retval = i;
                        break;
                }
        }

out:
        if (reply)
                *reply = internal_reply;
        else
                ippDelete (internal_reply);

        return retval;
}

static gboolean
_cph_cups_printer_class_set_users (CphCups     *cups,
                                   const char  *printer_name,
                                   const char **users,
                                   const char  *request_name,
                                   const char  *default_value)
{
        int              real_len;
        int              len;
        ipp_t           *request;
        ipp_attribute_t *attr;

        real_len = 0;
        len = 0;
        if (users) {
                while (users[real_len] != NULL) {
                        if (users[real_len][0] != '\0')
                                len++;
                        real_len++;
                }
        }

        request = ippNewRequest (CUPS_ADD_MODIFY_PRINTER);
        _cph_cups_add_printer_uri (request, printer_name);
        attr = ippAddStrings (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                              request_name, len ? len : 1, NULL, NULL);
        if (len == 0)
                attr->values[0].string.text = g_strdup (default_value);
        else {
                int i, j;
                for (i = 0, j = 0; i < real_len && j < len; i++) {
                        /* we skip empty user names */
                        if (users[i][0] == '\0')
                                continue;

                        attr->values[j].string.text = g_strdup (users[i]);
                        j++;
                }
        }

        if (_cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN))
                return TRUE;

        /* it failed, maybe it was a class? */
        if (cups->priv->last_status != IPP_NOT_POSSIBLE)
                return FALSE;

        request = ippNewRequest (CUPS_ADD_MODIFY_CLASS);
        _cph_cups_add_class_uri (request, printer_name);
        attr = ippAddStrings (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                              request_name, len ? len : 1, NULL, NULL);
        if (len == 0)
                attr->values[0].string.text = g_strdup (default_value);
        else {
                int i, j;
                for (i = 0, j = 0; i < real_len && j < len; i++) {
                        /* we skip empty user names */
                        if (users[i][0] == '\0')
                                continue;

                        attr->values[j].string.text = g_strdup (users[i]);
                        j++;
                }
        }

        return _cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN);
}

/******************************************************
 * Now, the real methods
 ******************************************************/

const char *
cph_cups_last_status_to_string (CphCups *cups)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), "");

        if (cups->priv->internal_status)
                return cups->priv->internal_status;
        else
                return ippErrorString (cups->priv->last_status);
}

gboolean
cph_cups_is_class (CphCups    *cups,
                   const char *name)
{
        const char * const  attrs[1] = { "member-names" };
        ipp_t              *request;
        const char         *resource_char;
        ipp_t              *reply;
        gboolean            retval;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        if (!_cph_cups_is_class_name_valid (cups, name))
                return FALSE;

        request = ippNewRequest (IPP_GET_PRINTER_ATTRIBUTES);
        _cph_cups_add_class_uri (request, name);
        ippAddStrings (request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD,
                       "requested-attributes", 1, NULL, attrs);

        resource_char = _cph_cups_get_resource (CPH_RESOURCE_ROOT);
        reply = cupsDoRequest (cups->priv->connection,
                               request, resource_char);

        if (!reply)
                return FALSE;

        /* Note: we need to look if the attribute is there, since we get a
         * reply if the name is a printer name and not a class name. The
         * attribute is the only way to distinguish the two cases. */
        retval = ippFindAttribute (reply, attrs[0], IPP_TAG_NAME) != NULL;

        if (reply)
                ippDelete (reply);

        return retval;
}

char *
cph_cups_printer_get_uri (CphCups    *cups,
                          const char *printer_name)
{
        const char * const  attrs[1] = { "device-uri" };
        ipp_t              *request;
        const char         *resource_char;
        ipp_t              *reply;
        ipp_attribute_t    *attr;
        char               *uri;

        g_return_val_if_fail (CPH_IS_CUPS (cups), NULL);

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return NULL;

        request = ippNewRequest (IPP_GET_PRINTER_ATTRIBUTES);
        _cph_cups_add_printer_uri (request, printer_name);
        ippAddStrings (request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD,
                       "requested-attributes", 1, NULL, attrs);

        resource_char = _cph_cups_get_resource (CPH_RESOURCE_ROOT);
        reply = cupsDoRequest (cups->priv->connection,
                               request, resource_char);

        if (!reply)
                return NULL;

        uri = NULL;

        for (attr = reply->attrs; attr; attr = attr->next) {
                while (attr && attr->group_tag != IPP_TAG_PRINTER)
                        attr = attr->next;

                if (attr == NULL)
                        break;

                while (attr && attr->group_tag == IPP_TAG_PRINTER) {
                        if (attr->name &&
                            strcmp (attr->name, attrs[0]) == 0 &&
                            attr->value_tag == IPP_TAG_URI) {
                                uri = g_strdup (attr->values[0].string.text);
                                break;
                        }

                        attr = attr->next;
                }

                if (uri != NULL || attr == NULL)
                        break;
        }

        ippDelete (reply);

        return uri;
}

gboolean
cph_cups_is_printer_local (CphCups    *cups,
                           const char *printer_name)
{
        char     *uri;
        gboolean  retval;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;

        uri = cph_cups_printer_get_uri (cups, printer_name);

        /* This can happen, especially since the printer might not exist, or if
         * it's actually a class and not a printer. In all cases, it should be
         * considered local. */
        if (!uri)
                return TRUE;

        retval = cph_cups_is_printer_uri_local (uri);

        g_free (uri);

        return retval;
}

gboolean
cph_cups_file_get (CphCups    *cups,
                   const char *resource,
                   const char *filename)
{
        struct stat file_stat;
        uid_t       uid;
        gid_t       gid;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        if (!_cph_cups_is_resource_valid (cups, resource))
                return FALSE;
        if (!_cph_cups_is_filename_valid (cups, filename))
                return FALSE;

        stat (filename, &file_stat);
        uid = file_stat.st_uid;
        gid = file_stat.st_gid;

        /* reset the internal status: we'll use the cups status */
        _cph_cups_set_internal_status (cups, NULL);

        cups->priv->last_status = cupsGetFile (cups->priv->connection,
                                               resource, filename);

        if (cups->priv->last_status != HTTP_OK) {
                if (cph_cups_reconnect (cups)) {
                        int fd;

                        /* if cupsGetFile fail then filename is erased */
                        fd = open (filename, O_CREAT, S_IRUSR | S_IWUSR);
                        close (fd);
                        chown (filename, uid, gid);

                        _cph_cups_set_internal_status (cups, NULL);

                        cups->priv->last_status = cupsGetFile (cups->priv->connection,
                                                               resource,
                                                               filename);
                }
        }

        return cups->priv->last_status == HTTP_OK;
}

gboolean
cph_cups_file_put (CphCups    *cups,
                   const char *resource,
                   const char *filename)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        if (!_cph_cups_is_resource_valid (cups, resource))
                return FALSE;
        if (!_cph_cups_is_filename_valid (cups, filename))
                return FALSE;

        /* reset the internal status: we'll use the cups status */
        _cph_cups_set_internal_status (cups, NULL);

        cups->priv->last_status = cupsPutFile (cups->priv->connection,
                                               resource, filename);

        /* CUPS is being restarted, so we need to reconnect */
        cph_cups_reconnect (cups);

        return (cups->priv->last_status == HTTP_OK ||
                cups->priv->last_status == HTTP_CREATED);
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

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;
        if (!_cph_cups_is_printer_uri_valid (cups, printer_uri))
                return FALSE;
        if (!_cph_cups_is_ppd_valid (cups, ppd_file))
                return FALSE;
        if (!_cph_cups_is_info_valid (cups, info))
                return FALSE;
        if (!_cph_cups_is_location_valid (cups, location))
                return FALSE;

        request = ippNewRequest (CUPS_ADD_MODIFY_PRINTER);
        _cph_cups_add_printer_uri (request, printer_name);

        ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                      "printer-name", NULL, printer_name);
        ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_URI,
                      "device-uri", NULL, printer_uri);
        ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                      "ppd-name", NULL, ppd_file);

        if (info && info[0] != '\0') {
                ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_TEXT,
                              "printer-info", NULL, info);
        }
        if (location && location[0] != '\0') {
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

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;
        if (!_cph_cups_is_printer_uri_valid (cups, printer_uri))
                return FALSE;
        if (!_cph_cups_is_ppd_filename_valid (cups, ppd_filename))
                return FALSE;
        if (!_cph_cups_is_info_valid (cups, info))
                return FALSE;
        if (!_cph_cups_is_location_valid (cups, location))
                return FALSE;

        request = ippNewRequest (CUPS_ADD_MODIFY_PRINTER);
        _cph_cups_add_printer_uri (request, printer_name);

        ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                      "printer-name", NULL, printer_name);

        /* In this specific case of ADD_MODIFY, the URI can be NULL/empty since
         * we provide a complete PPD. And cups fails if we pass an empty
         * string. */
        if (printer_uri && printer_uri[0] != '\0') {
                ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_URI,
                              "device-uri", NULL, printer_uri);
        }

        if (info && info[0] != '\0') {
                ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_TEXT,
                              "printer-info", NULL, info);
        }
        if (location && location[0] != '\0') {
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

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;
        if (!_cph_cups_is_printer_uri_valid (cups, printer_uri))
                return FALSE;

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

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;
        if (!_cph_cups_is_reject_jobs_reason_valid (cups, reason))
                return FALSE;

        if (accept)
                return _cph_cups_send_new_simple_request (cups,
                                                          CUPS_ACCEPT_JOBS,
                                                          printer_name,
                                                          CPH_RESOURCE_ADMIN);

        /* !accept */
        request = ippNewRequest (CUPS_REJECT_JOBS);
        _cph_cups_add_printer_uri (request, printer_name);

        if (reason && reason[0] == '\0')
                ippAddString (request, IPP_TAG_OPERATION, IPP_TAG_TEXT,
                              "printer-state-message", NULL, reason);

        return _cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN);
}

/* Functions that work on a class */

gboolean
cph_cups_class_add_printer (CphCups    *cups,
                            const char *class_name,
                            const char *printer_name)
{
        int              printer_index;
        ipp_t           *reply;
        ipp_t           *request;
        int              new_len;
        ipp_attribute_t *printer_uris;
        char             printer_uri[HTTP_MAX_URI + 1];
        ipp_attribute_t *attr;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        if (!_cph_cups_is_class_name_valid (cups, class_name))
                return FALSE;
        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;

        /* check that the printer is not already in the class */
        printer_index = _cph_cups_class_has_printer (cups,
                                                     class_name, printer_name,
                                                     &reply);
        if (printer_index >= 0) {
                char *error;

                if (reply)
                        ippDelete (reply);

                error = g_strdup_printf ("Printer %s is already in class %s.",
                                         printer_name, class_name);
                _cph_cups_set_internal_status (cups, error);
                g_free (error);

                return FALSE;
        }

        /* add the printer to the class */

        request = ippNewRequest (CUPS_ADD_CLASS);
        _cph_cups_add_class_uri (request, class_name);

        g_snprintf (printer_uri, sizeof (printer_uri),
                    "ipp://localhost/printers/%s", printer_name);

        /* new length: 1 + what we had before */
        new_len = 1;
        if (reply) {
                printer_uris = ippFindAttribute (reply,
                                                 "member-uris", IPP_TAG_URI);
                if (printer_uris)
                        new_len += printer_uris->num_values;
        } else
                printer_uris = NULL;

        attr = ippAddStrings (request, IPP_TAG_PRINTER, IPP_TAG_URI,
                              "member-uris", new_len,
                              NULL, NULL);
        if (printer_uris) {
                int i;

                for (i = 0; i < printer_uris->num_values; i++)
                        attr->values[i].string.text = g_strdup (printer_uris->values[i].string.text);
        }

        if (reply)
                ippDelete (reply);

        attr->values[new_len - 1].string.text = g_strdup (printer_uri);

        return _cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN);
}

gboolean
cph_cups_class_delete_printer (CphCups    *cups,
                               const char *class_name,
                               const char *printer_name)
{
        int              printer_index;
        ipp_t           *reply;
        ipp_t           *request;
        int              new_len;
        ipp_attribute_t *printer_uris;
        ipp_attribute_t *attr;
        int              i;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        if (!_cph_cups_is_class_name_valid (cups, class_name))
                return FALSE;
        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;

        /* check that the printer is in the class */
        printer_index = _cph_cups_class_has_printer (cups,
                                                     class_name, printer_name,
                                                     &reply);
        /* Note: the second condition (!reply) is only here for safety purpose.
         * When it's TRUE, the first one should be TRUE too */
        if (printer_index < 0 || !reply) {
                char *error;

                if (reply)
                        ippDelete (reply);

                error = g_strdup_printf ("Printer %s is not in class %s.",
                                         printer_name, class_name);
                _cph_cups_set_internal_status (cups, error);
                g_free (error);

                return FALSE;
        }

        /* remove the printer from the class */

        /* new length: -1 + what we had before */
        new_len = -1;
        printer_uris = ippFindAttribute (reply,
                                         "member-uris", IPP_TAG_URI);
        if (printer_uris)
                new_len += printer_uris->num_values;

        /* empty class: we delete it */
        if (new_len <= 0) {
                ippDelete (reply);
                return cph_cups_class_delete (cups, class_name);
        }

        /* printer_uris is not NULL and reply is not NULL */

        request = ippNewRequest (CUPS_ADD_CLASS);
        _cph_cups_add_class_uri (request, class_name);

        attr = ippAddStrings (request, IPP_TAG_PRINTER, IPP_TAG_URI,
                              "member-uris", new_len,
                              NULL, NULL);

        /* copy all printers from the class, except the one we remove */
        for (i = 0; i < printer_index; i++)
                attr->values[i].string.text = g_strdup (printer_uris->values[i].string.text);
        for (i = printer_index + 1; i < printer_uris->num_values; i++)
                attr->values[i].string.text = g_strdup (printer_uris->values[i].string.text);

        ippDelete (reply);

        return _cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN);
}

gboolean
cph_cups_class_delete (CphCups    *cups,
                       const char *class_name)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        return _cph_cups_send_new_simple_class_request (cups, CUPS_DELETE_CLASS,
                                                        class_name,
                                                        CPH_RESOURCE_ADMIN);
}

/* Functions that can work on printer and class */

gboolean
cph_cups_printer_class_set_info (CphCups    *cups,
                                 const char *printer_name,
                                 const char *info)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;
        if (!_cph_cups_is_info_valid (cups, info))
                return FALSE;

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

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;
        if (!_cph_cups_is_location_valid (cups, location))
                return FALSE;

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

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;

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

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;
        if (!_cph_cups_is_job_sheet_valid (cups, start))
                return FALSE;
        if (!_cph_cups_is_job_sheet_valid (cups, end))
                return FALSE;

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

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;
        if (!_cph_cups_is_error_policy_valid (cups, policy))
                return FALSE;

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

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;
        if (!_cph_cups_is_op_policy_valid (cups, policy))
                return FALSE;

        return _cph_cups_send_new_printer_class_request (cups, printer_name,
                                                         IPP_TAG_PRINTER,
                                                         IPP_TAG_NAME,
                                                         "printer-op-policy",
                                                         policy);
}

/* set users to NULL to allow all users */
gboolean
cph_cups_printer_class_set_users_allowed (CphCups     *cups,
                                          const char  *printer_name,
                                          const char **users)
{
        int len;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;
        /* check the validity of values, and get the length of the array at the
         * same time */
        len = 0;
        if (users) {
                while (users[len] != NULL) {
                        if (!_cph_cups_is_user_valid (cups, users[len]))
                                return FALSE;
                        len++;
                }
        }

        return _cph_cups_printer_class_set_users (cups, printer_name, users,
                                                  "requesting-user-name-allowed",
                                                  "all");
}

/* set users to NULL to deny no user */
gboolean
cph_cups_printer_class_set_users_denied (CphCups     *cups,
                                         const char  *printer_name,
                                         const char **users)
{
        int len;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;
        /* check the validity of values, and get the length of the array at the
         * same time */
        len = 0;
        if (users) {
                while (users[len] != NULL) {
                        if (!_cph_cups_is_user_valid (cups, users[len]))
                                return FALSE;
                        len++;
                }
        }

        return _cph_cups_printer_class_set_users (cups, printer_name, users,
                                                  "requesting-user-name-denied",
                                                  "none");
}

/* set values to NULL to delete the default */
gboolean
cph_cups_printer_class_set_option_default (CphCups     *cups,
                                           const char  *printer_name,
                                           const char  *option,
                                           const char **values)
{
        char            *option_name;
        int              len;
        ipp_t           *request;
        ipp_attribute_t *attr;
        gboolean         retval;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        if (!_cph_cups_is_printer_name_valid (cups, printer_name))
                return FALSE;
        if (!_cph_cups_is_option_valid (cups, option))
                return FALSE;
        /* check the validity of values, and get the length of the array at the
         * same time */
        len = 0;
        if (values) {
                while (values[len] != NULL) {
                        if (!_cph_cups_is_option_value_valid (cups,
                                                              values[len]))
                                return FALSE;
                        len++;
                }
        }

        option_name = g_strdup_printf ("%s-default", option);

        /* delete default value for option */
        if (len == 0) {
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

        /* set default value for option */

        request = ippNewRequest (CUPS_ADD_MODIFY_PRINTER);
        _cph_cups_add_printer_uri (request, printer_name);

        if (len == 1)
                ippAddString (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                              option_name, NULL, values[0]);
        else {
                int i;

                attr = ippAddStrings (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                                      option_name, len, NULL, NULL);

                for (i = 0; i < len; i++)
                        attr->values[i].string.text = g_strdup (values[i]);
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
                              option_name, NULL, values[0]);
        else {
                int i;

                attr = ippAddStrings (request, IPP_TAG_PRINTER, IPP_TAG_NAME,
                                      option_name, len, NULL, NULL);

                for (i = 0; i < len; i++)
                        attr->values[i].string.text = g_strdup (values[i]);
        }

        retval = _cph_cups_send_request (cups, request, CPH_RESOURCE_ADMIN);

out:
        g_free (option_name);

        return retval;
}

GHashTable *
cph_cups_server_get_settings (CphCups *cups)
{
        int            retval;
        GHashTable    *hash;
        cups_option_t *settings;
        int            num_settings, i;

        g_return_val_if_fail (CPH_IS_CUPS (cups), NULL);

        retval = cupsAdminGetServerSettings (cups->priv->connection,
                                             &num_settings, &settings);

        if (retval == 0) {
                char *error;

                error = g_strdup_printf ("Can not get server settings.");
                _cph_cups_set_internal_status (cups, error);
                g_free (error);

                return NULL;
        }

        hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                      g_free, g_free);

        for (i = 0; i < num_settings; i++)
                g_hash_table_replace (hash,
                                      g_strdup (settings[i].name),
                                      g_strdup (settings[i].value));

        cupsFreeOptions (num_settings, settings);

        return hash;
}

gboolean
cph_cups_server_set_settings (CphCups    *cups,
                              GHashTable *settings)
{
        int             retval;
        GHashTableIter  iter;
        /* key and value are strings, but we want to avoid compiler warnings */
        gpointer        key;
        gpointer        value;
        cups_option_t  *cups_settings;
        int             num_settings;

        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);
        g_return_val_if_fail (settings != NULL, FALSE);

        /* First pass to check the validity of the hashtable content */
        g_hash_table_iter_init (&iter, settings);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                if (!_cph_cups_is_option_valid (cups, key))
                        return FALSE;
                if (!_cph_cups_is_option_value_valid (cups, value))
                        return FALSE;
        }

        /* Second pass to actually set the settings */
        cups_settings = NULL;
        num_settings = 0;

        g_hash_table_iter_init (&iter, settings);
        while (g_hash_table_iter_next (&iter, &key, &value))
                num_settings = cupsAddOption (key, value,
                                              num_settings, &cups_settings);

        retval = cupsAdminSetServerSettings (cups->priv->connection,
                                             num_settings, cups_settings);

        /* CUPS is being restarted, so we need to reconnect */
        cph_cups_reconnect (cups);

        cupsFreeOptions (num_settings, cups_settings);

        if (retval == 0) {
                char *error;

                error = g_strdup_printf ("Can not set server settings.");
                _cph_cups_set_internal_status (cups, error);
                g_free (error);

                return FALSE;
        }

        return TRUE;
}

gboolean
cph_cups_job_cancel (CphCups    *cups,
                     int         job_id,
                     const char *user_name)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        return _cph_cups_send_new_simple_job_request (cups, IPP_CANCEL_JOB,
                                                      job_id,
                                                      user_name,
                                                      CPH_RESOURCE_ADMIN);
}

gboolean
cph_cups_job_restart (CphCups    *cups,
                      int         job_id,
                      const char *user_name)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        return _cph_cups_send_new_simple_job_request (cups, IPP_RESTART_JOB,
                                                      job_id,
                                                      user_name,
                                                      CPH_RESOURCE_ADMIN);
}

gboolean
cph_cups_job_set_hold_until (CphCups    *cups,
                             int         job_id,
                             const char *job_hold_until,
                             const char *user_name)
{
        g_return_val_if_fail (CPH_IS_CUPS (cups), FALSE);

        if (!_cph_cups_is_job_hold_until_valid (cups, job_hold_until))
                return FALSE;

        return _cph_cups_send_new_job_attributes_request (cups,
                                                          job_id,
                                                          "job-hold-until",
                                                          job_hold_until,
                                                          user_name,
                                                          CPH_RESOURCE_ADMIN);
}

CphJobStatus
cph_cups_job_get_status (CphCups    *cups,
                         int         job_id,
                         const char *user)
{
        CphJobStatus  status = CPH_JOB_STATUS_INVALID;
        cups_job_t   *jobs;
        int           num_jobs;
        int           i;

        g_return_val_if_fail (CPH_IS_CUPS (cups), CPH_JOB_STATUS_INVALID);

        num_jobs = cupsGetJobs2 (cups->priv->connection, &jobs, NULL, 0, 0);

        for (i = 0; i < num_jobs; i++) {
                if (jobs[i].id == job_id) {
                        if (user != NULL &&
                            g_strcmp0 (jobs[i].user, user) == 0)
                                status = CPH_JOB_STATUS_OWNED_BY_USER;
                        else
                                status = CPH_JOB_STATUS_NOT_OWNED_BY_USER;
                        break;
                }
        }

        cupsFreeJobs (num_jobs, jobs);

        return status;
}

/******************************************************
 * Non-object functions
 ******************************************************/

gboolean
cph_cups_is_printer_uri_local (const char *uri)
{
        char *lower_uri;

        g_return_val_if_fail (uri != NULL, FALSE);

        /* empty URI: can only be local... */
        if (uri[0] == '\0')
                return TRUE;

        lower_uri = g_ascii_strdown (uri, -1);

        /* clearly local stuff */
        if (g_str_has_prefix (lower_uri, "parallel:") ||
            g_str_has_prefix (lower_uri, "usb:") ||
            g_str_has_prefix (lower_uri, "hal:") ||
            /* beh is the backend error handler */
            g_str_has_prefix (lower_uri, "beh:") ||
            g_str_has_prefix (lower_uri, "scsi:") ||
            g_str_has_prefix (lower_uri, "serial:") ||
            g_str_has_prefix (lower_uri, "file:") ||
            g_str_has_prefix (lower_uri, "pipe:")) {
                g_free (lower_uri);
                return TRUE;
        }

        /* clearly remote stuff */
        if (g_str_has_prefix (lower_uri, "socket:") ||
            g_str_has_prefix (lower_uri, "ipp:") ||
            g_str_has_prefix (lower_uri, "http:") ||
            g_str_has_prefix (lower_uri, "lpd:") ||
            g_str_has_prefix (lower_uri, "smb:") ||
            g_str_has_prefix (lower_uri, "novell:")) {
                g_free (lower_uri);
                return FALSE;
        }

        /* hplip can be both, I think. Let's just check if we have an ip
         * argument in the URI */
        if (g_str_has_prefix (lower_uri, "hp:") ||
            g_str_has_prefix (lower_uri, "hpfax:")) {
                char *buf;

                buf = strchr (lower_uri, '?');

                while (buf) {
                        buf++;
                        if (g_str_has_prefix (buf, "ip="))
                                break;
                        buf = strchr (buf, '&');
                }

                g_free (lower_uri);
                return buf == NULL;
        }

        g_free (lower_uri);

        /* we don't know, so we assume it's not local */
        return FALSE;
}
