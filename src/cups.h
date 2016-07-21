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

#ifndef CPH_CUPS_H
#define CPH_CUPS_H

#include <glib-object.h>

G_BEGIN_DECLS

#define CPH_TYPE_CUPS         (cph_cups_get_type ())
#define CPH_CUPS(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), CPH_TYPE_CUPS, CphCups))
#define CPH_CUPS_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), CPH_TYPE_CUPS, CphCupsClass))
#define CPH_IS_CUPS(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), CPH_TYPE_CUPS))
#define CPH_IS_CUPS_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), CPH_TYPE_CUPS))
#define CPH_CUPS_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), CPH_TYPE_CUPS, CphCupsClass))

typedef struct CphCupsPrivate CphCupsPrivate;

typedef struct
{
        GObject         parent;
        CphCupsPrivate *priv;
} CphCups;

typedef struct
{
        GObjectClass parent_class;
} CphCupsClass;

typedef enum
{
        CPH_JOB_STATUS_INVALID,
        CPH_JOB_STATUS_OWNED_BY_USER,
        CPH_JOB_STATUS_NOT_OWNED_BY_USER
} CphJobStatus;

GType     cph_cups_get_type    (void);

CphCups  *cph_cups_new         (void);

const char *cph_cups_last_status_to_string (CphCups *cups);

gboolean cph_cups_is_class (CphCups    *cups,
                            const char *name);

char *cph_cups_printer_get_uri (CphCups    *cups,
                                const char *printer_name);

gboolean cph_cups_is_printer_local (CphCups    *cups,
                                    const char *printer_name);

gboolean cph_cups_file_get (CphCups      *cups,
                            const char   *resource,
                            const char   *filename,
                            unsigned int  sender_uid);

gboolean cph_cups_file_put (CphCups      *cups,
                            const char   *resource,
                            const char   *filename,
                            unsigned int  sender_uid);

gboolean cph_cups_server_get_settings (CphCups   *cups,
                                       GVariant **settings);

gboolean cph_cups_server_set_settings (CphCups  *cups,
                                       GVariant *settings);

gboolean cph_cups_devices_get (CphCups            *cups,
                               int                 timeout,
                               int                 limit,
                               const char *const  *include_schemes,
                               const char *const  *exclude_schemes,
                               GVariant          **devices);

gboolean cph_cups_printer_add (CphCups    *cups,
                               const char *printer_name,
                               const char *printer_uri,
                               const char *ppd_file,
                               const char *info,
                               const char *location);

gboolean cph_cups_printer_add_with_ppd_file (CphCups    *cups,
                                             const char *printer_name,
                                             const char *printer_uri,
                                             const char *ppd_filename,
                                             const char *info,
                                             const char *location);

gboolean cph_cups_printer_delete (CphCups    *cups,
                                  const char *printer_name);

gboolean cph_cups_printer_set_default (CphCups    *cups,
                                       const char *printer_name);

gboolean cph_cups_printer_set_enabled (CphCups    *cups,
                                       const char *printer_name,
                                       gboolean    enabled);

gboolean cph_cups_printer_set_uri (CphCups    *cups,
                                   const char *printer_name,
                                   const char *printer_uri);

gboolean cph_cups_printer_set_accept_jobs (CphCups    *cups,
                                           const char *printer_name,
                                           gboolean    enabled,
                                           const char *reason);

gboolean cph_cups_class_add_printer (CphCups    *cups,
                                     const char *class_name,
                                     const char *printer_name);

gboolean cph_cups_class_delete_printer (CphCups    *cups,
                                        const char *class_name,
                                        const char *printer_name);

gboolean cph_cups_class_delete (CphCups    *cups,
                                const char *class_name);

gboolean cph_cups_printer_class_rename (CphCups    *cups,
                                        const char *old_printer_name,
                                        const char *new_printer_name);

gboolean cph_cups_printer_class_set_info (CphCups    *cups,
                                          const char *printer_name,
                                          const char *info);

gboolean cph_cups_printer_class_set_location (CphCups    *cups,
                                              const char *printer_name,
                                              const char *location);

gboolean cph_cups_printer_class_set_shared (CphCups    *cups,
                                            const char *printer_name,
                                            gboolean    shared);

gboolean cph_cups_printer_class_set_job_sheets (CphCups    *cups,
                                                const char *printer_name,
                                                const char *start,
                                                const char *end);

gboolean cph_cups_printer_class_set_error_policy (CphCups    *cups,
                                                  const char *printer_name,
                                                  const char *policy);

gboolean cph_cups_printer_class_set_op_policy (CphCups    *cups,
                                               const char *printer_name,
                                               const char *policy);

gboolean cph_cups_printer_class_set_users_allowed (CphCups           *cups,
                                                   const char        *printer_name,
                                                   const char *const *users);

gboolean cph_cups_printer_class_set_users_denied (CphCups           *cups,
                                                  const char        *printer_name,
                                                  const char *const *users);

gboolean cph_cups_printer_class_set_option_default (CphCups           *cups,
                                                    const char        *printer_name,
                                                    const char        *option,
                                                    const char *const *values);

gboolean cph_cups_printer_class_set_option (CphCups           *cups,
                                            const char        *printer_name,
                                            const char        *option,
                                            const char *const *values);

gboolean cph_cups_job_cancel (CphCups    *cups,
                              int         job_id,
                              gboolean    purge_job,
                              const char *user_name);

gboolean cph_cups_job_restart (CphCups    *cups,
                               int         job_id,
                               const char *user_name);

gboolean cph_cups_job_set_hold_until (CphCups    *cups,
                                      int         job_id,
                                      const char *job_hold_until,
                                      const char *user_name);

CphJobStatus cph_cups_job_get_status (CphCups    *cups,
                                      int         job_id,
                                      const char *user);

gboolean cph_cups_is_printer_uri_local (const char *uri);

G_END_DECLS

#endif /* CPH_CUPS_H */
