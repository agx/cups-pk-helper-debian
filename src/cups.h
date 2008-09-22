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

GType     cph_cups_get_type    (void);

CphCups  *cph_cups_new         (void);

const char *cph_cups_last_status_to_string (CphCups *cups);

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

gboolean cph_cups_printer_class_set_option_default (CphCups    *cups,
                                                    const char *printer_name,
                                                    const char *option,
                                                    const char *first_value,
                                                    ...);
G_END_DECLS

#endif /* CPH_CUPS_H */
