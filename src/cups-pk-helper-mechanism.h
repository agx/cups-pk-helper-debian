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
 * The code is originally based on gnome-clock-applet-mechanism.h, which
 * is under the same license and with the following copyright:
 *
 * Copyright (C) 2007 David Zeuthen <david@fubar.dk>
 *
 */

#ifndef CPH_MECHANISM_H
#define CPH_MECHANISM_H

#include <glib-object.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

#define CPH_TYPE_MECHANISM         (cph_mechanism_get_type ())
#define CPH_MECHANISM(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), CPH_TYPE_MECHANISM, CphMechanism))
#define CPH_MECHANISM_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), CPH_TYPE_MECHANISM, CphMechanismClass))
#define CPH_IS_MECHANISM(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), CPH_TYPE_MECHANISM))
#define CPH_IS_MECHANISM_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), CPH_TYPE_MECHANISM))
#define CPH_MECHANISM_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), CPH_TYPE_MECHANISM, CphMechanismClass))

typedef struct CphMechanismPrivate CphMechanismPrivate;

typedef struct
{
        GObject              parent;
        CphMechanismPrivate *priv;
} CphMechanism;

typedef struct
{
        GObjectClass parent_class;
} CphMechanismClass;

typedef enum
{
        CPH_MECHANISM_ERROR_GENERAL,
        CPH_MECHANISM_ERROR_NOT_PRIVILEGED,
        CPH_MECHANISM_NUM_ERRORS
} CphMechanismError;

#define CPH_MECHANISM_ERROR cph_mechanism_error_quark ()

GType cph_mechanism_error_get_type (void);
#define CPH_MECHANISM_TYPE_ERROR (cph_mechanism_error_get_type ())


GQuark         cph_mechanism_error_quark (void);
GType          cph_mechanism_get_type    (void);

CphMechanism  *cph_mechanism_new         (void);

/* exported methods */

gboolean
cph_mechanism_file_get (CphMechanism          *mechanism,
                        const char            *resource,
                        const char            *filename,
                        DBusGMethodInvocation *context);

gboolean
cph_mechanism_file_put (CphMechanism          *mechanism,
                        const char            *resource,
                        const char            *filename,
                        DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_add (CphMechanism          *mechanism,
                           const char            *name,
                           const char            *uri,
                           const char            *ppd,
                           const char            *info,
                           const char            *location,
                           DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_add_with_ppd_file (CphMechanism          *mechanism,
                                         const char            *name,
                                         const char            *uri,
                                         const char            *ppdfile,
                                         const char            *info,
                                         const char            *location,
                                         DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_set_device (CphMechanism          *mechanism,
                                  const char            *name,
                                  const char            *device,
                                  DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_set_info (CphMechanism          *mechanism,
                                const char            *name,
                                const char            *info,
                                DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_set_location (CphMechanism          *mechanism,
                                    const char            *name,
                                    const char            *location,
                                    DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_set_shared (CphMechanism          *mechanism,
                                  const char            *name,
                                  gboolean               shared,
                                  DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_set_job_sheets (CphMechanism          *mechanism,
                                      const char            *name,
                                      const char            *start,
                                      const char            *end,
                                      DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_set_error_policy (CphMechanism          *mechanism,
                                        const char            *name,
                                        const char            *policy,
                                        DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_set_op_policy (CphMechanism          *mechanism,
                                     const char            *name,
                                     const char            *policy,
                                     DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_set_users_allowed (CphMechanism           *mechanism,
                                         const char             *name,
                                         const char            **users,
                                         DBusGMethodInvocation  *context);

gboolean
cph_mechanism_printer_set_users_denied (CphMechanism           *mechanism,
                                        const char             *name,
                                        const char            **users,
                                        DBusGMethodInvocation  *context);

gboolean
cph_mechanism_printer_add_option_default (CphMechanism           *mechanism,
                                          const char             *name,
                                          const char             *option,
                                          const char            **values,
                                          DBusGMethodInvocation  *context);

gboolean
cph_mechanism_printer_delete_option_default (CphMechanism          *mechanism,
                                             const char            *name,
                                             const char            *option,
                                             DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_delete (CphMechanism          *mechanism,
                              const char            *name,
                              DBusGMethodInvocation *context);

gboolean
cph_mechanism_class_add_printer (CphMechanism          *mechanism,
                                 const char            *name,
                                 const char            *printer,
                                 DBusGMethodInvocation *context);
gboolean
cph_mechanism_class_delete_printer (CphMechanism          *mechanism,
                                    const char            *name,
                                    const char            *printer,
                                    DBusGMethodInvocation *context);
gboolean
cph_mechanism_class_delete (CphMechanism          *mechanism,
                            const char            *name,
                            DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_set_default (CphMechanism          *mechanism,
                                   const char            *name,
                                   DBusGMethodInvocation *context);

gboolean
cph_mechanism_printer_set_enabled (CphMechanism          *mechanism,
                                   const char            *name,
                                   gboolean               enabled,
                                   DBusGMethodInvocation *context);


gboolean
cph_mechanism_printer_set_accept_jobs (CphMechanism          *mechanism,
                                       const char            *name,
                                       gboolean               enabled,
                                       const char            *reason,
                                       DBusGMethodInvocation *context);

gboolean
cph_mechanism_server_get_settings (CphMechanism          *mechanism,
                                   DBusGMethodInvocation *context);

gboolean
cph_mechanism_server_set_settings (CphMechanism          *mechanism,
                                   GHashTable            *settings,
                                   DBusGMethodInvocation *context);

gboolean
cph_mechanism_job_cancel (CphMechanism          *mechanism,
                          int                    id,
                          DBusGMethodInvocation *context);

gboolean
cph_mechanism_job_restart (CphMechanism          *mechanism,
                           int                    id,
                           DBusGMethodInvocation *context);

gboolean
cph_mechanism_job_set_hold_until (CphMechanism          *mechanism,
                                  int                    id,
                                  const char            *job_hold_until,
                                  DBusGMethodInvocation *context);

gboolean
cph_mechanism_devices_get (CphMechanism           *mechanism,
                           int                     timeout,
                           int                     limit,
                           const char            **include_schemes,
                           const char            **exclude_schemes,
                           DBusGMethodInvocation  *context);

G_END_DECLS

#endif /* CPH_MECHANISM_H */
