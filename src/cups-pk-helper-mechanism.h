/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
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

G_END_DECLS

#endif /* CPH_MECHANISM_H */
