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

#include <glib.h>
#include <glib-object.h>

#include "cups.h"

int
main (int argc, char **argv)
{
        CphCups *cups;

        g_type_init ();

        cups = cph_cups_new ();

        if (cups == NULL)
                return 1;

        //if (cph_cups_add_printer (cups, "MyPrinter", "smb://really/cool", "HP/Business_Inkjet_2200-chp2200.ppd.gz", "This is my printer", "At home")) {
        //if (cph_cups_printer_delete (cups, "MyPrinter")) {
        if (cph_cups_printer_class_set_job_sheets (cups, "DesignJet-650C", "none", "none")) {
                g_print ("worked\n");
        } else {
                g_print ("ouch: %s\n", cph_cups_last_status_to_string (cups));
        }

        g_object_unref (cups);

        return 0;
}
