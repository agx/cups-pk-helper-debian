#!/usr/bin/python
# vim: set ts=4 sw=4 et: coding=UTF-8
#
# Copyright (C) 2008 Novell, Inc.
#
# Authors: Vincent Untz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

import os
import sys

import dbus

def removeprinter(cups_pk, printer_name):
    error = cups_pk.PrinterDelete(printer_name)

    if not type(error) in [dbus.String, dbus.UTF8String]:
           print 'Unexpected return value'
           return

    if error == '':
        print 'Worked!'
    else:
        print 'Ouch: %s' % error

def addprinter(cups_pk, printer_name, printer_uri, ppd_file, info, location):
    error = cups_pk.PrinterAdd(printer_name, printer_uri, ppd_file, info, location)

    if not type(error) in [dbus.String, dbus.UTF8String]:
           print 'Unexpected return value'
           return

    if error == '':
        print 'Worked!'
    else:
        print 'Ouch: %s' % error

def acceptjobs(cups_pk, printer_name, enabled, reason):
    error = cups_pk.PrinterSetAcceptJobs(printer_name, enabled, reason)

    if not type(error) in [dbus.String, dbus.UTF8String]:
           print 'Unexpected return value'
           return

    if error == '':
        print 'Worked!'
    else:
        print 'Ouch: %s' % error

def changeoption(cups_pk, printer_name, option, value):
    error = cups_pk.PrinterAddOptionDefault(printer_name, option, value)

    if not type(error) in [dbus.String, dbus.UTF8String]:
           print 'Unexpected return value'
           return

    if error == '':
        print 'Worked!'
    else:
        print 'Ouch: %s' % error

def main(args):
    system_bus = dbus.SystemBus()

    cups_pk_object = system_bus.get_object('org.opensuse.CupsPkHelper.Mechanism', '/')
    cups_pk_interface = dbus.Interface(cups_pk_object, 'org.opensuse.CupsPkHelper.Mechanism')

    try:
        #removeprinter(cups_pk_interface, "MyPrinter")
        addprinter(cups_pk_interface, "MyPrinter", "smb://really/cool", "HP/Business_Inkjet_2200-chp2200.ppd.gz", "This is my printer", "At home")
        #changeoption(cups_pk_interface, "MyPrinter", "toto", "At home")
        #acceptjobs(cups_pk_interface, "MyPrinter", True, "")
    except dbus.exceptions.DBusException, e:
        print 'Error: %s' % e


if __name__ == '__main__':
    try:
      main(sys.argv)
    except KeyboardInterrupt:
      pass
