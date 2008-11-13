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

def pk_auth(bus, action, result):
    pk_auth_object =bus.get_object('org.freedesktop.PolicyKit.AuthenticationAgent', '/')
    pk_auth = dbus.Interface(pk_auth_object, 'org.freedesktop.PolicyKit.AuthenticationAgent')

    ret = pk_auth.ObtainAuthorization(action, dbus.UInt32(0), dbus.UInt32(os.getpid()))

    if not type(ret) == dbus.Boolean:
        return False

    return ret != 0

def handle_exception_with_auth(session_bus, e):
    if e.get_dbus_name() != 'org.opensuse.CupsPkHelper.Mechanism.NotPrivileged':
        print 'dbus error: %s' % e
        return False

    tokens = e.get_dbus_message().split(' ', 2)
    if len(tokens) != 3:
        print 'helper return string malformed'
        return False

    try:
        # Note: the async version fails because of timeout if the user waits
        # too long
        ret = pk_auth(session_bus, tokens[0], tokens[1])
    except dbus.exceptions.DBusException, e_auth:
        print 'dbus error: %s' % e_auth
        return False

    if not ret:
        print 'not authorized'

    return ret

def removeprinter(cups_pk, printer_name):
    error = cups_pk.PrinterRemove(printer_name)

    if not type(error) in [dbus.String, dbus.UTF8String]:
           print 'unexpected return value'
           return

    if error == '':
        print 'worked!'
    else:
        print 'ouch: %s' % error

def addprinter(cups_pk, printer_name, printer_uri, ppd_file, info, location):
    error = cups_pk.PrinterAdd(printer_name, printer_uri, ppd_file, info, location)

    if not type(error) in [dbus.String, dbus.UTF8String]:
           print 'unexpected return value'
           return

    if error == '':
        print 'worked!'
    else:
        print 'ouch: %s' % error

def acceptjobs(cups_pk, printer_name, enabled, reason):
    error = cups_pk.PrinterSetAcceptJobs(printer_name, enabled, reason)

    if not type(error) in [dbus.String, dbus.UTF8String]:
           print 'unexpected return value'
           return

    if error == '':
        print 'worked!'
    else:
        print 'ouch: %s' % error

def changeoption(cups_pk, printer_name, option, value):
    error = cups_pk.PrinterAddOptionDefault(printer_name, option, value)

    if not type(error) in [dbus.String, dbus.UTF8String]:
           print 'unexpected return value'
           return

    if error == '':
        print 'worked!'
    else:
        print 'ouch: %s' % error

def main(args):
    session_bus = dbus.SessionBus()
    system_bus = dbus.SystemBus()

    cups_pk_object = system_bus.get_object('org.opensuse.CupsPkHelper.Mechanism', '/')
    cups_pk_interface = dbus.Interface(cups_pk_object, 'org.opensuse.CupsPkHelper.Mechanism')

    while True:
        try:
            #removeprinter(cups_pk_interface, "MyPrinter")
            addprinter(cups_pk_interface, "MyPrinter", "smb://really/cool", "HP/Business_Inkjet_2200-chp2200.ppd.gz", "This is my printer", "At home")
            #changeoption(cups_pk_interface, "MyPrinter", "toto", "At home")
            #acceptjobs(cups_pk_interface, "MyPrinter", True, "")
            break
        except dbus.exceptions.DBusException, e:
            if handle_exception_with_auth(session_bus, e):
                continue
            break


if __name__ == '__main__':
    try:
      main(sys.argv)
    except KeyboardInterrupt:
      pass
