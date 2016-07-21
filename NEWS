=============
Version 0.2.6
=============

+ Enable UTF-8 chars in names and texts (Marek)
+ Introduce CPH_PATH_MAX (Pino Toscano)
+ New/updated translations: ca, cs, da, de, en, en_GB, gl, ia, kk, ko, oc, pt,
  ru, sk, sr
+ Add function for printer renaming (Martin Hatina)

=============
Version 0.2.5
=============

+ Revert "Be stricter when validating printer names" (Vincent)
+ New/updated translations: cs, eo, es, eu, fr, gl, hr, hu, ia, id, it, pl, sr, sv, uk.

=============
Version 0.2.4
=============

+ Fix detection of CUPS version (Jürg Billeter, Vincent)

=============
Version 0.2.3
=============

+ Fix security flaw in cupsGetFile/cupsPutFile wrappers (CVE-2012-4510)
  (Vincent)
+ Escape printer/class names before putting them in URIs (Vincent)
+ Be stricter when validating printer names (Vincent)
+ Fix build with CUPS >= 1.6 (Jiri Popelka)
+ New/updated translations: de, es, fi, ka, lv, pt_BR, sl, tr, zh_CN.

=============
Version 0.2.2
=============

+ Add PrinterAddOption D-Bus method. (Marek Kasik)
+ Set requesting-user-name tag in requests. (Marek Kasik)
+ Code cleanups. (Vincent)
+ Build fixes and improvements. (Vincent, Marek Kasik)
+ New/updated translations: ja, nl, sk, zh_TW.

=============
Version 0.2.1
=============

+ Do not pass ppd file if empty when adding a printer. (Tim Waugh)
+ Accept NULL for ppd file as valid when adding a printer. (Vincent)
+ Allow inactive/any users to authenticate. (Marek Kasik)
+ New/udpated translations: gl, it, ko, zh_TW.

=============
Version 0.2.0
=============

+ Port to GDBus. (Vincent)
+ Stop using deprecated polkit API. (Vincent)
+ Drop gthread handling. (Vincent)
+ Add org.freedesktop.DBus.Deprecated annotation to JobCancel. (Vincent)
+ Code cleanups. (Vincent)
+ Build system improvements. (Vincent)
+ New/udpated translations: hu.

=============
Version 0.1.3
=============

+ Allow file request with NULL filename, to add raw printers. (Marek Kašík)
+ Modernize build system a bit. (Vincent)
+ New/udpated translations: eo, id, pl, sl, uk.

=============
Version 0.1.2
=============

+ Add all-edit action to enable authenticating only once in tools (Marek Kašík)
+ Build system improvements. (Vincent)
+ New/udpated translations: fr, hu, it, pl, tr, uk.

=============
Version 0.1.1
=============

+ Make the include/exclude schemes work when getting devices with cups 1.4
  (Dominique Leuenberger)
+ Fix confusion between IPP and HTTP status when getting/putting a file
  (Vincent)
+ Clarify a string. (Vincent)
+ Add some basic documentation. (Vincent)
+ Build system improvements. (Vincent)
+ First translations: cz (Mrs Jenkins), de (Andre Klapper), fr (Vincent).

=============
Version 0.1.0
=============

+ Port to PolicyKit 1. (Marek Kasik, Vincent)
+ Add DevicesGet method. (Marek Kasik, Vincent)
+ Add JobCancelPurge method. (Marek Kasik)
+ Support adding printer without device URI. (Tim Waugh)
+ Add check for string length in validity checks. (Vincent)
+ Improve performance of job-related methods. (Marek Kasik)
+ Make sure to correctly handle all CUPS replies. (Vincent)
+ Avoid timeout on job-related methods for invalid jobs. (Vincent)
+ Always return a non-empty error string in case of failures. (Vincent)
+ Remove GTK+/GIO requirements. (Vincent)
+ Minor fixes and improvements in tests. (Vincent)
+ Code cleanups. (Vincent)
+ Build system improvements. (Vincent)

=============
Version 0.0.4
=============

+ Remove bare send_interface lines in the DBus rules.
+ Add job related functions. (Marek Kasik)
+ Reconnect to the cups server if necessary. (Marek Kasik)
+ Accept file: URI as local. (Marek Kasik)
+ Change default policy for job-edit to yes (jobs are owned by the user).
+ Add more checks for the new job-related functions.
+ Code cleanups.

=============
Version 0.0.3
=============

+ Make PrinterAddOptionDefault work for options with more than one value.
+ Implement PrinterSetUsersAllowed/PrinterSetUsersDenied methods.
+ Implement ServerGetSettings/ServerSetSettings methods.
+ Implement ClassAddPrinter/ClassDeletePrinter/ClassDelete methods.
+ Add more fine-grained policies, including local vs remote printers.
+ Fix major bug that made it impossible to change many settings.
+ Implement FileGet/FilePut methods.

=============
Version 0.0.2
=============

+ Make the AcceptJobs method work.
+ Add checks to arguments passed over dbus, for more security.

=============
Version 0.0.1
=============

Initial release.
