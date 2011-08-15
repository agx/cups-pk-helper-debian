/*
 * Generated by gdbus-codegen 2.29.9. DO NOT EDIT.
 *
 * The license of this code is the same as for the source it was derived from.
 */

#ifndef __CPH_IFACE_MECHANISM_H__
#define __CPH_IFACE_MECHANISM_H__

#include <gio/gio.h>

G_BEGIN_DECLS


/* ------------------------------------------------------------------------ */
/* Declarations for org.opensuse.CupsPkHelper.Mechanism */

#define CPH_IFACE_TYPE_MECHANISM (cph_iface_mechanism_get_type ())
#define CPH_IFACE_MECHANISM(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), CPH_IFACE_TYPE_MECHANISM, CphIfaceMechanism))
#define CPH_IFACE_IS_MECHANISM(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), CPH_IFACE_TYPE_MECHANISM))
#define CPH_IFACE_MECHANISM_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), CPH_IFACE_TYPE_MECHANISM, CphIfaceMechanism))

struct _CphIfaceMechanism;
typedef struct _CphIfaceMechanism CphIfaceMechanism;
typedef struct _CphIfaceMechanismIface CphIfaceMechanismIface;

struct _CphIfaceMechanismIface
{
  GTypeInterface parent_iface;

  gboolean (*handle_class_add_printer) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *printer);

  gboolean (*handle_class_delete) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name);

  gboolean (*handle_class_delete_printer) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *printer);

  gboolean (*handle_devices_get) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    gint timeout,
    gint limit,
    const gchar *const *include_schemes,
    const gchar *const *exclude_schemes);

  gboolean (*handle_file_get) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *resource,
    const gchar *filename);

  gboolean (*handle_file_put) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *resource,
    const gchar *filename);

  gboolean (*handle_job_cancel) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    gint jobid);

  gboolean (*handle_job_cancel_purge) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    gint jobid,
    gboolean purge);

  gboolean (*handle_job_restart) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    gint jobid);

  gboolean (*handle_job_set_hold_until) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    gint jobid,
    const gchar *job_hold_until);

  gboolean (*handle_printer_add) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *uri,
    const gchar *ppd,
    const gchar *info,
    const gchar *location);

  gboolean (*handle_printer_add_option_default) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *option,
    const gchar *const *values);

  gboolean (*handle_printer_add_with_ppd_file) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *uri,
    const gchar *ppd,
    const gchar *info,
    const gchar *location);

  gboolean (*handle_printer_delete) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name);

  gboolean (*handle_printer_delete_option_default) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *option);

  gboolean (*handle_printer_set_accept_jobs) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    gboolean enabled,
    const gchar *reason);

  gboolean (*handle_printer_set_default) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name);

  gboolean (*handle_printer_set_device) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *device);

  gboolean (*handle_printer_set_enabled) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    gboolean enabled);

  gboolean (*handle_printer_set_error_policy) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *policy);

  gboolean (*handle_printer_set_info) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *info);

  gboolean (*handle_printer_set_job_sheets) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *start,
    const gchar *end);

  gboolean (*handle_printer_set_location) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *location);

  gboolean (*handle_printer_set_op_policy) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *policy);

  gboolean (*handle_printer_set_shared) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    gboolean shared);

  gboolean (*handle_printer_set_users_allowed) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *const *users);

  gboolean (*handle_printer_set_users_denied) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *name,
    const gchar *const *users);

  gboolean (*handle_server_get_settings) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_server_set_settings) (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    GVariant *settings);

};

GType cph_iface_mechanism_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *cph_iface_mechanism_interface_info (void);


/* D-Bus method call completion functions: */
void cph_iface_mechanism_complete_file_get (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_file_put (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_server_get_settings (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error,
    GVariant *settings);

void cph_iface_mechanism_complete_server_set_settings (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_devices_get (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error,
    GVariant *devices);

void cph_iface_mechanism_complete_printer_add (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_add_with_ppd_file (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_set_device (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_set_default (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_set_enabled (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_set_accept_jobs (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_delete (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_class_add_printer (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_class_delete_printer (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_class_delete (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_set_info (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_set_location (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_set_shared (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_set_job_sheets (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_set_error_policy (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_set_op_policy (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_set_users_allowed (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_set_users_denied (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_add_option_default (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_printer_delete_option_default (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

G_GNUC_DEPRECATED void cph_iface_mechanism_complete_job_cancel (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_job_cancel_purge (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_job_restart (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);

void cph_iface_mechanism_complete_job_set_hold_until (
    CphIfaceMechanism *object,
    GDBusMethodInvocation *invocation,
    const gchar *error);



/* D-Bus method calls: */
void cph_iface_mechanism_call_file_get (
    CphIfaceMechanism *proxy,
    const gchar *resource,
    const gchar *filename,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_file_get_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_file_get_sync (
    CphIfaceMechanism *proxy,
    const gchar *resource,
    const gchar *filename,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_file_put (
    CphIfaceMechanism *proxy,
    const gchar *resource,
    const gchar *filename,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_file_put_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_file_put_sync (
    CphIfaceMechanism *proxy,
    const gchar *resource,
    const gchar *filename,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_server_get_settings (
    CphIfaceMechanism *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_server_get_settings_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GVariant **out_settings,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_server_get_settings_sync (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GVariant **out_settings,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_server_set_settings (
    CphIfaceMechanism *proxy,
    GVariant *settings,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_server_set_settings_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_server_set_settings_sync (
    CphIfaceMechanism *proxy,
    GVariant *settings,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_devices_get (
    CphIfaceMechanism *proxy,
    gint timeout,
    gint limit,
    const gchar *const *include_schemes,
    const gchar *const *exclude_schemes,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_devices_get_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GVariant **out_devices,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_devices_get_sync (
    CphIfaceMechanism *proxy,
    gint timeout,
    gint limit,
    const gchar *const *include_schemes,
    const gchar *const *exclude_schemes,
    gchar **out_error,
    GVariant **out_devices,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_add (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *uri,
    const gchar *ppd,
    const gchar *info,
    const gchar *location,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_add_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_add_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *uri,
    const gchar *ppd,
    const gchar *info,
    const gchar *location,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_add_with_ppd_file (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *uri,
    const gchar *ppd,
    const gchar *info,
    const gchar *location,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_add_with_ppd_file_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_add_with_ppd_file_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *uri,
    const gchar *ppd,
    const gchar *info,
    const gchar *location,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_set_device (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *device,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_set_device_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_set_device_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *device,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_set_default (
    CphIfaceMechanism *proxy,
    const gchar *name,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_set_default_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_set_default_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_set_enabled (
    CphIfaceMechanism *proxy,
    const gchar *name,
    gboolean enabled,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_set_enabled_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_set_enabled_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    gboolean enabled,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_set_accept_jobs (
    CphIfaceMechanism *proxy,
    const gchar *name,
    gboolean enabled,
    const gchar *reason,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_set_accept_jobs_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_set_accept_jobs_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    gboolean enabled,
    const gchar *reason,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_delete (
    CphIfaceMechanism *proxy,
    const gchar *name,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_delete_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_delete_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_class_add_printer (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *printer,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_class_add_printer_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_class_add_printer_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *printer,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_class_delete_printer (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *printer,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_class_delete_printer_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_class_delete_printer_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *printer,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_class_delete (
    CphIfaceMechanism *proxy,
    const gchar *name,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_class_delete_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_class_delete_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_set_info (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *info,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_set_info_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_set_info_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *info,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_set_location (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *location,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_set_location_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_set_location_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *location,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_set_shared (
    CphIfaceMechanism *proxy,
    const gchar *name,
    gboolean shared,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_set_shared_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_set_shared_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    gboolean shared,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_set_job_sheets (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *start,
    const gchar *end,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_set_job_sheets_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_set_job_sheets_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *start,
    const gchar *end,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_set_error_policy (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *policy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_set_error_policy_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_set_error_policy_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *policy,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_set_op_policy (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *policy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_set_op_policy_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_set_op_policy_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *policy,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_set_users_allowed (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *const *users,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_set_users_allowed_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_set_users_allowed_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *const *users,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_set_users_denied (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *const *users,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_set_users_denied_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_set_users_denied_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *const *users,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_add_option_default (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *option,
    const gchar *const *values,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_add_option_default_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_add_option_default_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *option,
    const gchar *const *values,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_printer_delete_option_default (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *option,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_printer_delete_option_default_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_printer_delete_option_default_sync (
    CphIfaceMechanism *proxy,
    const gchar *name,
    const gchar *option,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

G_GNUC_DEPRECATED void cph_iface_mechanism_call_job_cancel (
    CphIfaceMechanism *proxy,
    gint jobid,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

G_GNUC_DEPRECATED gboolean cph_iface_mechanism_call_job_cancel_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

G_GNUC_DEPRECATED gboolean cph_iface_mechanism_call_job_cancel_sync (
    CphIfaceMechanism *proxy,
    gint jobid,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_job_cancel_purge (
    CphIfaceMechanism *proxy,
    gint jobid,
    gboolean purge,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_job_cancel_purge_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_job_cancel_purge_sync (
    CphIfaceMechanism *proxy,
    gint jobid,
    gboolean purge,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_job_restart (
    CphIfaceMechanism *proxy,
    gint jobid,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_job_restart_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_job_restart_sync (
    CphIfaceMechanism *proxy,
    gint jobid,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);

void cph_iface_mechanism_call_job_set_hold_until (
    CphIfaceMechanism *proxy,
    gint jobid,
    const gchar *job_hold_until,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean cph_iface_mechanism_call_job_set_hold_until_finish (
    CphIfaceMechanism *proxy,
    gchar **out_error,
    GAsyncResult *res,
    GError **error);

gboolean cph_iface_mechanism_call_job_set_hold_until_sync (
    CphIfaceMechanism *proxy,
    gint jobid,
    const gchar *job_hold_until,
    gchar **out_error,
    GCancellable *cancellable,
    GError **error);



/* ---- */

#define CPH_IFACE_TYPE_MECHANISM_PROXY (cph_iface_mechanism_proxy_get_type ())
#define CPH_IFACE_MECHANISM_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), CPH_IFACE_TYPE_MECHANISM_PROXY, CphIfaceMechanismProxy))
#define CPH_IFACE_MECHANISM_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), CPH_IFACE_TYPE_MECHANISM_PROXY, CphIfaceMechanismProxyClass))
#define CPH_IFACE_MECHANISM_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), CPH_IFACE_TYPE_MECHANISM_PROXY, CphIfaceMechanismProxyClass))
#define CPH_IFACE_IS_MECHANISM_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), CPH_IFACE_TYPE_MECHANISM_PROXY))
#define CPH_IFACE_IS_MECHANISM_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), CPH_IFACE_TYPE_MECHANISM_PROXY))

typedef struct _CphIfaceMechanismProxy CphIfaceMechanismProxy;
typedef struct _CphIfaceMechanismProxyClass CphIfaceMechanismProxyClass;
typedef struct _CphIfaceMechanismProxyPrivate CphIfaceMechanismProxyPrivate;

struct _CphIfaceMechanismProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  CphIfaceMechanismProxyPrivate *priv;
};

struct _CphIfaceMechanismProxyClass
{
  GDBusProxyClass parent_class;
};

GType cph_iface_mechanism_proxy_get_type (void) G_GNUC_CONST;

void cph_iface_mechanism_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
CphIfaceMechanism *cph_iface_mechanism_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
CphIfaceMechanism *cph_iface_mechanism_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void cph_iface_mechanism_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
CphIfaceMechanism *cph_iface_mechanism_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
CphIfaceMechanism *cph_iface_mechanism_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define CPH_IFACE_TYPE_MECHANISM_SKELETON (cph_iface_mechanism_skeleton_get_type ())
#define CPH_IFACE_MECHANISM_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), CPH_IFACE_TYPE_MECHANISM_SKELETON, CphIfaceMechanismSkeleton))
#define CPH_IFACE_MECHANISM_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), CPH_IFACE_TYPE_MECHANISM_SKELETON, CphIfaceMechanismSkeletonClass))
#define CPH_IFACE_MECHANISM_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), CPH_IFACE_TYPE_MECHANISM_SKELETON, CphIfaceMechanismSkeletonClass))
#define CPH_IFACE_IS_MECHANISM_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), CPH_IFACE_TYPE_MECHANISM_SKELETON))
#define CPH_IFACE_IS_MECHANISM_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), CPH_IFACE_TYPE_MECHANISM_SKELETON))

typedef struct _CphIfaceMechanismSkeleton CphIfaceMechanismSkeleton;
typedef struct _CphIfaceMechanismSkeletonClass CphIfaceMechanismSkeletonClass;
typedef struct _CphIfaceMechanismSkeletonPrivate CphIfaceMechanismSkeletonPrivate;

struct _CphIfaceMechanismSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  CphIfaceMechanismSkeletonPrivate *priv;
};

struct _CphIfaceMechanismSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType cph_iface_mechanism_skeleton_get_type (void) G_GNUC_CONST;

CphIfaceMechanism *cph_iface_mechanism_skeleton_new (void);


/* ---- */

#define CPH_IFACE_TYPE_OBJECT (cph_iface_object_get_type ())
#define CPH_IFACE_OBJECT(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), CPH_IFACE_TYPE_OBJECT, CphIfaceObject))
#define CPH_IFACE_IS_OBJECT(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), CPH_IFACE_TYPE_OBJECT))
#define CPH_IFACE_OBJECT_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), CPH_IFACE_TYPE_OBJECT, CphIfaceObject))

struct _CphIfaceObject;
typedef struct _CphIfaceObject CphIfaceObject;
typedef struct _CphIfaceObjectIface CphIfaceObjectIface;

struct _CphIfaceObjectIface
{
  GTypeInterface parent_iface;
};

GType cph_iface_object_get_type (void) G_GNUC_CONST;

CphIfaceMechanism *cph_iface_object_get_mechanism (CphIfaceObject *object);
CphIfaceMechanism *cph_iface_object_peek_mechanism (CphIfaceObject *object);

#define CPH_IFACE_TYPE_OBJECT_PROXY (cph_iface_object_proxy_get_type ())
#define CPH_IFACE_OBJECT_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), CPH_IFACE_TYPE_OBJECT_PROXY, CphIfaceObjectProxy))
#define CPH_IFACE_OBJECT_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), CPH_IFACE_TYPE_OBJECT_PROXY, CphIfaceObjectProxyClass))
#define CPH_IFACE_OBJECT_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), CPH_IFACE_TYPE_OBJECT_PROXY, CphIfaceObjectProxyClass))
#define CPH_IFACE_IS_OBJECT_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), CPH_IFACE_TYPE_OBJECT_PROXY))
#define CPH_IFACE_IS_OBJECT_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), CPH_IFACE_TYPE_OBJECT_PROXY))

typedef struct _CphIfaceObjectProxy CphIfaceObjectProxy;
typedef struct _CphIfaceObjectProxyClass CphIfaceObjectProxyClass;
typedef struct _CphIfaceObjectProxyPrivate CphIfaceObjectProxyPrivate;

struct _CphIfaceObjectProxy
{
  /*< private >*/
  GDBusObjectProxy parent_instance;
  CphIfaceObjectProxyPrivate *priv;
};

struct _CphIfaceObjectProxyClass
{
  GDBusObjectProxyClass parent_class;
};

GType cph_iface_object_proxy_get_type (void) G_GNUC_CONST;
CphIfaceObjectProxy *cph_iface_object_proxy_new (GDBusConnection *connection, const gchar *object_path);

#define CPH_IFACE_TYPE_OBJECT_SKELETON (cph_iface_object_skeleton_get_type ())
#define CPH_IFACE_OBJECT_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), CPH_IFACE_TYPE_OBJECT_SKELETON, CphIfaceObjectSkeleton))
#define CPH_IFACE_OBJECT_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), CPH_IFACE_TYPE_OBJECT_SKELETON, CphIfaceObjectSkeletonClass))
#define CPH_IFACE_OBJECT_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), CPH_IFACE_TYPE_OBJECT_SKELETON, CphIfaceObjectSkeletonClass))
#define CPH_IFACE_IS_OBJECT_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), CPH_IFACE_TYPE_OBJECT_SKELETON))
#define CPH_IFACE_IS_OBJECT_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), CPH_IFACE_TYPE_OBJECT_SKELETON))

typedef struct _CphIfaceObjectSkeleton CphIfaceObjectSkeleton;
typedef struct _CphIfaceObjectSkeletonClass CphIfaceObjectSkeletonClass;
typedef struct _CphIfaceObjectSkeletonPrivate CphIfaceObjectSkeletonPrivate;

struct _CphIfaceObjectSkeleton
{
  /*< private >*/
  GDBusObjectSkeleton parent_instance;
  CphIfaceObjectSkeletonPrivate *priv;
};

struct _CphIfaceObjectSkeletonClass
{
  GDBusObjectSkeletonClass parent_class;
};

GType cph_iface_object_skeleton_get_type (void) G_GNUC_CONST;
CphIfaceObjectSkeleton *cph_iface_object_skeleton_new (const gchar *object_path);
void cph_iface_object_skeleton_set_mechanism (CphIfaceObjectSkeleton *object, CphIfaceMechanism *interface_);

/* ---- */

#define CPH_IFACE_TYPE_OBJECT_MANAGER_CLIENT (cph_iface_object_manager_client_get_type ())
#define CPH_IFACE_OBJECT_MANAGER_CLIENT(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), CPH_IFACE_TYPE_OBJECT_MANAGER_CLIENT, CphIfaceObjectManagerClient))
#define CPH_IFACE_OBJECT_MANAGER_CLIENT_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), CPH_IFACE_TYPE_OBJECT_MANAGER_CLIENT, CphIfaceObjectManagerClientClass))
#define CPH_IFACE_OBJECT_MANAGER_CLIENT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), CPH_IFACE_TYPE_OBJECT_MANAGER_CLIENT, CphIfaceObjectManagerClientClass))
#define CPH_IFACE_IS_OBJECT_MANAGER_CLIENT(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), CPH_IFACE_TYPE_OBJECT_MANAGER_CLIENT))
#define CPH_IFACE_IS_OBJECT_MANAGER_CLIENT_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), CPH_IFACE_TYPE_OBJECT_MANAGER_CLIENT))

typedef struct _CphIfaceObjectManagerClient CphIfaceObjectManagerClient;
typedef struct _CphIfaceObjectManagerClientClass CphIfaceObjectManagerClientClass;
typedef struct _CphIfaceObjectManagerClientPrivate CphIfaceObjectManagerClientPrivate;

struct _CphIfaceObjectManagerClient
{
  /*< private >*/
  GDBusObjectManagerClient parent_instance;
  CphIfaceObjectManagerClientPrivate *priv;
};

struct _CphIfaceObjectManagerClientClass
{
  GDBusObjectManagerClientClass parent_class;
};

GType cph_iface_object_manager_client_get_type (void) G_GNUC_CONST;

GType cph_iface_object_manager_client_get_proxy_type (GDBusObjectManagerClient *manager, const gchar *object_path, const gchar *interface_name, gpointer user_data);

void cph_iface_object_manager_client_new (
    GDBusConnection        *connection,
    GDBusObjectManagerClientFlags  flags,
    const gchar            *name,
    const gchar            *object_path,
    GCancellable           *cancellable,
    GAsyncReadyCallback     callback,
    gpointer                user_data);
GDBusObjectManager *cph_iface_object_manager_client_new_finish (
    GAsyncResult        *res,
    GError             **error);
GDBusObjectManager *cph_iface_object_manager_client_new_sync (
    GDBusConnection        *connection,
    GDBusObjectManagerClientFlags  flags,
    const gchar            *name,
    const gchar            *object_path,
    GCancellable           *cancellable,
    GError                **error);

void cph_iface_object_manager_client_new_for_bus (
    GBusType                bus_type,
    GDBusObjectManagerClientFlags  flags,
    const gchar            *name,
    const gchar            *object_path,
    GCancellable           *cancellable,
    GAsyncReadyCallback     callback,
    gpointer                user_data);
GDBusObjectManager *cph_iface_object_manager_client_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
GDBusObjectManager *cph_iface_object_manager_client_new_for_bus_sync (
    GBusType                bus_type,
    GDBusObjectManagerClientFlags  flags,
    const gchar            *name,
    const gchar            *object_path,
    GCancellable           *cancellable,
    GError                **error);


G_END_DECLS

#endif /* __CPH_IFACE_MECHANISM_H__ */
