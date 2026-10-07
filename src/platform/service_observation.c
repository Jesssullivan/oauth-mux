#define _GNU_SOURCE
#include "service_observation.h"
#include <string.h>
#include <stddef.h>
#if defined(__linux__)
#include <gio/gio.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* API references:
 * https://docs.gtk.org/gio/method.DBusConnection.call_sync.html
 * https://raw.githubusercontent.com/systemd/systemd/main/man/org.freedesktop.systemd1.xml
 */
struct operation {
    GCancellable *cancel;
    GMutex mutex;
    GCond condition;
    GThread *watchdog;
    gint64 until;
    gboolean done;
};
static gpointer watchdog(gpointer pointer) {
    struct operation *op = pointer;
    g_mutex_lock(&op->mutex);
    while (!op->done) if (!g_cond_wait_until(&op->condition, &op->mutex, op->until)) {
        g_cancellable_cancel(op->cancel);
        break;
    }
    g_mutex_unlock(&op->mutex);
    return NULL;
}
static int start_operation(struct operation *op, uint32_t timeout) {
    memset(op, 0, sizeof(*op));
    op->cancel = g_cancellable_new();
    op->until = g_get_monotonic_time() + (gint64)timeout * 1000;
    g_mutex_init(&op->mutex);
    g_cond_init(&op->condition);
    op->watchdog = g_thread_try_new("omux-service-read", watchdog, op, NULL);
    if (op->watchdog) return 1;
    g_cond_clear(&op->condition);
    g_mutex_clear(&op->mutex);
    g_object_unref(op->cancel);
    return 0;
}
static void end_operation(struct operation *op) {
    g_mutex_lock(&op->mutex);
    op->done = TRUE;
    g_cond_signal(&op->condition);
    g_mutex_unlock(&op->mutex);
    g_thread_join(op->watchdog);
    g_cond_clear(&op->condition);
    g_mutex_clear(&op->mutex);
    g_object_unref(op->cancel);
}
static int remaining(struct operation *op) {
    gint64 left = op->until - g_get_monotonic_time();
    if (left <= 0 || g_cancellable_is_cancelled(op->cancel)) return 0;
    return (int)((left + 999) / 1000);
}
static int absolute(const char *path) {
    if (!path || path[0] != '/') return 0;
    size_t size = strnlen(path, 4097);
    if (size < 2 || size > 4096 || path[size - 1] == '/') return 0;
    const char *part = path + 1;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t length = end ? (size_t)(end - part) : strlen(part);
        if (!length || (length == 1 && part[0] == '.') ||
            (length == 2 && part[0] == '.' && part[1] == '.')) return 0;
        if (!end) break;
        part = end + 1;
    }
    return 1;
}
static int safe_ancestor(int fd) {
    struct stat status;
    if (fstat(fd, &status)) return 0;
    int protected_sticky = status.st_uid == 0 && (status.st_mode & S_ISVTX);
    return (status.st_uid == 0 || status.st_uid == getuid()) &&
        (!(status.st_mode & 022) || protected_sticky);
}
static int private_runtime(const char *path) {
    char copy[4097];
    memcpy(copy, path, strlen(path) + 1);
    int current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0) return -1;
    if (!safe_ancestor(current)) { close(current); return -1; }
    char *save = NULL;
    for (char *part = strtok_r(copy + 1, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        int next = openat(current, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        close(current);
        if (next < 0) return -1;
        if (!safe_ancestor(next)) { close(next); return -1; }
        current = next;
    }
    struct stat status;
    if (fstat(current, &status) || status.st_uid != getuid() ||
        (status.st_mode & 077) != 0) { close(current); return -1; }
    return current;
}
static int open_bus(const char *runtime, struct operation *op, int *unsafe) {
    *unsafe = 0;
    int parent = private_runtime(runtime);
    if (parent < 0) { *unsafe = 1; return -1; }
    struct stat before, after;
    if (fstatat(parent, "bus", &before, AT_SYMLINK_NOFOLLOW)) { close(parent); return -1; }
    if (!S_ISSOCK(before.st_mode) || before.st_uid != getuid()) {
        close(parent); *unsafe = 1; return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) { close(parent); return -1; }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    int length = snprintf(address.sun_path, sizeof(address.sun_path), "/proc/self/fd/%d/bus", parent);
    if (length <= 0 || (size_t)length >= sizeof(address.sun_path)) goto fail;
    if (connect(fd, (struct sockaddr *)&address, offsetof(struct sockaddr_un, sun_path) + (size_t)length + 1)) {
        if (errno != EINPROGRESS) goto fail;
        struct pollfd pending = { .fd = fd, .events = POLLOUT };
        int ready;
        do { int left = remaining(op); if (!left) goto fail; ready = poll(&pending, 1, left); } while (ready < 0 && errno == EINTR);
        if (ready <= 0) goto fail;
        int error = 0; socklen_t error_len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) || error) goto fail;
    }
    struct ucred peer; socklen_t peer_len = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) ||
        peer_len != sizeof(peer) || peer.uid != getuid()) { *unsafe = 1; goto fail; }
    if (fstatat(parent, "bus", &after, AT_SYMLINK_NOFOLLOW) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_uid != after.st_uid || before.st_mode != after.st_mode) {
        *unsafe = 1; goto fail;
    }
    close(parent);
    return fd;
fail:
    close(parent); close(fd); return -1;
}
static GVariant *call(GDBusConnection *connection, struct operation *op,
    const char *owner, const char *path, const char *interface, const char *method,
    GVariant *parameters, const GVariantType *reply) {
    int left = remaining(op);
    if (!left) { if (parameters) g_variant_unref(g_variant_ref_sink(parameters)); return NULL; }
    GError *error = NULL;
    GVariant *result = g_dbus_connection_call_sync(connection, owner, path, interface,
        method, parameters, reply, G_DBUS_CALL_FLAGS_NO_AUTO_START, left, op->cancel, &error);
    if (error) g_error_free(error);
    return result;
}
static char *manager_owner(GDBusConnection *connection, struct operation *op) {
    GVariant *reply = call(connection, op, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "GetNameOwner", g_variant_new("(s)", "org.freedesktop.systemd1"), G_VARIANT_TYPE("(s)"));
    if (!reply) return NULL;
    const char *value = NULL; g_variant_get(reply, "(&s)", &value);
    char *result = value && value[0] == ':' && strlen(value) <= 128 ? g_strdup(value) : NULL;
    g_variant_unref(reply); return result;
}
static int same_user_owner(GDBusConnection *connection, struct operation *op, const char *owner) {
    GVariant *reply = call(connection, op, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "GetConnectionUnixUser", g_variant_new("(s)", owner), G_VARIANT_TYPE("(u)"));
    if (!reply) return 0;
    guint32 uid; g_variant_get(reply, "(u)", &uid); g_variant_unref(reply);
    return uid == (guint32)getuid();
}
static GVariant *property(GDBusConnection *connection, struct operation *op,
    const char *owner, const char *object, const char *interface, const char *name,
    const GVariantType *type) {
    GVariant *reply = call(connection, op, owner, object, "org.freedesktop.DBus.Properties",
        "Get", g_variant_new("(ss)", interface, name), G_VARIANT_TYPE("(v)"));
    if (!reply) return NULL;
    GVariant *boxed = g_variant_get_child_value(reply, 0);
    GVariant *value = g_variant_get_variant(boxed);
    g_variant_unref(boxed); g_variant_unref(reply);
    if (!g_variant_is_of_type(value, type)) { g_variant_unref(value); return NULL; }
    return value;
}
static int string_property(GDBusConnection *connection, struct operation *op,
    const char *owner, const char *object, const char *interface, const char *name, char *out, size_t size) {
    GVariant *value = property(connection, op, owner, object, interface, name, G_VARIANT_TYPE_STRING);
    if (!value) return 0;
    gsize length = 0; const char *text = g_variant_get_string(value, &length);
    int fits = length < size;
    if (fits) memcpy(out, text, length + 1);
    g_variant_unref(value); return fits;
}
int omux_service_observe(const char *runtime, const char *unit,
    const char *fragment, uint32_t timeout, struct omux_service_observation *out) {
    if (!out) return OMUX_SERVICE_INVALID;
    memset(out, 0, sizeof(*out)); out->status = OMUX_SERVICE_UNAVAILABLE;
    if (!absolute(runtime) || !absolute(fragment) || !unit ||
        (strcmp(unit, "ai.xoxd.omux.service") && strcmp(unit, "ai.xoxd.omux.dev.service")))
        return out->status = OMUX_SERVICE_INVALID;
    timeout = timeout ? timeout : 1; if (timeout > 2000) timeout = 2000;
    struct operation op;
    if (!start_operation(&op, timeout)) return out->status;
    GSocket *socket = NULL; GSocketConnection *stream = NULL;
    GDBusConnection *connection = NULL; char *owner = NULL, *last_owner = NULL, *object = NULL;
    GVariant *reply = NULL; GError *error = NULL;
    int unsafe = 0; int fd = open_bus(runtime, &op, &unsafe);
    if (fd < 0) { if (unsafe) out->status = OMUX_SERVICE_UNSAFE_BUS; goto finish; }
    socket = g_socket_new_from_fd(fd, &error);
    if (!socket) { close(fd); goto finish; }
    stream = g_socket_connection_factory_create_connection(socket);
    connection = g_dbus_connection_new_sync(G_IO_STREAM(stream), NULL,
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
        NULL, op.cancel, &error);
    if (!connection) goto finish;
    g_dbus_connection_set_exit_on_close(connection, FALSE);
    owner = manager_owner(connection, &op);
    if (!owner) goto finish;
    if (!same_user_owner(connection, &op, owner)) { out->status = OMUX_SERVICE_UNSAFE_BUS; goto finish; }
    reply = call(connection, &op, owner, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
        "GetUnit", g_variant_new("(s)", unit), G_VARIANT_TYPE("(o)"));
    if (!reply) goto finish;
    const char *object_value; g_variant_get(reply, "(&o)", &object_value);
    if (strlen(object_value) > 1024) goto finish;
    object = g_strdup(object_value); g_variant_unref(reply); reply = NULL;
    char id[128], selected_fragment[4097], active[32], loaded[32];
    if (!string_property(connection, &op, owner, object, "org.freedesktop.systemd1.Unit", "Id", id, sizeof(id)) ||
        !string_property(connection, &op, owner, object, "org.freedesktop.systemd1.Unit", "FragmentPath", selected_fragment, sizeof(selected_fragment)) ||
        !string_property(connection, &op, owner, object, "org.freedesktop.systemd1.Unit", "ActiveState", active, sizeof(active)) ||
        !string_property(connection, &op, owner, object, "org.freedesktop.systemd1.Unit", "LoadState", loaded, sizeof(loaded))) goto finish;
    GVariant *pid = property(connection, &op, owner, object, "org.freedesktop.systemd1.Service", "MainPID", G_VARIANT_TYPE_UINT32);
    if (!pid) goto finish;
    out->responder_pid = g_variant_get_uint32(pid) == (guint32)getpid() ? OMUX_SERVICE_MATCHES : OMUX_SERVICE_DIFFERS;
    g_variant_unref(pid);
    GVariant *drops = property(connection, &op, owner, object, "org.freedesktop.systemd1.Unit", "DropInPaths", G_VARIANT_TYPE_STRING_ARRAY);
    if (!drops) goto finish;
    out->no_dropins = g_variant_n_children(drops) == 0 ? OMUX_SERVICE_MATCHES : OMUX_SERVICE_DIFFERS;
    g_variant_unref(drops);
    GVariant *reload = property(connection, &op, owner, object, "org.freedesktop.systemd1.Unit", "NeedDaemonReload", G_VARIANT_TYPE_BOOLEAN);
    if (!reload) goto finish;
    out->no_reload = g_variant_get_boolean(reload) ? OMUX_SERVICE_DIFFERS : OMUX_SERVICE_MATCHES;
    g_variant_unref(reload);
    reply = call(connection, &op, owner, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
        "GetUnitFileState", g_variant_new("(s)", unit), G_VARIANT_TYPE("(s)"));
    if (!reply) goto finish;
    const char *enabled; g_variant_get(reply, "(&s)", &enabled);
    out->persistent_enabled = !strcmp(enabled, "enabled") ? OMUX_SERVICE_MATCHES :
        (!strcmp(enabled, "disabled") || !strcmp(enabled, "masked") || !strcmp(enabled, "enabled-runtime")) ? OMUX_SERVICE_ABSENT : OMUX_SERVICE_UNKNOWN;
    g_variant_unref(reply); reply = NULL;
    last_owner = manager_owner(connection, &op);
    if (!last_owner || strcmp(owner, last_owner)) goto finish;
    out->unit_identity = !strcmp(id, unit) && !strcmp(loaded, "loaded") ? OMUX_SERVICE_MATCHES : OMUX_SERVICE_DIFFERS;
    out->fragment_binding = !strcmp(selected_fragment, fragment) ? OMUX_SERVICE_MATCHES : OMUX_SERVICE_DIFFERS;
    out->active = !strcmp(active, "active") ? OMUX_SERVICE_MATCHES : OMUX_SERVICE_ABSENT;
    out->status = OMUX_SERVICE_OK;
finish:
    if (!remaining(&op)) out->status = OMUX_SERVICE_TIMEOUT;
    if (out->status != OMUX_SERVICE_OK) {
        uint32_t status = out->status; memset(out, 0, sizeof(*out)); out->status = status;
    }
    if (reply) g_variant_unref(reply);
    g_free(owner); g_free(last_owner); g_free(object);
    if (error) g_error_free(error);
    if (connection) {
        /* Closing is local and asynchronous; never wait for manager work. */
        g_dbus_connection_close(connection, NULL, NULL, NULL);
        g_object_unref(connection);
    }
    if (stream) g_object_unref(stream);
    if (socket) g_object_unref(socket);
    end_operation(&op); return (int)out->status;
}
#else
int omux_service_observe(const char *runtime, const char *unit,
    const char *fragment, uint32_t timeout, struct omux_service_observation *out) {
    (void)runtime; (void)unit; (void)fragment; (void)timeout;
    if (!out) return OMUX_SERVICE_INVALID;
    memset(out, 0, sizeof(*out)); out->status = OMUX_SERVICE_UNSUPPORTED;
    return OMUX_SERVICE_UNSUPPORTED;
}
#endif
