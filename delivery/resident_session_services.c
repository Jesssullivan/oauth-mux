#define _GNU_SOURCE
#include <gio/gio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static gint64 until;
static int remaining(void) {
    gint64 left = until - g_get_monotonic_time();
    if (left <= 0) return 0;
    return (int)(left > 20000000 ? 20000 : (left + 999) / 1000);
}
static GVariant *invoke(GDBusConnection *bus, const char *method, const char *name, const char *reply) {
    int timeout = remaining();
    if (!timeout) return NULL;
    GError *error = NULL;
    GVariant *value = g_dbus_connection_call_sync(bus,
        "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
        method, g_variant_new("(s)", name), G_VARIANT_TYPE(reply),
        G_DBUS_CALL_FLAGS_NO_AUTO_START, timeout, NULL, &error);
    if (error) g_error_free(error);
    return value;
}
static char *owner(GDBusConnection *bus, const char *name) {
    GVariant *value = invoke(bus, "GetNameOwner", name, "(s)");
    if (!value) return NULL;
    const char *text = NULL;
    g_variant_get(value, "(&s)", &text);
    char *result = NULL;
    if (text && text[0] == ':' && strlen(text) < 128) {
        int safe = 1;
        for (const char *p = text+1; *p; ++p)
            if ((*p < '0' || *p > '9') && *p != '.') safe = 0;
        if (safe) result = g_strdup(text);
    }
    g_variant_unref(value);
    return result;
}
static int number(GDBusConnection *bus, const char *method, const char *name, guint32 *out) {
    GVariant *value = invoke(bus, method, name, "(u)");
    if (!value) return 0;
    g_variant_get(value, "(u)", out);
    g_variant_unref(value);
    return 1;
}
static int name_is_absent(GDBusConnection *bus, const char *name) {
    GVariant *value = invoke(bus, "NameHasOwner", name, "(b)");
    if (!value) return 0;
    gboolean present = TRUE;
    g_variant_get(value, "(b)", &present);
    g_variant_unref(value);
    return !present && remaining();
}
int main(int argc, char **argv) {
    const char *address = getenv("DBUS_SESSION_BUS_ADDRESS");
    const char *deadline = getenv("OMUX_RESIDENT_ORIGINAL_DEADLINE_NS");
    int allow_missing = argc == 2 && !strcmp(argv[1], "--allow-missing-secret-service-before-first-start");
    if ((argc != 1 && !allow_missing) || !address || strcmp(address, "unix:path=/omux-resident-inputs/bus")
        || !deadline || !*deadline || strlen(deadline) > 20) return 1;
    for (const char *p = deadline; *p; ++p) if (*p < '0' || *p > '9') return 1;
    char *end = NULL;
    unsigned long long ns = strtoull(deadline, &end, 10);
    if (!end || *end || ns > INT64_MAX || ns/1000 > (unsigned long long)g_get_monotonic_time()+1200000000ULL)
        return 1;
    until = (gint64)(ns/1000);
    if (!remaining()) return 1;
    GError *error = NULL;
    GDBusConnection *bus = g_dbus_connection_new_for_address_sync(address,
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
        NULL, NULL, &error);
    if (error) g_error_free(error);
    if (!bus) return 1;
    GIOStream *stream = g_dbus_connection_get_stream(bus);
    struct ucred broker; socklen_t size = sizeof(broker);
    int ok = G_IS_SOCKET_CONNECTION(stream);
    if (ok) {
        GSocket *socket = g_socket_connection_get_socket(G_SOCKET_CONNECTION(stream));
        ok = !getsockopt(g_socket_get_fd(socket), SOL_SOCKET, SO_PEERCRED, &broker, &size)
            && size == sizeof(broker) && broker.uid == getuid() && broker.pid > 1;
    }
    char *manager = ok ? owner(bus, "org.freedesktop.systemd1") : NULL;
    char *secret = manager ? owner(bus, "org.freedesktop.secrets") : NULL;
    guint32 manager_uid=0, manager_pid=0, secret_uid=0, secret_pid=0;
    ok = manager && number(bus, "GetConnectionUnixUser", manager, &manager_uid)
        && number(bus, "GetConnectionUnixProcessID", manager, &manager_pid)
        && manager_uid == getuid() && manager_pid > 1 && remaining();
    if (secret) ok = ok && number(bus, "GetConnectionUnixUser", secret, &secret_uid)
        && number(bus, "GetConnectionUnixProcessID", secret, &secret_pid)
        && secret_uid == getuid() && secret_pid > 1 && remaining();
    else ok = ok && allow_missing && name_is_absent(bus, "org.freedesktop.secrets");
    if (ok) {
        printf("{\"schema_version\":1,\"broker\":{\"pid\":%d,\"uid\":%u},"
            "\"manager\":{\"owner\":\"%s\",\"pid\":%u,\"uid\":%u},\"secret_service\":",
            broker.pid, broker.uid, manager, manager_pid, manager_uid);
        if (secret) printf("{\"owner\":\"%s\",\"pid\":%u,\"uid\":%u}",secret,secret_pid,secret_uid);
        else printf("null");
        printf("}\n");
    }
    g_free(manager); g_free(secret); g_object_unref(bus);
    return ok ? 0 : 1;
}
