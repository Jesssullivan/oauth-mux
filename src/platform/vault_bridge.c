#define _GNU_SOURCE
#include "vault_bridge.h"

#include <stddef.h>
#include <stdbool.h>
#include <string.h>

static void clear_bytes(void *memory, size_t count) {
    volatile unsigned char *bytes = memory;
    while (count--) *bytes++ = 0;
}

static int valid_root(const char *root) {
    size_t length = 0;
    if (!root) return 0;
    for (; root[length] && length <= 96; ++length) {
        unsigned char c = (unsigned char)root[length];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'))
            return 0;
    }
    return length > 0 && length <= 96;
}

#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <pthread.h>
#if defined(OMUX_VAULT_REALPROOF)
#include <stdlib.h>
#endif

static const char root_service[] = "ai.xoxd.omux.wrapping-root";
static pthread_mutex_t apple_operation_mutex = PTHREAD_MUTEX_INITIALIZER;

static int apple_status(OSStatus status) {
    switch (status) {
    case errSecSuccess: return OMUX_VAULT_OK;
    case errSecItemNotFound: return OMUX_VAULT_MISSING;
    case errSecInteractionNotAllowed: return OMUX_VAULT_LOCKED;
    case errSecAuthFailed: return OMUX_VAULT_DENIED;
    case errSecUserCanceled: return OMUX_VAULT_CANCELLED;
    case errSecNotAvailable: return OMUX_VAULT_UNAVAILABLE;
    case errSecDuplicateItem: return OMUX_VAULT_CONFLICT;
    case errSecDecode: return OMUX_VAULT_INVALID_KEY;
    default: return OMUX_VAULT_BACKEND_FAILURE;
    }
}

static int apple_keychain_status(SecKeychainRef keychain, OSStatus status) {
    if (status != errSecInteractionNotAllowed) return apple_status(status);
    SecKeychainStatus state = 0;
    OSStatus inspected = SecKeychainGetStatus(keychain, &state);
    if (inspected != errSecSuccess) return OMUX_VAULT_UNAVAILABLE;
    return (state & kSecUnlockStateStatus) ? OMUX_VAULT_DENIED : OMUX_VAULT_LOCKED;
}

/* The standalone daemon explicitly uses the configured default file-based
 * Keychain. Data Protection keychain requires a separately proved signed
 * entitlement. File-based Keychain does not honor every SecItem dictionary
 * UI flag, so serialized native calls disable interaction globally and
 * restore the prior value afterward. All Security custody calls in this
 * helper use this guard; the thin UI lives in a separate process. */
static int apple_begin(SecKeychainRef *keychain, Boolean *interaction) {
    if (pthread_mutex_lock(&apple_operation_mutex) != 0) return OMUX_VAULT_BACKEND_FAILURE;
    OSStatus status = SecKeychainGetUserInteractionAllowed(interaction);
    if (status != errSecSuccess) {
        pthread_mutex_unlock(&apple_operation_mutex);
        return apple_status(status);
    }
    status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) {
        pthread_mutex_unlock(&apple_operation_mutex);
        return apple_status(status);
    }
#if defined(OMUX_VAULT_REALPROOF)
    /* Test-only build: never consult the user's default keychain. */
    const char *proof_keychain = getenv("OMUX_PROOF_KEYCHAIN");
    status = proof_keychain && *proof_keychain
        ? SecKeychainOpen(proof_keychain, keychain) : errSecNoDefaultKeychain;
#else
    status = SecKeychainCopyDefault(keychain);
#endif
    if (status == errSecSuccess && *keychain) return OMUX_VAULT_OK;
    OSStatus restored = SecKeychainSetUserInteractionAllowed(*interaction);
    pthread_mutex_unlock(&apple_operation_mutex);
    if (restored != errSecSuccess) return OMUX_VAULT_BACKEND_FAILURE;
    return status == errSecNoDefaultKeychain || (status == errSecSuccess && !*keychain)
        ? OMUX_VAULT_UNAVAILABLE : apple_status(status);
}

static int apple_end(SecKeychainRef keychain, Boolean interaction, int result) {
    CFRelease(keychain);
    OSStatus restored = SecKeychainSetUserInteractionAllowed(interaction);
    pthread_mutex_unlock(&apple_operation_mutex);
    return restored == errSecSuccess ? result : OMUX_VAULT_BACKEND_FAILURE;
}

int omux_vault_load(const char *root_id, unsigned char out[OMUX_VAULT_KEY_BYTES]) {
    clear_bytes(out, OMUX_VAULT_KEY_BYTES);
    if (!valid_root(root_id)) return OMUX_VAULT_INVALID_ROOT;
    SecKeychainRef keychain = NULL;
    Boolean interaction = false;
    int status = apple_begin(&keychain, &interaction);
    if (status != OMUX_VAULT_OK) return status;
    SecKeychainAttribute attributes[] = {
        { kSecServiceItemAttr, sizeof(root_service) - 1, (void *)root_service },
        { kSecAccountItemAttr, (UInt32)strlen(root_id), (void *)root_id }
    };
    SecKeychainAttributeList list = { 2, attributes };
    SecKeychainSearchRef search = NULL;
    SecKeychainItemRef item = NULL;
    SecKeychainItemRef duplicate = NULL;
    void *bytes = NULL;
    UInt32 length = 0;
    status = apple_keychain_status(keychain, SecKeychainSearchCreateFromAttributes(keychain,
        kSecGenericPasswordItemClass, &list, &search));
    if (status != OMUX_VAULT_OK) goto finish;
    status = apple_keychain_status(keychain, SecKeychainSearchCopyNext(search, &item));
    if (status != OMUX_VAULT_OK) goto finish;
    OSStatus next = SecKeychainSearchCopyNext(search, &duplicate);
    if (next == errSecSuccess) { status = OMUX_VAULT_CONFLICT; goto finish; }
    if (next != errSecItemNotFound) { status = apple_keychain_status(keychain, next); goto finish; }
    status = apple_keychain_status(keychain, SecKeychainItemCopyContent(item, NULL, NULL, &length, &bytes));
    if (status != OMUX_VAULT_OK) goto finish;
    if (!bytes || length != OMUX_VAULT_KEY_BYTES) status = OMUX_VAULT_INVALID_KEY;
    else memcpy(out, bytes, OMUX_VAULT_KEY_BYTES);
finish:
    if (bytes) {
        clear_bytes(bytes, length);
        SecKeychainItemFreeContent(NULL, bytes);
    }
    if (duplicate) CFRelease(duplicate);
    if (item) CFRelease(item);
    if (search) CFRelease(search);
    status = apple_end(keychain, interaction, status);
    if (status != OMUX_VAULT_OK) clear_bytes(out, OMUX_VAULT_KEY_BYTES);
    return status;
}

int omux_vault_create(const char *root_id, unsigned char out[OMUX_VAULT_KEY_BYTES]) {
    clear_bytes(out, OMUX_VAULT_KEY_BYTES);
    if (!valid_root(root_id)) return OMUX_VAULT_INVALID_ROOT;
    SecKeychainRef keychain = NULL;
    Boolean interaction = false;
    int status = apple_begin(&keychain, &interaction);
    if (status != OMUX_VAULT_OK) return status;
    unsigned char candidate[OMUX_VAULT_KEY_BYTES] = {0};
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(candidate), candidate) != errSecSuccess) {
        status = OMUX_VAULT_BACKEND_FAILURE;
    } else {
        /* Insert-only AddGenericPassword enforces account/service uniqueness
         * in this declared keychain. No delete/update/upsert operation. */
        status = apple_keychain_status(keychain, SecKeychainAddGenericPassword(keychain,
            sizeof(root_service) - 1, root_service, (UInt32)strlen(root_id), root_id,
            sizeof(candidate), candidate, NULL));
        if (status == OMUX_VAULT_OK) memcpy(out, candidate, sizeof(candidate));
    }
    clear_bytes(candidate, sizeof(candidate));
    status = apple_end(keychain, interaction, status);
    if (status != OMUX_VAULT_OK) clear_bytes(out, OMUX_VAULT_KEY_BYTES);
    return status;
}

#elif defined(__linux__)

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <libsecret/secret.h>

/* libsecret's default service can automatically present prompts, including
 * from CreateItem. Our private service class refuses both prompt paths. */
typedef struct { SecretService parent; } OmuxSecretService;
typedef struct { SecretServiceClass parent; } OmuxSecretServiceClass;
G_DEFINE_TYPE(OmuxSecretService, omux_secret_service, SECRET_TYPE_SERVICE)

static GVariant *deny_prompt_sync(SecretService *self, SecretPrompt *prompt,
                                 GCancellable *cancellable, const GVariantType *type,
                                 GError **error) {
    (void)self; (void)prompt; (void)cancellable; (void)type;
    g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                        "Vault requires explicit user authorization");
    return NULL;
}

static void deny_prompt_async(SecretService *self, SecretPrompt *prompt,
                              const GVariantType *type, GCancellable *cancellable,
                              GAsyncReadyCallback callback, gpointer data) {
    (void)prompt; (void)type;
    GTask *task = g_task_new(self, cancellable, callback, data);
    g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                           "Vault requires explicit user authorization");
    g_object_unref(task);
}

static GVariant *deny_prompt_finish(SecretService *self, GAsyncResult *result, GError **error) {
    (void)self;
    return g_task_propagate_pointer(G_TASK(result), error);
}

static void omux_secret_service_class_init(OmuxSecretServiceClass *klass) {
    SecretServiceClass *service = SECRET_SERVICE_CLASS(klass);
    service->prompt_sync = deny_prompt_sync;
    service->prompt_async = deny_prompt_async;
    service->prompt_finish = deny_prompt_finish;
}

static void omux_secret_service_init(OmuxSecretService *self) { (void)self; }

static const SecretSchema root_schema = {
    .name = "ai.xoxd.omux.WrappingRoot",
    .flags = SECRET_SCHEMA_NONE,
    .attributes = {
        { "service", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { "root", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { NULL, 0 }
    }
};

static int linux_error(const GError *error) {
    if (!error) return OMUX_VAULT_BACKEND_FAILURE;
    if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) return OMUX_VAULT_CANCELLED;
    if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED) ||
        g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED) ||
        g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_AUTH_FAILED)) return OMUX_VAULT_DENIED;
    if (g_error_matches(error, SECRET_ERROR, SECRET_ERROR_IS_LOCKED)) return OMUX_VAULT_LOCKED;
    if (g_error_matches(error, SECRET_ERROR, SECRET_ERROR_NO_SUCH_OBJECT)) return OMUX_VAULT_MISSING;
    if (g_error_matches(error, SECRET_ERROR, SECRET_ERROR_ALREADY_EXISTS)) return OMUX_VAULT_CONFLICT;
    if (error->domain == G_DBUS_ERROR || error->domain == G_IO_ERROR) return OMUX_VAULT_UNAVAILABLE;
    return OMUX_VAULT_BACKEND_FAILURE;
}

/* C foreign calls must have their own cancellation. std.Io cancellation
 * cannot preempt libsecret. One watchdog bounds the entire native operation. */
typedef struct {
    GCancellable *cancellable;
    GMutex mutex;
    GCond condition;
    gboolean done;
    GThread *watchdog;
} VaultOperation;

static gpointer deadline_watchdog(gpointer pointer) {
    VaultOperation *operation = pointer;
    gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
    g_mutex_lock(&operation->mutex);
    while (!operation->done) {
        if (!g_cond_wait_until(&operation->condition, &operation->mutex, deadline)) {
            g_cancellable_cancel(operation->cancellable);
            break;
        }
    }
    g_mutex_unlock(&operation->mutex);
    return NULL;
}

static int operation_start(VaultOperation *operation) {
    memset(operation, 0, sizeof(*operation));
    operation->cancellable = g_cancellable_new();
    g_mutex_init(&operation->mutex);
    g_cond_init(&operation->condition);
    GError *error = NULL;
    operation->watchdog = g_thread_try_new("omux-vault-deadline", deadline_watchdog, operation, &error);
    if (operation->watchdog) return 1;
    if (error) g_error_free(error);
    g_cond_clear(&operation->condition);
    g_mutex_clear(&operation->mutex);
    g_object_unref(operation->cancellable);
    return 0;
}

static void operation_end(VaultOperation *operation) {
    g_mutex_lock(&operation->mutex);
    operation->done = TRUE;
    g_cond_signal(&operation->condition);
    g_mutex_unlock(&operation->mutex);
    g_thread_join(operation->watchdog);
    g_cond_clear(&operation->condition);
    g_mutex_clear(&operation->mutex);
    g_object_unref(operation->cancellable);
}

static SecretService *open_service(VaultOperation *operation, GError **error) {
    SecretService *service = secret_service_open_sync(
        omux_secret_service_get_type(), "org.freedesktop.secrets",
        SECRET_SERVICE_OPEN_SESSION, operation->cancellable, error);
    if (service) g_dbus_proxy_set_default_timeout(G_DBUS_PROXY(service), 10000);
    return service;
}

static int linux_load(SecretService *service, const char *root_id,
                      VaultOperation *operation, unsigned char *out) {
    GHashTable *attributes = secret_attributes_build(
        &root_schema, "service", "omux-installation", "root", root_id, NULL);
    GError *error = NULL;
    GList *items = secret_service_search_sync(service, &root_schema, attributes,
        SECRET_SEARCH_ALL | SECRET_SEARCH_LOAD_SECRETS, operation->cancellable, &error);
    g_hash_table_unref(attributes);
    int status;
    if (error) {
        status = linux_error(error);
        g_error_free(error);
    } else if (!items) {
        status = OMUX_VAULT_MISSING;
    } else if (items->next) {
        status = OMUX_VAULT_CONFLICT;
    } else if (secret_item_get_locked(SECRET_ITEM(items->data))) {
        status = OMUX_VAULT_LOCKED;
    } else {
        SecretValue *value = secret_item_get_secret(SECRET_ITEM(items->data));
        if (!value) {
            status = OMUX_VAULT_UNAVAILABLE;
        } else {
            gsize length = 0;
            const gchar *bytes = secret_value_get(value, &length);
            const gchar *content_type = secret_value_get_content_type(value);
            /* GNOME Keyring preserves the raw binary value but normalizes its
             * returned content type to text/plain. SecretValue's explicit
             * byte count remains authoritative; never strlen/decode the key.
             * Creation additionally verifies exact candidate readback. */
            if (!bytes || length != OMUX_VAULT_KEY_BYTES || !content_type ||
                (strcmp(content_type, "application/octet-stream") != 0 &&
                 strcmp(content_type, "text/plain") != 0)) {
                status = OMUX_VAULT_INVALID_KEY;
            } else {
                memcpy(out, bytes, OMUX_VAULT_KEY_BYTES);
                status = OMUX_VAULT_OK;
            }
            secret_value_unref(value);
        }
    }
    g_list_free_full(items, g_object_unref);
    return status;
}

/* Secret Service CreateItem lacks a unique insert primitive. Serialize Omux
 * creators in the user's private runtime directory, then use CREATE_NONE and
 * reject duplicate search results. Never use CREATE_REPLACE/store/upsert. */
/* Resolve every component without following symlinks. A safe final directory
 * does not compensate for a redirected ancestor. Parent directories must be
 * owned by root or this user and cannot be writable by another user, except
 * for root-owned sticky directories (for isolated /tmp test runtimes). */
static int runtime_directory(const char *path) {
    if (!path || path[0] != '/' || !path[1]) return -1;
    int directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return -1;
    const char *cursor = path + 1;
    while (*cursor) {
        const char *end = strchr(cursor, '/');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        char component[256];
        if (!length || length >= sizeof(component) ||
            (length == 1 && cursor[0] == '.') ||
            (length == 2 && cursor[0] == '.' && cursor[1] == '.')) goto invalid;
        memcpy(component, cursor, length);
        component[length] = 0;
        int child = openat(directory, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child < 0) goto invalid;
        close(directory);
        directory = child;
        struct stat metadata;
        if (fstat(directory, &metadata) != 0 ||
            (metadata.st_uid != 0 && metadata.st_uid != getuid()) ||
            ((metadata.st_mode & 0022) &&
             !(metadata.st_uid == 0 && (metadata.st_mode & S_ISVTX)))) goto invalid;
        if (!end) return directory;
        cursor = end + 1;
        if (!*cursor) goto invalid;
    }
invalid:
    close(directory);
    return -1;
}

static int creation_lock(GCancellable *cancellable) {
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    char default_runtime[64];
    /* Absence permits the OS per-user runtime convention; an explicitly empty
     * or unsafe override fails closed instead of silently changing custody. */
    if (!runtime) {
        int count = snprintf(default_runtime, sizeof(default_runtime), "/run/user/%lu", (unsigned long)getuid());
        if (count <= 0 || (size_t)count >= sizeof(default_runtime)) return -1;
        runtime = default_runtime;
    }
    int directory = runtime_directory(runtime);
    if (directory < 0) return -1;
    struct stat metadata;
    if (fstat(directory, &metadata) != 0 || metadata.st_uid != getuid() ||
        (metadata.st_mode & 0777) != 0700) {
        close(directory);
        return -1;
    }
    int descriptor = openat(directory, "omux-vault-roots.lock",
                            O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    close(directory);
    if (descriptor < 0) return -1;
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != getuid() || (metadata.st_mode & 0777) != 0600 || metadata.st_nlink != 1) {
        close(descriptor);
        return -1;
    }
    for (unsigned int attempt = 0; attempt < 1000; ++attempt) {
        if (g_cancellable_is_cancelled(cancellable)) break;
        if (flock(descriptor, LOCK_EX | LOCK_NB) == 0) return descriptor;
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) break;
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000 };
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
            if (g_cancellable_is_cancelled(cancellable)) break;
        }
    }
    close(descriptor);
    return -1;
}

static int random_key(unsigned char *key, GCancellable *cancellable) {
    size_t filled = 0;
    while (filled < OMUX_VAULT_KEY_BYTES) {
        if (g_cancellable_is_cancelled(cancellable)) return 0;
        /* Invoke the kernel directly: getrandom's libc symbol needs glibc
         * 2.25, while the Zig native target can retain an older ABI floor. */
        ssize_t count = syscall(SYS_getrandom, key + filled, OMUX_VAULT_KEY_BYTES - filled, GRND_NONBLOCK);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        filled += (size_t)count;
    }
    return 1;
}

int omux_vault_load(const char *root_id, unsigned char out[OMUX_VAULT_KEY_BYTES]) {
    clear_bytes(out, OMUX_VAULT_KEY_BYTES);
    if (!valid_root(root_id)) return OMUX_VAULT_INVALID_ROOT;
    VaultOperation operation;
    if (!operation_start(&operation)) return OMUX_VAULT_UNAVAILABLE;
    GError *error = NULL;
    SecretService *service = open_service(&operation, &error);
    int status = service ? linux_load(service, root_id, &operation, out) : linux_error(error);
    if (error) g_error_free(error);
    if (service) g_object_unref(service);
    operation_end(&operation);
    if (status != OMUX_VAULT_OK) clear_bytes(out, OMUX_VAULT_KEY_BYTES);
    return status;
}

int omux_vault_create(const char *root_id, unsigned char out[OMUX_VAULT_KEY_BYTES]) {
    clear_bytes(out, OMUX_VAULT_KEY_BYTES);
    if (!valid_root(root_id)) return OMUX_VAULT_INVALID_ROOT;
    VaultOperation operation;
    if (!operation_start(&operation)) return OMUX_VAULT_UNAVAILABLE;
    int lock = creation_lock(operation.cancellable);
    if (lock < 0) {
        int status = g_cancellable_is_cancelled(operation.cancellable)
            ? OMUX_VAULT_CANCELLED : OMUX_VAULT_UNAVAILABLE;
        operation_end(&operation);
        return status;
    }
    GError *error = NULL;
    SecretService *service = open_service(&operation, &error);
    SecretCollection *collection = NULL;
    GHashTable *attributes = NULL;
    SecretValue *value = NULL;
    SecretItem *item = NULL;
    unsigned char candidate[OMUX_VAULT_KEY_BYTES] = {0};
    unsigned char existing[OMUX_VAULT_KEY_BYTES] = {0};
    int status = service ? linux_load(service, root_id, &operation, existing) : linux_error(error);
    clear_bytes(existing, sizeof(existing));
    if (status == OMUX_VAULT_OK) status = OMUX_VAULT_CONFLICT;
    if (status != OMUX_VAULT_MISSING) goto finish;
    collection = secret_collection_for_alias_sync(service, SECRET_COLLECTION_DEFAULT,
        SECRET_COLLECTION_NONE, operation.cancellable, &error);
    if (!collection) { status = error ? linux_error(error) : OMUX_VAULT_UNAVAILABLE; goto finish; }
    if (secret_collection_get_locked(collection)) { status = OMUX_VAULT_LOCKED; goto finish; }
    if (!random_key(candidate, operation.cancellable)) {
        status = g_cancellable_is_cancelled(operation.cancellable)
            ? OMUX_VAULT_CANCELLED : OMUX_VAULT_BACKEND_FAILURE;
        goto finish;
    }
    attributes = secret_attributes_build(
        &root_schema, "service", "omux-installation", "root", root_id, NULL);
    value = secret_value_new((const gchar *)candidate, sizeof(candidate), "application/octet-stream");
    item = secret_item_create_sync(collection, &root_schema, attributes,
        "Omux encrypted grant custody", value, SECRET_ITEM_CREATE_NONE, operation.cancellable, &error);
    if (!item) { status = error ? linux_error(error) : OMUX_VAULT_DENIED; goto finish; }
    /* A service/client outside Omux might have created the same root. Read
     * all matches to fail closed on ambiguity before using any ciphertext. */
    status = linux_load(service, root_id, &operation, out);
    if (status == OMUX_VAULT_OK && memcmp(candidate, out, sizeof(candidate)) != 0)
        status = OMUX_VAULT_CONFLICT;
finish:
    clear_bytes(candidate, sizeof(candidate));
    if (item) g_object_unref(item);
    if (value) secret_value_unref(value);
    if (attributes) g_hash_table_unref(attributes);
    if (collection) g_object_unref(collection);
    if (service) g_object_unref(service);
    if (error) g_error_free(error);
    operation_end(&operation);
    close(lock);
    if (status != OMUX_VAULT_OK) clear_bytes(out, OMUX_VAULT_KEY_BYTES);
    return status;
}

#else

int omux_vault_load(const char *root_id, unsigned char out[OMUX_VAULT_KEY_BYTES]) {
    clear_bytes(out, OMUX_VAULT_KEY_BYTES);
    return valid_root(root_id) ? OMUX_VAULT_UNAVAILABLE : OMUX_VAULT_INVALID_ROOT;
}

int omux_vault_create(const char *root_id, unsigned char out[OMUX_VAULT_KEY_BYTES]) {
    clear_bytes(out, OMUX_VAULT_KEY_BYTES);
    return valid_root(root_id) ? OMUX_VAULT_UNAVAILABLE : OMUX_VAULT_INVALID_ROOT;
}

#endif
