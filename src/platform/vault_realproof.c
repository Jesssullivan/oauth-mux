#define _GNU_SOURCE
#include "vault_bridge.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
static int zero(const unsigned char *bytes);

#if defined(__linux__)
#include <libsecret/secret.h>
#include <sys/stat.h>
#include <fcntl.h>
static const SecretSchema schema = {
    .name = "ai.xoxd.omux.WrappingRoot", .flags = SECRET_SCHEMA_NONE,
    .attributes = { {"service", SECRET_SCHEMA_ATTRIBUTE_STRING},
                    {"root", SECRET_SCHEMA_ATTRIBUTE_STRING}, {NULL, 0} }
};
/* This driver may only run inside the harness's private bus/keyring. */
static int remove_test_item(const char *root) {
    GError *error = NULL;
    gboolean removed = secret_password_clear_sync(&schema, NULL, &error,
        "service", "omux-installation", "root", root, NULL);
    if (error) { g_error_free(error); return 0; }
    return removed;
}
static int corrupt_test_item(const char *root) {
    GError *error = NULL;
    SecretService *service = secret_service_get_sync(SECRET_SERVICE_OPEN_SESSION, NULL, &error);
    if (!service) { if (error) g_error_free(error); return 0; }
    GHashTable *attributes = secret_attributes_build(&schema,
        "service", "omux-installation", "root", root, NULL);
    GList *items = secret_service_search_sync(service, &schema, attributes,
        SECRET_SEARCH_ALL, NULL, &error);
    int ok = !error && items && !items->next;
    if (ok) {
        unsigned char binary[OMUX_VAULT_KEY_BYTES] = {0};
        binary[1] = 255;
        SecretValue *binary_value = secret_value_new((const char *)binary, sizeof(binary), "application/octet-stream");
        ok = secret_item_set_secret_sync(SECRET_ITEM(items->data), binary_value, NULL, &error);
        secret_value_unref(binary_value);
        unsigned char loaded[OMUX_VAULT_KEY_BYTES];
        if (ok) ok = omux_vault_load(root, loaded) == OMUX_VAULT_OK && !memcmp(binary, loaded, sizeof(binary));
        memset(binary, 0, sizeof(binary));
        memset(loaded, 0, sizeof(loaded));
        const unsigned char invalid[] = {0, 255, 0};
        SecretValue *value = secret_value_new((const char *)invalid, sizeof(invalid), "application/octet-stream");
        if (ok) ok = secret_item_set_secret_sync(SECRET_ITEM(items->data), value, NULL, &error);
        secret_value_unref(value);
    }
    if (error) g_error_free(error);
    g_list_free_full(items, g_object_unref);
    g_hash_table_unref(attributes);
    g_object_unref(service);
    return ok;
}
static int rejects_unsafe_runtime(const char *root) {
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    if (!runtime || !*runtime) return 0;
    char *saved = strdup(runtime);
    if (!saved) return 0;
    unsigned char output[OMUX_VAULT_KEY_BYTES];
    int ok = setenv("XDG_RUNTIME_DIR", "", 1) == 0 &&
        omux_vault_create(root, output) == OMUX_VAULT_UNAVAILABLE && zero(output);
    ok = ok && setenv("XDG_RUNTIME_DIR", "relative-runtime", 1) == 0 &&
        omux_vault_create(root, output) == OMUX_VAULT_UNAVAILABLE && zero(output);
    char child[4096], alias[4096], redirected[4096];
    int a = snprintf(child, sizeof(child), "%s/proof-child", saved);
    int b = snprintf(alias, sizeof(alias), "%s-proof-symlink", saved);
    int c = snprintf(redirected, sizeof(redirected), "%s/proof-child", alias);
    if (a <= 0 || b <= 0 || c <= 0 || (size_t)a >= sizeof(child) ||
        (size_t)b >= sizeof(alias) || (size_t)c >= sizeof(redirected)) ok = 0;
    else if (mkdir(child, 0700) != 0) ok = 0;
    else {
        if (symlink(saved, alias) != 0) ok = 0;
        else {
            ok = ok && setenv("XDG_RUNTIME_DIR", redirected, 1) == 0 &&
                omux_vault_create(root, output) == OMUX_VAULT_UNAVAILABLE && zero(output);
            if (unlink(alias) != 0) ok = 0;
        }
        if (rmdir(child) != 0) ok = 0;
    }
    if (setenv("XDG_RUNTIME_DIR", saved, 1) != 0) ok = 0;
    char lock_path[4096], linked_path[4096];
    a = snprintf(lock_path, sizeof(lock_path), "%s/omux-vault-roots.lock", saved);
    b = snprintf(linked_path, sizeof(linked_path), "%s/proof-linked-lock", saved);
    if (a <= 0 || b <= 0 || (size_t)a >= sizeof(lock_path) || (size_t)b >= sizeof(linked_path)) ok = 0;
    else {
        int fd = open(linked_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) ok = 0;
        else {
            if (close(fd) != 0) ok = 0;
            if (link(linked_path, lock_path) != 0) ok = 0;
            else {
                ok = ok && omux_vault_create(root, output) == OMUX_VAULT_UNAVAILABLE && zero(output);
                if (unlink(lock_path) != 0) ok = 0;
            }
            if (unlink(linked_path) != 0) ok = 0;
        }
    }
    free(saved);
    return ok;
}
#elif defined(__APPLE__)
#include <Security/Security.h>
static int remove_test_item(const char *root) {
    SecKeychainRef keychain = NULL;
    SecKeychainItemRef item = NULL;
    Boolean allowed = false;
    if (SecKeychainGetUserInteractionAllowed(&allowed) != errSecSuccess ||
        SecKeychainSetUserInteractionAllowed(false) != errSecSuccess) return 0;
    const char service[] = "ai.xoxd.omux.wrapping-root";
    const char *path = getenv("OMUX_PROOF_KEYCHAIN");
    OSStatus status = path && *path ? SecKeychainOpen(path, &keychain) : errSecNoDefaultKeychain;
    if (status == errSecSuccess)
        status = SecKeychainFindGenericPassword(keychain, sizeof(service) - 1, service,
            (UInt32)strlen(root), root, NULL, NULL, &item);
    if (status == errSecSuccess) status = SecKeychainItemDelete(item);
    if (item) CFRelease(item);
    if (keychain) CFRelease(keychain);
    if (SecKeychainSetUserInteractionAllowed(allowed) != errSecSuccess) return 0;
    return status == errSecSuccess;
}
static int corrupt_test_item(const char *root) {
    SecKeychainRef keychain = NULL;
    SecKeychainItemRef item = NULL;
    Boolean allowed = false;
    const char *path = getenv("OMUX_PROOF_KEYCHAIN");
    if (!path || SecKeychainGetUserInteractionAllowed(&allowed) != errSecSuccess ||
        SecKeychainSetUserInteractionAllowed(false) != errSecSuccess) return 0;
    const char service[] = "ai.xoxd.omux.wrapping-root";
    OSStatus status = SecKeychainOpen(path, &keychain);
    if (status == errSecSuccess)
        status = SecKeychainFindGenericPassword(keychain, sizeof(service) - 1, service,
            (UInt32)strlen(root), root, NULL, NULL, &item);
    if (status == errSecSuccess) {
        unsigned char binary[OMUX_VAULT_KEY_BYTES] = {0};
        binary[1] = 255;
        status = SecKeychainItemModifyContent(item, NULL, sizeof(binary), binary);
        unsigned char loaded[OMUX_VAULT_KEY_BYTES];
        if (status == errSecSuccess && (omux_vault_load(root, loaded) != OMUX_VAULT_OK ||
            memcmp(binary, loaded, sizeof(binary)))) status = errSecDecode;
        memset(loaded, 0, sizeof(loaded));
        memset(binary, 0, sizeof(binary));
        const unsigned char invalid[] = {0, 255, 0};
        if (status == errSecSuccess)
            status = SecKeychainItemModifyContent(item, NULL, sizeof(invalid), invalid);
    }
    if (item) CFRelease(item);
    if (keychain) CFRelease(keychain);
    if (SecKeychainSetUserInteractionAllowed(allowed) != errSecSuccess) return 0;
    return status == errSecSuccess;
}
#else
static int remove_test_item(const char *root) { (void)root; return 0; }
#endif

static int zero(const unsigned char *bytes) {
    for (size_t i = 0; i < OMUX_VAULT_KEY_BYTES; ++i) if (bytes[i]) return 0;
    return 1;
}

int main(void) {
#if defined(__APPLE__)
    /* Dedicated temporary database; never change the default or search list. */
    const char *path = getenv("OMUX_PROOF_KEYCHAIN");
    SecKeychainRef proof_keychain = NULL;
    CFArrayRef search_before = NULL;
    unsigned char password[32];
    /* Apple StorageManager adds only login/System paths to search preferences.
     * Refuse those names, and verify metadata equality without restoring or
     * printing any personal keychain paths. */
    if (!path || !*path || strstr(path, "/login.keychain") ||
        strcmp(path, "/Library/Keychains/System.keychain") == 0 ||
        SecKeychainCopySearchList(&search_before) != errSecSuccess ||
        SecRandomCopyBytes(kSecRandomDefault, sizeof(password), password) != errSecSuccess) return 1;
    OSStatus created_keychain = SecKeychainCreate(path, sizeof(password),
        password, false, NULL, &proof_keychain);
    memset(password, 0, sizeof(password));
    if (created_keychain != errSecSuccess) { CFRelease(search_before); return 1; }
#endif
#if defined(__linux__)
    /* Refuse standalone execution, including accidentally inherited real bus. */
    const char *isolated = getenv("OMUX_ISOLATED_VAULT_PROOF");
    if (!isolated || strcmp(isolated, "private-bus-private-xdg") != 0) return 1;
#endif
    char root[96];
    snprintf(root, sizeof(root), "omux-realproof-v1-%lu", (unsigned long)getpid());
    unsigned char key[OMUX_VAULT_KEY_BYTES], reopened[OMUX_VAULT_KEY_BYTES];
    int created = 0, result = 1;
    const char *stage = "runtime-policy";
#if defined(__linux__)
    if (!rejects_unsafe_runtime(root)) goto done;
#endif
    stage = "missing-read";
    int initial = OMUX_VAULT_UNAVAILABLE;
    for (unsigned int attempt = 0; attempt < 50; ++attempt) {
        initial = omux_vault_load(root, reopened);
        if (initial != OMUX_VAULT_UNAVAILABLE) break;
        usleep(100000);
    }
    if (initial != OMUX_VAULT_MISSING || !zero(reopened)) {
        fprintf(stderr, "native isolated custody initial status=%d\n", initial);
        goto done;
    }
    stage = "create";
    int status = omux_vault_create(root, key);
    if (status != OMUX_VAULT_OK) { fprintf(stderr, "native custody create status=%d\n", status); goto done; }
    created = 1;
    stage = "reopen";
    if (zero(key) || omux_vault_load(root, reopened) != OMUX_VAULT_OK || memcmp(key, reopened, sizeof(key))) goto done;
    stage = "immutable";
    if (omux_vault_create(root, reopened) != OMUX_VAULT_CONFLICT || !zero(reopened)) goto done;
    if (omux_vault_load(root, reopened) != OMUX_VAULT_OK || memcmp(key, reopened, sizeof(key))) goto done;
#if defined(__linux__) || defined(__APPLE__)
    stage = "malformed";
    if (!corrupt_test_item(root) || omux_vault_load(root, reopened) != OMUX_VAULT_INVALID_KEY || !zero(reopened)) goto done;
#endif
    if (!remove_test_item(root)) goto done;
    stage = "deleted-read";
    created = 0;
    if (omux_vault_load(root, reopened) != OMUX_VAULT_MISSING || !zero(reopened)) goto done;
    result = 0;
done:
    if (created && !remove_test_item(root)) result = 1;
#if defined(__APPLE__)
    if (SecKeychainDelete(proof_keychain) != errSecSuccess) result = 1;
    CFRelease(proof_keychain);
    CFArrayRef search_after = NULL;
    if (SecKeychainCopySearchList(&search_after) != errSecSuccess ||
        !search_after || !CFEqual(search_before, search_after)) result = 1;
    if (search_after) CFRelease(search_after);
    CFRelease(search_before);
#endif
    memset(key, 0, sizeof(key));
    memset(reopened, 0, sizeof(reopened));
    if (result) fprintf(stderr, "native isolated custody failed stage=%s\n", stage);
    if (!result) puts("native isolated custody: create/reopen/immutable/delete passed");
    return result;
}
