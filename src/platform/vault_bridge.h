#ifndef OMUX_VAULT_BRIDGE_H
#define OMUX_VAULT_BRIDGE_H

/* Stable, narrow ABI. No secret appears in a command line or error string. */
enum omux_vault_status {
    OMUX_VAULT_OK = 0,
    OMUX_VAULT_MISSING = 1,
    OMUX_VAULT_LOCKED = 2,
    OMUX_VAULT_DENIED = 3,
    OMUX_VAULT_CANCELLED = 4,
    OMUX_VAULT_UNAVAILABLE = 5,
    OMUX_VAULT_INVALID_KEY = 6,
    OMUX_VAULT_CONFLICT = 7,
    OMUX_VAULT_BACKEND_FAILURE = 8,
    OMUX_VAULT_INVALID_ROOT = 9
};

#define OMUX_VAULT_KEY_BYTES 32

/* root_id is non-secret, versioned and limited to [A-Za-z0-9._-], 1..96 bytes.
 * Read never creates/unlocks a collection or prompts. Create is insert-only;
 * existing roots are immutable, including when a concurrent creator wins.
 * Outputs are cleared before every operation and remain zero on failure.
 * Linux creators share one per-user OS-store lock, across installations.
 * An explicit XDG_RUNTIME_DIR must be absolute, traverse no symlinks, and end
 * in a user-owned 0700 directory. Empty/unsafe overrides fail unavailable.
 * Only an absent override permits the same checks on /run/user/<uid>.
 * Parent directories must be root/user-owned and not writable by others,
 * except root-owned sticky parents. No directory is created as a fallback. */
int omux_vault_load(const char *root_id, unsigned char out[OMUX_VAULT_KEY_BYTES]);
int omux_vault_create(const char *root_id, unsigned char out[OMUX_VAULT_KEY_BYTES]);

#endif
