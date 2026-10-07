#include "vault_bridge.h"
#include <stddef.h>
#include <string.h>

/* These negative ABI tests never access a user's actual credential store.
 * Invalid identifiers must be rejected before platform IO and clear output. */
static int rejects_and_clears(const char *root) {
    unsigned char key[OMUX_VAULT_KEY_BYTES];
    memset(key, 0xa7, sizeof(key));
    if (omux_vault_load(root, key) != OMUX_VAULT_INVALID_ROOT) return 1;
    for (size_t i = 0; i < sizeof(key); ++i) if (key[i] != 0) return 1;
    memset(key, 0xa7, sizeof(key));
    if (omux_vault_create(root, key) != OMUX_VAULT_INVALID_ROOT) return 1;
    for (size_t i = 0; i < sizeof(key); ++i) if (key[i] != 0) return 1;
    return 0;
}

int main(void) {
    char too_long[98];
    memset(too_long, 'a', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';
    if (rejects_and_clears(NULL) || rejects_and_clears("") ||
        rejects_and_clears("../root") || rejects_and_clears("root\n") ||
        rejects_and_clears(too_long)) return 1;
    return 0;
}
