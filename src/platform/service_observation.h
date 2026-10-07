#ifndef OMUX_SERVICE_OBSERVATION_H
#define OMUX_SERVICE_OBSERVATION_H
#include <stdint.h>
/* Read-only diagnostic bridge. No bus auto-launch or systemd mutation. */
enum omux_service_status {
    OMUX_SERVICE_OK = 0, OMUX_SERVICE_UNSUPPORTED, OMUX_SERVICE_UNAVAILABLE,
    OMUX_SERVICE_UNSAFE_BUS, OMUX_SERVICE_TIMEOUT, OMUX_SERVICE_INVALID
};
enum omux_service_probe {
    OMUX_SERVICE_UNKNOWN = 0, OMUX_SERVICE_MATCHES, OMUX_SERVICE_DIFFERS,
    OMUX_SERVICE_ABSENT
};
struct omux_service_observation {
    uint32_t status, unit_identity, fragment_binding, responder_pid;
    uint32_t no_dropins, persistent_enabled, active, no_reload;
};
/* runtime_dir is an explicit launch-time selector. The bridge walks it without
 * symlinks, requires same-user private custody and verifies the connected peer.
 * unit is one of the two fixed Omux names. expected_fragment must already have
 * an independently verified digest. No supplied path is diagnostic authority.
 * timeout_ms is clamped to 1..2000 for the entire operation. */
int omux_service_observe(const char *runtime_dir, const char *unit,
    const char *expected_fragment, uint32_t timeout_ms,
    struct omux_service_observation *out);
#endif
