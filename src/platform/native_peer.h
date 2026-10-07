#ifndef OMUX_NATIVE_PEER_H
#define OMUX_NATIVE_PEER_H
#include <stddef.h>
#include <stdint.h>

#define OMUX_PEER_MAX_PACKET 65536u
#define OMUX_PEER_PROFILE_PIDFS64 1u
enum omux_peer_status {
    OMUX_PEER_OK = 0, OMUX_PEER_UNSUPPORTED, OMUX_PEER_PERMISSION,
    OMUX_PEER_INVALID, OMUX_PEER_WRONG_USER, OMUX_PEER_NAMESPACE,
    OMUX_PEER_CHANGED, OMUX_PEER_DEPARTED, OMUX_PEER_TRUNCATED,
    OMUX_PEER_RIGHTS, OMUX_PEER_WOULD_BLOCK, OMUX_PEER_INTERRUPTED,
    OMUX_PEER_SYSTEM, OMUX_PEER_CLOSED
};
struct omux_peer_namespace { uint64_t device, inode; };
struct omux_peer_witness {
    uint32_t profile;
    unsigned char boot_id[16];
    uint64_t pidfs_device, pidfs_inode;
    struct omux_peer_namespace user_namespace, pid_namespace;
    uint32_t uid, gid;
};
/* Owns pidfd, borrows socket_fd. Never serialize this struct as authority.
 * Single owner; no concurrent receive/close. Initialize only with capture. */
struct omux_peer_context {
    int socket_fd, pidfd, owns_socket;
    struct omux_peer_witness witness;
};
/* Set on listener before listen and outgoing socket before connect. */
int omux_peer_enable(int fd);
int omux_peer_capture(int fd, uint32_t expected_uid, struct omux_peer_context *out);
/* Nonblocking. packet_mode requires SOCK_SEQPACKET; segment mode SOCK_STREAM.
 * Bytes become usable only on OK. All ancillary descriptors are consumed/closed.
 * A caller must discard partial framing and close on any authentication fault. */
int omux_peer_receive(struct omux_peer_context *peer, unsigned char *buffer,
                      size_t capacity, int packet_mode, size_t *received);
int omux_peer_alive(const struct omux_peer_context *peer);
/* Dup owns both duplicated descriptors, leaving original ownership intact. */
int omux_peer_duplicate(const struct omux_peer_context *peer, struct omux_peer_context *out);
void omux_peer_close(struct omux_peer_context *peer);
#endif
