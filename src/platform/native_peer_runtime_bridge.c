/* Owned opaque ABI for Python; production native peer is the only authority.
 * Single owner. No concurrent close/recheck/receive; Python serializes calls. */
#define _GNU_SOURCE
#include "native_peer.h"
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

struct omux_runtime_peer { struct omux_peer_context context; int image; struct stat original_image; };

static int same_image(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_nlink == b->st_nlink && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

int omux_runtime_enable(int socket_fd) { return omux_peer_enable(socket_fd); }

int omux_runtime_capture(int socket_fd, unsigned int uid, int image_fd,
                         struct omux_runtime_peer **out) {
    if (!out) return OMUX_PEER_INVALID;
    *out = NULL;
    struct omux_runtime_peer *peer = calloc(1, sizeof(*peer));
    if (!peer) return OMUX_PEER_SYSTEM;
    peer->context.socket_fd = peer->context.pidfd = peer->image = -1;
    int socket_copy = fcntl(socket_fd, F_DUPFD_CLOEXEC, 0);
    if (socket_copy < 0) { free(peer); return OMUX_PEER_SYSTEM; }
    int status = omux_peer_capture(socket_copy, uid, &peer->context);
    if (status != OMUX_PEER_OK) { close(socket_copy); free(peer); return status; }
    peer->context.owns_socket = 1;
    peer->image = fcntl(image_fd, F_DUPFD_CLOEXEC, 0);
    if (peer->image < 0) status = OMUX_PEER_SYSTEM;
    else if (fstat(peer->image, &peer->original_image)) status = OMUX_PEER_SYSTEM;
    else status = omux_peer_verify_executable_image(&peer->context, peer->image);
    if (status != OMUX_PEER_OK) {
        if (peer->image >= 0) close(peer->image);
        omux_peer_close(&peer->context); free(peer); return status;
    }
    *out = peer; return OMUX_PEER_OK;
}

int omux_runtime_recheck(struct omux_runtime_peer *peer) {
    if (!peer) return OMUX_PEER_INVALID;
    struct stat before, after;
    if (fstat(peer->image, &before)) return OMUX_PEER_IMAGE_UNAVAILABLE;
    if (!same_image(&peer->original_image, &before)) return OMUX_PEER_IMAGE_MISMATCH;
    int status = omux_peer_verify_executable_image(&peer->context, peer->image);
    if (status != OMUX_PEER_OK) return status;
    if (fstat(peer->image, &after)) return OMUX_PEER_IMAGE_UNAVAILABLE;
    return same_image(&peer->original_image, &after) ? OMUX_PEER_OK : OMUX_PEER_IMAGE_MISMATCH;
}

int omux_runtime_receive(struct omux_runtime_peer *peer, unsigned char *buffer,
                         size_t capacity, size_t *received, int *descriptor) {
    if (!received || !descriptor) return OMUX_PEER_INVALID;
    *received = 0; *descriptor = -1;
    if (!peer || !buffer || !capacity || capacity > OMUX_PEER_MAX_PACKET) return OMUX_PEER_INVALID;
    int status = omux_runtime_recheck(peer);
    if (status != OMUX_PEER_OK) return status;
    status = omux_peer_receive_descriptor(&peer->context, buffer, capacity, received, descriptor);
    if (status == OMUX_PEER_OK) status = omux_runtime_recheck(peer);
    if (status != OMUX_PEER_OK) {
        if (*descriptor >= 0) close(*descriptor);
        *descriptor = -1; *received = 0;
        for (size_t index = 0; index < capacity; ++index) buffer[index] = 0;
    }
    return status;
}

void omux_runtime_close(struct omux_runtime_peer *peer) {
    if (!peer) return;
    if (peer->image >= 0) close(peer->image);
    omux_peer_close(&peer->context); free(peer);
}

unsigned int omux_runtime_abi_version(void) { return 1; }
