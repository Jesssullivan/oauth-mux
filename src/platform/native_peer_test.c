#define _GNU_SOURCE
#include "native_peer.h"
#include <stdio.h>
#include <string.h>

#if defined(__linux__)
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int ready(int fd, short events) {
    struct pollfd p = { .fd = fd, .events = events };
    return poll(&p, 1, 2500) > 0;
}
static int owned_fd_count(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] == '.') continue;
        if (++count > 256) { count = -1; break; }
    }
    closedir(directory); return count;
}
static int send_right(int channel, int fd, const char *payload) {
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct iovec iov = { .iov_base = (void *)payload, .iov_len = 1 };
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes) };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    return sendmsg(channel, &message, MSG_NOSIGNAL) == 1;
}
static int receive_right(int channel) {
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
    unsigned char byte;
    struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes) };
    if (!ready(channel, POLLIN) || recvmsg(channel, &message, MSG_CMSG_CLOEXEC) != 1) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    if (!cmsg || message.msg_flags & MSG_CTRUNC || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) return -1;
    int fd; memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd)); return fd;
}
/* Every native fixture creates/listens its endpoint itself, after fork.
 * An inherited parent socketpair would authenticate the wrong origin. */
static int native_child(const char *path, int announce, int kind) {
    alarm(6);
    int stream = kind == 4;
    int listener = socket(AF_UNIX, (stream ? SOCK_STREAM : SOCK_SEQPACKET) | SOCK_CLOEXEC, 0);
    if (listener < 0 || omux_peer_enable(listener) != OMUX_PEER_OK) return 10;
    struct sockaddr_un address; memset(&address, 0, sizeof(address)); address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path)) return 11;
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || chmod(path, 0600) || listen(listener, 1)) return 12;
    if (write(announce, "r", 1) != 1 || !ready(listener, POLLIN)) return 13;
    close(announce);
    int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    close(listener);
    if (fd < 0 || omux_peer_enable(fd) != OMUX_PEER_OK) return 14;
    struct omux_peer_context peer;
    if (omux_peer_capture(fd, (uint32_t)getuid(), &peer) != OMUX_PEER_OK) return 15;
    unsigned char bytes[64]; size_t count = 0;
    if (!ready(fd, POLLIN) || omux_peer_receive(&peer, bytes, sizeof(bytes), !stream, &count) != OMUX_PEER_OK || count != 1 || bytes[0] != 'q') return 16;
    omux_peer_close(&peer);
    if (kind == 1 || kind == 4 || kind == 5) {
        int transfer[2] = { -1, -1 };
        if (kind == 4 && send(fd, "{", 1, MSG_NOSIGNAL) != 1) return 17;
        if (kind == 5 && socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, transfer)) return 18;
        pid_t writer = fork();
        if (writer < 0) return 19;
        if (!writer) {
            alarm(3);
            int output = fd;
            if (kind == 5) {
                close(fd); close(transfer[0]);
                output = receive_right(transfer[1]); close(transfer[1]);
            }
            if (output < 0) _exit(20);
            int result = send(output, "}", 1, MSG_NOSIGNAL) == 1;
            unsigned char acknowledgement;
            if (result) result = ready(output, POLLIN) && recv(output, &acknowledgement, 1, 0) == 0;
            close(output); _exit(result ? 0 : 21);
        }
        if (kind == 5) {
            close(transfer[1]);
            if (!send_right(transfer[0], fd, "f")) { kill(writer, SIGKILL); waitpid(writer, NULL, 0); return 22; }
            close(transfer[0]);
        }
        int child_status;
        if (waitpid(writer, &child_status, 0) != writer || !WIFEXITED(child_status) || WEXITSTATUS(child_status)) return 23;
    } else if (kind == 2) {
        int extra = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (extra < 0 || !send_right(fd, extra, "x")) return 24;
        close(extra);
    } else if (kind == 3) {
        unsigned char large[64]; memset(large, 'x', sizeof(large));
        if (send(fd, large, sizeof(large), MSG_NOSIGNAL) != (ssize_t)sizeof(large)) return 25;
    } else if (send(fd, "same-thread", 11, MSG_NOSIGNAL) != 11) return 26;
    /* Keep the origin alive until the parent has consumed/rejected its reply. */
    if (!ready(fd, POLLIN)) return 27;
    if (recv(fd, bytes, sizeof(bytes), 0) != 0) return 28;
    close(fd); return 0;
}

static int fixture(int kind, struct omux_peer_witness *original) {
    char directory[] = "/tmp/omux-peer-owned-XXXXXX", path[108];
    if (!mkdtemp(directory)) return 30;
    snprintf(path, sizeof(path), "%s/peer", directory);
    int pipes[2], socket_fd = -1, duplicate_active = 0, active = 0, result = 31;
    pid_t child = -1;
    struct omux_peer_context peer, duplicate;
    if (pipe2(pipes, O_CLOEXEC)) goto cleanup;
    child = fork();
    if (child < 0) { close(pipes[0]); close(pipes[1]); goto cleanup; }
    if (!child) { close(pipes[0]); _exit(native_child(path, pipes[1], kind)); }
    close(pipes[1]);
    unsigned char announcement;
    int announced = ready(pipes[0], POLLIN) && read(pipes[0], &announcement, 1) == 1;
    close(pipes[0]); if (!announced) goto cleanup;
    socket_fd = socket(AF_UNIX, (kind == 4 ? SOCK_STREAM : SOCK_SEQPACKET) | SOCK_CLOEXEC, 0);
    if (socket_fd < 0 || omux_peer_enable(socket_fd) != OMUX_PEER_OK) goto cleanup;
    struct sockaddr_un address; memset(&address, 0, sizeof(address)); address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address))) goto cleanup;
    int status = omux_peer_capture(socket_fd, (uint32_t)getuid(), &peer);
    if (status != OMUX_PEER_OK) { result = 40 + status; goto cleanup; }
    active = 1;
    if (omux_peer_duplicate(&peer, &duplicate) != OMUX_PEER_OK) goto cleanup;
    duplicate_active = 1;
    if (peer.witness.pidfs_inode != duplicate.witness.pidfs_inode) goto cleanup;
    if (original) *original = peer.witness;
    /* Repeated capture is fresh kernel evidence for the same live process. */
    struct omux_peer_context recaptured;
    if (omux_peer_capture(socket_fd, (uint32_t)getuid(), &recaptured) != OMUX_PEER_OK) goto cleanup;
    int same = recaptured.witness.pidfs_inode == peer.witness.pidfs_inode && recaptured.witness.pidfs_device == peer.witness.pidfs_device;
    omux_peer_close(&recaptured); if (!same) goto cleanup;
    omux_peer_close(&duplicate); duplicate_active = 0;
    if (send(socket_fd, "q", 1, MSG_NOSIGNAL) != 1 || !ready(socket_fd, POLLIN)) goto cleanup;
    unsigned char buffer[64]; memset(buffer, 0xA5, sizeof(buffer)); size_t count;
    int descriptor_count = owned_fd_count();
    if (descriptor_count < 0) goto cleanup;
    status = omux_peer_receive(&peer, buffer, kind == 3 ? 8 : sizeof(buffer), kind != 4, &count);
    if (kind == 0) { if (status != OMUX_PEER_OK || count != 11 || memcmp(buffer, "same-thread", 11)) goto cleanup; }
    else if (kind == 2) { if (status != OMUX_PEER_RIGHTS || count != 0 || buffer[0] != 0) goto cleanup; }
    else if (kind == 3) { if (status != OMUX_PEER_TRUNCATED || count != 0 || buffer[0] != 0) goto cleanup; }
    else if (kind == 4) {
        if (status != OMUX_PEER_OK || count != 1 || buffer[0] != '{' || !ready(socket_fd, POLLIN)) goto cleanup;
        status = omux_peer_receive(&peer, buffer, sizeof(buffer), 0, &count);
        if (status != OMUX_PEER_CHANGED || count != 0 || buffer[0] != 0) goto cleanup;
    } else if (status != OMUX_PEER_CHANGED || count != 0 || buffer[0] != 0) goto cleanup;
    if (owned_fd_count() != descriptor_count) goto cleanup;
    close(socket_fd); socket_fd = -1;
    int child_status;
    if (waitpid(child, &child_status, 0) != child) goto cleanup;
    child = -1;
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) || omux_peer_alive(&peer) != OMUX_PEER_DEPARTED) goto cleanup;
    result = 0;
cleanup:
    if (duplicate_active) omux_peer_close(&duplicate);
    if (active) omux_peer_close(&peer);
    if (socket_fd >= 0) close(socket_fd);
    if (child > 0) { kill(child, SIGKILL); waitpid(child, NULL, 0); }
    unlink(path); rmdir(directory);
    return result;
}

int main(void) {
    struct omux_peer_witness first, second;
    for (int kind = 0; kind < 6; ++kind) {
        int status = fixture(kind, kind == 0 ? &first : NULL);
        if (status) { fprintf(stderr, "owned peer fixture %d failed category %d\n", kind, status); return 1; }
    }
    if (fixture(0, &second) || first.pidfs_inode == second.pidfs_inode) {
        fputs("owned replacement incarnation fixture failed\n", stderr); return 1;
    }
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) ||
        omux_peer_enable(sockets[0]) || omux_peer_enable(sockets[1])) return 1;
    struct omux_peer_context original, owned;
    if (omux_peer_capture(sockets[0], (uint32_t)getuid(), &original) || omux_peer_duplicate(&original, &owned)) return 1;
    omux_peer_close(&original); close(sockets[0]);
    if (send(sockets[1], "d", 1, MSG_NOSIGNAL) != 1) return 1;
    unsigned char byte[1]; size_t received;
    int status = omux_peer_receive(&owned, byte, 1, 1, &received);
    omux_peer_close(&owned); close(sockets[1]);
    if (status != OMUX_PEER_OK || received != 1 || byte[0] != 'd') return 1;
    return 0;
}
#else
int main(void) {
    struct omux_peer_context context;
    return omux_peer_capture(-1, 0, &context) == OMUX_PEER_UNSUPPORTED ? 0 : 1;
}
#endif
