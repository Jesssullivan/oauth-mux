#define _GNU_SOURCE
#include "native_peer.h"
#include <string.h>

#if defined(__linux__) && defined(__LP64__)
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/ioctl.h>
#include <linux/magic.h>
#include <unistd.h>

/* No libc pidfd wrapper is used. Import the declared kernel UAPI when
 * available; old SDKs compile closed stubs. linux/pidfd.h imports fcntl
 * definitions, so preserve libc's spellings and suppress only its redundant
 * flock structures via the kernel's explicit HAVE_ARCH_STRUCT_FLOCK guard.
 * The kernel also unconditionally declares f_owner_ex; scope an unused kernel
 * tag spelling to this inclusion without changing libc's existing structure. */
#if defined(__has_include)
# if __has_include(<linux/pidfd.h>)
#  pragma push_macro("HAVE_ARCH_STRUCT_FLOCK")
#  undef HAVE_ARCH_STRUCT_FLOCK
#  pragma push_macro("F_SETLEASE")
#  undef F_SETLEASE
#  pragma push_macro("F_GETLEASE")
#  undef F_GETLEASE
#  pragma push_macro("F_NOTIFY")
#  undef F_NOTIFY
#  pragma push_macro("F_DUPFD_QUERY")
#  undef F_DUPFD_QUERY
#  pragma push_macro("F_CREATED_QUERY")
#  undef F_CREATED_QUERY
#  pragma push_macro("F_CANCELLK")
#  undef F_CANCELLK
#  pragma push_macro("F_DUPFD_CLOEXEC")
#  undef F_DUPFD_CLOEXEC
#  pragma push_macro("F_SETPIPE_SZ")
#  undef F_SETPIPE_SZ
#  pragma push_macro("F_GETPIPE_SZ")
#  undef F_GETPIPE_SZ
#  pragma push_macro("F_ADD_SEALS")
#  undef F_ADD_SEALS
#  pragma push_macro("F_GET_SEALS")
#  undef F_GET_SEALS
#  pragma push_macro("F_GET_RW_HINT")
#  undef F_GET_RW_HINT
#  pragma push_macro("F_SET_RW_HINT")
#  undef F_SET_RW_HINT
#  pragma push_macro("F_GET_FILE_RW_HINT")
#  undef F_GET_FILE_RW_HINT
#  pragma push_macro("F_SET_FILE_RW_HINT")
#  undef F_SET_FILE_RW_HINT
#  pragma push_macro("AT_HANDLE_FID")
#  undef AT_HANDLE_FID
#  pragma push_macro("AT_HANDLE_MNT_ID_UNIQUE")
#  undef AT_HANDLE_MNT_ID_UNIQUE
#  pragma push_macro("AT_HANDLE_CONNECTABLE")
#  undef AT_HANDLE_CONNECTABLE
#  pragma push_macro("f_owner_ex")
#  undef f_owner_ex
#  define f_owner_ex omux_unused_kernel_f_owner_ex
#  define HAVE_ARCH_STRUCT_FLOCK 1
#  include <linux/pidfd.h>
#  pragma pop_macro("f_owner_ex")
#  pragma pop_macro("AT_HANDLE_CONNECTABLE")
#  pragma pop_macro("AT_HANDLE_MNT_ID_UNIQUE")
#  pragma pop_macro("AT_HANDLE_FID")
#  pragma pop_macro("F_SET_FILE_RW_HINT")
#  pragma pop_macro("F_GET_FILE_RW_HINT")
#  pragma pop_macro("F_SET_RW_HINT")
#  pragma pop_macro("F_GET_RW_HINT")
#  pragma pop_macro("F_GET_SEALS")
#  pragma pop_macro("F_ADD_SEALS")
#  pragma pop_macro("F_GETPIPE_SZ")
#  pragma pop_macro("F_SETPIPE_SZ")
#  pragma pop_macro("F_DUPFD_CLOEXEC")
#  pragma pop_macro("F_CANCELLK")
#  pragma pop_macro("F_CREATED_QUERY")
#  pragma pop_macro("F_DUPFD_QUERY")
#  pragma pop_macro("F_NOTIFY")
#  pragma pop_macro("F_GETLEASE")
#  pragma pop_macro("F_SETLEASE")
#  pragma pop_macro("HAVE_ARCH_STRUCT_FLOCK")
# endif
#endif

/* glibc 2.28 lacks this read-only ancillary enum. Linux v6.17.13
 * include/linux/socket.h defines SCM_PIDFD=0x04. Enable this compatibility
 * spelling only with actual modern kernel UAPI, never as an old-header fallback. */
#if defined(SO_PEERPIDFD) && defined(SO_PASSPIDFD) && defined(PID_FS_MAGIC) && defined(PIDFD_GET_USER_NAMESPACE) && defined(PIDFD_GET_PID_NAMESPACE)
# ifndef SCM_PIDFD
#  define SCM_PIDFD 0x04
# endif
#endif

#if defined(SO_PEERPIDFD) && defined(SO_PASSPIDFD) && defined(SCM_PIDFD) && defined(PID_FS_MAGIC) && defined(PIDFD_GET_USER_NAMESPACE) && defined(PIDFD_GET_PID_NAMESPACE)
#define OMUX_PEER_SUPPORTED_HEADERS 1
#endif
#endif

static void empty_context(struct omux_peer_context *out) {
    memset(out, 0, sizeof(*out));
    out->socket_fd = out->pidfd = -1;
}

#ifdef OMUX_PEER_SUPPORTED_HEADERS
static int failure(void) {
    switch (errno) {
    case ENOPROTOOPT: case EOPNOTSUPP: case ENOSYS: case ENOTTY:
        return OMUX_PEER_UNSUPPORTED;
    case EACCES: case EPERM: return OMUX_PEER_PERMISSION;
    case ESRCH: case ENODATA: return OMUX_PEER_DEPARTED;
    case EAGAIN: return OMUX_PEER_WOULD_BLOCK;
    case EINTR: return OMUX_PEER_INTERRUPTED;
    default: return OMUX_PEER_SYSTEM;
    }
}

static int fd_identity(int fd, long magic, struct omux_peer_namespace *out) {
    struct statfs fs;
    struct stat stat;
    if (fstatfs(fd, &fs) || fstat(fd, &stat)) return failure();
    if (fs.f_type != magic || !stat.st_ino) return OMUX_PEER_UNSUPPORTED;
    out->device = (uint64_t)stat.st_dev;
    out->inode = (uint64_t)stat.st_ino;
    return OMUX_PEER_OK;
}

static int same_namespace(struct omux_peer_namespace a, struct omux_peer_namespace b) {
    return a.device == b.device && a.inode == b.inode;
}

static int read_boot(unsigned char out[16]) {
    char bytes[38];
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return failure();
    struct statfs fs;
    int status = OMUX_PEER_OK;
    if (fstatfs(fd, &fs)) status = failure();
    else if (fs.f_type != PROC_SUPER_MAGIC) status = OMUX_PEER_UNSUPPORTED;
    ssize_t count = status == OMUX_PEER_OK ? read(fd, bytes, sizeof(bytes)) : -1;
    if (status == OMUX_PEER_OK && count < 0) status = failure();
    close(fd);
    if (status != OMUX_PEER_OK) return status;
    if (count != 37 || bytes[36] != '\n') return OMUX_PEER_INVALID;
    unsigned int digit = 0, value = 0, nonzero = 0;
    for (unsigned int i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (bytes[i] != '-') return OMUX_PEER_INVALID;
            continue;
        }
        unsigned int n;
        if (bytes[i] >= '0' && bytes[i] <= '9') n = (unsigned int)(bytes[i] - '0');
        else if (bytes[i] >= 'a' && bytes[i] <= 'f') n = (unsigned int)(bytes[i] - 'a' + 10);
        else return OMUX_PEER_INVALID;
        value = (value << 4) | n;
        if (++digit % 2 == 0) { out[digit / 2 - 1] = (unsigned char)value; nonzero |= value; value = 0; }
    }
    return digit == 32 && nonzero ? OMUX_PEER_OK : OMUX_PEER_INVALID;
}

static int namespace_witness(int pidfd, unsigned long command, const char *self,
                             struct omux_peer_namespace *out) {
    int peer_namespace = ioctl(pidfd, command, 0);
    if (peer_namespace < 0) return failure();
    int status = fd_identity(peer_namespace, NSFS_MAGIC, out);
    close(peer_namespace);
    if (status != OMUX_PEER_OK) return status;
    int self_namespace = open(self, O_RDONLY | O_CLOEXEC);
    if (self_namespace < 0) return failure();
    struct omux_peer_namespace current;
    status = fd_identity(self_namespace, NSFS_MAGIC, &current);
    close(self_namespace);
    if (status != OMUX_PEER_OK) return status;
    return same_namespace(*out, current) ? OMUX_PEER_OK : OMUX_PEER_NAMESPACE;
}

static int witness_for_pidfd(int fd, struct omux_peer_witness *out) {
    struct omux_peer_namespace identity;
    int status = fd_identity(fd, PID_FS_MAGIC, &identity);
    if (status != OMUX_PEER_OK) return status;
    out->profile = OMUX_PEER_PROFILE_PIDFS64;
    out->pidfs_device = identity.device;
    out->pidfs_inode = identity.inode;
    status = read_boot(out->boot_id);
    if (status != OMUX_PEER_OK) return status;
    status = namespace_witness(fd, PIDFD_GET_USER_NAMESPACE, "/proc/self/ns/user", &out->user_namespace);
    if (status != OMUX_PEER_OK) return status;
    return namespace_witness(fd, PIDFD_GET_PID_NAMESPACE, "/proc/self/ns/pid", &out->pid_namespace);
}

static int same_witness(const struct omux_peer_witness *a, const struct omux_peer_witness *b) {
    return a->profile == b->profile && a->pidfs_device == b->pidfs_device &&
        a->pidfs_inode == b->pidfs_inode && !memcmp(a->boot_id, b->boot_id, 16) &&
        same_namespace(a->user_namespace, b->user_namespace) &&
        same_namespace(a->pid_namespace, b->pid_namespace) && a->uid == b->uid && a->gid == b->gid;
}

int omux_peer_enable(int fd) {
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) ||
        setsockopt(fd, SOL_SOCKET, SO_PASSPIDFD, &one, sizeof(one))) return failure();
    return OMUX_PEER_OK;
}

int omux_peer_alive(const struct omux_peer_context *peer) {
    if (!peer || peer->pidfd < 0) return OMUX_PEER_INVALID;
    struct pollfd p = { .fd = peer->pidfd, .events = POLLIN };
    int ready = poll(&p, 1, 0);
    if (ready < 0) return failure();
    return ready || p.revents ? OMUX_PEER_DEPARTED : OMUX_PEER_OK;
}

int omux_peer_capture(int fd, uint32_t expected_uid, struct omux_peer_context *out) {
    if (!out) return OMUX_PEER_INVALID;
    empty_context(out);
    struct ucred credentials;
    socklen_t length = sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length)) return failure();
    if (length != sizeof(credentials) || credentials.pid <= 0) return OMUX_PEER_INVALID;
    if (credentials.uid != expected_uid || expected_uid != (uint32_t)getuid()) return OMUX_PEER_WRONG_USER;
    const int options[] = { SO_PASSCRED, SO_PASSPIDFD };
    for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); ++i) {
        int enabled = 0;
        length = sizeof(enabled);
        if (getsockopt(fd, SOL_SOCKET, options[i], &enabled, &length)) return failure();
        if (length != sizeof(enabled) || enabled != 1) return OMUX_PEER_UNSUPPORTED;
    }
    int pidfd = -1;
    length = sizeof(pidfd);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &length)) return failure();
    if (length != sizeof(pidfd) || pidfd < 0) { if (pidfd >= 0) close(pidfd); return OMUX_PEER_INVALID; }
    out->socket_fd = fd;
    out->pidfd = pidfd;
    out->witness.uid = credentials.uid;
    out->witness.gid = credentials.gid;
    int status = witness_for_pidfd(pidfd, &out->witness);
    if (status == OMUX_PEER_OK) status = omux_peer_alive(out);
    if (status != OMUX_PEER_OK) omux_peer_close(out);
    return status;
}

int omux_peer_receive(struct omux_peer_context *peer, unsigned char *buffer,
                      size_t capacity, int packet_mode, size_t *received) {
    if (!received) return OMUX_PEER_INVALID;
    *received = 0;
    if (!peer || !buffer || !capacity || capacity > OMUX_PEER_MAX_PACKET || peer->socket_fd < 0)
        return OMUX_PEER_INVALID;
    int status = omux_peer_alive(peer);
    if (status != OMUX_PEER_OK) return status;
    int type = 0;
    socklen_t type_size = sizeof(type);
    if (getsockopt(peer->socket_fd, SOL_SOCKET, SO_TYPE, &type, &type_size)) return failure();
    if (type_size != sizeof(type) || type != (packet_mode ? SOCK_SEQPACKET : SOCK_STREAM)) return OMUX_PEER_INVALID;
    /* Deliberately bounded. Unexpected delivered rights are all closed;
     * undelivered excess rights are disposed by the kernel on truncation. */
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int)) + CMSG_SPACE(8 * sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct iovec iov = { .iov_base = buffer, .iov_len = capacity };
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes) };
    ssize_t count = recvmsg(peer->socket_fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (count < 0) return failure();
    int writer = -1, credential_count = 0, writer_count = 0;
    struct ucred credentials;
    memset(&credentials, 0, sizeof(credentials));
    status = message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) ? OMUX_PEER_TRUNCATED : OMUX_PEER_OK;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        size_t offset = (size_t)((unsigned char *)cmsg - control.bytes);
        if (cmsg->cmsg_len < CMSG_LEN(0) || offset > message.msg_controllen ||
            cmsg->cmsg_len > message.msg_controllen - offset) { status = OMUX_PEER_INVALID; break; }
        size_t payload = cmsg->cmsg_len - CMSG_LEN(0);
        if (cmsg->cmsg_level != SOL_SOCKET) { status = OMUX_PEER_INVALID; continue; }
        if (cmsg->cmsg_type == SCM_RIGHTS || cmsg->cmsg_type == SCM_PIDFD) {
            if (payload % sizeof(int)) status = OMUX_PEER_INVALID;
            for (size_t i = 0; i + sizeof(int) <= payload; i += sizeof(int)) {
                int fd;
                memcpy(&fd, (unsigned char *)CMSG_DATA(cmsg) + i, sizeof(fd));
                if (cmsg->cmsg_type == SCM_PIDFD && payload == sizeof(int) && ++writer_count == 1 && fd >= 0) writer = fd;
                else { if (fd >= 0) close(fd); if (cmsg->cmsg_type == SCM_PIDFD) status = OMUX_PEER_INVALID; }
            }
            if (cmsg->cmsg_type == SCM_RIGHTS) status = OMUX_PEER_RIGHTS;
        } else if (cmsg->cmsg_type == SCM_CREDENTIALS) {
            if (payload != sizeof(credentials) || ++credential_count != 1) status = OMUX_PEER_INVALID;
            else memcpy(&credentials, CMSG_DATA(cmsg), sizeof(credentials));
        } else status = OMUX_PEER_INVALID;
    }
    if (status == OMUX_PEER_OK && (!count || credential_count != 1 || writer_count != 1 || writer < 0))
        status = !count ? OMUX_PEER_CLOSED : OMUX_PEER_INVALID;
    if (status == OMUX_PEER_OK && (credentials.uid != peer->witness.uid || credentials.pid <= 0)) status = OMUX_PEER_WRONG_USER;
    if (status == OMUX_PEER_OK) {
        struct omux_peer_witness current;
        memset(&current, 0, sizeof(current));
        current.uid = credentials.uid;
        current.gid = credentials.gid;
        status = witness_for_pidfd(writer, &current);
        if (status == OMUX_PEER_OK && !same_witness(&peer->witness, &current)) status = OMUX_PEER_CHANGED;
    }
    if (writer >= 0) close(writer);
    if (status == OMUX_PEER_OK) status = omux_peer_alive(peer);
    if (status != OMUX_PEER_OK) { if (count > 0) memset(buffer, 0, (size_t)count); return status; }
    *received = (size_t)count;
    return OMUX_PEER_OK;
}

void omux_peer_close(struct omux_peer_context *peer) {
    if (!peer) return;
    if (peer->pidfd >= 0) close(peer->pidfd);
    if (peer->owns_socket && peer->socket_fd >= 0) close(peer->socket_fd);
    empty_context(peer);
}

int omux_peer_duplicate(const struct omux_peer_context *peer, struct omux_peer_context *out) {
    if (!out || !peer || out == peer) return OMUX_PEER_INVALID;
    empty_context(out);
    int status = omux_peer_alive(peer);
    if (status != OMUX_PEER_OK) return status;
    int socket_fd = fcntl(peer->socket_fd, F_DUPFD_CLOEXEC, 0);
    if (socket_fd < 0) return failure();
    int pidfd = fcntl(peer->pidfd, F_DUPFD_CLOEXEC, 0);
    if (pidfd < 0) { status = failure(); close(socket_fd); return status; }
    *out = *peer;
    out->socket_fd = socket_fd;
    out->pidfd = pidfd;
    out->owns_socket = 1;
    return OMUX_PEER_OK;
}
#else
int omux_peer_enable(int fd) { (void)fd; return OMUX_PEER_UNSUPPORTED; }
int omux_peer_capture(int fd, uint32_t uid, struct omux_peer_context *out) {
    (void)fd; (void)uid;
    if (!out) return OMUX_PEER_INVALID;
    empty_context(out); return OMUX_PEER_UNSUPPORTED;
}
int omux_peer_receive(struct omux_peer_context *p, unsigned char *b, size_t n, int packet, size_t *out) {
    (void)p; (void)b; (void)n; (void)packet;
    if (out) *out = 0;
    return OMUX_PEER_UNSUPPORTED;
}
int omux_peer_alive(const struct omux_peer_context *p) { (void)p; return OMUX_PEER_UNSUPPORTED; }
int omux_peer_duplicate(const struct omux_peer_context *p, struct omux_peer_context *out) {
    (void)p; if (out) empty_context(out); return OMUX_PEER_UNSUPPORTED;
}
void omux_peer_close(struct omux_peer_context *p) { if (p) empty_context(p); }
#endif
