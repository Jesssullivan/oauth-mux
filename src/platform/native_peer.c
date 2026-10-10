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
#include <stdio.h>
#include <sys/sysmacros.h>
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

/* Image attribution uses kernel-owned numeric metadata, not argv, mapped
 * filenames or caller-provided hashes. The held authenticated role descriptors
 * prevent inode reuse. Full role-byte authentication belongs to the opaque
 * selection writer; bounded readback here checks actual access and drift. */
#define OMUX_IMAGE_MAPS_LIMIT (1024u * 1024u)
#define OMUX_IMAGE_LINE_LIMIT 4096u
struct image_mapping { uint64_t start, end, offset, major, minor, inode; char permissions[4]; };
struct image_maps { struct image_mapping zero, executable; };

static int image_failure(void) {
    if (errno == ENOENT || errno == ESRCH) return OMUX_PEER_DEPARTED;
    if (errno == EINTR) return OMUX_PEER_INTERRUPTED;
    return OMUX_PEER_IMAGE_UNAVAILABLE;
}

static int image_stat_equal(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
        a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static int image_role(int fd, uint32_t uid, uint64_t limit, struct stat *out) {
    if (fd < 0) return OMUX_PEER_INVALID;
    if (fstat(fd, out)) return image_failure();
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return image_failure();
    if (!S_ISREG(out->st_mode) || !out->st_ino || out->st_size < 64 ||
        (uint64_t)out->st_size > limit || !(out->st_mode & 0111) ||
        (out->st_mode & 0022) || (out->st_uid != uid && out->st_uid != 0) ||
        (flags & O_PATH) || (flags & O_ACCMODE) != O_RDONLY) return OMUX_PEER_IMAGE_MISMATCH;
    return OMUX_PEER_OK;
}

static int image_readback(int actual, int qualified, const struct stat *expected) {
    struct stat before, after;
    if (fstat(actual, &before)) return image_failure();
    if (!image_stat_equal(&before, expected)) return OMUX_PEER_IMAGE_MISMATCH;
    unsigned char first[4096], second[4096];
    size_t length = expected->st_size < (off_t)sizeof(first) ? (size_t)expected->st_size : sizeof(first);
    for (int tail = 0; tail < 2; ++tail) {
        off_t offset = tail ? expected->st_size - (off_t)length : 0;
        ssize_t a = pread(actual, first, length, offset);
        ssize_t b = pread(qualified, second, length, offset);
        if (a < 0 || b < 0) return image_failure();
        if (a != (ssize_t)length || b != (ssize_t)length || memcmp(first, second, length))
            return OMUX_PEER_IMAGE_MISMATCH;
        if (!tail && (memcmp(first, "\177ELF", 4) || first[4] != 2 || first[5] != 1))
            return OMUX_PEER_IMAGE_MALFORMED;
    }
    if (fstat(actual, &after)) return image_failure();
    return image_stat_equal(&before, &after) ? OMUX_PEER_OK : OMUX_PEER_IMAGE_MISMATCH;
}

static int image_number(const char **cursor, const char *end, unsigned int base, uint64_t *out) {
    const char *p = *cursor;
    uint64_t value = 0;
    unsigned int count = 0;
    while (p < end) {
        unsigned int digit;
        if (*p >= '0' && *p <= '9') digit = (unsigned int)(*p - '0');
        else if (*p >= 'a' && *p <= 'f') digit = (unsigned int)(*p - 'a' + 10);
        else break;
        if (digit >= base) break;
        if (value > (UINT64_MAX - digit) / base) return 0;
        value = value * base + digit; ++p; ++count;
    }
    if (!count) return 0;
    *cursor = p; *out = value; return 1;
}

static int image_space(const char **cursor, const char *end) {
    const char *start = *cursor;
    while (*cursor < end && (**cursor == ' ' || **cursor == '\t')) ++*cursor;
    return *cursor != start;
}

static int image_parse_mapping(const char *line, size_t length, struct image_mapping *out) {
    const char *p = line, *end = line + length;
    memset(out, 0, sizeof(*out));
    if (!image_number(&p, end, 16, &out->start) || p == end || *p++ != '-' ||
        !image_number(&p, end, 16, &out->end) || out->start >= out->end || !image_space(&p, end) ||
        end - p < 4) return OMUX_PEER_IMAGE_MALFORMED;
    memcpy(out->permissions, p, 4); p += 4;
    if ((out->permissions[0] != 'r' && out->permissions[0] != '-') ||
        (out->permissions[1] != 'w' && out->permissions[1] != '-') ||
        (out->permissions[2] != 'x' && out->permissions[2] != '-') ||
        (out->permissions[3] != 'p' && out->permissions[3] != 's') ||
        !image_space(&p, end) || !image_number(&p, end, 16, &out->offset) ||
        !image_space(&p, end) || !image_number(&p, end, 16, &out->major) ||
        p == end || *p++ != ':' || !image_number(&p, end, 16, &out->minor) ||
        !image_space(&p, end) || !image_number(&p, end, 10, &out->inode) ||
        (p < end && !image_space(&p, end))) return OMUX_PEER_IMAGE_MALFORMED;
    /* Remaining pathname is intentionally uninterpreted and never compared. */
    return OMUX_PEER_OK;
}

typedef int (*image_line_consumer)(const char *, size_t, void *);
static int image_lines(int directory, const char *name, size_t limit, image_line_consumer consume, void *argument) {
    int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return image_failure();
    struct statfs fs;
    int status = OMUX_PEER_OK;
    if (fstatfs(fd, &fs)) status = image_failure();
    else if (fs.f_type != PROC_SUPER_MAGIC) status = OMUX_PEER_IMAGE_UNAVAILABLE;
    char bytes[4096], line[OMUX_IMAGE_LINE_LIMIT];
    size_t total = 0, used = 0;
    while (status == OMUX_PEER_OK) {
        ssize_t count = read(fd, bytes, sizeof(bytes));
        if (count < 0) { status = image_failure(); break; }
        if (!count) { if (used) status = OMUX_PEER_IMAGE_MALFORMED; break; }
        if ((size_t)count > limit - total) { status = OMUX_PEER_IMAGE_MALFORMED; break; }
        total += (size_t)count;
        for (ssize_t i = 0; i < count && status == OMUX_PEER_OK; ++i) {
            if (!bytes[i] || used == sizeof(line)) { status = OMUX_PEER_IMAGE_MALFORMED; break; }
            if (bytes[i] == '\n') { status = consume(line, used, argument); used = 0; }
            else line[used++] = bytes[i];
        }
    }
    close(fd); return status;
}

struct image_status { uint64_t pid; uint32_t uid, gid; int pid_seen, namespace_seen, uid_seen, gid_seen; };
static int image_status_line(const char *line, size_t length, void *argument) {
    struct image_status *status = argument;
    int is_pid = length >= 4 && !memcmp(line, "Pid:", 4);
    int is_namespace = length >= 6 && !memcmp(line, "NSpid:", 6);
    int is_uid = length >= 4 && !memcmp(line, "Uid:", 4);
    int is_gid = length >= 4 && !memcmp(line, "Gid:", 4);
    if (is_uid || is_gid) {
        const char *p = line + 4, *end = line + length;
        uint64_t value;
        for (int i = 0; i < 4; ++i) {
            if (!image_space(&p, end) || !image_number(&p, end, 10, &value)) return OMUX_PEER_IMAGE_MALFORMED;
            if (value != (is_uid ? status->uid : status->gid)) return OMUX_PEER_WRONG_USER;
        }
        (void)image_space(&p, end);
        if (p != end) return OMUX_PEER_IMAGE_MALFORMED;
        if (is_uid) { if (status->uid_seen++) return OMUX_PEER_IMAGE_MALFORMED; }
        else { if (status->gid_seen++) return OMUX_PEER_IMAGE_MALFORMED; }
        return OMUX_PEER_OK;
    }
    if (!is_pid && !is_namespace) return OMUX_PEER_OK;
    const char *p = line + (is_pid ? 4 : 6), *end = line + length;
    uint64_t pid;
    if (!image_space(&p, end) || !image_number(&p, end, 10, &pid)) return OMUX_PEER_IMAGE_MALFORMED;
    (void)image_space(&p, end);
    /* Single NSpid binds this proc mount's numeric view to our peer namespace.
     * An ancestor-mounted procfs with multiple NSpid values is unsupported. */
    if (p != end) return OMUX_PEER_NAMESPACE;
    if (pid != status->pid) return OMUX_PEER_CHANGED;
    if (is_pid) { if (status->pid_seen++) return OMUX_PEER_IMAGE_MALFORMED; }
    else { if (status->namespace_seen++) return OMUX_PEER_IMAGE_MALFORMED; }
    return OMUX_PEER_OK;
}

struct image_scan { const struct stat *backend; struct image_maps *out; int zero_seen, executable_seen; uint64_t last_end; };
static int image_maps_line(const char *line, size_t length, void *argument) {
    struct image_scan *scan = argument;
    struct image_mapping row;
    int status = image_parse_mapping(line, length, &row);
    if (status != OMUX_PEER_OK) return status;
    if (row.start < scan->last_end) return OMUX_PEER_IMAGE_MALFORMED;
    scan->last_end = row.end;
    if (row.major != (uint64_t)major(scan->backend->st_dev) ||
        row.minor != (uint64_t)minor(scan->backend->st_dev) || row.inode != (uint64_t)scan->backend->st_ino)
        return OMUX_PEER_OK;
    if (row.offset >= (uint64_t)scan->backend->st_size || (row.permissions[1] == 'w' && row.permissions[2] == 'x'))
        return OMUX_PEER_IMAGE_MISMATCH;
    if (!row.offset && !scan->zero_seen) { scan->out->zero = row; scan->zero_seen = 1; }
    if (row.permissions[2] == 'x' && !scan->executable_seen) { scan->out->executable = row; scan->executable_seen = 1; }
    return OMUX_PEER_OK;
}

static int image_proc_check(int directory, uint64_t pid, const struct omux_peer_witness *witness) {
    struct image_status parsed = { .pid = pid, .uid = witness->uid, .gid = witness->gid };
    int status = image_lines(directory, "status", 65536, image_status_line, &parsed);
    if (status != OMUX_PEER_OK) return status;
    if (parsed.pid_seen != 1 || parsed.namespace_seen != 1 || parsed.uid_seen != 1 || parsed.gid_seen != 1)
        return OMUX_PEER_IMAGE_MALFORMED;
    const char *names[] = { "ns/user", "ns/pid" };
    const struct omux_peer_namespace *expected[] = { &witness->user_namespace, &witness->pid_namespace };
    for (size_t i = 0; i < 2; ++i) {
        /* Follow only these kernel namespace symlinks under held procfs. */
        int fd = openat(directory, names[i], O_RDONLY | O_CLOEXEC);
        if (fd < 0) return image_failure();
        struct omux_peer_namespace observed;
        status = fd_identity(fd, NSFS_MAGIC, &observed); close(fd);
        if (status != OMUX_PEER_OK) return status;
        if (!same_namespace(observed, *expected[i])) return OMUX_PEER_NAMESPACE;
    }
    return OMUX_PEER_OK;
}

static int image_peer_recheck(const struct omux_peer_context *peer, uint64_t *pid) {
    struct omux_peer_context fresh;
    int status = omux_peer_alive(peer);
    if (status != OMUX_PEER_OK) return status;
    status = omux_peer_capture(peer->socket_fd, peer->witness.uid, &fresh);
    if (status != OMUX_PEER_OK) return status;
    if (!same_witness(&fresh.witness, &peer->witness)) status = OMUX_PEER_CHANGED;
    omux_peer_close(&fresh);
    if (status != OMUX_PEER_OK) return status;
    struct ucred credentials;
    socklen_t length = sizeof(credentials);
    if (getsockopt(peer->socket_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length)) return failure();
    if (length != sizeof(credentials) || credentials.pid <= 0) return OMUX_PEER_INVALID;
    if (credentials.uid != peer->witness.uid || credentials.gid != peer->witness.gid) return OMUX_PEER_WRONG_USER;
    *pid = (uint64_t)credentials.pid;
    return omux_peer_alive(peer);
}

int omux_peer_verify_bundled_image(const struct omux_peer_context *peer, int loader_fd, int backend_fd) {
    (void)peer; (void)loader_fd; (void)backend_fd;
    return OMUX_PEER_UNSUPPORTED;
}

int omux_peer_inspect_bundled_mappings(const struct omux_peer_context *peer, int loader_fd, int backend_fd) {
    if (!peer || peer->socket_fd < 0 || peer->pidfd < 0) return OMUX_PEER_INVALID;
    uint64_t pid, after_pid;
    int status = image_peer_recheck(peer, &pid);
    if (status != OMUX_PEER_OK) return status;
    struct stat loader, backend, after;
    status = image_role(loader_fd, peer->witness.uid, 128u * 1024u * 1024u, &loader);
    if (status == OMUX_PEER_OK) status = image_role(backend_fd, peer->witness.uid, 512u * 1024u * 1024u, &backend);
    if (status != OMUX_PEER_OK) return status;
    if (loader.st_dev == backend.st_dev && loader.st_ino == backend.st_ino) return OMUX_PEER_IMAGE_MISMATCH;
    char path[64];
    int length = snprintf(path, sizeof(path), "/proc/%llu", (unsigned long long)pid);
    if (length < 0 || (size_t)length >= sizeof(path)) return OMUX_PEER_INVALID;
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return image_failure();
    int executable = -1;
    struct statfs fs;
    if (fstatfs(directory, &fs)) status = image_failure();
    else if (fs.f_type != PROC_SUPER_MAGIC) status = OMUX_PEER_IMAGE_UNAVAILABLE;
    if (status == OMUX_PEER_OK) status = image_proc_check(directory, pid, &peer->witness);
    if (status == OMUX_PEER_OK) {
        /* Intentional kernel exe symlink; actual fd identity must match loader. */
        executable = openat(directory, "exe", O_RDONLY | O_CLOEXEC);
        status = executable < 0 ? image_failure() : image_readback(executable, loader_fd, &loader);
    }
    if (status == OMUX_PEER_OK) status = image_readback(backend_fd, backend_fd, &backend);
    struct image_maps first, second;
    memset(&first, 0, sizeof(first)); memset(&second, 0, sizeof(second));
    for (int pass = 0; pass < 2 && status == OMUX_PEER_OK; ++pass) {
        struct image_scan scan = { .backend = &backend, .out = pass ? &second : &first };
        status = image_lines(directory, "maps", OMUX_IMAGE_MAPS_LIMIT, image_maps_line, &scan);
        if (status == OMUX_PEER_OK && (!scan.zero_seen || !scan.executable_seen)) status = OMUX_PEER_IMAGE_MISMATCH;
        if (status == OMUX_PEER_OK && pass && memcmp(&first, &second, sizeof(first))) status = OMUX_PEER_IMAGE_MISMATCH;
    }
    if (status == OMUX_PEER_OK) status = image_proc_check(directory, pid, &peer->witness);
    if (status == OMUX_PEER_OK) {
        int current = openat(directory, "exe", O_RDONLY | O_CLOEXEC);
        status = current < 0 ? image_failure() : image_readback(current, loader_fd, &loader);
        if (current >= 0) close(current);
    }
    if (status == OMUX_PEER_OK) status = image_readback(backend_fd, backend_fd, &backend);
    if (status == OMUX_PEER_OK && (fstat(loader_fd, &after) || !image_stat_equal(&loader, &after))) status = OMUX_PEER_IMAGE_MISMATCH;
    if (status == OMUX_PEER_OK && (fstat(backend_fd, &after) || !image_stat_equal(&backend, &after))) status = OMUX_PEER_IMAGE_MISMATCH;
    if (status == OMUX_PEER_OK) status = image_peer_recheck(peer, &after_pid);
    if (status == OMUX_PEER_OK && after_pid != pid) status = OMUX_PEER_CHANGED;
    if (executable >= 0) close(executable);
    close(directory); return status;
}

int omux_peer_verify_executable_image(const struct omux_peer_context *peer, int backend_fd) {
    if (!peer || peer->socket_fd < 0 || peer->pidfd < 0) return OMUX_PEER_INVALID;
    uint64_t pid, after_pid;
    int status = image_peer_recheck(peer, &pid);
    if (status != OMUX_PEER_OK) return status;
    struct stat backend, after;
    status = image_role(backend_fd, peer->witness.uid, 512u * 1024u * 1024u, &backend);
    if (status != OMUX_PEER_OK) return status;
    char path[64];
    int length = snprintf(path, sizeof(path), "/proc/%llu", (unsigned long long)pid);
    if (length < 0 || (size_t)length >= sizeof(path)) return OMUX_PEER_INVALID;
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return image_failure();
    struct statfs fs;
    if (fstatfs(directory, &fs)) status = image_failure();
    else if (fs.f_type != PROC_SUPER_MAGIC) status = OMUX_PEER_IMAGE_UNAVAILABLE;
    if (status == OMUX_PEER_OK) status = image_proc_check(directory, pid, &peer->witness);
    /* Independent actual exe opens bracket descriptor readback. A loader or
     * other process mapping the qualified backend is rejected by dev/inode. */
    for (int pass = 0; pass < 2 && status == OMUX_PEER_OK; ++pass) {
        int executable = openat(directory, "exe", O_RDONLY | O_CLOEXEC);
        status = executable < 0 ? image_failure() : image_readback(executable, backend_fd, &backend);
        if (executable >= 0) close(executable);
        if (status == OMUX_PEER_OK) status = image_readback(backend_fd, backend_fd, &backend);
        if (status == OMUX_PEER_OK) status = image_proc_check(directory, pid, &peer->witness);
    }
    if (status == OMUX_PEER_OK) {
        if (fstat(backend_fd, &after)) status = image_failure();
        else if (!image_stat_equal(&backend, &after)) status = OMUX_PEER_IMAGE_MISMATCH;
    }
    if (status == OMUX_PEER_OK) status = image_peer_recheck(peer, &after_pid);
    if (status == OMUX_PEER_OK && after_pid != pid) status = OMUX_PEER_CHANGED;
    close(directory); return status;
}

static int sealed_payload(int fd, uint32_t uid) {
    struct stat info;
    struct statfs filesystem;
    if (fstat(fd, &info) || fstatfs(fd, &filesystem)) return failure();
    const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int seals = fcntl(fd, F_GET_SEALS);
    if (seals < 0 || (seals & required) != required || filesystem.f_type != TMPFS_MAGIC ||
        !S_ISREG(info.st_mode) || info.st_uid != uid || info.st_nlink != 0 ||
        (info.st_mode & 07777) != 0600 || info.st_size <= 0 || info.st_size > 16384)
        return OMUX_PEER_RIGHTS;
    return OMUX_PEER_OK;
}

static int receive_message(struct omux_peer_context *peer, unsigned char *buffer,
                      size_t capacity, int packet_mode, size_t *received, int *descriptor) {
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
    int writer = -1, payload_fd = -1, rights_count = 0, credential_count = 0, writer_count = 0;
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
                else if (cmsg->cmsg_type == SCM_RIGHTS && descriptor && ++rights_count == 1 && fd >= 0) payload_fd = fd;
                else { if (fd >= 0) close(fd); if (cmsg->cmsg_type == SCM_PIDFD) status = OMUX_PEER_INVALID;
                    else if (descriptor) status = OMUX_PEER_RIGHTS; }
            }
            if (cmsg->cmsg_type == SCM_RIGHTS && !descriptor) status = OMUX_PEER_RIGHTS;
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
    if (status == OMUX_PEER_OK && descriptor)
        status = rights_count == 1 && payload_fd >= 0 ? sealed_payload(payload_fd, peer->witness.uid) : OMUX_PEER_RIGHTS;
    if (status == OMUX_PEER_OK) status = omux_peer_alive(peer);
    if (status != OMUX_PEER_OK) {
        if (payload_fd >= 0) close(payload_fd);
        if (count > 0) memset(buffer, 0, (size_t)count);
        return status;
    }
    if (descriptor) *descriptor = payload_fd;
    *received = (size_t)count;
    return OMUX_PEER_OK;
}

int omux_peer_receive(struct omux_peer_context *peer, unsigned char *buffer,
                      size_t capacity, int packet_mode, size_t *received) {
    return receive_message(peer, buffer, capacity, packet_mode, received, NULL);
}

int omux_peer_receive_descriptor(struct omux_peer_context *peer, unsigned char *buffer,
                                size_t capacity, size_t *received, int *descriptor) {
    if (descriptor) *descriptor = -1;
    if (received) *received = 0;
    int status = descriptor ? receive_message(peer, buffer, capacity, 1, received, descriptor) : OMUX_PEER_INVALID;
    if (status != OMUX_PEER_OK && buffer && capacity <= OMUX_PEER_MAX_PACKET) memset(buffer, 0, capacity);
    return status;
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
int omux_peer_receive_descriptor(struct omux_peer_context *p, unsigned char *b, size_t n, size_t *out, int *fd) {
    (void)p;
    if (out) *out = 0;
    if (fd) *fd = -1;
    if (b && n <= OMUX_PEER_MAX_PACKET) memset(b, 0, n);
    return OMUX_PEER_UNSUPPORTED;
}
int omux_peer_alive(const struct omux_peer_context *p) { (void)p; return OMUX_PEER_UNSUPPORTED; }
int omux_peer_verify_bundled_image(const struct omux_peer_context *p, int loader, int backend) {
    (void)p; (void)loader; (void)backend; return OMUX_PEER_UNSUPPORTED;
}
int omux_peer_inspect_bundled_mappings(const struct omux_peer_context *p, int loader, int backend) {
    (void)p; (void)loader; (void)backend; return OMUX_PEER_UNSUPPORTED;
}
int omux_peer_verify_executable_image(const struct omux_peer_context *p, int backend) {
    (void)p; (void)backend; return OMUX_PEER_UNSUPPORTED;
}
int omux_peer_duplicate(const struct omux_peer_context *p, struct omux_peer_context *out) {
    (void)p; if (out) empty_context(out); return OMUX_PEER_UNSUPPORTED;
}
void omux_peer_close(struct omux_peer_context *p) { if (p) empty_context(p); }
#endif
