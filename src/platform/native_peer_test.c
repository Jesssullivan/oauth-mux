#define _GNU_SOURCE
#include "native_peer.h"
#include <stdio.h>
#include <string.h>

#if defined(__linux__)
#include <errno.h>
#include <elf.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
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
static int send_payload(int channel, int descriptor, int multiple, int large_frame) {
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(2 * sizeof(int))]; } control;
    unsigned char payload[64]; memset(payload, 's', sizeof(payload));
    memset(&control, 0, sizeof(control));
    struct iovec iov = { .iov_base = payload, .iov_len = large_frame ? sizeof(payload) : 1 };
    size_t rights = multiple ? 2 * sizeof(int) : sizeof(int);
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = CMSG_SPACE(rights) };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS; cmsg->cmsg_len = CMSG_LEN(rights);
    int descriptors[2] = { descriptor, descriptor };
    memcpy(CMSG_DATA(cmsg), descriptors, rights);
    return sendmsg(channel, &message, MSG_NOSIGNAL) == (ssize_t)iov.iov_len;
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
    } else if (kind >= 6 && kind != 11) {
        int payload = memfd_create("omux-owned-payload-model", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        int size = kind == 8 ? 16385 : kind == 13 ? 0 : 1;
        if (payload < 0 || fchmod(payload, kind == 12 ? 0644 : kind == 16 ? 0400 : 0600) || ftruncate(payload, size)) return 29;
        if (size && pwrite(payload, "a", 1, 0) != 1) return 29;
        if (kind != 7 && fcntl(payload, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) return 29;
        if (kind == 15) {
            char name[64];
            int length = snprintf(name, sizeof(name), "/proc/self/fd/%d", payload);
            if (length <= 0 || (size_t)length >= sizeof(name)) return 29;
            int readonly = open(name, O_RDONLY | O_CLOEXEC);
            struct stat before, after;
            if (readonly < 0 || fstat(payload, &before) || fstat(readonly, &after) ||
                before.st_dev != after.st_dev || before.st_ino != after.st_ino) return 29;
            close(payload); payload = readonly;
        }
        if (!send_payload(fd, payload, kind == 9, kind == 14)) return 29;
        close(payload);
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
    int payload = -1;
    if (kind >= 6 && kind != 10)
        status = omux_peer_receive_descriptor(&peer, buffer, kind == 14 ? 8 : sizeof(buffer), &count, &payload);
    else status = omux_peer_receive(&peer, buffer, kind == 3 ? 8 : sizeof(buffer), kind != 4, &count);
    if (kind == 6 || kind == 15) {
        unsigned char content;
        int seals = payload < 0 ? -1 : fcntl(payload, F_GET_SEALS);
        struct stat metadata;
        if (status != OMUX_PEER_OK || count != 1 || buffer[0] != 's' || payload < 0 ||
            pread(payload, &content, 1, 0) != 1 || content != 'a' ||
            (fcntl(payload, F_GETFD) & FD_CLOEXEC) == 0 ||
            (fcntl(payload, F_GETFL) & O_ACCMODE) != (kind == 15 ? O_RDONLY : O_RDWR) ||
            fstat(payload, &metadata) || (metadata.st_mode & 07777) != 0600 ||
            metadata.st_uid != getuid() || metadata.st_nlink != 0 || metadata.st_size != 1 ||
            seals != (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) ||
            pwrite(payload, "b", 1, 0) != -1 || errno != (kind == 15 ? EBADF : EPERM)) {
            if (payload >= 0) close(payload);
            goto cleanup;
        }
        close(payload);
    } else if (kind >= 7) {
        if (payload != -1 || count != 0 || status != (kind == 14 ? OMUX_PEER_TRUNCATED : OMUX_PEER_RIGHTS)) goto cleanup;
        size_t cleared = kind == 10 ? 1 : kind == 14 ? 8 : sizeof(buffer);
        for (size_t i = 0; i < cleared; ++i) if (buffer[i] != 0) goto cleanup;
    }
    else if (kind == 0) { if (status != OMUX_PEER_OK || count != 11 || memcmp(buffer, "same-thread", 11)) goto cleanup; }
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

/* Real explicit-loader fixture: /proc/exe is the loader while the backend's
 * zero-offset ELF headers and executable PT_LOAD are separate kernel rows.
 * Synthetic role descriptors only exercise attribution, not selection trust. */
extern char **environ;
static int image_fixture_loader(int backend) {
    Elf64_Ehdr header;
    if (pread(backend, &header, sizeof(header), 0) != (ssize_t)sizeof(header) ||
        memcmp(header.e_ident, ELFMAG, SELFMAG) || header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_phnum > 64 || header.e_phentsize != sizeof(Elf64_Phdr)) return -1;
    for (uint16_t i = 0; i < header.e_phnum; ++i) {
        Elf64_Phdr program;
        if (pread(backend, &program, sizeof(program), (off_t)(header.e_phoff + (uint64_t)i * sizeof(program))) != (ssize_t)sizeof(program)) return -1;
        if (program.p_type != PT_INTERP) continue;
        char path[1024];
        if (program.p_filesz < 2 || program.p_filesz > sizeof(path) ||
            pread(backend, path, (size_t)program.p_filesz, (off_t)program.p_offset) != (ssize_t)program.p_filesz ||
            path[program.p_filesz - 1] || memchr(path, 0, (size_t)program.p_filesz - 1)) return -1;
        return open(path, O_RDONLY | O_CLOEXEC);
    }
    return -1;
}
static int image_fixture_copy(int backend, const char *path) {
    int writer = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (writer < 0) return -1;
    unsigned char bytes[4096]; off_t offset = 0;
    int okay = 1;
    for (;;) {
        ssize_t count = pread(backend, bytes, sizeof(bytes), offset);
        if (count < 0) { okay = 0; break; }
        if (!count) break;
        if (write(writer, bytes, (size_t)count) != count) { okay = 0; break; }
        offset += count;
    }
    if (okay && fchmod(writer, 0500)) okay = 0;
    close(writer);
    return okay ? open(path, O_RDONLY | O_CLOEXEC) : -1;
}
static int image_fixture(int direct) {
    char directory[] = "/tmp/omux-image-owned-XXXXXX", path[108], copy_path[108];
    if (!mkdtemp(directory)) return 100;
    snprintf(path, sizeof(path), "%s/peer", directory);
    snprintf(copy_path, sizeof(copy_path), "%s/unmapped", directory);
    int backend = -1, loader = -1, copy = -1, socket_fd = -1, pipes[2] = { -1, -1 }, active = 0, result = 101;
    pid_t child = -1;
    struct omux_peer_context peer;
    backend = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (backend < 0 || (loader = image_fixture_loader(backend)) < 0 || (copy = image_fixture_copy(backend, copy_path)) < 0) goto cleanup;
    if (pipe2(pipes, O_CLOEXEC)) goto cleanup;
    child = fork();
    if (child < 0) goto cleanup;
    if (!child) {
        close(pipes[0]);
        if (fcntl(backend, F_SETFD, 0) || fcntl(copy, F_SETFD, 0) || fcntl(pipes[1], F_SETFD, 0)) _exit(102);
        char backend_path[64], announce[32], copy_arg[32], backend_arg[32], decoy_arg[2];
        snprintf(backend_path, sizeof(backend_path), "/proc/self/fd/%d", backend);
        snprintf(announce, sizeof(announce), "%d", pipes[1]);
        snprintf(copy_arg, sizeof(copy_arg), "%d", copy);
        snprintf(backend_arg, sizeof(backend_arg), "%d", backend);
        snprintf(decoy_arg, sizeof(decoy_arg), "%d", direct == 2);
        char *arguments[] = { (char *)"owned-loader", backend_path, (char *)"--image-child", path, announce, copy_arg, backend_arg, decoy_arg, NULL };
        char *direct_arguments[] = { backend_path, (char *)"--image-child", path, announce, copy_arg, backend_arg, decoy_arg, NULL };
        execveat(direct == 2 ? copy : direct ? backend : loader, "", direct ? direct_arguments : arguments, environ, AT_EMPTY_PATH); _exit(103);
    }
    close(pipes[1]); pipes[1] = -1;
    unsigned char announcement;
    int announced = ready(pipes[0], POLLIN) && read(pipes[0], &announcement, 1) == 1;
    close(pipes[0]); pipes[0] = -1; if (!announced) goto cleanup;
    socket_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (socket_fd < 0 || omux_peer_enable(socket_fd)) goto cleanup;
    struct sockaddr_un address; memset(&address, 0, sizeof(address)); address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) || omux_peer_capture(socket_fd, (uint32_t)getuid(), &peer)) goto cleanup;
    active = 1;
    int count = owned_fd_count();
    if (count < 0) goto cleanup;
    if (omux_peer_verify_bundled_image(&peer, loader, backend) != OMUX_PEER_UNSUPPORTED) { result = 104; goto cleanup; }
    if (omux_peer_inspect_bundled_mappings(&peer, loader, backend) != (direct ? OMUX_PEER_IMAGE_MISMATCH : OMUX_PEER_OK)) { result = 112; goto cleanup; }
    /* Explicit-loader execution really maps the selected backend, yet it is
     * not the kernel primary image. Diagnostic success must not authorize it. */
    if (omux_peer_verify_executable_image(&peer, backend) != (direct == 1 ? OMUX_PEER_OK : OMUX_PEER_IMAGE_MISMATCH)) { result = 113; goto cleanup; }
    /* Same-size/full-byte-identical inode is not selected backend authority.
     * Child maps its offset zero read-only; executable mapping is mandatory. */
    if (omux_peer_inspect_bundled_mappings(&peer, loader, copy) != OMUX_PEER_IMAGE_MISMATCH) { result = 105; goto cleanup; }
    if (omux_peer_verify_executable_image(&peer, copy) != (direct == 2 ? OMUX_PEER_OK : OMUX_PEER_IMAGE_MISMATCH)) { result = 114; goto cleanup; }
    if (!direct && omux_peer_inspect_bundled_mappings(&peer, backend, loader) != OMUX_PEER_IMAGE_MISMATCH) { result = 106; goto cleanup; }
    if (omux_peer_inspect_bundled_mappings(&peer, loader, loader) != OMUX_PEER_IMAGE_MISMATCH) { result = 107; goto cleanup; }
    if (omux_peer_verify_executable_image(&peer, -1) != OMUX_PEER_INVALID) { result = 108; goto cleanup; }
    if (owned_fd_count() != count) { result = 109; goto cleanup; }
    if (send(socket_fd, "q", 1, MSG_NOSIGNAL) != 1 || !ready(socket_fd, POLLIN)) goto cleanup;
    unsigned char reply[64]; size_t received;
    if (omux_peer_receive(&peer, reply, sizeof(reply), 1, &received) || received != 11) goto cleanup;
    if (omux_peer_verify_executable_image(&peer, backend) != (direct == 1 ? OMUX_PEER_OK : OMUX_PEER_IMAGE_MISMATCH) || owned_fd_count() != count) { result = 110; goto cleanup; }
    close(socket_fd); socket_fd = -1;
    int child_status;
    if (waitpid(child, &child_status, 0) != child) goto cleanup;
    child = -1;
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) ||
        omux_peer_verify_executable_image(&peer, backend) != OMUX_PEER_DEPARTED) goto cleanup;
    result = 0;
cleanup:
    if (active) omux_peer_close(&peer);
    if (socket_fd >= 0) close(socket_fd);
    if (pipes[0] >= 0) close(pipes[0]);
    if (pipes[1] >= 0) close(pipes[1]);
    if (child > 0) { kill(child, SIGKILL); waitpid(child, NULL, 0); }
    if (copy >= 0) close(copy);
    if (loader >= 0) close(loader);
    if (backend >= 0) close(backend);
    unlink(path); unlink(copy_path); rmdir(directory); return result;
}

int main(int argc, char **argv) {
    if (argc == 7 && !strcmp(argv[1], "--image-child")) {
        int copy = atoi(argv[4]);
        void *mapping = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, copy, 0);
        if (mapping == MAP_FAILED) return 111;
        void *decoy = MAP_FAILED;
        size_t decoy_length = 0;
        if (atoi(argv[6])) {
            struct stat backend;
            int backend_fd = atoi(argv[5]);
            if (fstat(backend_fd, &backend) || backend.st_size <= 0) return 115;
            decoy_length = (size_t)backend.st_size;
            decoy = mmap(NULL, decoy_length, PROT_READ | PROT_EXEC, MAP_PRIVATE, backend_fd, 0);
            if (decoy == MAP_FAILED) return 116;
        }
        int result = native_child(argv[2], atoi(argv[3]), 0);
        if (decoy != MAP_FAILED) munmap(decoy, decoy_length);
        munmap(mapping, 4096); close(copy); return result;
    }
    for (int direct = 0; direct < 3; ++direct) {
        int image_status = image_fixture(direct);
        if (image_status) { fprintf(stderr, "owned primary-image fixture profile %d failed category %d\n", direct, image_status); return 1; }
    }
    struct omux_peer_witness first, second;
    for (int kind = 0; kind < 17; ++kind) {
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
