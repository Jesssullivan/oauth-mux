#define _GNU_SOURCE
#include "service_observation.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
static double monotonic_seconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) abort();
    return value.tv_sec + value.tv_nsec / 1000000000.0;
}
static int observe(const char *runtime, unsigned timeout) {
    struct omux_service_observation result;
    int status = omux_service_observe(runtime, "ai.xoxd.omux.service",
        "/fixture/verified-omux.service", timeout, &result);
    if (status != (int)result.status || result.unit_identity || result.fragment_binding ||
        result.responder_pid || result.no_dropins || result.persistent_enabled || result.active || result.no_reload) return -1;
    return status;
}
static int stop_owned_child(pid_t child, int stop_fd) {
    /* R-N11: this exact PID is the child created below by this test. No named
     * host service, default tmux socket or other session is inspected/signalled. */
    char stop = 'x';
    int notified = 1;
    ssize_t sent;
    do { sent = write(stop_fd, &stop, 1); } while (sent < 0 && errno == EINTR);
    if (sent < 0 && errno != EPIPE) notified = 0;
    close(stop_fd);
    double until = monotonic_seconds() + 1.0;
    int status = 0;
    while (monotonic_seconds() < until) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return notified && WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (result < 0 && errno != EINTR) return 0;
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 1000000 };
        nanosleep(&pause, NULL);
    }
    if (kill(child, SIGKILL) && errno != ESRCH) return 0;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 0;
    return 0;
}
int main(void) {
    int success = 1;
    char runtime[] = "/tmp/omux-service-observation-XXXXXX";
    if (!mkdtemp(runtime) || chmod(runtime, 0700)) return 1;
    char link_path[512], socket_path[512], writable_parent[512], private_child[512];
    snprintf(link_path, sizeof(link_path), "%s/symlink-runtime", runtime);
    snprintf(socket_path, sizeof(socket_path), "%s/bus", runtime);
    snprintf(writable_parent, sizeof(writable_parent), "%s/writable-ancestor", runtime);
    snprintf(private_child, sizeof(private_child), "%s/writable-ancestor/private-child", runtime);
    if (mkdir(writable_parent, 0777) || chmod(writable_parent, 0777) || mkdir(private_child, 0700) ||
        observe(private_child, 100) != OMUX_SERVICE_UNSAFE_BUS) success = 0;
    rmdir(private_child); rmdir(writable_parent);
    if (observe(runtime, 100) != OMUX_SERVICE_UNAVAILABLE) success = 0;
    if (symlink(runtime, link_path) || observe(link_path, 100) != OMUX_SERVICE_UNSAFE_BUS) success = 0;
    unlink(link_path);
    if (chmod(runtime, 0755) || observe(runtime, 100) != OMUX_SERVICE_UNSAFE_BUS) success = 0;
    if (chmod(runtime, 0700)) success = 0;
    /* Changing owner is tested where the sandbox permits it; no privilege
     * escalation or host-owned path is used to manufacture this condition. */
    if (geteuid() == 0) {
        uid_t alternate = getuid() == 1 ? 2 : 1;
        if (chown(runtime, alternate, (gid_t)-1)) success = 0;
        else if (observe(runtime, 100) != OMUX_SERVICE_UNSAFE_BUS) success = 0;
        if (chown(runtime, getuid(), (gid_t)-1)) success = 0;
    }
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(address.sun_path)) { rmdir(runtime); return 1; }
    strcpy(address.sun_path, socket_path);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address,
        offsetof(struct sockaddr_un, sun_path) + strlen(socket_path) + 1) || listen(listener, 1)) {
        if (listener >= 0) close(listener);
        unlink(socket_path); rmdir(runtime); return 1;
    }
    int stopped[2];
    if (pipe2(stopped, O_CLOEXEC)) { close(listener); unlink(socket_path); rmdir(runtime); return 1; }
    pid_t child = fork();
    if (child < 0) { close(stopped[0]); close(stopped[1]); close(listener); unlink(socket_path); rmdir(runtime); return 1; }
    if (child == 0) {
        close(stopped[1]);
        struct pollfd pending[2] = { { .fd = listener, .events = POLLIN }, { .fd = stopped[0], .events = POLLIN } };
        int peer = -1;
        int result;
        do { result = poll(pending, 2, 5000); } while (result < 0 && errno == EINTR);
        if (result > 0 && (pending[0].revents & POLLIN)) peer = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        close(listener);
        /* Accept but never reply to D-Bus authentication. The parent operation
         * must cancel its own handshake; this child has a separate finite wait. */
        struct pollfd stop = { .fd = stopped[0], .events = POLLIN };
        do { result = poll(&stop, 1, 5000); } while (result < 0 && errno == EINTR);
        if (peer >= 0) close(peer);
        close(stopped[0]);
        _exit(result > 0 ? 0 : 1);
    }
    close(stopped[0]); close(listener);
    signal(SIGPIPE, SIG_IGN);
    double began = monotonic_seconds();
    int status = observe(runtime, 2000);
    double elapsed = monotonic_seconds() - began;
    if (status != OMUX_SERVICE_TIMEOUT || elapsed > 2.5) {
        fprintf(stderr, "Service handshake timeout status=%d elapsed=%.3f seconds.\n", status, elapsed);
        success = 0;
    }
    if (!stop_owned_child(child, stopped[1])) success = 0;
    unlink(socket_path);
    if (rmdir(runtime)) success = 0;
    if (!success) fputs("Service observation negative IO fixture failed.\n", stderr);
    return success ? 0 : 1;
}
#else
int main(void) { return 0; }
#endif
