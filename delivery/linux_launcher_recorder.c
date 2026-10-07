/* Declared, provider-free loader-boundary fixture. Run only inside Bazel. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void hex(FILE *out, const unsigned char *data, size_t size) {
    fputc('"', out);
    for (size_t i = 0; i < size; ++i) fprintf(out, "%02x", data[i]);
    fputc('"', out);
}

static void vector(FILE *out, char **values) {
    fputc('[', out);
    for (size_t i = 0; values[i] != NULL; ++i) {
        if (i != 0) fputc(',', out);
        hex(out, (const unsigned char *)values[i], strlen(values[i]));
    }
    fputc(']', out);
}

static void descriptor(FILE *out, int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(out, "{\"closed\":%d}", errno);
        return;
    }
    fprintf(out, "{\"dev\":%llu,\"ino\":%llu,\"fdflags\":%d,\"statusflags\":%d}",
            (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
            fcntl(fd, F_GETFD), fcntl(fd, F_GETFL));
}

static int denied(long number, int fork_like) {
    errno = 0;
    long result = fork_like ? syscall(number) : syscall(number, ~0UL, NULL, NULL, NULL, NULL);
    if (fork_like && result == 0) _exit(98);
    if (fork_like && result > 0) {
        int status;
        while (waitpid((pid_t)result, &status, 0) < 0 && errno == EINTR) {}
        return 0;
    }
    return result < 0 ? errno : 0;
}

int main(int argc, char **argv) {
    (void)argc;
    const char *report_value = getenv("OMUX_TEST_REPORT_FD");
    const char *extra_value = getenv("OMUX_TEST_EXTRA_FD");
    if (!report_value || !extra_value) return 90;
    int report_fd = atoi(report_value), extra_fd = atoi(extra_value);
    FILE *out = fdopen(report_fd, "w");
    if (!out) return 91;
    struct stat cwd;
    if (stat(".", &cwd) != 0) return 92;
    struct rlimit stack;
    if (getrlimit(RLIMIT_STACK, &stack) != 0) return 92;
    fprintf(out, "{\"pid\":%ld,\"cwd\":[%llu,%llu],\"fds\":{", (long)getpid(),
            (unsigned long long)cwd.st_dev, (unsigned long long)cwd.st_ino);
    for (int fd = 0; fd < 3; ++fd) {
        fprintf(out, "%s\"%d\":", fd ? "," : "", fd);
        descriptor(out, fd);
    }
    fprintf(out, ",\"extra\":");
    descriptor(out, extra_fd);
    fprintf(out, "},\"stack\":[%llu,%llu],\"argv\":",
            (unsigned long long)stack.rlim_cur, (unsigned long long)stack.rlim_max);
    vector(out, argv);
    fprintf(out, ",\"environ\":");
    vector(out, environ);
    unsigned char input[4096];
    size_t used = 0;
    if (fcntl(0, F_GETFD) >= 0) {
        while (used < sizeof(input)) {
            ssize_t got = read(0, input + used, sizeof(input) - used);
            if (got < 0 && errno == EINTR) continue;
            if (got < 0) return 93;
            if (got == 0) break;
            used += (size_t)got;
        }
    }
    fprintf(out, ",\"stdin\":");
    hex(out, input, used);
    fprintf(out, ",\"extraOffset\":%lld,\"openFds\":[", (long long)lseek(extra_fd, 0, SEEK_CUR));
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return 94;
    int first = 1;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        char *end;
        long fd = strtol(entry->d_name, &end, 10);
        if (*entry->d_name == '\0' || *end != '\0' || fd == dirfd(directory)) continue;
        fprintf(out, "%s%ld", first ? "" : ",", fd);
        first = 0;
        errno = 0;
    }
    if (errno != 0 || closedir(directory) != 0) return 95;
    fprintf(out, "],\"denied\":[");
    if (getenv("OMUX_TEST_DENY")) {
#if defined(__x86_64__)
        fprintf(out, "%d,%d,", denied(SYS_fork, 1), denied(SYS_vfork, 1));
#elif !defined(__aarch64__)
#error unsupported fixture architecture
#endif
        fprintf(out, "%d,%d", denied(SYS_clone, 0), denied(SYS_clone3, 0));
    }
    fprintf(out, "]}\n");
    if (fflush(out) != 0) return 96;
    if (getenv("OMUX_TEST_STDOUT") && write(1, "fixture-stdout\n", 15) != 15) return 97;
    if (getenv("OMUX_TEST_STDERR") && write(2, "fixture-stderr\n", 15) != 15) return 97;
    const char *exit_value = getenv("OMUX_TEST_EXIT");
    return exit_value ? atoi(exit_value) : 0;
}
