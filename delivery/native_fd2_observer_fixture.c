/* Synthetic observer stimuli only. Payloads are fixed public literals. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
static void *thread_exec(void *command) {
    char *args[] = {command, (char *)"write", NULL};
    execv(command, args); _exit(2);
}
static void *thread_wait(void *ignored) { (void)ignored; for (;;) pause(); return NULL; }
static void *thread_group_exit(void *ignored) { (void)ignored; _exit(0); }
static void *thread_write(void *ignored) { (void)ignored; write(2, "ignored payload\n", 16); return NULL; }
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "silent")) return 0;
    if (!strcmp(argv[1], "stdout")) return write(1, "fixed stdout\n", 13) != 13;
    if (!strcmp(argv[1], "write")) return write(2, "ignored payload\n", 16) != 16;
    if (!strcmp(argv[1], "writev")) {
        struct iovec v[] = {{(void *)"ignored ", 8}, {(void *)"payload\n", 8}};
        return writev(2, v, 2) != 16;
    }
    if (!strcmp(argv[1], "failed-write")) { close(2); return write(2, "ignored", 7) >= 0; }
    if (!strcmp(argv[1], "sink-other")) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd < 0 || dup2(fd, 2) < 0) return 2;
        close(fd); return write(2, "ignored", 7) != 7;
    }
    if (!strcmp(argv[1], "fork")) {
        pid_t id = fork();
        if (id < 0) return 2;
        if (!id) _exit(write(2, "ignored payload\n", 16) != 16);
        int status; return waitpid(id, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status);
    }
    if (!strcmp(argv[1], "vfork-exec")) {
        char *args[] = {argv[0], (char *)"write", NULL};
        pid_t id = vfork();
        if (id < 0) return 2;
        if (!id) { execv(argv[0], args); _exit(2); }
        int status; return waitpid(id, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status);
    }
    if (!strcmp(argv[1], "thread-exit-group")) {
        pthread_t waiting[3], exiting;
        for (unsigned i = 0; i < 3; ++i)
            if (pthread_create(&waiting[i], NULL, thread_wait, NULL)) return 2;
        if (pthread_create(&exiting, NULL, thread_group_exit, NULL)) return 2;
        for (;;) pause();
    }
    if (!strcmp(argv[1], "thread")) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, thread_write, NULL)) return 2;
        return pthread_join(thread, NULL) != 0;
    }
    if (!strcmp(argv[1], "thread-exec")) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, thread_exec, argv[0])) return 2;
        return pthread_join(thread, NULL) != 0;
    }
    if (!strcmp(argv[1], "exec")) {
        char *args[] = {argv[0], (char *)"write", NULL};
        execv(argv[0], args); return 2;
    }
    if (!strcmp(argv[1], "cancel")) {
        pid_t id = fork();
        if (id < 0) return 2;
        if (id > 0 && write(1, "owned descendants ready\n", 24) != 24) return 2;
        for (;;) pause();
    }
    if (!strcmp(argv[1], "stop-bound")) {
        for (unsigned i = 0; i < 100001; ++i) getpid();
        return 0;
    }
    return 2;
}
