/* Diagnostic only: trace one owned launch. Never read argument buffers,
 * iovecs, names, logs or application memory; maps retain numeric fields only. No continuity authority. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error diagnostic observer requires Linux x86_64
#endif
#define TASK_CAP 256
#define STOP_CAP 100000
/* Reserve 0.5s for cleanup inside the absolute 19s budget. */
#define RUN_NS 18500000000LL
#define TOTAL_NS 19000000000LL

/* Fixed Linux ptrace UAPI layout, without importing conflicting enum macros. */
struct syscall_info {
    uint8_t op, pad[3];
    uint32_t arch;
    uint64_t instruction_pointer, stack_pointer;
    union {
        struct { uint64_t nr, args[6]; } entry;
        struct { int64_t rval; uint8_t is_error; } exit;
    } u;
};
struct task {
    pid_t id;
    int pending;
    const char *image, *sink, *call, *origin;
};
static struct task tasks[TASK_CAP];
static unsigned count, stops;
static int role_fds[3];
static volatile sig_atomic_t cancelled;
static void on_signal(int ignored) { (void)ignored; cancelled = 1; }
static int64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}
static struct task *find(pid_t id) {
    for (unsigned i = 0; i < count; ++i)
        if (tasks[i].id == id) return &tasks[i];
    return NULL;
}
static struct task *add(pid_t id) {
    struct task *t = find(id);
    if (t) return t;
    if (count == TASK_CAP) return NULL;
    t = &tasks[count++];
    memset(t, 0, sizeof(*t));
    t->id = id;
    return t;
}
static void remove_task(pid_t id) {
    for (unsigned i = 0; i < count; ++i)
        if (tasks[i].id == id) { tasks[i] = tasks[--count]; return; }
}
static int same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino
        && (a->st_mode & S_IFMT) == (b->st_mode & S_IFMT);
}
static int proc_single_namespace(int proc, int64_t end_ns) {
    /* NSpid is relative to the proc mount's PID namespace. Exactly one value
     * equal to getpid refuses ancestor-mounted views even on numeric collision.
     * Only this literal metadata field is retained; all other fields, including
     * process names, are discarded while streaming. */
    int fd = openat(proc, "self/status", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    const char key[] = "NSpid:";
    char chunk[4096], field[64];
    size_t bytes = 0, used = 0;
    int match = 1, seen = 0, ok = 0;
    for (;;) {
        if (now_ns() < 0 || now_ns() >= end_ns) break;
        ssize_t got = read(fd, chunk, sizeof(chunk));
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) break;
        if (!got) { ok = seen == 1; break; }
        bytes += (size_t)got;
        if (bytes > 65536) break;
        for (ssize_t i = 0; i < got; ++i) {
            char ch = chunk[i];
            if (ch == '\n') {
                if (match && used >= sizeof(key) - 1) {
                    if (++seen != 1) goto done_ns;
                    field[used] = 0;
                    const char *p = field + sizeof(key) - 1;
                    while (*p == ' ' || *p == '\t') ++p;
                    if (*p < '1' || *p > '9') goto done_ns;
                    unsigned long value = 0;
                    do {
                        if (value > 214748364UL) goto done_ns;
                        value = value * 10 + (unsigned)(*p++ - '0');
                    } while (*p >= '0' && *p <= '9');
                    while (*p == ' ' || *p == '\t') ++p;
                    if (*p || value != (unsigned long)getpid()) goto done_ns;
                }
                used = 0; match = 1;
            } else if (match) {
                if (used < sizeof(key) - 1 && ch != key[used]) { match = 0; continue; }
                if (used == sizeof(field) - 1) goto done_ns;
                field[used++] = ch;
            }
        }
    }
done_ns:
    explicit_bzero(chunk, sizeof(chunk));
    explicit_bzero(field, sizeof(field));
    close(fd);
    return ok ? 0 : -1;
}
static int proc_profile(int proc, int64_t end_ns) {
    /* Refuse a proc mount whose numeric IDs do not match this PID namespace.
     * No readlink, process name or namespace path is collected or emitted. */
    char numeric[32];
    if (snprintf(numeric, sizeof(numeric), "%ld", (long)getpid()) <= 0) return -1;
    int own = openat(proc, "self", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int named = openat(proc, numeric, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    struct stat a, b;
    int ok = own >= 0 && named >= 0 && !fstat(own, &a) && !fstat(named, &b) && same(&a, &b);
    if (own >= 0) close(own);
    if (named >= 0) close(named);
    return ok && !proc_single_namespace(proc, end_ns) ? 0 : -1;
}
static int stable(const struct stat *a, const struct stat *b) {
    return same(a, b) && a->st_mode == b->st_mode && a->st_nlink == b->st_nlink
        && a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_size == b->st_size
        && a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec
        && a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static int64_t deadline_arg(const char *s) {
    char *end; errno = 0;
    long long n = strtoll(s, &end, 10);
    return !errno && *s && !*end && n > 0 ? n : -1;
}
static int fd_arg(const char *s) {
    char *end;
    errno = 0;
    long n = strtol(s, &end, 10);
    return !errno && *s && !*end && n >= 3 && n <= 1048575 ? (int)n : -1;
}
static const char *map_origin(int dir, uint64_t pc, const struct stat *backend,
                              const struct stat *loader, const struct stat *libc, int64_t end_ns) {
    int fd = openat(dir, "maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || pc < 2) { if (fd >= 0) close(fd); return "origin-unavailable"; }
    pc -= 2; /* x86_64 syscall instruction preceding the sampled entry RIP. */
    char chunk[4096], prefix[256];
    size_t used = 0, bytes = 0, lines = 0;
    int fields = 0, in_field = 0, discard = 0;
    const char *result = "origin-unavailable";
    for (;;) {
        if (now_ns() < 0 || now_ns() >= end_ns) break;
        ssize_t got = read(fd, chunk, sizeof(chunk));
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) break;
        if (!got) { if (!used && !fields) result = "origin-other"; break; }
        bytes += (size_t)got;
        if (bytes > 1048576) break;
        for (ssize_t i = 0; i < got; ++i) {
            unsigned char ch = (unsigned char)chunk[i];
            if (ch == '\n') {
                if (++lines > 4096 || fields != 5 || used == sizeof(prefix) - 1) goto done;
                prefix[used] = 0;
                unsigned long long lo, hi, offset, inode;
                unsigned major_no, minor_no;
                char flags[5];
                int end = 0;
                if (sscanf(prefix, "%llx-%llx %4s %llx %x:%x %llu %n",
                           &lo, &hi, flags, &offset, &major_no, &minor_no, &inode, &end) != 7
                        || end <= 0 || prefix[end] || lo >= hi || strlen(flags) != 4
                        || (flags[0] != 'r' && flags[0] != '-')
                        || (flags[1] != 'w' && flags[1] != '-')
                        || (flags[2] != 'x' && flags[2] != '-')
                        || (flags[3] != 'p' && flags[3] != 's')) goto done;
                if (pc >= lo && pc < hi) {
                    if (flags[2] != 'x') goto done;
                    const struct stat *roles[] = {backend, loader, libc};
                    const char *names[] = {"origin-backend", "origin-loader", "origin-libc"};
                    result = "origin-other";
                    for (unsigned role = 0; role < 3; ++role)
                        if ((unsigned long long)roles[role]->st_ino == inode
                                && major(roles[role]->st_dev) == major_no
                                && minor(roles[role]->st_dev) == minor_no) { result = names[role]; break; }
                    goto done;
                }
                used = 0; fields = 0; in_field = 0; discard = 0;
            } else if (!discard) {
                int space = ch == ' ' || ch == '\t';
                if (!space && !in_field) { ++fields; in_field = 1; }
                if (space && in_field) {
                    in_field = 0;
                    if (fields == 5) { discard = 1; continue; }
                }
                if (used == sizeof(prefix) - 1) goto done;
                prefix[used++] = (char)ch;
            }
            /* Filenames in the bounded input chunk are never parsed, copied,
             * compared, emitted or persisted. Only five numeric map fields
             * survive this streaming parser. This is diagnostic mapping, not
             * backend exec identity or a causal application callsite. */
        }
    }
done:
    explicit_bzero(chunk, sizeof(chunk));
    explicit_bzero(prefix, sizeof(prefix));
    close(fd);
    return result;
}

static int sample(int proc, pid_t id, const struct stat *backend,
                  const struct stat *loader, const struct stat *libc,
                  const struct stat *capture, uint64_t pc, int64_t end_ns, struct task *t) {
    const struct stat *roles[] = {backend, loader, libc};
    for (unsigned i = 0; i < 3; ++i) {
        struct stat current;
        if (fstat(role_fds[i], &current) || !stable(&current, roles[i])) return -1;
    }
    /* Numeric names are private OS selectors only, never evidence outputs. */
    char name[32];
    if (snprintf(name, sizeof(name), "%ld", (long)id) <= 0) return -1;
    int dir = openat(proc, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) return -1;
    int image = openat(dir, "exe", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    int sink = openat(dir, "fd/2", O_PATH | O_CLOEXEC);
    struct stat a, b;
    t->image = "image-unavailable";
    t->sink = "sink-unavailable";
    t->origin = map_origin(dir, pc, backend, loader, libc, end_ns);
    if (image >= 0 && !fstat(image, &a))
        t->image = same(&a, backend) ? "image-backend"
                 : same(&a, loader) ? "image-loader" : "image-other";
    if (sink >= 0 && !fstat(sink, &b))
        t->sink = same(&b, capture) ? "sink-sampled-capture" : "sink-sampled-other";
    if (image >= 0) close(image);
    if (sink >= 0) close(sink);
    close(dir);
    return 0;
}
static const char *error_kind(int number) {
    /* Closed errno classes only. Never emit a numeric errno or strerror. */
    switch (number) {
    case 0: return "none";
    case ECHILD: return "child";
    case ESRCH: return "task-gone";
    case EACCES: case EPERM: return "permission";
    case EINVAL: return "argument";
    case EIO: return "io";
    case ENOSYS: case EOPNOTSUPP: return "unsupported";
    case EINTR: return "interrupted";
    case EAGAIN: return "busy";
    case ENOMEM: return "memory";
    default: return "other";
    }
}
static int record(int fd, const char *state, const char *writer,
                  const char *image, const char *sink, const char *call, const char *origin) {
    char data[224];
    int n = snprintf(data, sizeof(data), "OMUX_FD2_OBSERVER_V1/%s/%s/%s/%s/%s/%s\n",
                     state, writer, image, sink, call, origin);
    if (n <= 0 || (size_t)n >= sizeof(data)) return -1;
    /* One atomic, nonblocking write, never a stderr diagnostic. */
    return write(fd, data, (size_t)n) == n ? 0 : -1;
}
static int cleanup(int64_t end) {
    /* Entries remain unreaped until this table consumes their wait status, so
     * numeric signals refer only to this observer's owned tracees. EXITKILL
     * additionally kills all still-traced tasks if the observer is killed. */
    for (unsigned i = 0; i < count; ++i) {
        kill(tasks[i].id, SIGKILL);
        ptrace(PTRACE_CONT, tasks[i].id, 0, SIGKILL);
    }
    while (now_ns() >= 0 && now_ns() < end) {
        int status;
        pid_t id = waitpid(-1, &status, __WALL | WNOHANG);
        if (id > 0) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) remove_task(id);
            else if (WIFSTOPPED(status)) {
                /* A fork event may have installed a tracee before its event
                 * was consumed. waitpid ownership supplies this cleanup set. */
                ptrace(PTRACE_CONT, id, 0, SIGKILL);
                kill(id, SIGKILL);
            }
        } else if (id < 0 && errno == ECHILD) { count = 0; return 0; }
        else if (id < 0 && errno != EINTR) break;
        else { struct timespec gap = {0, 1000000}; nanosleep(&gap, NULL); }
    }
    return -1;
}
int main(int argc, char **argv) {
    int64_t start = now_ns();
    if (argc < 8 || start < 0) return 125;
    int report = fd_arg(argv[1]), backend_fd = fd_arg(argv[2]), loader_fd = fd_arg(argv[3]),
        libc_fd = fd_arg(argv[4]);
    if (report < 0 || backend_fd < 0 || loader_fd < 0 || libc_fd < 0
            || report == backend_fd || report == loader_fd || backend_fd == loader_fd
            || libc_fd == report || libc_fd == backend_fd || libc_fd == loader_fd
            || strcmp(argv[6], "--")) return 125;
    int64_t end = deadline_arg(argv[5]);
    if (end < 0 || end <= start) return 125;
    if (end - start > TOTAL_NS) end = start + TOTAL_NS;
    struct stat backend, loader, libc, capture, reporting;
    struct statfs fs;
    int proc = open("/proc", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (proc < 0 || fstatfs(proc, &fs) || fs.f_type != PROC_SUPER_MAGIC || proc_profile(proc, end - (TOTAL_NS - RUN_NS))
            || fstat(backend_fd, &backend) || !S_ISREG(backend.st_mode)
            || fstat(loader_fd, &loader) || !S_ISREG(loader.st_mode)
            || fstat(libc_fd, &libc) || !S_ISREG(libc.st_mode)
            || fstat(STDERR_FILENO, &capture) || !S_ISFIFO(capture.st_mode)
            || fstat(report, &reporting) || !S_ISFIFO(reporting.st_mode)
            || same(&capture, &reporting)) {
        if (proc >= 0) close(proc);
        record(report, "unavailable", "writer-none", "image-none", "sink-none", "call-none", "origin-none");
        return 125;
    }
    role_fds[0] = backend_fd; role_fds[1] = loader_fd; role_fds[2] = libc_fd;
    if (fcntl(report, F_SETFL, O_NONBLOCK) < 0) { close(proc); return 125; }
    struct sigaction action = {.sa_handler = on_signal};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)
            || sigaction(SIGHUP, &action, NULL)) { close(proc); return 125; }
    signal(SIGPIPE, SIG_IGN);
    pid_t parent = getpid(), root = fork();
    if (root == 0) {
        /* Protect the launch gap before ptrace EXITKILL is installed. */
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(125);
        close(report); close(backend_fd); close(loader_fd); close(libc_fd); close(proc);
        action.sa_handler = SIG_DFL;
        sigaction(SIGTERM, &action, NULL); sigaction(SIGINT, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
        signal(SIGPIPE, SIG_DFL);
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) || raise(SIGSTOP)) _exit(125);
        execv(argv[7], argv + 7);
        _exit(127);
    }
    const char *state = "error", *writer = "writer-none", *image = "image-none",
               *sink = "sink-none", *call = "call-none", *origin = "origin-none";
    int root_code = 125, root_done = 0, first = 0, initialized = 0;
    const char *fault_stage = "launch-table";
    int fault_errno = 0;
    if (root < 0) { fault_stage = "launch-fork"; fault_errno = errno; goto finish; }
    if (!add(root)) goto finish;
    while (count) {
        int64_t now = now_ns();
        if (cancelled) { state = "cancelled"; break; }
        if (now < 0) { fault_stage = "clock"; fault_errno = errno; break; }
        if (now >= end - (TOTAL_NS - RUN_NS)) { state = "deadline"; break; }
        int status;
        pid_t id = waitpid(-1, &status, __WALL | WNOHANG);
        if (id == 0 || (id < 0 && errno == EINTR)) {
            struct timespec gap = {0, 1000000};
            nanosleep(&gap, NULL); continue;
        }
        if (id < 0) { fault_stage = "wait"; fault_errno = errno; break; }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (id == root) {
                root_done = 1;
                root_code = WIFEXITED(status) ? WEXITSTATUS(status) : 125;
            }
            /* Exit wait has reaped the task. Never signal this ID afterward. */
            remove_task(id); continue;
        }
        if (!WIFSTOPPED(status)) { fault_stage = "wait-kind"; break; }
        struct task *t = find(id);
        if (!t) { /* Only this helper's stopped traced children are waitable. */
            t = add(id);
            if (!t) { kill(id, SIGKILL); state = "task-bound"; break; }
        }
        if (++stops > STOP_CAP) { state = "stop-bound"; break; }
        if (!initialized && id == root) {
            unsigned long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC
                | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK
                | PTRACE_O_EXITKILL;
            if (WSTOPSIG(status) != SIGSTOP
                    || ptrace(PTRACE_SETOPTIONS, id, 0, options)) {
                state = "unavailable"; break;
            }
            initialized = 1;
        }
        unsigned event = (unsigned)status >> 16;
        if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK
                || event == PTRACE_EVENT_VFORK) {
            unsigned long child;
            if (ptrace(PTRACE_GETEVENTMSG, id, 0, &child)) {
                fault_stage = "fork-event"; fault_errno = errno; break;
            }
            if (child == 0) { fault_stage = "fork-zero"; break; }
            if (!add((pid_t)child)) {
                kill((pid_t)child, SIGKILL);
                /* Auto-attached tracees inherit EXITKILL even at a cap. */
                state = "task-bound"; break;
            }
        } else if (event == PTRACE_EVENT_EXEC) {
            unsigned long former;
            if (ptrace(PTRACE_GETEVENTMSG, id, 0, &former)) {
                fault_stage = "exec-event"; fault_errno = errno; break;
            }
            if (former && (pid_t)former != id) remove_task((pid_t)former);
            t = find(id); if (!t) { fault_stage = "exec-table"; break; }
            t->pending = 0;
        } else if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            struct syscall_info info;
            memset(&info, 0, sizeof(info));
            long got = ptrace(PTRACE_GET_SYSCALL_INFO, id, sizeof(info), &info);
            if (got < (long)offsetof(struct syscall_info, u) || info.arch != AUDIT_ARCH_X86_64
                    || (info.op == 1 && got < (long)(offsetof(struct syscall_info, u) + sizeof(info.u.entry)))
                    || (info.op == 2 && got < (long)(offsetof(struct syscall_info, u) + sizeof(int64_t) + 1))) {
                state = "unavailable"; break;
            }
            if (info.op == 1) {
                t->pending = !first && info.u.entry.args[0] == 2
                    && (info.u.entry.nr == SYS_write || info.u.entry.nr == SYS_writev);
                if (t->pending) {
                    t->call = info.u.entry.nr == SYS_write ? "call-write" : "call-writev";
                    if (sample(proc, id, &backend, &loader, &libc, &capture, info.instruction_pointer, end - (TOTAL_NS - RUN_NS), t)) {
                        state = "unavailable"; break;
                    }
                }
            } else if (info.op == 2) {
                if (!first && t->pending && !info.u.exit.is_error && info.u.exit.rval > 0) {
                    first = 1;
                    writer = id == root ? "writer-root-task" : "writer-other-task";
                    image = t->image; sink = t->sink; call = t->call; origin = t->origin;
                }
                t->pending = 0;
            } else { state = "unavailable"; break; }
        }
        /* Suppress only ptrace protocol SIGSTOP/TRAP. Deliver other signals. */
        int sig = event || WSTOPSIG(status) == (SIGTRAP | 0x80)
            || WSTOPSIG(status) == SIGSTOP ? 0 : WSTOPSIG(status);
        if (ptrace(PTRACE_SYSCALL, id, 0, sig)) {
            fault_stage = "resume"; fault_errno = errno; break;
        }
    }
    if (!count && root_done) state = first ? "observed" : "no-write";
    else if (!count) fault_stage = "root-exit-missing";
finish:
    if (cleanup(end)) state = "cleanup-incomplete";
    close(proc);
    char qualified[64];
    if (!strcmp(state, "error")) {
        int length = snprintf(qualified, sizeof(qualified), "error-%s-%s",
                              fault_stage, error_kind(fault_errno));
        if (length <= 0 || (size_t)length >= sizeof(qualified)) return 125;
        state = qualified;
    }
    int ok = record(report, state, writer, image, sink, call, origin);
    return !ok && (!strcmp(state, "observed") || !strcmp(state, "no-write")) ? root_code : 125;
}
