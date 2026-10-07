# Provider-free status CLI FD2 observer proposal, 2026-10-06

Authority: user-authorized native integration investigation; root AGENTS.md,
R-HOOK-CONVERGENCE-20261004 / R-N13. This is an unapplied diagnostic proposal.
No build, test, installed rerun, provider request or source mutation was performed
by its author/reviewer.

The instrumented success marker is OMUX_INSTALLED_LEGACY_NATIVE_FD2_DIAGNOSTIC_OK;
it never emits the ordinary proof success marker.

The ordinary installed legacy TUI target continues to require exit zero, empty
stderr and the exact strict status response. Its separate instrumented target is
//delivery:installed_legacy_native_fd2_diagnostic_test. Retained-input admission
rejects mixing this instrumented target with ordinary proof consumers.

The locked native/resolved tool manifest exposes no strace, ltrace, perf or gdb.
The reachable elfutils output contains libraries, not a tracing executable. The
observer is therefore a Linux x86_64 C binary compiled through the declared
Bazel/Nix toolchain. It wraps only the original provider-free status invocation;
it does not attach to unrelated processes or change product integration.

The observer samples the first observed successful write/writev whose argument FD is 2,
using ptrace syscall-exit observation order (not a global kernel write order).
It uses syscall metadata without reading any application buffer, iovec,
stack, log or application memory. A separate private pipe carries one bounded
closed record; stdout and stderr still go directly to the fixture's original
distinct pipes. The stopped FD2 target is compared with the original stderr
pipe. Kernel exe identity is compared with held expected role files, whose bytes
the caller independently verifies against the already verified portable bundle.
Held role metadata is checked while sampling, and the caller rehashes all held
role bytes and metadata after exit before decoding or emitting any observation.

A bounded private maps scan retains five numeric metadata fields only, discards
filenames, clears its temporary buffers, and compares the syscall instruction
mapping device/inode with the held backend, loader and libc. Map input is capped
at 1 MiB, 4096 lines and a 255-byte metadata prefix. Its role is a sampled mapping
observation, not backend exec identity or a causal application callsite.
origin-libc may identify only a syscall stub.

The current portable Omux launcher execs the bundled loader. image-loader is
therefore expected and cannot be reported as backend executable attribution.
These samples carry no exec-incarnation, artifact lineage, native support,
accepted history or same-process continuity authority. This instrumented target
never substitutes for an ordinary installed proof.

The task table is capped at 256, ptrace stops at 100000. Its absolute deadline
is the earlier of 19 seconds after observer entry and the caller's original
20-second deadline. The final 0.5 seconds are reserved for exact owned tracee
cleanup. The proc mount must be actual procfs, match the helper's own numeric
process-directory identity, and expose exactly one canonical NSpid value equal
to its current PID. Unknown or ancestor-namespace views fail closed.
TRACEME covers only its child; fork/vfork/clone/exec events are traced,
EXITKILL protects all traced descendants and PDEATHSIG protects the launch gap.
Cancellation signals only unreaped owned tracees. The observer drains owned wait
statuses and reports cleanup-incomplete if the bounded cleanup cannot finish.
No PID, PC, size, errno, filename, symbol or diagnostic bytes are emitted.

Proposed tests cover closed-record privacy, exact expected bytes/FD closure,
write/writev, stdout-only and failed writes, fork/thread/exec including nonleader-thread exec, replacement of
FD2, deadline, SIGTERM cancellation and observer SIGKILL/EXITKILL after an owned
descendant exists. All tests are
unrun. ReleaseSafe behavior and the production empty-stderr condition are
unchanged; no source cause for c9e1's unknown ASCII stderr has been established.

The follow-up diagnostic refinement names each previously generic-error edge
using finite error-stage and errno-class literals. It never emits the numeric
errno or error text. Resume errors remain fatal; no ESRCH filtering is added.
A portable model executes unchanged linux_launcher bytes through the existing
@omux_nix//:interpreter_bash capability in POSIX mode, with its declared
bash_tools closure. Its declared wrapper adds an exec before the script. It covers script command substitution and explicit loader topology,
not the product's kernel /bin/sh shebang binding or ambient OS shell version.
The C fixture and copied loader/libc bytes are independently declared. It expects kernel image-loader and
origin-libc and carries no production CLI or native proof. Additional stimuli
cover vfork-exec and multithreaded exit_group. New modeled cases remain unrun;
9bb484f9's generic instrumentation error establishes no original CLI cause.
