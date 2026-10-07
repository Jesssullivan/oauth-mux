# Provider-free detach CLI failure observation

R-N13 / R-HOOK-CONVERGENCE-20261004. Source applied in the owned follow-on
branch based on a4bf48e. Its twelve helper models passed in epoch0322d305;
that batch failed its documentation check because this note was unclassified.
The authority entry is corrected; docs/source passed in epocha634ab32. No installed
diagnostic or native resume is proved by these models.
Parent evidence: ordinary installed44d7 failed at detach-rpc before exact ACK
and cold resume; instrumented158b failed observer fork with EAGAIN before
status CLI execution. Neither establishes the original stderr writer or a
measured resource-limit cause.

The optional shared run_cli hook delivers one closed failure record
for its original exception. It classifies launch, input, capture, wait,
process predicate, JSON parse and result predicate stages; closed exception
type/errno/static predicate labels; already observed exit class; and stream
presence only. It never passes command, parameters, exception text, IDs,
paths or captured stream bytes to the callback. Record schema is
OMUX_RUN_CLI_FAILURE_V1 with five allowlisted fields and a192-byte bound.
The parser rejects extra lines/fields, private tails and unknown labels.

Disabled and successful callers produce no observation. Classification or
callback exceptions, including callback cancellation/SystemExit, produce a
missing diagnostic and cannot replace the operation failure being rethrown.
The existing cleanup runs afterward. Missing observations do not establish
that a child launched or that no failure occurred. Selector construction is
outside the original helper try block and remains outside this hook; cleanup
failures retain their original behavior and are not claimed as observed.

Only the explicit FD2 diagnostic fixture routes its selected
integrations.detach call through the callback. The callback is reset per call,
and inside/outer failure reporting validates the entire bounded record.
The ordinary target does not enable the callback or add a failure record.
Both targets declare the module because the shared legacy file imports it.
Existing markers remain distinct. The optional hook does not trace a child,
read /proc, open pidfds, sample cgroups or change production code.

All original helper predicates and deadlines are preserved: one Popen with
the same argv/environment/pipes, one original stdin encoding/write, unchanged
1MiB captures, original20-second drain/wait budget, exit0 plus empty stderr,
and original JSON/result acceptance. This hook does not strengthen the
shared helper envelope check or change the stricter status_cli check.
Native process/ref/history/config/SQL/inode/prefix/ordinal and empty-work
predicates are untouched. No automatic mutation retry, status query,
accepted stream replay or tool execution is added. Missing ACK remains an
unknown mutation outcome; production control can emit unresolved guidance
after exchange, invalid-reply or refusal failure.

The declared native_run_cli_failure_test has12 modeled methods. It invokes
the actual shared helper with mocked Popen and bounded local model pipes;
no CLI binary, provider or native process is run. Models cover successful
baseline acceptance and silent hook, original process/exit0-stderr failure,
launch EAGAIN, stdin EPIPE, capture limit/deadline, wait timeout, malformed
JSON/refusal result, RuntimeError/KeyboardInterrupt/SystemExit callbacks,
disabled failure behavior, diagnostic wiring and one invocation/request,
closed unknown-private-payload/errno/record negatives, and original cleanup.
Private test payloads use synthetic token-like sentinels, never real account
or authentication data. These models prove only their stated helper behavior;
they are not installed native resume or cgroup admission evidence.

Independent source review completed before application. Root ran the declared
native_run_cli_failure_test through locked Nix/Bazel execution; the twelve
modeled methods passed, separately from the whole batch's documentation failure.
Any later installed diagnostic
needs a fresh exact source/archive receipt and its retained009/Tokio1.52.3
fixture environment qualification. No cause, successful fork, resume or
support claim is made by this observation or its modeled gate.
