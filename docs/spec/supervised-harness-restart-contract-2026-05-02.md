# Supervised Harness Restart Contract
Date: 2026-05-02

Issue context: Linear `TIN-911`, GitHub `#123`, parent `TIN-738` / GitHub
`#67`. Parallel higher-upside proof: Linear `TIN-913`, GitHub `#125`,
`docs/spec/codex-inplace-auth-broker-proof-2026-05-02.md`.

Update, 2026-05-03: this contract is still the right wrapper-owned restart
boundary, but the route examples below are historical. Current Codex Max
dogfood has four routes: `max-1#codex-max` selected after spend-gated
revalidation, `max-4#codex-max` spare fallback, and `max-2#codex-max` /
`max-3#codex-max` provider quota-exhausted. The usage-limit classifier and
restart engine exist for wrapper-owned children; interactive PTY capture and
real usage-limit restart dogfood remain tracked by TIN-937 / GitHub #162.

## State

`oauth-mux` can now keep route evidence warm, expose fresh daemon snapshots,
queue user-mediated repair handoffs, and launch the next harness process through
`oauth-mux stay-afloat launch -- <command>`.

That is not the same as hot-swapping an already-running Codex, Claude, Figma, or
other upstream harness process. Live dogfood on 2026-05-02 showed the concrete
shape:

- the running Codex session reported a revoked/invalidated OAuth token during a
  remote compact path;
- `daemon supervise --profile codex-max --capability codex-max` could select a
  fresh fallback route;
- `daemon status --json` could prove `current_loop_observed:true`,
  `stale:false`, selected `codex:max-3`, and `claim.level:"prepared_fallback"`;
- the claim still correctly kept `current_process_hotswap:false`,
  `supervised_restart:false`, and `per_request_muxing:false`.

The next portable claim level is therefore not "background daemon magically
fixes the current process." It is "oauth-mux owns a wrapper process that can
restart a harness under another selected account after a typed failure."

For Codex specifically, a later source review found an app-server external-auth
broker path that may allow current-process account switching for sessions
launched under oauth-mux mediation. That does not invalidate this contract:
supervised restart remains the generic fallback for unmanaged harnesses and for
providers without a proven reload/broker API.

## Claim Levels

### Level 1: prepared_fallback

Already implemented.

The route state is fresh enough that the next mediated launch can choose an
account. The mediation command is:

```bash
oauth-mux stay-afloat launch --profile <profile> --capability <capability> -- <command>
```

The implementation uses `execve` for the target. On success, the `oauth-mux`
process is replaced by the harness process. This is correct for shell ergonomics
and process trees, but it means `oauth-mux` cannot observe the later target
exit, stderr, auth error, or compact failure.

`prepared_fallback` may retry another route only before the target starts, when
the selected route is reclassified during the final `oauth-mux exec` preflight.

### Level 2: supervised_restart

First implementation slice exists.

The parent-wrapper command is:

```bash
oauth-mux stay-afloat supervise \
  --profile <profile> \
  --capability <capability> \
  --max-restarts <n> \
  --restart-on-exit-code <code> \
  -- <command>
```

Unlike `stay-afloat launch`, this command must not `execve` into the target. It
must:

1. run the normal stay-afloat route selection;
2. prepare the selected account environment;
3. spawn the target as a child process;
4. wait for the child to exit;
5. classify the child result conservatively;
6. record redacted evidence;
7. relaunch with a different selectable route only when policy admits restart;
8. stop after a bounded restart count.

The first implementation classifies only an operator-declared exit code. It does
not parse arbitrary provider output and does not persist route-health evidence
from generic child failure. This is deliberate: the wrapper can prove
`claim.supervised_restart:true` for the child it owns after an actual restart,
while still avoiding claims about in-process token replacement, unmanaged TUI
handoff, or per-request muxing.

### Level 3: current_process_hotswap

Not implemented in oauth-mux.

This requires direct support from the upstream harness, an oauth-mux-aware
plugin/adapter inside that running process, or a sidecar protocol the harness
already trusts. A parent daemon cannot replace tokens that a child process has
already loaded unless the child cooperates. Codex app-server external auth is
the first candidate for such cooperation and is tracked separately from this
restart contract.

### Level 4: per_request_muxing

Not implemented.

This requires request-level proxying, an SDK adapter, or provider-native account
muxing. It is a different product surface from shell launch wrappers.

## Restart Admission

The supervised restart path must be more conservative than route planning.
Generic nonzero exit is not enough to poison a credential. A failing command may
exit because of user code, network conditions, interrupted terminal state, bad
flags, or provider auth.

Initial admission requires one of:

- provider-specific classifier evidence from captured stderr/stdout;
- an explicit wrapper policy such as `--restart-on-exit-code <code>` for test
  fixtures and operator-confirmed workflows;
- a pre-start route reclassification from the existing pipeline;
- a follow-up `stay-afloat refresh --execute` tick that marks the current route
  degraded, dead, quota-exhausted, or temporarily unavailable.

The current implementation uses the explicit `--restart-on-exit-code` path. It
inherits child output in text mode and suppresses it in JSON mode, so JSON
evidence remains redacted. A future provider-specific classifier can add bounded
stderr/stdout capture, but that must remain opt-in.

## JSON Shape

A future supervised restart result should expose:

```json
{
  "mode": "supervise",
  "claim": {
    "level": "supervised_restart",
    "prepared_fallback": true,
    "supervised_restart": true,
    "current_process_hotswap": false,
    "per_request_muxing": false
  },
  "selected": {
    "provider": "codex",
    "account": "max-3",
    "capability": "codex-max"
  },
  "attempts": [
    {
      "provider": "codex",
      "account": "max-1",
      "exit_code": 1,
      "classification": "quota_exhausted",
      "restart_admitted": true
    }
  ],
  "restart_count": 1,
  "max_restarts": 2
}
```

The text mode should be operator-friendly and avoid emitting provider secrets,
token paths, or captured response bodies.

## Codex Dogfood Procedure

When the extra paid Codex account is ready:

1. Refresh local route evidence:

   ```bash
   oauth-mux stay-afloat refresh --profile codex-max --capability codex-max --json
   oauth-mux route explain --profile codex-max --capability codex-max --json
   ```

2. Prove the current daemon beta status is fresh:

   ```bash
   oauth-mux daemon supervise --profile codex-max --capability codex-max --iterations 3 --interval-ms 500
   oauth-mux daemon status --json
   ```

   Required evidence:

   - `stay_afloat_snapshot.current_loop_observed:true`
   - `stay_afloat_snapshot.stale:false`
   - selected route is the expected credited account
   - `claim.current_process_hotswap:false`

3. Start a fresh harness through the existing launch boundary:

   ```bash
   oauth-mux stay-afloat launch --profile codex-max --capability codex-max -- codex
   ```

4. Do not count the original unmanaged Codex session as a successful handoff.
   It was not started under the supervised wrapper or the app-server broker
   topology and cannot be mutated by file swapping from outside.

5. After `stay-afloat supervise` exists, repeat the test with a wrapper-owned
   Codex process and record whether the wrapper can restart into the credited
   fallback account after a typed failure.

## Implementation Order

1. Keep PR #122's freshness and active-loop correlation as the proof gate.
2. Add this contract and public docs language before implementing a new command.
3. Add a toy-provider E2E fixture for wrapper-owned child restart. Done.
4. Add the `stay-afloat supervise` CLI parser and help text. Done.
5. Refactor exec environment preparation so `launch` can keep using `execve`
   while `supervise` can spawn with the same selected env. First spawn path
   added.
6. Add bounded restart JSON and event logging. Done for exit-code and Codex
   usage-limit classifiers; events are redacted `stay_afloat_supervise` records.
7. Add Codex usage-limit output classification. Done for wrapper-owned child
   processes with `--restart-on-codex-usage-limit`: captured output is hidden,
   route health is recorded as quota-exhausted, and selection moves to the next
   route.
8. Add an opt-in streaming capture path. Done for tee-based pipe streaming with
   `--stream-capture`: child output is visible to the operator while bounded
   classifier buffers and redacted JSON/events are retained. This is not a PTY
   or raw-terminal claim.
9. Run Codex dogfood with one exhausted account and one credited fallback
   account.
10. Only then consider promoting `claim.supervised_restart:true` for the exact
   wrapper path that passed.

## Open Decisions

- Whether restart classification should be provider-owned, command-owned, or a
  generic table in config.
- Output capture is now admitted only for the Codex usage-limit classifier and
  remains redacted. Generic arbitrary provider-output parsing remains out of
  scope.
- Whether a long-running terminal UI such as Codex should be restarted
  automatically, or whether the first version should stop and print the exact
  relaunch command for user confirmation.
- Whether Windows should support `stay-afloat supervise` immediately through
  `std.process.Child`, even while `daemon supervise` remains unsupported there.
