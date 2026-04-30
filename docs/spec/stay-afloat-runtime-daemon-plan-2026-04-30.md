# Stay-Afloat Runtime And Daemon Plan
Date: 2026-04-30

Issue context: follow-up to `TIN-736`, `TIN-815`, and daemon-boundary work
from `TIN-738`. Linear writes were unavailable during this checkpoint because
the connected account had exhausted Codex usage until 2026-05-05 13:20.

## Correction

The project has proven installability, first-run diagnostics, typed liveness,
and real Codex fallback. It has not yet proven the stronger product promise:
keep a developer afloat automatically while accounts move through quota,
rate-limit, logged-out, stale-token, permission-denied, and reauth states.

That stronger promise needs a runtime layer. The current daemon is only a stub:
it can start, stop, and report status. It is not yet a safe product surface for
background refresh or repair.

## Fresh Dogfood Evidence

PR `#28` merged at `928ffdf` and added:

- `just first-run-e2e`;
- a temp `HOME`/XDG first-run proof;
- `init --codex-max` store-root alignment with `OMUX_CODEX_STORE_ROOT`,
  `XDG_DATA_HOME`, or `$HOME/.local/share/oauth-mux/codex`;
- first-run docs and install matrix updates.

The next dogfood check found a false negative:

```text
oauth-mux codex probe-all --capability codex-mini --json
```

inside the Codex sandbox classified every account as
`degraded:unknown_4xx`. The raw Codex error showed the actual problem:
Codex could not create session files under the isolated `CODEX_HOME`, so the
failure was runtime permission/session ownership, not provider OAuth state.

Running outside that sandbox gave the real signal:

```text
CODEX_HOME=.../max-3 codex exec --json --ephemeral ... gpt-5.3-codex-spark
```

returned `OMUX_CODEX_MINI_PROBE`.

Then the product-level mux proof succeeded:

```text
oauth-mux probe --profile codex-mini --capability codex-mini --json
```

selected `codex:max-1#codex-mini` with HTTP 200 and `live.available`.

The max route exercised actual fallback:

```text
oauth-mux probe --profile codex-max --capability codex-max --json
```

recorded `codex:max-1#codex-max` as `live.quota_exhausted`, with
`decision=try_next_account` and a reset timestamp of `1777987200`, then selected
`codex:max-2#codex-max` with HTTP 200 and `live.available`.

The important result: route-scoped fallback is real. The missing result:
automatic account repair and stay-afloat orchestration are not real yet.

## Runtime Gap Taxonomy

### 1. Credential state

`oauth-mux` can read secret backends and parse credentials. It cannot yet safely
write refreshed credentials back to every backend. The current refresh path
updates only the in-memory pipeline context.

Required work:

- define backend write capability: `readonly`, `replace_file`, `command_write`,
  `keychain_write`, `sops_write`, `unsupported`;
- preserve permissions and atomic writes for file-backed OAuth stores;
- refuse automatic refresh when writeback semantics are unknown;
- record the selected writeback path in redacted health evidence.

### 2. Token age semantics

The generic provider parser treats `expires_in` as relative to read time. That
is correct for a fresh token endpoint response, but unsafe for persisted
credentials unless the store also includes an issued-at or absolute expiry
field. Codex currently exposes `tokens.expires_in` in the provider definition,
so the mux may believe a stale persisted token is fresh every time it reads it.

Required work:

- distinguish `expires_in` from token responses versus persisted stores;
- add `issued_at_path`, `created_at_path`, or provider-specific age rules;
- prefer absolute `expires_at` when available;
- for CLI-owned stores such as Codex, use the upstream CLI status/exec behavior
  as the authoritative liveness check rather than trusting persisted relative
  expiry fields.

### 3. CLI-owned sessions

Codex and Claude own more than an OAuth token. They also own config files,
session directories, model caches, account identifiers, and sometimes keychain
entries. A mux that only swaps token files is incomplete.

Required work:

- `oauth-mux doctor runtime` or equivalent that verifies each account store is
  readable and writable by the current user;
- explicit classification for `runtime_permission_denied`, separate from
  OAuth `dead` and provider `degraded`;
- session/cache probes that do not spend provider calls where upstream CLIs
  expose them;
- safer output when sandbox policies block a provider CLI.

### 4. Reauth ownership

Some providers can be refreshed by `oauth-mux`; some must be repaired through
their upstream CLI; some require user/browser/device interaction. Automatic
reauth should never pretend these are equivalent.

Required work:

- account state variant: `needs_reauth(methods, reason, last_attempt_at)`;
- repair plan output:
  - `codex login <account>`;
  - `codex login-device <account>`;
  - `claude /login` or `claude` interactive launch;
  - provider-specific browser/device flows when supported by spec;
- non-interactive mode that prints exact commands instead of launching flows;
- interactive mode that asks before opening browser/device auth.

### 5. Background budgets

The daemon must avoid surprise spend. It should not run arbitrary live probes
in the background just because a route exists.

Required work:

- per-provider and per-capability budgets;
- no-spend probes by default;
- live probes only with explicit policy;
- jittered schedules and cooldown windows;
- account lock files so two daemon/processes do not refresh or reauth the same
  account concurrently;
- redacted event log for every background action.

### 6. Selection semantics

Current `probe-all` is evidence collection. It intentionally probes each named
account. Stay-afloat UX needs a separate selection command that answers:
"what account would be used right now, and why?"

Required work:

- `oauth-mux route select --profile <p> --capability <c> --json`;
- `oauth-mux route explain --profile <p> --capability <c> --json`;
- output skipped accounts with typed reasons:
  - quota window;
  - retry-after;
  - dead token;
  - needs reauth;
  - runtime permission denied;
  - provider unavailable.

## Daemon Shape

The daemon should become a small supervisor, not a magic OAuth authority.

Suggested responsibilities:

1. Load config and health.
2. Maintain redacted account and route state.
3. Run no-spend runtime checks on a budget.
4. Refresh only providers/backends admitted for automatic writeback.
5. Queue user-visible reauth plans when automation is not admitted.
6. Expose local status over the existing socket.
7. Never perform live/spending probes unless policy allows it.

Suggested commands:

```bash
oauth-mux daemon start
oauth-mux daemon status --json
oauth-mux daemon events --json
oauth-mux daemon repair-plan --profile codex-max --json
oauth-mux daemon repair --account codex:max-1 --interactive
oauth-mux route select --profile codex-max --capability codex-max --json
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux doctor runtime --json
```

## Extensibility Contract

Stay-afloat must be easy to extend without teaching every new harness about
every platform. The core product should expose a small runtime protocol; each
harness adapter should describe only the facts it owns.

### Adapter ladder

New harnesses should enter through the cheapest sufficient layer:

1. `schema_only`
   A JSON provider definition describes credential parse paths, injection,
   command/http probes, and failure rules. This should cover many harnesses
   whose auth state is a token file, environment variable, command output, or
   HTTP OAuth resource.

2. `command_adapter`
   The harness owns login/session/refresh behavior, so `oauth-mux` calls its
   CLI through bounded commands and classifies stdout/stderr/status. Codex and
   Claude-like tools belong here until their direct OAuth repair semantics are
   officially documented and tested.

3. `secret_backend_adapter`
   The existing secret backends are insufficient, so the core gains a new
   read/write backend capability. This is still provider-neutral.

4. `transport_adapter`
   The provider needs a protocol primitive the core does not have, such as a
   new sender-constrained token mechanism, dynamic client metadata document
   behavior, or MCP-specific protected-resource discovery that cannot be
   expressed with existing schema fields.

5. `compiled_provider_adapter`
   Last resort. Use only when provider behavior cannot be expressed by data,
   command probes, secret backends, or transport primitives.

This ladder keeps future harnesses such as OpenCode, Pi, Air, or private
on-prem tools from turning into separate forks of the mux loop.

### Harness descriptor

Each harness should be modeled as a descriptor with these stable sections:

```text
identity:
  provider name, account names, capability names

storage:
  secret backend, config/session/cache roots, writeback capability

runtime:
  required binaries, environment variables, writable paths, lock scope

auth:
  token endpoint, refresh ownership, reauth methods, user-interaction mode

probes:
  no-spend checks, live checks, timeout, budget class, output parser

classification:
  status/body/header/exit-code rules into liveness and runtime states

repair:
  automatic actions, manual actions, commands to print, commands to run
```

The descriptor should be serializable as JSON for external authors, and the
compiled Zig structs should mirror it closely enough that examples can be moved
into built-ins without redesign.

### Runtime states

The current liveness algebra should gain a sibling runtime algebra rather than
overloading OAuth liveness:

```text
CredentialLiveness =
    live(availability)
  | degraded(reason)
  | dead(reason)

RuntimeReadiness =
    ready
  | missing_binary(binary)
  | permission_denied(path, operation)
  | unwritable_store(path)
  | session_unavailable(path)
  | sandbox_blocked(operation)
  | needs_reauth(methods, reason)
  | repair_in_progress(account, started_at)
```

Selection should require both `CredentialLiveness` and `RuntimeReadiness`.
The current conservative product rule is:

```text
SelectableRoute = live.available + ready_runtime_state
```

A denied session directory should not be reported as provider quota or OAuth
death. A revoked token should not be reported as a sandbox problem.

### Capability budgeting

Every probe or repair action needs a budget class:

```text
free_local          local file/stat/JSON parse
free_command        upstream CLI status that should not call the provider
cheap_provider      identity/status endpoint or documented no-spend probe
spend_provider      model/tool call or any route that may consume quota
interactive         opens browser, device auth, TTY prompt, or upstream login
mutating            writes credentials, revokes tokens, creates API keys
```

Defaults:

- daemon may run `free_local` and admitted `free_command` checks;
- daemon may run `cheap_provider` only when the provider descriptor marks the
  route no-spend and a user policy enables it;
- daemon never runs `spend_provider`, `interactive`, or `mutating` without an
  explicit operator policy and redacted event log entry.

### Repair ownership

Each provider/account must declare one repair owner:

```text
oauth_mux_refresh       mux refreshes and writes credentials
upstream_cli_login      mux calls or prints upstream login commands
external_secret_owner   vault/SOPS/keychain owner rotates outside mux
manual_only             mux can diagnose but not repair
```

The repair owner decides what the daemon may do. For example, a Codex-like
subscription harness should initially be `upstream_cli_login`: `oauth-mux` can
verify the isolated home, print `oauth-mux codex login-device max-1`, and
optionally run it in interactive mode, but it should not silently rewrite the
store from a guessed token endpoint.

### Cross-platform service boundary

The core daemon should not depend on `systemctl`, `launchctl`, cron, Homebrew
services, Windows Services, or a particular init system.

Core behavior:

- foreground daemon mode;
- pid/socket paths from XDG/runtime abstractions or platform-neutral fallbacks;
- JSON status/events over local socket or stdio;
- no shell-specific behavior inside the daemon;
- advisory lock files implemented with `std.fs` primitives where possible;
- all timeouts and budgets in config, not service-manager units.

Packaging wrappers are separate:

- `oauth-mux daemon run` is the portable primitive;
- Homebrew may wrap it with `brew services`;
- Linux packages may ship optional systemd user units;
- macOS packages may ship optional launchd plists;
- Windows may later ship a service wrapper or scheduled-task recipe;
- curl/npm installs should still work without any service manager.

This keeps daemon support useful on developer laptops, CI sandboxes, SSH hosts,
containers, Nix shells, and on-prem workstations.

### Functional DX

A new harness author should be able to start with one file and one loop:

```bash
oauth-mux provider scaffold opencode > opencode.provider.json
oauth-mux provider validate opencode.provider.json
oauth-mux provider fixture add opencode --case auth-dead
oauth-mux route explain --profile work --capability code --json
oauth-mux repair-plan --profile work --json
```

The authoring loop should produce useful errors:

- missing binary;
- secret backend unreadable;
- configured account store not writable;
- probe classified as unknown because no failure rule matched;
- live probe refused because budget policy disallows spend;
- repair refused because owner is `manual_only`.

The goal is not to hide complexity. The goal is to make the next correct action
obvious and copy-pastable for humans and agents.

## Admission Matrix

| Provider class | Auto-refresh | Auto-reauth | Live probe | Notes |
| --- | --- | --- | --- | --- |
| File-backed OAuth with known token endpoint and atomic writeback | admissible after tests | no | budgeted | Requires refresh-token rotation handling. |
| Keychain/secret-tool OAuth | admissible after writeback implementation | no | budgeted | Must shell out safely; no FFI. |
| SOPS/age stores | likely manual first | no | budgeted | Avoid rewriting encrypted team secrets until policy exists. |
| CLI-owned subscription stores | usually not by token endpoint | CLI-mediated only | explicit | Codex/Claude own sessions and account metadata. |
| API keys/PATs | no refresh | no | cheap identity probes | Treat as key validity, not OAuth freshness. |
| MCP HTTP resources | spec-driven discovery | depends on auth server | explicit | Use RFC 9728 and server metadata before assuming endpoints. |

## Product Gates

### M1: Stay-Afloat One-Shot

- Add `route select` and `route explain`.
- Add runtime permission classification.
- Add a dogfood script that runs real `oauth-mux probe` outside restricted
  sandboxes and stores redacted evidence.
- Prove current Codex state:
  - `max-1#codex-mini` available;
  - `max-1#codex-max` quota exhausted;
  - `max-2#codex-max` selected as fallback.

Implementation note, 2026-04-30: `route select` and `route explain` now exist
as one-shot, no-spend commands over recorded liveness. They do not probe live
providers, open browsers, run repair commands, or mutate secret stores.
Unrecorded routes surface as `probe_needed`; `route select` exits nonzero when
there is no `live.available` route with ready runtime state.

Implementation note, 2026-04-30: `doctor runtime --json` now checks local
runtime prerequisites without provider calls. It reports missing upstream
binaries, configured account store presence, local write access via a temporary
marker file, and expected session-file presence. It does not read token values
or create missing account stores.

Dogfood note, 2026-04-30: running the runtime doctor from the current Codex
sandbox classified configured Codex account stores as not writable from this
process while their session files were present. `route explain` now consumes the
same account runtime readiness, so an otherwise `live.available` Codex account
is not selected when the current process cannot write its account store.

Implementation note, 2026-04-30: `doctor runtime` now accepts the same
`--profile`, `--provider`, `--account`, and `--capability` selectors as
`repair-plan` and `route`. Scoped runtime doctor reports route-level readiness,
which lets a user or agent prove that a specific stay-afloat profile is usable
even when unrelated configured accounts still need cleanup.

### M2: Repair Plan

- Add `needs_reauth` state.
- Add `oauth-mux repair-plan --json`.
- For Codex, output exact `oauth-mux codex login[-device] <account>` commands
  and verify `CODEX_HOME` writability before suggesting live auth.

Implementation note, 2026-04-30: the first repair-plan surface is intentionally
non-mutating. It expands profiles and explicit provider/account routes, reads
runtime readiness plus recorded liveness, emits typed action JSON, and suggests
copy-pastable commands. The `daemon repair-plan` spelling is an alias for that
one-shot planner, not daemon automation.

Implementation note, 2026-04-30: `oauth-mux repair run` is the first explicit
foreground admission gate for mutating repair. It does not change
`repair-plan`; it reuses the same typed action model, refuses mutation without
`--confirm-repair`, no-ops when a profile is already afloat, and only runs
provider-owned repair commands that are represented as first-class actions.
Confirmed interactive repair is intentionally rejected in `--json` mode because
upstream CLIs can write browser/device auth output to stdout or stderr.

Implementation note, 2026-04-30: repair execution now has the first daemon-safe
substrate. `repair run` appends redacted JSONL events, confirmed repair takes
an account-scoped advisory lock, and route/runtime planning reports an active
lock as `repair_in_progress`. `oauth-mux daemon events --json` reads the event
log without requiring the daemon to be running. This is still one-shot
foreground repair; it is the audit and concurrency layer needed before any
background loop.

Implementation note, 2026-04-30: daemon admission policy now exists in config.
The default `policy.daemon.allowed_budgets` is `free_local` and `free_command`,
with `allow_interactive=false` and `allow_mutating=false`. `repair-plan --json`
and `route explain --json` emit the effective policy plus per-route
`daemon_probe` and `daemon_repair` admission decisions. This keeps the future
daemon loop policy-driven while preserving the current product boundary: no
provider calls, quota-spending probes, browser/device auth, or credential
mutation in background mode unless an operator opts in explicitly.

Implementation note, 2026-04-30: `oauth-mux daemon tick --once --json` now
provides the first daemon-shaped dogfood primitive. It loads route runtime,
recorded liveness, repair actions, and daemon admission policy, then reports
what a future daemon loop would be allowed to consider. The tick is explicitly
planning-only and emits `executed:false`; it does not run provider probes,
repair commands, browser/device auth, or secret mutation.

Implementation note, 2026-04-30: daemon tick beta execution now exists behind
`--execute`. Execute mode runs at most one admitted non-interactive action per
tick, then re-reads route state before rendering JSON. This is intentionally
small: `free_command` probes can keep route evidence fresh, provider-spending
probes require explicit policy, and interactive reauth becomes a redacted
`daemon_handoff` event with a user command instead of silent background auth.
Tick JSON now includes `execution_mode`, `executions`, `handoff_queued`, and
`next_tick_after` scheduling hints.

Implementation note, 2026-04-30: `oauth-mux daemon handoffs --json` now exposes
the filtered pending handoff queue from the same redacted local event stream.
Later route-selectable or successful execution events clear matching pending
handoffs; `--all` keeps the historical handoff events visible for audit. This
gives users, wrappers, and agents a stable way to discover user-mediated repairs
without scraping the full audit log.

Implementation note, 2026-04-30: bounded foreground loop mode now exists through
`oauth-mux daemon tick --loop --iterations <n> --interval-ms <ms> --json`. This
keeps the daemon beta portable and wrapper-friendly: no system service manager
is assumed, each iteration re-reads local health/runtime state, and the default
policy still refuses provider spend, interactive auth, and mutation.

Implementation note, 2026-04-30: `oauth-mux stay-afloat` is now the
operator-facing alias for the same portable tick engine. `daemon tick` remains
available as the lower-level implementation surface, but docs and onboarding
should lead with `stay-afloat --once` and `stay-afloat --loop`.

Implementation note, 2026-04-30: `oauth-mux stay-afloat handoffs --json` now
aliases the pending handoff queue. This keeps user-facing recovery flows under
the same product command while leaving `daemon handoffs` available for lower
level debugging.

### M3: Refresh Writeback

- Implement backend write capabilities.
- Persist refreshed tokens atomically for admitted providers.
- Add fixtures for refresh-token rotation.
- Refuse refresh when a backend is read-only or token age semantics are
  ambiguous.

Implementation note, 2026-04-30: the first writeback matrix now exists. Route,
runtime, repair-plan, and daemon tick JSON expose `writeback.capability`,
`writeback.automatic_refresh_admitted`, and `writeback.reason` for each account.
This deliberately separates "oauth-mux can read the local credential" from
"oauth-mux is allowed to rewrite this credential during automatic refresh."
CLI-owned stores such as Codex may resolve to a writable file backend while
still refusing automatic oauth-mux mutation because repair ownership remains
with the upstream CLI login flow.

Implementation note, 2026-04-30: provider-neutral `replace_file` writeback is
implemented as atomic same-path replacement, and the pipeline refresh path is
now gated by the writeback plan before it calls a token endpoint. That means
automatic refresh requires both `repair.owner = "oauth_mux_refresh"` and an
admitted backend. Read-only, command, keychain, SOPS, unsupported, and
upstream-owned backends fail closed.

Implementation note, 2026-04-30: refresh admission and writeback outcomes are
now written to the redacted local event stream as `token_refresh` events. Events
include route identity, writeback capability, admission, outcome, and redacted
reason; they intentionally omit tokens, credential paths, and provider response
bodies. `oauth-mux daemon events --json` remains the single local evidence
surface for both foreground repair and pipeline refresh behavior.

### M4: Daemon Beta

- Promote daemon to opt-in beta.
- Add status JSON beyond the current repair-run event log, advisory lock
  substrate, and config-level daemon admission policy.
- Keep live probes disabled by default.
- Add Homebrew/systemd/launchd packaging notes only after stop/status behavior
  is proven.

## Linear Split To Create When Linear Is Available

- Stay-afloat route selection and explanation CLI.
- Runtime permission/session ownership doctor.
- Codex dogfood stay-afloat e2e with redacted evidence artifacts.
- Credential writeback capability matrix and file backend implementation.
- Refresh-token rotation fixtures and safety tests.
- Reauth state algebra and repair-plan CLI.
- Daemon event log, budgets, and lock files.
- Daemon beta packaging boundary.

## Standards And Provider References

- OAuth 2.1 current work item:
  <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15>
- OAuth 2.0 Security Best Current Practice, RFC 9700:
  <https://datatracker.ietf.org/doc/html/rfc9700>
- OAuth 2.0 Protected Resource Metadata, RFC 9728:
  <https://www.rfc-editor.org/rfc/rfc9728>
- MCP authorization draft:
  <https://modelcontextprotocol.io/specification/draft/basic/authorization>
- OpenAI Codex with ChatGPT plan:
  <https://help.openai.com/en/articles/11369540>
- Claude Code authentication and precedence:
  <https://code.claude.com/docs/en/authentication>
- GitHub expiring user access tokens:
  <https://docs.github.com/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens>
- Vercel refresh-token rotation:
  <https://vercel.com/docs/sign-in-with-vercel/tokens>
- Figma OAuth refresh:
  <https://developers.figma.com/docs/rest-api/authentication/>
