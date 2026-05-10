# Codex Managed Resume UX Refactor
Date: 2026-05-06
Status: implementation-backed refactor contract. Original P0/P1 planning
items remain here, with current-main truth notes appended as findings.

Anchors:

- `AGENTS.md`
- `docs/spec/broker-mcp-contract-2026-05-03.md`
- `docs/spec/codex-adapter-contract-2026-05-03.md`
- `docs/spec/harness-session-authority-bridge-2026-05-05.md`

## 0. Product Bar

This work exists only to support the broker product bar:

> The user runs `oauth-mux <harness>`. The active subscription account
> exhausts its quota. Another credited account is substituted in place. The
> harness process is not restarted. The user is not prompted.

For Codex, the daily-use spelling must feel like Codex:

```bash
oauth-mux codex
oauth-mux codex resume --last
oauth-mux codex resume <session-id>
oauth-mux codex exec ...
```

Raw adapter plumbing such as `oauth-mux codex run -- --no-alt-screen resume
--last` may continue to exist for tests and diagnostics, but it is not the
primary UX.

## 1. Incident That Triggered This Spec

The operator attempted to resume an existing Codex session inside a managed
oauth-mux frame:

```bash
./zig-out/bin/oauth-mux codex run \
  --profile codex-max \
  --json-status-file dist/live-qa/managed-resume-20260506TXXXXXXZ/status.ndjson \
  -- --no-alt-screen resume --last
```

The command failed with:

```text
[ERR] codex run: FileNotFound
```

Two separate UX defects are visible:

1. `--json-status-file` opens the destination file directly. If the parent
   directory does not already exist, startup fails before Codex or the session
   authority bridge is exercised.
2. `oauth-mux codex run` only forwards harness args after `--`. Unrecognized
   args before `--` are silently ignored by the adapter parser. Attempts such
   as `oauth-mux codex run codex resume` do not do what the operator expects.

Both are acceptance failures. They make the correct architecture hard to use
and turn ordinary resume behavior into command-shape coercion.

## 2. Current Implementation Boundary

Already real on `main`:

- `oauth-mux codex run` creates a temporary `CODEX_HOME` with mux-owned
  `auth.json` and generated `config.toml`.
- First-class `oauth-mux codex resume`, `resume --last`, and
  `resume <session-id>` route through the managed adapter frame without raw
  `codex run -- ...` spelling.
- `sessions/`, `history.jsonl`, `session_index.jsonl`, and
  `shell_snapshots/` are bridged by reference to canonical Codex session
  authority by default.
- `--session-home`, `OMUX_CODEX_SESSION_HOME`, and
  `--isolated-session-store` exist.
- `oauth-mux codex resume` with no id preserves the native chooser. Before
  spawning Codex, oauth-mux verifies the overlay exposes required canonical
  session-authority entries and emits a redacted `resume_authority_check`
  diagnostic if parity is unavailable.
- Managed config preserves canonical Codex behavior settings while replacing
  mux-owned provider keys. Forwarded `--config` / `-c` provider overrides are
  rejected before child spawn with redacted `config_passthrough_check` status.
- Managed launches emit `launch_timing` status phases through `child_spawn` for
  startup latency diagnosis.
- Synthetic smokes prove the bridge structure and write-through behavior.
- Synthetic smokes prove A -> `usage_limit_reached` -> B swap through the
  adapter/proxy in one stable child PID.
- Installed-runtime dogfood has produced managed load/resume quota handoff
  evidence and an engineered managed-session quota handoff artifact; see
  `docs/spec/codex-live-quota-handoff-evidence-2026-05-08.md` and
  `docs/evidence/codex-engineered-quota-handoff-20260509/`.

Not real yet:

- Same-thread continuity across account swap.
- Mid-turn streaming recovery after partial response delivery.
- Bare `codex` plus background oauth-mux seamless handoff.

## 3. UX Contract

### 3.1 Primary Commands

The supported user-facing commands SHOULD be:

```bash
oauth-mux codex [adapter-options] [-- codex-args...]
oauth-mux codex resume [session-id]
oauth-mux codex resume --last
oauth-mux codex resume
oauth-mux codex exec ...
```

`oauth-mux codex resume` with no id should delegate to Codex's native session
chooser inside the managed frame when Codex supports that path.

### 3.2 Adapter Options

Adapter-owned options are consumed by oauth-mux:

- `--profile <name>`
- `--account <provider:account>`
- `--session-home <path>`
- `--isolated-session-store`
- `--json-status`
- `--json-status-file <path>`
- future `--status-dir <path>` if a directory-based artifact API proves
  friendlier than file paths

Harness-owned args are forwarded exactly, in order, without reinterpretation.
The only exception is mux-owned provider configuration: forwarded Codex
`--config` / `-c` assignments that override `model_provider`,
`*.model_provider`, or `model_providers.oauth_mux_openai*` MUST fail before
child spawn with a redacted typed diagnostic. Other Codex config overrides
remain harness-owned and are forwarded.

### 3.3 Parser Rules

The parser MUST NOT silently drop unknown args.

Recommended command grammar:

1. Existing account-management subcommands keep their current meaning:
   `login`, `login-device`, `login-status`, `login-status-all`,
   `broker-*`, `revalidate-exhausted`, and other diagnostic surfaces.
2. `run` remains the explicit raw adapter command for tests and scripts.
3. `resume`, `exec`, and otherwise harness-shaped commands are promoted to
   adapter mode and forwarded to Codex.
4. Inside `codex run`, any unknown arg before `--` is a hard error with a
   suggestion:

   ```text
   oauth-mux codex run: unknown adapter option "resume".
   Use `oauth-mux codex resume ...` or `oauth-mux codex run -- resume ...`.
   ```

5. For top-level `oauth-mux codex`, unknown harness-shaped args are forwarded
   rather than ignored.

### 3.4 Status Artifact Rules

`--json-status-file <path>` MUST:

- create parent directories if they do not exist;
- fail with a typed, helpful error when the parent cannot be created;
- never print token material, credential paths, raw JWTs, full session paths,
  transcript content, or session ids in normal output;
- prefer relative/redacted path descriptions in user-facing errors, while
  debug logs may carry full paths only under an explicit debug mode.

## 4. Refactor Plan

### Phase 0: Spec and Tracker Truthing

- Add this spec.
- Link it from the session-authority bridge spec and current quarry todo.
- Keep TIN-979 open until live managed-frame resume succeeds.
- If needed, split a new implementation ticket for "managed Codex UX
  command grammar and status artifact hardening".

### Phase 1: No-Spend UX Hardening

Implementation targets:

1. Add a small status-file opener that creates parent directories and returns
   typed startup errors.
2. Make `codex run` parser strict: unknown pre-`--` args fail loudly.
3. Add first-class `oauth-mux codex resume ...` alias that forwards into
   managed adapter mode.
4. Add first-class `oauth-mux codex exec ...` alias only when command parity
   is understood; otherwise fail with a clear "not yet brokered" message.
5. Keep legacy diagnostic subcommands unambiguous.

No provider calls are required for Phase 1.

### Phase 2: Managed Resume Acceptance

Acceptance targets:

1. `oauth-mux codex resume <existing-id>` sees the same canonical session
   authority as bare `codex resume <existing-id>`.
2. `oauth-mux codex resume --last` resolves the same latest session as bare
   `codex resume --last`.
3. `oauth-mux codex resume` opens the native chooser or equivalent managed
   chooser without requiring the user to know a slug.
4. A new managed session writes to canonical session authority and is visible
   to bare `codex resume`.
5. The adapter status stream reports `session_authority:"canonical_bridge"`,
   `auth_authority:"mux_owned_overlay"`, and `managed_config:"mux_owned_overlay"`.

### Phase 3: Level 3 Live Swap Acceptance

Run only after Phase 2 is green.

Acceptance target:

- A real interactive `oauth-mux codex` session observes provider-originated
  quota exhaustion on account A and continues on credited account B without
  restart or prompt.

This remains TIN-951 territory. Phase 2 is not allowed to claim this.

### Phase 4: Public Surface Cleanup

- Document `oauth-mux codex` as the product entrypoint.
- Move `oauth-mux codex run` into an advanced/testing section.
- Keep `stay-afloat`, `codex managed`, and restart-shaped command surfaces
  labeled as diagnostics or Level 1 infrastructure only.

## 5. Regression Guards

### 5.1 Unit Tests

Parser tests:

- `oauth-mux codex run resume --last` fails with an unknown-option diagnostic.
- `oauth-mux codex run -- resume --last` forwards exactly
  `["resume", "--last"]`.
- `oauth-mux codex resume --last` forwards exactly `["resume", "--last"]`
  through managed adapter mode.
- `oauth-mux codex resume <id>` forwards exactly `["resume", "<id>"]`.
- `oauth-mux codex resume` forwards exactly `["resume"]` or enters the
  managed chooser path.
- Existing `oauth-mux codex login-device <account>` and diagnostic subcommands
  still parse to legacy command variants.

Status-file tests:

- Nested relative status-file paths create parents.
- Absolute status-file paths create parents when allowed.
- Unwritable parent returns a typed error, not bare `FileNotFound`.
- Status-file startup failure happens before proxy binding or child spawn.

Session bridge tests:

- Overlay points session-authority entries at canonical authority by reference.
- `auth.json` and `config.toml` remain mux-owned overlay files.
- Missing chooser-required authority entries are not manufactured inside the
  managed overlay. For chooser mode they produce a pre-spawn diagnostic; for
  non-chooser launches native Codex owns any normal first-run initialization.
- For chooser mode, missing canonical session-authority entries fail before
  child spawn with a redacted `resume_authority_check` status event. The
  adapter must not create placeholder authority entries that would make native
  Codex show an empty or misleading chooser.
- Chooser mode does not recursively snapshot `sessions/` before launch. Native
  Codex owns chooser enumeration; oauth-mux only validates that the managed
  overlay exposes the required authority paths by reference.

### 5.2 Property-Based Tests

Add deterministic PBTs under `zig build test`; keep seeds printed on failure.

Recommended properties:

1. **CLI forwarding preservation.**
   For generated argument vectors containing safe byte strings, when args occur
   after `--` or after a first-class harness alias, the forwarded argv equals
   the generated sequence exactly.

2. **No silent parser drops.**
   For generated unknown pre-`--` args in `codex run`, parsing returns a typed
   error or help diagnostic; it never produces a runnable adapter command with
   those args omitted.

3. **Status path preparation.**
   For generated nested relative path shapes, status-file preparation either
   creates all parents and the file or returns one typed permission/path error.
   It never returns bare `FileNotFound`.

4. **Session authority reference integrity.**
   For generated subsets of Codex session-authority entries, overlay creation
   preserves reference semantics: writes through the overlay are observable in
   canonical authority, and no full recursive copy of `sessions/` occurs.

5. **Redaction closure.**
   For generated secret-like strings placed in auth paths, tokens, JWT
   fragments, account ids, and session ids, normal output and status frames do
   not contain those strings.

6. **Swap state-machine invariants.**
   For generated traces of upstream classes (`ok`, `401`,
   `usage_limit_reached`, `usage_not_included`, generic `429`, `5xx`), the
   adapter:
   - observes quota before swap;
   - swaps at most once per turn boundary;
   - never restarts child state;
   - does not swap on `usage_not_included`;
   - returns typed no-account-selectable when all candidates are blocked.

7. **Refresh serialization model.**
   For generated concurrent refresh requests on the same account, the model
   allows exactly one provider refresh attempt and shares the result with
   waiters.

### 5.3 E2E and Smoke Tests

Add or extend shell smokes:

- `scripts/smoke-codex-cli-ux.sh`
  - exercises first-class `oauth-mux codex resume ...` aliases against
    `scripts/test-stub-codex.py`;
  - asserts legacy diagnostics still parse;
  - asserts wrong `codex run resume` form fails helpfully.

- `scripts/smoke-codex-managed-resume.sh`
  - builds a fake canonical Codex home with session authority;
  - runs managed adapter with `resume <id>`, `resume --last`, and `resume`;
  - stub proves it can read canonical session files through the overlay;
  - status artifact parent directory is intentionally absent before startup.

- Extend `scripts/smoke-codex-concurrent-sessions.sh`
  - two managed resumes against the same canonical session authority;
  - distinct proxy ports and distinct overlay configs;
  - shared session authority remains safe.

- Keep `scripts/smoke-codex-acceptance.sh`
  - no-spend A -> 429 -> B synthetic swap in one stable child PID.

### 5.4 Cassette Coverage

Use three cassette layers, each with redaction and replay:

1. **CLI/session cassettes.**
   Captured local stub transcripts for command shapes:
   `resume <id>`, `resume --last`, `resume`, failed unknown arg, status-file
   parent missing, isolated session store. These are safe to check in because
   they use stubs and contain no transcript content.

2. **Codex app-server JSON-RPC cassettes.**
   Redacted method/event sequences for `initialize`, login, account update,
   refresh request, and failure surfaces. These protect the IDE-role adapter
   contract from Codex protocol drift.

3. **Wire proxy HTTP/SSE cassettes.**
   Redacted `chatgpt.com/backend-api/codex` flows for 200, 401, 429
   `usage_limit_reached`, `usage_not_included`, compact, memory, and WebSocket
   upgrade when available. These sit between synthetic mocks and live spend.

Replay requirements:

- Matching by method + path + ordered occurrence.
- Header allow-list and deny-list assertions.
- Secret scanner before fixtures can be committed.
- Miss diagnostics are structural, not raw-body dumps.

### 5.5 Live QA Gates

Live gates are not substitutes for tests; they are final evidence:

1. Managed resume gate:
   - run `oauth-mux codex resume --last` against a real existing session;
   - store redacted status artifact;
   - verify no prompt slug coercion was required.

2. Level 3 gate:
   - run real `oauth-mux codex`;
   - observe provider-originated account A quota exhaustion;
   - verify continuation on account B in the same child process;
   - emit runtime claim no stronger than actual evidence.

## 6. Advanced Testing and Analysis

The hard part is not just code coverage. The product is a runtime protocol
system with auth state, route health, process ownership, and provider
responses. Use higher-leverage testing where it fits.

### 6.1 Model-Based Testing

Build a small pure state-machine model for:

- accounts and availability;
- active adapter session;
- turn lifecycle;
- upstream response classification;
- credential refresh;
- account swap;
- child process lifecycle;
- status events.

Then generate traces and compare the implementation's emitted events to the
model. This is the highest-value advanced technique for this repo because the
product contract is already state-machine shaped.

### 6.2 Bounded Exhaustive Exploration

Before reaching for full symbolic tooling, exhaustively enumerate small cases:

- accounts: 0, 1, 2, 3;
- events: 200, 401, 429 quota, 429 tier, 5xx;
- session modes: canonical, isolated, explicit override;
- command modes: alias, raw `run --`, malformed pre-`--`.

This catches edge cases such as all accounts exhausted, one spare fallback,
and wrong-route resume without requiring a symbolic executor.

### 6.3 Concolic or Symbolic Execution

Useful in theory, expensive in this Zig codebase today.

Candidate targets if we later invest:

- CLI parser: bounded symbolic argv tokens could prove no unknown arg is
  silently dropped.
- HTTP classification parser: symbolic response bodies could prove only
  `usage_limit_reached` triggers quota swap.
- path preparation: symbolic path components could expose traversal or
  parent-creation mistakes.

Non-goal for now: full-process symbolic execution of the adapter/proxy. The
state space includes filesystem, process spawning, network, and provider
protocols; model-based and cassette tests will produce better signal sooner.

### 6.4 Differential Testing

For single-account, no-swap flows:

- run bare `codex resume --last` under canonical `CODEX_HOME`;
- run `oauth-mux codex resume --last` with one selectable route;
- compare observable session selection behavior, exit status, and non-secret
  command shape.

The outputs need not be byte-identical because oauth-mux owns status frames,
but the user-visible semantic result should match.

### 6.5 Metamorphic Testing

Replay the same cassette under transformations that should not change the
outcome:

- reorder non-semantic headers;
- vary casing of HTTP header names;
- rotate account priority while keeping only one selectable account;
- add irrelevant config fields;
- vary path nesting for status artifacts.

The expected account decision and claim level should remain stable.

### 6.6 Concurrency and Race Testing

Use deterministic stress smokes, not unbounded sleeps:

- multiple adapters sharing canonical session authority;
- multiple adapters refreshing the same account;
- route-health update racing with account selection;
- status file creation racing with parent directory creation;
- proxy serving while child exits.

Invariants:

- no account-local `config.toml` clobber;
- no duplicate refresh attempts for a single refresh token;
- no child restart presented as recovery;
- no status/event path leaks.

### 6.7 Mutation Testing

Lightweight manual mutation is worthwhile:

- flip `usage_limit_reached` to generic `429` and expect tests to fail;
- remove parent-dir creation and expect status-file tests to fail;
- drop `--` forwarding and expect CLI PBT to fail;
- print a generated secret string and expect redaction PBT to fail.

This can be scripted later, but even a small mutation checklist will prevent
false confidence.

## 7. Definition of Done

This refactor is done when:

1. Daily commands work:
   - `oauth-mux codex resume --last`
   - `oauth-mux codex resume <id>`
   - `oauth-mux codex resume`
2. Raw `codex run` misuse fails helpfully and never silently drops args.
3. `--json-status-file` creates parents and never fails as bare
   `FileNotFound`.
4. Stub e2e proves managed resume parity through canonical session authority.
5. Live dogfood proves managed resume parity with a real Codex session.
6. Status output remains redacted.
7. TIN-979 is not closed until the live dogfood passes.
8. No doc or claim uses managed resume success as a substitute for Level 3
   live account-swap success.

## 8. Dogfood Finding: Same-Account 401 Refresh Loop

The first real managed `resume --last` dogfood after PR #194 did not prove
resume parity. Status evidence showed the adapter started with
`session_authority:"canonical_bridge"` and selected `codex:max-1`, then the
wire proxy observed repeated upstream `401` responses.

Root cause:

- Codex can refresh the selected account inside the managed overlay after a
  `401`.
- The proxy was still re-signing every upstream request from oauth-mux's
  materialized route credential.
- That meant Codex's refreshed child `Authorization` header was ignored, so
  the next request could keep using the stale materialized access token.

Correct behavior:

- If inbound `ChatGPT-Account-ID` still matches the broker-elected account,
  preserve the child's inbound `Authorization` header. This lets Codex's
  native same-account refresh loop work.
- If oauth-mux elects a different account, substitute the elected account's
  materialized `Authorization` / `ChatGPT-Account-ID` as before.

Regression guard:

- `scripts/smoke-codex-child-refresh.sh` drives two synthetic same-account
  turns with different child bearer tokens and asserts that the upstream sees
  the bearer change without an account swap or a stale 401 loop.

## 9. Dogfood Finding: Splash Screen Is Not Resume Evidence

The second real managed `resume --last` dogfood after the same-account refresh
fix completed a provider turn through the proxy, but the Codex TUI still
looked like a fresh startup screen. That is not enough evidence either way:
Codex can resume a rollout without replaying enough transcript in the visible
startup pane to make the operator confident.

Correct evidence:

- Before launching the child, oauth-mux snapshots the bridged Codex session
  authority.
- After the child exits, oauth-mux reports whether an existing rollout was
  changed, whether a fresh rollout was created, and whether an explicit resume
  target changed.
- The status frame continues to redact session ids and paths.

Regression guard:

- `scripts/smoke-codex-cli-ux.sh` now requires managed resume aliases to emit
  `resume_preflight` and `resume_writeback` frames, and the stub child appends
  through the bridged session authority so the adapter proves writeback
  observation instead of relying on terminal appearance.

## 10. Dogfood Finding: Brokered Resume Works, Cloudflare 400 Was Framing

The first successful brokered resume proof used:

```bash
./zig-out/bin/oauth-mux codex --profile codex-max \
  --json-status-file dist/live-qa/managed-resume-dogfood-5/status.ndjson \
  resume 019dea53-49a0-7890-9580-e88decb97af0
```

Evidence:

- The process environment reported `OMUX_ACTIVE_PROVIDER=codex`,
  `OMUX_ACTIVE_ACCOUNT=max-1`, and `OMUX_ACTIVE_PROFILE=codex-max`.
- The managed `CODEX_HOME` overlay was active.
- `resume_preflight` found the explicit canonical rollout before launch.
- `proxy_turn` frames showed the main
  `POST /backend-api/codex/responses` path as `status:200`,
  `classification:"ok"`, and `body_class:"none"`.

The prior `dogfood-4` run had already proven that explicit resume writeback
worked, but the main `responses` POST returned Cloudflare `400 Bad Request`.
The likely root cause was proxy request framing: oauth-mux forwarded inbound
`Content-Length` and set `Host` as extra headers while `std.http.Client` was
also responsible for those fields. The proxy now drops inbound `Host`,
`Content-Length`, and `Transfer-Encoding` and lets `std.http.Client` own
request framing.

Remaining Level 3 evidence still required:

- Observe a real provider-originated `429 usage_limit_reached` for the active
  account inside this managed session.
- Confirm oauth-mux records the quota event and the next turn selects a
  distinct fallback account.
- Do not treat this brokered-resume success as proof of live account-swap
  success until an actual `proxy_turn` / swap sequence shows it.

## 11. Dogfood Finding: Managed Overlay Auth Can Go Stale Across Restarts

The first dogfood restart after refreshing the oauth-mux executable used:

```bash
./zig-out/bin/oauth-mux codex --profile codex-max \
  --json-status-file dist/live-qa/managed-resume-dogfood-6/status.ndjson \
  resume 019dea53-49a0-7890-9580-e88decb97af0
```

Evidence:

- The adapter did start a broker-owned managed frame:
  `session_started`, `auth_authority:"mux_owned_overlay"`,
  `session_authority:"canonical_bridge"`.
- The explicit resume target was found before launch and writeback was observed.
- Every proxied upstream request returned `401 auth_unauthorized`, including
  the main `POST /backend-api/codex/responses` turns.
- Codex surfaced the provider refresh-token failure:
  "Your access token could not be refreshed because your refresh token was
  already used. Please log out and sign in again."
- `broker-session-plan`, `doctor runtime`, and `codex login-status-all` still
  reported `codex:max-1` as locally ready/available because the source
  `auth.json` remained structurally parseable and the stored route liveness was
  stale-positive.

Interpretation:

- PR #195's same-account child-auth preservation fixed stale access-token
  re-signing within one managed session.
- It did not prove durable refresh-token writeback from the mux-owned
  `CODEX_HOME` auth overlay back to the route authority used for the next
  managed launch.
- A successful long-running managed session can therefore consume/rotate a
  refresh token inside its overlay, while the next managed launch starts from
  an older route auth tuple and falls into unrecovered 401.

Truth boundary:

- This is not quota exhaustion and not live account-substitution evidence.
- This is a P0/P1 auth-authority gap for long-running dogfood reliability:
  mux-owned auth overlays either need durable token writeback/import back to the
  selected account store, or repeated 401/refresh-token-failure evidence must
  mark the route auth-unready and select a fallback account on the next launch.

Follow-up implemented:

- The adapter now records unrecovered managed-session 401s as account-credential
  health only after the child exits and only when the overlay auth did not
  change. The status stream emits `auth_health_observed` with
  `quota_claim:false`, and the next `broker-session-plan` should route around
  that stale auth source when another healthy route exists.
- The proxy now buffers selected-account 401s and, when a different account is
  selectable, retries the same request against that fallback before Codex sees
  the 401. Status evidence is `proxy_auth_same_turn_retry` plus a fallback
  `proxy_turn` with `status:200`; the summarizer reports
  `verdict:"auth_fallback_sequence_observed"`. This remains separate from live
  quota fallback evidence.

## 12. Dogfood Finding: Live Quota Was Observed, Handoff Failed

Dogfood-9 is not a successful managed quota stay-afloat artifact. It first
proved auth continuity by retrying selected-account `401 auth_unauthorized`
responses from `codex:max-1` through `max-2` and `max-3`, then continuing
with successful traffic on `codex:max-4`.

Later in the same managed frame, `codex:max-4` returned provider-originated
`429 usage_limit_reached` / `classification:"quota_exhausted"`. oauth-mux did
not substitute another credited account; status evidence ended with
`proxy_same_turn_retry_unavailable` / `NoAccountSelectable` instead of a
distinct-account `200` fallback turn.

Correct interpretation:

- `verdict:"quota_handoff_failed"` is the status-oracle result for this
  artifact.
- TIN-916 / GitHub #131 and TIN-951 / GitHub #177 remain open.
- Future live dogfood must enter through an actually installed `oauth-mux`
  executable on PATH: `oauth-mux codex resume <id>`. Repo-local
  `./zig-out/bin/oauth-mux`, extra dogfood wrapper scripts, and arg-clad
  launch helpers are not acceptance evidence.
- A future acceptance artifact must show quota/rate evidence on account A,
  durable route evidence, same-process retry or swap to account B, and a
  successful response on B without logout, login, restart, or manual resume.

## 13. 2026-05-08 Finding: Managed Load Quota Handoff Succeeded

Two installed-runtime managed resume/load artifacts now satisfy the narrower
managed quota-handoff evidence shape:

- `<oauth-mux-state>/codex/status/managed-1778271585359.ndjson`
- `<oauth-mux-state>/codex/status/managed-1778273610565.ndjson`

Both were entered through installed `oauth-mux codex resume <id>`, selected
`codex:default`, observed provider-originated `429 usage_limit_reached` on
`POST /backend-api/codex/responses`, recorded quota, dropped
`x-codex-turn-state`, retried the same request on `codex:max-2`, and received
`status:200` from the fallback account before Codex saw the 429. The updated
status oracle reports `verdict:"successful_live_quota_handoff"`.

The 2026-05-09 installed-runtime engineered artifact
`<oauth-mux-state>/codex/status/managed-1778362718969.ndjson` satisfies the
stricter managed-session evidence shape: successful `codex:max-2` traffic,
provider-originated `usage_limit_reached`, same-request retry to
`codex:max-3`, and fallback `status:200`. The reviewed proof bundle is
`docs/evidence/codex-engineered-quota-handoff-20260509/`.

Correct interpretation:

- Managed load/resume quota fallback is live-proven for Codex.
- Dogfood-9 remains historical failed-quota evidence and should keep its
  original verdict.
- Same-thread continuity, mid-turn recovery, unmanaged `codex` hot-swap, and
  non-Codex harnesses remain unclaimed.

## 14. 2026-05-09 Finding: Chooser Authority And Startup Timing

Current main now has the managed-resume chooser guard this spec originally
called for:

- `oauth-mux codex resume` forwards exactly `["resume"]` into the managed
  frame so native Codex keeps chooser ownership.
- Before child spawn, oauth-mux checks that the mux-owned overlay exposes the
  required canonical session-authority entries by reference:
  `sessions/`, `shell_snapshots/`, `history.jsonl`, and
  `session_index.jsonl`.
- If chooser parity is unavailable, oauth-mux emits
  `kind:"resume_authority_check", ok:false` with only counts and a typed
  diagnostic, then exits before spawning Codex. It does not print paths,
  tokens, or session ids.
- If chooser parity is available, oauth-mux emits the same event with
  `ok:true` and launches Codex.
- `--isolated-session-store` remains an explicit opt-out from canonical
  chooser parity.

Startup timing is now status evidence, not user-facing terminal noise.
Managed launches emit redacted `launch_timing` events for config/health load,
route election, auth refresh/preflight, proxy bind, overlay creation,
resume-authority check, binary resolution, env build, and child spawn.
`oauth-mux codex status-latest --json` and
`scripts/summarize-codex-status.py` both summarize this as:

```json
{"launch_timing":{"events":9,"child_spawn_elapsed_ms":19,"total_elapsed_ms":19}}
```

The exact millisecond values are diagnostic. They are not a product claim, but
they protect the fast-visible-TUI requirement: chooser mode must not do a
recursive rollout scan before child spawn.
