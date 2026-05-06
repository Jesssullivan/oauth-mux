# Codex Managed Resume UX Refactor
Date: 2026-05-06
Status: P0/P1 planning contract. This is a refactor and regression plan,
not an implementation record.

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
- `sessions/`, `history.jsonl`, `session_index.jsonl`, and
  `shell_snapshots/` are bridged by reference to canonical Codex session
  authority by default.
- `--session-home`, `OMUX_CODEX_SESSION_HOME`, and
  `--isolated-session-store` exist.
- Synthetic smokes prove the bridge structure and write-through behavior.
- Synthetic smokes prove A -> `usage_limit_reached` -> B swap through the
  adapter/proxy in one stable child PID.

Not real yet:

- Live managed-frame `resume <id>` parity.
- Live managed-frame `resume --last` parity.
- Provider-originated live Level 3 account swap in a real interactive
  `oauth-mux codex` session.
- Same-thread continuity across account swap.
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
- Missing `history.jsonl` or `session_index.jsonl` is created in canonical
  authority, not copied into an isolated fork.

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
