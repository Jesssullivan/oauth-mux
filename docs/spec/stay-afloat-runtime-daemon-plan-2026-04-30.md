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
it can start, stop, report status, and experiment with refresh. It is not yet a
safe product surface for background repair.

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

### M2: Repair Plan

- Add `needs_reauth` state.
- Add `oauth-mux repair-plan --json`.
- For Codex, output exact `oauth-mux codex login[-device] <account>` commands
  and verify `CODEX_HOME` writability before suggesting live auth.

### M3: Refresh Writeback

- Implement backend write capabilities.
- Persist refreshed tokens atomically for admitted providers.
- Add fixtures for refresh-token rotation.
- Refuse refresh when a backend is read-only or token age semantics are
  ambiguous.

### M4: Daemon Beta

- Promote daemon to opt-in beta.
- Add budgets, event log, lock files, and status JSON.
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
