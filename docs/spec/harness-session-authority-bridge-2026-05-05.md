# Harness Session Authority Bridge
Date: 2026-05-05
Status: planning contract. This is a P1 product/architecture issue until
`oauth-mux <harness>` can preserve ordinary harness session continuity while
oauth-mux owns muxed auth/config state.

Anchor: `docs/spec/broker-mcp-contract-2026-05-03.md`.
Codex implementation anchor: `docs/spec/codex-adapter-contract-2026-05-03.md`.
Managed Codex resume UX/refactor plan:
`docs/spec/codex-managed-resume-ux-refactor-2026-05-06.md`.

## 0.0 Current Implementation Checkpoint

The Codex bridge is implemented for the first-class `oauth-mux codex` managed
frame. The adapter builds a composed managed `CODEX_HOME` with mux-owned
`auth.json` and generated proxy `config.toml`, while session-authority entries
are bridged by reference. Default session authority is the parent `CODEX_HOME`
when set, otherwise `~/.codex`; `OMUX_CODEX_SESSION_HOME` and
`--session-home <path>` can override that authority; `--isolated-session-store`
opts out for tests/privacy.

The synthetic acceptance smoke proves the managed overlay exposes
`sessions/`, `history.jsonl`, `session_index.jsonl`, `shell_snapshots/`, and
documented Codex SQLite authority by reference without printing paths.
`oauth-mux codex resume` with no id now runs the native chooser path only after
a pre-spawn authority check verifies those entries are available; missing
authority emits redacted `resume_authority_check` status and exits before
spawning Codex. Installed-runtime dogfood has also proven managed resume/load
through the proxy, including live quota handoff evidence tracked in
`docs/spec/codex-live-quota-handoff-evidence-2026-05-08.md`.

Implementation update, 2026-05-26: Codex 0.132 reads native SQLite resume
state from `CODEX_SQLITE_HOME` when set, and the chooser can depend on
`logs_2.sqlite*` as well as `state_5.sqlite*`. Canonical bridge mode keeps the
managed `CODEX_HOME` as mux-owned auth/config, sets child `CODEX_SQLITE_HOME`
to the canonical session authority home, and bridges both SQLite families by
reference when present. Isolated mode leaves SQLite state in the overlay and
removes inherited `CODEX_SQLITE_HOME`.

The 2026-05-06 dogfood-6 auth failure exposed the auth-side counterpart:
Codex can refresh tokens inside the managed overlay, and the adapter must
import changed overlay `auth.json` back into the selected mux-owned account
source before the next managed frame. Current code emits a redacted
`auth_writeback` frame for that import. This writeback is scoped to the
oauth-mux account source, not canonical `~/.codex/auth.json`. The import
does not overwrite a source auth file that changed independently after the
overlay was created; that conflict is surfaced as `source_conflict:true`.

## 0. Problem

`oauth-mux codex run` currently creates a temporary `CODEX_HOME` overlay so
oauth-mux can own the selected account auth material and generated proxy
`config.toml` without mutating the user's normal Codex home. That fixed the
account-local `config.toml` clobber race.

It also exposed a separate bug: Codex stores auth, config, sessions, history,
shell snapshots, logs, and caches under the same `CODEX_HOME` root. When
oauth-mux points Codex at a temporary home, `codex resume <id>` cannot see a
session that exists under the canonical Codex session store. The operator
observed this directly: the session file existed under `~/.codex/sessions`,
but `oauth-mux codex run -- ... resume <id>` failed with "No saved session
found" because the temporary `CODEX_HOME` did not include that session
authority.

Blindly copying `~/.codex/sessions` into each temporary overlay is rejected.
The operator's local Codex session store was several GiB. Copying it would be
slow, racy, confusing, and wrong: oauth-mux would fork the user's session
authority instead of retaining it.

## 1. Product Bar

This problem does not change the product metric:

> The user runs `oauth-mux <harness>`. The active subscription account exhausts
> its quota. Another credited account is substituted in place. The harness
> process is not restarted. The user is not prompted.

Session authority is a prerequisite for the UX around that metric. A managed
`oauth-mux codex` frame must be able to resume the same sessions a normal
Codex user expects, without handing auth/config control back to bare Codex.

## 2. Store Taxonomy

Every harness adapter MUST classify its local state into these buckets before
claiming managed-session parity.

### 2.1 Auth Authority Store

Account-bound secrets and identity material:

- access tokens, refresh tokens, id tokens, account ids;
- provider-specific auth cookies or bearer material;
- installation ids when they participate in auth;
- any per-account state that can authorize provider requests.

oauth-mux owns this boundary during a brokered session. It may materialize a
copy into an adapter overlay, but it must not mutate the user's canonical auth
store unless the user is explicitly enrolling or reauthing that account.

For Codex today: `auth.json` and likely `installation_id` are auth-authority
inputs for the managed overlay. If Codex mutates overlay `auth.json` during
its native 401 refresh path, oauth-mux writes the changed file back to the
selected account source so route auth does not go stale between managed
frames.

### 2.2 Managed Config Overlay

Adapter-controlled configuration needed to interpose the broker:

- model provider/base URL override;
- proxy transport settings;
- mux instrumentation flags;
- account/profile policy settings that belong to oauth-mux.

oauth-mux owns this boundary. For Codex, this is the generated
`config.toml` selecting `model_provider = "openai"` and `openai_base_url =
"http://127.0.0.1:<port>/backend-api"`. The adapter must not write that
configuration into the canonical `~/.codex/config.toml` by default.

Managed config is not permission to erase harness behavior settings. For Codex,
the temporary overlay must preserve or deliberately reapply unrelated native
config such as `[features]`, legacy `experimental_*` keys, MCP servers, hooks,
rules, approval/sandbox policy, profiles, and model defaults. The known Codex
gap is tracked as <https://github.com/Jesssullivan/oauth-mux/issues/211>; the
initial implementation is landed. Config authority follows
`OMUX_CODEX_CONFIG_HOME`, then a non-managed parent `CODEX_HOME`, then
`~/.codex`, and is independent from session authority. A parent `CODEX_HOME`
that is itself an oauth-mux temporary overlay is not reusable authority;
nested managed sessions fall back to canonical config/session state instead of
recursively inheriting a reduced overlay. oauth-mux removes routing conflicts,
including profile-scoped `model_provider` and `openai_base_url`, then appends
the managed proxy base URL. Forwarded `--config` / `-c` attempts to override
mux-owned provider/base-url keys fail before child spawn with redacted status.

### 2.3 Session Authority Store

User-visible conversation/session continuity:

- transcript/session files;
- session indexes;
- history files;
- shell snapshots or command-resume artifacts;
- any provider/harness metadata needed for `resume`, `resume --last`, or
  equivalent user workflows.

oauth-mux SHOULD retain this authority by reference, not copy it. The default
managed frame should see the same session authority as the ordinary harness
unless the user explicitly requests an isolated session namespace.

For Codex today, candidate session-authority files are:

- `~/.codex/sessions/`
- `~/.codex/session_index.jsonl`
- `~/.codex/history.jsonl`
- `~/.codex/shell_snapshots/`
- `~/.codex/state_5.sqlite*` when present, for native SQLite state
- `~/.codex/logs_2.sqlite*` when present, for Codex 0.132+ native chooser
  previews

The current required set is pinned by fixture smoke coverage and pre-spawn
chooser authority checks. `logs_2.sqlite` or `state_5.sqlite` is sufficient
chooser authority when present; otherwise the legacy entries above remain the
fallback authority set. Add new entries only with evidence that native Codex
requires them for chooser/resume parity.

For canonical Codex SQLite authority, managed resume may probe SQLite's
standard lock byte range on `state_5.sqlite` before child spawn. A held lock is
reported as redacted `session_authority_locked` / `database_locked` status with
the database basename only. oauth-mux must not kill the lock holder, rewrite the
canonical database, or create an overlay-local SQLite authority to bypass the
lock.

### 2.4 Cache, Log, and Runtime State

Local state that may be large, private, or not required for session continuity:

- model caches;
- SQLite logs/state;
- telemetry/debug logs;
- temporary files.

Default: do not bridge unless evidence shows the harness requires it for
normal operation. Keep this state local to the managed overlay or to an
oauth-mux-owned runtime directory. If a harness needs a cache bridge, it must
be explicit and documented separately from session authority.

For Codex, `state_5.sqlite*` and `logs_2.sqlite*` are narrowly scoped
session-authority bridges for native chooser parity. Other `logs_*.sqlite`,
`state_*.sqlite`, and model caches are not bridged by default without fresh
native evidence.

### 2.5 oauth-mux Evidence Store

Redacted oauth-mux status and proof artifacts:

- NDJSON status files;
- cassette captures and replay metadata;
- route-health/quota evidence;
- broker event logs.

This state is oauth-mux-owned and MUST remain separate from harness session
authority. It must not leak token material, raw JWTs, credential paths, or
session file contents.

## 3. Design Principle

oauth-mux owns auth/config. The harness owns user session continuity.

For adapters that only expose a single home directory environment variable,
oauth-mux must build a composed home:

1. auth/config entries are adapter-generated and mux-owned;
2. session-authority entries are references to the canonical session store;
3. cache/log/runtime entries are isolated unless proven necessary;
4. evidence entries live outside the harness home.

This is a bridge, not a full copy. If the adapter cannot safely bridge session
authority, it must refuse or clearly report `session_authority:"isolated"`
instead of pretending managed resume parity exists.

## 4. Codex-Specific Options

### Option A: Upstream Split Session Paths

Best long-term shape: Codex accepts separate session/history paths while
`CODEX_HOME` continues to point at the mux-owned auth/config overlay.

Possible upstream surfaces:

- `CODEX_SESSION_HOME`
- `CODEX_HISTORY_PATH`
- `CODEX_SHELL_SNAPSHOTS_DIR`
- equivalent `config.toml` keys

This is the cleanest design because it avoids filesystem tricks and makes the
boundary explicit in Codex itself. It requires upstream Codex support.

### Option B: Local Session Bridge by Reference

Near-term shape: the temporary `CODEX_HOME` contains mux-owned `auth.json` and
`config.toml`, while session-authority paths are symlinks, directory links, or
adapter-managed references to the canonical Codex store.

For Codex on Unix-like systems, a candidate overlay is:

```text
<tmp>/oauth-mux-codex-XXXX/
  auth.json                 # copied from selected account auth source
  installation_id           # copied if auth-relevant
  config.toml               # generated proxy config
  sessions -> ~/.codex/sessions
  session_index.jsonl -> ~/.codex/session_index.jsonl
  history.jsonl -> ~/.codex/history.jsonl
  shell_snapshots -> ~/.codex/shell_snapshots
  state_5.sqlite -> ~/.codex/state_5.sqlite       # when canonical has it
  state_5.sqlite-wal -> ~/.codex/state_5.sqlite-wal
  state_5.sqlite-shm -> ~/.codex/state_5.sqlite-shm
  logs_2.sqlite -> ~/.codex/logs_2.sqlite         # when canonical has it
  logs_2.sqlite-wal -> ~/.codex/logs_2.sqlite-wal
  logs_2.sqlite-shm -> ~/.codex/logs_2.sqlite-shm
```

This keeps `resume <id>` and `resume --last` pointed at the canonical session
authority without mutating canonical auth/config. For Codex 0.132+,
`CODEX_SQLITE_HOME` is also set to the canonical authority home in this mode.

Risks to resolve:

- symlink/junction behavior on Windows;
- file creation if `session_index.jsonl` or `history.jsonl` does not exist;
- concurrent writes from bare `codex` and `oauth-mux codex`;
- privacy expectations when a user wants isolated managed sessions;
- whether any Codex session entry embeds account identity that makes
  cross-account continuation impossible at the provider layer.

### Option C: Targeted Resume Import/Export

Fallback if Option B is unsafe: for an explicit `resume <id>`, locate only the
matching session file and bridge or import that one session into the overlay,
then export any updated session file back on clean exit.

This is worse than Option B because it creates writeback and conflict
questions. It is acceptable only as an explicit compatibility mode, not as the
default user experience.

### Option D: Copy the Whole Session Store

Rejected. It is too large, too slow, racy under concurrent sessions, and
creates a forked session authority that neither bare Codex nor oauth-mux can
explain cleanly.

## 5. Default Policy

Recommended default after tests are green:

- `oauth-mux codex run` uses canonical Codex session authority by reference.
- `--isolated-session-store` or equivalent opts into a managed-only session
  namespace for tests/privacy.
- `--session-home <path>` is an advanced override for operators who keep
  Codex sessions outside `~/.codex`.
- Normal output reports booleans such as
  `session_authority:"canonical_bridge"` and
  `canonical_session_paths_printed:false`. It does not print session ids,
  full paths, or transcript content.

This default matches user expectation: if they can run `codex resume <id>`,
then `oauth-mux codex run -- ... resume <id>` should see the same session
authority unless they deliberately isolated it.

## 6. Harness-General Contract

Each adapter must define:

- `auth_authority`: what files/env/keychain entries authorize provider calls;
- `managed_config`: what oauth-mux must generate or override;
- `session_authority`: what files or service APIs implement resume/history;
- `runtime_state`: what caches/logs are safe to isolate;
- `bridge_mode`: `canonical_bridge`, `isolated`, `targeted_import`, or
  `unsupported`;
- `writeback_policy`: canonical, isolated, import_export, or read_only.

The broker MCP contract should gain a session-authority status field so future
adapters can report this consistently:

```jsonc
{
  "kind": "session_started",
  "adapter": "codex",
  "claim_level": "broker_owned",
  "session_authority": "canonical_bridge",
  "auth_authority": "mux_owned_overlay",
  "managed_config": "mux_owned_overlay",
  "session_paths_printed": false,
  "sqlite_authority": "canonical_env"
}
```

## 7. Acceptance Criteria

P1 is satisfied for Codex when all of these are true:

1. `oauth-mux codex run -- ... resume <existing-id>` finds a session that
   exists only in the canonical Codex session authority, without copying the
   full session store.
2. `oauth-mux codex run -- ... resume --last` resolves against the same
   canonical session authority bare `codex` would use.
3. A new session started under `oauth-mux codex run` writes to the chosen
   session authority and can later be found by bare `codex resume` unless the
   user opted into isolation.
4. The adapter does not mutate canonical `~/.codex/auth.json` or
   `~/.codex/config.toml`.
5. Concurrent `oauth-mux codex run` sessions do not clobber auth/config
   overlays and can both read/write session authority safely.
6. Tests prove no full-store copy happens.
7. Normal output and status frames do not print token material, credential
   paths, raw JWTs, transcript contents, full session paths, or session ids by
   default.
8. If Codex/provider refuses cross-account continuation for a resumed thread,
   oauth-mux reports that as provider/thread continuity evidence, not as a
   session-authority bridge failure.

## 8. Test Plan

1. Fixture layout smoke:
   - create a fake canonical Codex home with `sessions/`, `history.jsonl`,
     `session_index.jsonl`, and `shell_snapshots/`;
   - create an oauth-mux managed overlay with mux-owned auth/config and
     canonical session bridge references;
   - prove the overlay exposes the fixture session without copying the store.
2. Resume command smoke:
   - run a stub `codex resume <id>` under `CODEX_HOME=<overlay>`;
   - stub asserts it can read the bridged canonical session file and that
     `auth.json`/`config.toml` came from the overlay.
3. Concurrent sessions:
   - start two managed overlays against the same canonical session authority;
   - prove both use distinct generated proxy configs and neither mutates
     canonical auth/config.
4. Redaction check:
   - status output must report bridge mode, not raw paths or ids.
5. Live operator proof:
   - run `oauth-mux codex run --profile codex-max -- ... resume <known-id>`;
   - verify the same session is available without copying `~/.codex/sessions`.

## 9. Decision Points

- Do we implement Option B locally first, or open an upstream Codex request for
  Option A before local bridge code? Recommendation: implement Option B as the
  near-term P1 and file the upstream split-path request in parallel.
- Should canonical session bridge be default immediately? Recommendation:
  yes, after smoke coverage; provide an isolated opt-out.
- Which Codex files are required for `resume --last`: only `sessions/`, or
  also `history.jsonl` / `session_index.jsonl` / `shell_snapshots/`?
  Recommendation: test before deciding.
- Should managed sessions write new transcripts to canonical `~/.codex`
  by default? Recommendation: yes, because the user expects `codex resume` and
  `oauth-mux codex resume` to describe the same work history.

## 10. Phase Plan

### Phase 0: Reproduce and Spec

- Add this plan.
- Add a failing/diagnostic smoke that documents `resume <id>` invisibility
  under isolated temporary `CODEX_HOME`.
- Record current Codex state layout without logging paths in normal output.

### Phase 1: Adapter Store Classification

- Add Codex adapter metadata for auth/config/session/cache/evidence stores.
- Emit redacted `session_authority` and `auth_authority` status fields.
- Keep behavior unchanged until the bridge smoke exists.

### Phase 2: Codex Canonical Session Bridge

- Build the composed `CODEX_HOME` overlay:
  mux-owned auth/config, canonical session-authority references, isolated
  cache/log state.
- Add fixture and concurrent-session tests.
- Support `--isolated-session-store` and optional `--session-home`.

### Phase 3: Managed Resume Acceptance

- Prove `resume <id>` and `resume --last` work through
  `oauth-mux codex run`.
- Run one live managed-frame resume dogfood with redacted status artifact.

### Phase 4: Harness-Generalization

- Promote the store taxonomy into `docs/spec/harness-adapter-pattern-2026-05-03.md`.
- Require every future adapter (`oauth-mux claude`, etc.) to declare its
  session-authority bridge before claiming managed-session parity.

## 11. Non-Goals

- This does not prove provider thread continuity across accounts.
- This does not prove same-thread quota recovery.
- This does not make bare `codex` plus a background oauth-mux daemon seamless.
- This does not justify restart or manual resume as product success.
- This does not copy or inspect user transcript content.
