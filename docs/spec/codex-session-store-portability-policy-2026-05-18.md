# Codex Session-Store Portability And Resume Import Policy
Date: 2026-05-18
Status: historical policy for #161 / TIN-936; updated 2026-06-12 for the
TIN-1851 home-is-store architecture.

> Current main no longer uses canonical session bridging as the default muxed
> Codex model. The default is `isolated_persistent`: the selected route's
> durable account home is `CODEX_HOME`, owns its own `state_5.sqlite` /
> `logs_2.sqlite`, and does not set canonical `CODEX_SQLITE_HOME`.
> `shared_canonical` remains an explicit legacy/diagnostic mode for operators
> who choose to point a managed session at canonical Codex authority.

This policy defines what oauth-mux supports for Codex session continuity when
auth/config are mux-owned. It supersedes the early idea of making every
account-scoped Codex home independently portable by copying or importing
session stores.

## Product Boundary

oauth-mux owns managed auth/config for `oauth-mux codex`. Native Codex owns the
canonical `~/.codex` session store. Current managed Codex uses a route-local
durable account home as `CODEX_HOME` by default so muxed auth, config, sessions,
and SQLite authority stay together and do not poison canonical native Codex
state. Canonical bridging is opt-in only.

The bridge is not a provider-thread-continuity guarantee. If a provider refuses
continuation across accounts, that is thread/provider evidence, not a local
session-store portability failure.

## Supported Modes

| Mode | Status | Behavior |
| --- | --- | --- |
| Route-local persistent account home | Supported default | `oauth-mux codex` uses the selected account's durable home as `CODEX_HOME`; muxed sessions and SQLite authority remain route-local and persistent. |
| Canonical session bridge | Supported opt-in / legacy | `TINYLAND_CODEX_MUX_MODE=shared_canonical` or `--mux-mode shared_canonical` exposes canonical Codex session authority to the managed child while keeping auth/config mux-owned. Use only when the operator deliberately accepts canonical SQLite contention risk. |
| Explicit session home | Supported advanced override | `--session-home <path>` or `OMUX_CODEX_SESSION_HOME=<path>` selects a non-default session authority for bridge-style operation. |
| Ephemeral isolated managed store | Supported diagnostic override | `--isolated-session-store` keeps managed sessions private to a disposable overlay. It intentionally gives up persistent muxed resume parity. |
| Native chooser under managed frame | Scoped | In default route-local mode, the chooser sees the selected route-local account home. In `shared_canonical` mode it can see canonical Codex authority after the pre-spawn authority check. |
| Route-local account home resume | Supported for muxed sessions | A route-local account directory is the managed session authority in default mode. It is not a promise that native bare Codex will see those sessions from canonical `~/.codex`. |
| Targeted import/export | Not shipped | No command imports unmanaged rollout files into a mux account store. Add only with explicit operator confirmation, redaction review, and conflict/writeback semantics. |
| Full session-store copy | Rejected | Copying `~/.codex/sessions` or SQLite state into every account store is too large, racy, private, and creates forked session authority. |

## Canonical Authority Set

This section applies only to `shared_canonical` bridge mode. In default
`isolated_persistent` mode these entries live under the selected route-local
account home instead of being bridged from `~/.codex`.

The managed overlay bridges these canonical Codex entries by reference when
present:

- `sessions/`
- `history.jsonl`
- `session_index.jsonl`
- `shell_snapshots/`
- `state_5.sqlite`
- `state_5.sqlite-wal`
- `state_5.sqlite-shm`
- `logs_2.sqlite`
- `logs_2.sqlite-wal`
- `logs_2.sqlite-shm`

`state_5.sqlite` and `logs_2.sqlite` are treated as native chooser authority
when present. In canonical bridge mode oauth-mux sets child `CODEX_SQLITE_HOME`
to the canonical session authority home so Codex 0.132+ reads the same runtime
SQLite store as bare Codex. Older Codex homes fall back to the legacy
session/history/index/snapshot set. Other SQLite databases, logs, caches, and
telemetry state are not bridged unless a future Codex version proves they are
required for normal resume/chooser parity.

## Resume And Write Policy

- Existing sessions are discovered through canonical authority, not copied into
  route-local stores.
- Managed sessions write through the bridged canonical authority unless
  `shared_canonical` is explicitly selected. Default managed sessions write to
  the selected route-local persistent account home.
- The managed overlay may write mux-owned auth/config only inside the temporary
  child home and selected account source. It must not mutate canonical
  `~/.codex/auth.json` or `~/.codex/config.toml` as part of resume.
- `oauth-mux codex resume <id>` reports redacted lookup evidence such as
  `resume_lookup_source`, not raw session ids, transcript content, or full
  paths.
- Missing chooser authority fails before child spawn with a redacted
  `resume_authority_check` diagnostic.

## Explicit Non-Claims

oauth-mux does not currently claim:

- same-thread provider continuity across account boundaries;
- mid-turn streaming recovery after partial response delivery;
- unmanaged bare-Codex process hot-swap;
- safe import of arbitrary unmanaged rollout JSONL into a route-local account
  store;
- one account-local Codex home per OAuth route as a complete native Codex home.

## Diagnostic Proof

Current diagnostic regression coverage is split between historical bridge
smokes and newer home-is-store e2e gates:

- `scripts/smoke-codex-cli-ux.sh`
  - proves first-class managed `resume`, `resume --last`, and `resume <id>`
    forwarding;
  - proves canonical `sessions/`, `history.jsonl`, `session_index.jsonl`,
    `shell_snapshots/`, `state_5.sqlite*`, and `logs_2.sqlite*` are bridged by
    reference, with `CODEX_SQLITE_HOME` pointed at the canonical authority home;
  - proves a managed child write appends through bridged session authority;
  - proves missing chooser authority fails before child spawn;
  - proves status output redacts session ids and paths.
- `scripts/smoke-codex-acceptance.sh`
  - proves the managed overlay uses mux-owned auth/config while session
    authority is bridged by reference.
- `scripts/smoke-codex-concurrent-sessions.sh`
  - proves concurrent managed overlays keep distinct proxy/auth/config state
    while sharing canonical session authority safely.

These smokes are diagnostic. Current completion proof must run through the
remote validation lanes. They prove filesystem/session-authority behavior, not
provider acceptance of cross-account thread continuation.

## Future Import Gate

A future `oauth-mux codex import-session ...` or equivalent command would need a
new issue and all of these gates:

1. explicit operator confirmation;
2. source and destination authority shown as redacted labels, not paths;
3. no transcript content printed in normal output;
4. dry-run conflict detection before writeback;
5. atomic writeback or rollback for every touched index/SQLite/file entry;
6. proof that bare Codex can resume the imported session afterward;
7. explicit claim text that file import is not same-thread provider continuity.

Until those gates exist, the supported portability answer is route-local
persistent managed homes by default, or explicit `shared_canonical` bridge mode
when an operator deliberately wants canonical Codex authority exposed.
