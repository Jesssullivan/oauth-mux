# Codex Session-Store Portability And Resume Import Policy
Date: 2026-05-18
Status: implementation-backed policy for #161 / TIN-936.

This policy defines what oauth-mux supports for Codex session continuity when
auth/config are mux-owned. It supersedes the early idea of making every
account-scoped Codex home independently portable by copying or importing
session stores.

## Product Boundary

oauth-mux owns managed auth/config for `oauth-mux codex`. Native Codex owns the
user-visible session store. The supported daily UX is therefore a composed
managed `CODEX_HOME`: mux-owned `auth.json` and generated proxy `config.toml`,
with canonical session authority bridged by reference.

The bridge is not a provider-thread-continuity guarantee. If a provider refuses
continuation across accounts, that is thread/provider evidence, not a local
session-store portability failure.

## Supported Modes

| Mode | Status | Behavior |
| --- | --- | --- |
| Canonical session bridge | Supported default | `oauth-mux codex`, `oauth-mux codex resume`, `resume --last`, and `resume <id>` expose the same canonical Codex session authority to the managed child while keeping auth/config mux-owned. |
| Explicit session home | Supported advanced override | `--session-home <path>` or `OMUX_CODEX_SESSION_HOME=<path>` selects a non-default canonical session authority. |
| Isolated managed session store | Supported opt-in | `--isolated-session-store` keeps managed sessions private to the overlay. It intentionally gives up native Codex resume parity. |
| Native chooser under managed frame | Supported | `oauth-mux codex resume` with no id runs Codex's chooser only after a pre-spawn authority check proves chooser state is available. |
| Route-local account home resume | Unsupported as a product claim | A route-local account directory is auth material, not session authority. oauth-mux does not promise `codex resume <id>` will work inside each account-local auth store. |
| Targeted import/export | Not shipped | No command imports unmanaged rollout files into a mux account store. Add only with explicit operator confirmation, redaction review, and conflict/writeback semantics. |
| Full session-store copy | Rejected | Copying `~/.codex/sessions` or SQLite state into every account store is too large, racy, private, and creates forked session authority. |

## Canonical Authority Set

The managed overlay bridges these canonical Codex entries by reference when
present:

- `sessions/`
- `history.jsonl`
- `session_index.jsonl`
- `shell_snapshots/`
- `state_5.sqlite`
- `state_5.sqlite-wal`
- `state_5.sqlite-shm`

`state_5.sqlite` is treated as native chooser authority when present. Older
Codex homes fall back to the legacy session/history/index/snapshot set. Other
SQLite databases, logs, caches, and telemetry state are not bridged unless a
future Codex version proves they are required for normal resume/chooser parity.

## Resume And Write Policy

- Existing sessions are discovered through canonical authority, not copied into
  route-local stores.
- Managed sessions write through the bridged canonical authority unless
  `--isolated-session-store` is set.
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

## No-Spend Proof

Current no-spend regression coverage:

- `scripts/smoke-codex-cli-ux.sh`
  - proves first-class managed `resume`, `resume --last`, and `resume <id>`
    forwarding;
  - proves canonical `sessions/`, `history.jsonl`, `session_index.jsonl`,
    `shell_snapshots/`, and `state_5.sqlite*` are bridged by reference;
  - proves a managed child write appends through bridged session authority;
  - proves missing chooser authority fails before child spawn;
  - proves status output redacts session ids and paths.
- `scripts/smoke-codex-acceptance.sh`
  - proves the managed overlay uses mux-owned auth/config while session
    authority is bridged by reference.
- `scripts/smoke-codex-concurrent-sessions.sh`
  - proves concurrent managed overlays keep distinct proxy/auth/config state
    while sharing canonical session authority safely.

These smokes are local and no-spend. They prove filesystem/session-authority
behavior, not provider acceptance of cross-account thread continuation.

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

Until those gates exist, the supported portability answer is the canonical
session bridge, not import/export.

