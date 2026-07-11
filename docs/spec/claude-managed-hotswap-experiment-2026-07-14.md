# Claude Managed Hot-Swap Experiment (E1) — Guarded Singleton Switch

> **SUPERSEDED 2026-07-11; DO NOT EXECUTE.** This file is historical input,
> not active design authority. Binding invariants moved to
> `docs/plans/oauth-mux-v0.2-full-broker-foss-program-2026-07-11.md` and
> `docs/security/omux-v0.2-threat-model-2026-07-11.md`. It is pending deletion
> under the v0.2 deletion ledger; Git is the archive. Preserve cited immutable
> evidence and shipped release history.

Date: 2026-07-14 (target live run; commit date may precede it).

Status: operator-gated lab runbook. The live run requires the operator present
per TIN-2721 acceptance — this is a hard requirement, not a suggestion.
Failure is a valid completion.

Trackers: TIN-2721 (this experiment), TIN-2077 (Claude adapter parity gate —
this experiment supplies its gating evidence), TIN-2719 (singleton valet MVP,
downstream consumer of the verdict).

Design SSOT: `docs/spec/stay-afloat-valet-and-browser-evidence-2026-07-09.md`,
property 4 ("No blind singleton write") and decomposition step W4 ("Guarded
Singleton Switch Proof").

Commands below are POSIX/bash. If the interactive shell is fish, wrap
multi-stage pipelines in `bash -c '...'`.

## 1. Purpose and claim boundary

**Question under test:** does atomically writing account B's fresh credential
into the canonical Claude keychain item, under a LIVE Claude Code session
running as account A, yield seamless continuation as B — no restart, no
reprompt, next API call succeeds as B?

This experiment gates TIN-2077 (Claude adapter parity). It does not implement
a product feature. There is no `stay-afloat switch` verb yet; the write in
this runbook is a manual, out-of-band operator action performed directly with
`security(1)`, never routed through oauth-mux's own automatic refresh
writeback path. **The TIN-2054 refresh-writeback guard
(`src/pipeline.zig:985-1010`, the refusal to auto-rotate the canonical
unsuffixed `Claude Code-credentials` keychain item) stays byte-identical.**
This runbook does not touch it, test it, or route around it — it documents a
separate, manual, consent-carrying write that a future `stay-afloat switch`
verb would need to formalize only after this gate closes.

Failure is a valid completion. A failed arm updates TIN-2077's stance with a
failure-mode catalog entry; it is never spun as partial success. No product
claim is made either way until the evidence directory
(`docs/evidence/claude-hotswap-<UTCts>/`) is committed with a verdict line.

### Forbidden language (until the evidence dir is committed, and forever for
anything not directly observed)

- "Claude adapter parity achieved"
- "seamless singleton handoff proven"
- "production hot-swap feature" / "stay-afloat switch shipped"
- "Claude quota keepalive" or "Claude model keepalive"
- "service residency" (unrelated to this experiment; do not conflate with
  TIN-1830 evidence)
- Any claim about statsig, usage-panel, or org-level attribution correctness
  beyond what this experiment directly observed (see risk register item 3)

### Allowed language (post-evidence only, and only matching the verdict)

- "Claude managed hot-swap lab experiment (E1), single live run"
- "keychain-only vs. keychain+identity-file arms"
- "seamless continuation as B: yes / no / conditional" (the exact verdict
  line, never softened or strengthened in retelling)

## 2. Preconditions checklist

### 2.1 Determine the current canonical occupant — decision point, do this first

The canonical unsuffixed keychain service (`Claude Code-credentials`, no
`CLAUDE_CONFIG_DIR` suffix) is whatever bare `claude` CLI invocations use.
Per the existing dogfood runbook, `personal` is documented as the account
that historically occupies this canonical service. **Before any other setup
step, verify what currently occupies it — do not assume.**

Preferred method (never touches a raw UUID):

```bash
bash -c '/Users/jess/.local/bin/oauth-mux accounts list --provider claude --json \
  | jq "[.accounts[] | {account, auth_identity}]"'
```

Look for the account entry whose secret backend maps to the unsuffixed
`Claude Code-credentials` service (typically `personal`, if configured in
`~/.config/oauth-mux/config.json`). Record its `account_id_hash`
(`sha256_12hex`) as the pre-state identity for the canonical slot.

If `personal` is not a configured oauth-mux account at all, fall back to
reading the CLI's own state file (still redacted — hash only, never print the
raw UUID):

```bash
bash -c 'printf "%s" "$(jq -r ".oauthAccount.accountUuid" ~/.claude.json)" \
  | shasum -a 256 | cut -c1-12'
```

**Decision point (must be resolved and written into the evidence dir's
README before Arm 1 starts):**

- If the canonical slot currently holds `personal`: this is a real,
  operator-depended-on account, not lab material. The experiment plan is a
  **THROWAWAY window** for `personal` — every bare `claude` invocation during
  the arms will authenticate as A (xoxd) or B (sulliwood), not `personal`.
  The operator must explicitly accept this before proceeding: either (a)
  quiesce any other bare Claude Code sessions using the default config dir
  before starting, or (b) accept the interruption as a bounded, backed-up,
  reversible window. Record which choice was made and why.
- If the canonical slot currently holds something else (already xoxd, empty,
  or an unrelated identity): record the actual pre-state hash. Lower risk,
  but still take the full shadow-backup protocol below — do not skip it
  because the risk looks smaller.

This decision and its recorded rationale are mandatory evidence-dir content
(section 7).

### 2.2 Accounts

- **A = xoxd** — becomes the canonical occupant for the live session under
  test (the identity the long-running Claude Code session starts as).
- **B = sulliwood** — the account whose credential gets hot-swapped into the
  canonical slot mid-session.
- **`personal` is excluded from enrollment/warm-pool changes.** Its
  credential lives in the canonical store under test; it is the subject of
  the decision point above, not a participant account.

### 2.3 Remove B from the warm pool for the window

This is the dual-writer family-revocation guard (TIN-2113): B's config-dir
copy must not be proactively refreshed by the keepalive daemon while the
canonical slot also holds a copy of B's material, or two writers can race the
same single-use rotating refresh-token family.

Back up config first:

```bash
bash -c 'cp ~/.config/oauth-mux/config.json \
  ~/.config/oauth-mux/config.json.backup-$(date -u +%Y%m%dT%H%M%SZ)'
```

Edit `providers.claude.accounts.sulliwood.allow_proactive_refresh` to
`false` (manual JSON edit — there is no `config set` subcommand in this
repo):

```bash
bash -c 'jq ".providers.claude.accounts.sulliwood.allow_proactive_refresh = false" \
  ~/.config/oauth-mux/config.json > /tmp/omux-config.edit \
  && mv /tmp/omux-config.edit ~/.config/oauth-mux/config.json \
  && /Users/jess/.local/bin/oauth-mux config validate'
```

Reload the keepalive daemon so it picks up the change:

```bash
launchctl kickstart -k gui/501/dev.xoxd.omux.keepalive
```

(`dev.xoxd.omux.keepalive` is the attested label for the single shared
keepalive LaunchAgent — `scripts/keepalive-service.sh`,
`dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl`. The `kickstart -k`
invocation itself is not attested verbatim elsewhere in this repo for this
label; treat it as inferred-consistent and confirm the daemon actually
restarted, e.g. via `just keepalive-service-status`, before proceeding.)

**Reverse this after the experiment (see section 6) — flip
`allow_proactive_refresh` back to `true` and kickstart again before
re-admitting B to the warm pool.**

### 2.4 Shadow backups (operator-held, outside the repo, 0600)

```bash
bash -c '
mkdir -p ~/omux-e1-backups && chmod 700 ~/omux-e1-backups
ts=$(date -u +%Y%m%dT%H%M%SZ)
security find-generic-password -s "Claude Code-credentials" -w -a "$(whoami)" \
  > ~/omux-e1-backups/canonical-credentials.pre-${ts}.json
cp ~/.claude.json ~/omux-e1-backups/claude-dot-json.pre-${ts}.json
chmod 600 ~/omux-e1-backups/canonical-credentials.pre-${ts}.json \
           ~/omux-e1-backups/claude-dot-json.pre-${ts}.json
'
```

Record the exact backup paths and timestamp in the evidence dir's README
(paths only — never commit the backup files themselves into the repo).

### 2.5 Pre-state identity hashes

```bash
bash -c '/Users/jess/.local/bin/oauth-mux accounts list --provider claude --json \
  | jq "[.accounts[] | select(.provider==\"claude\") | {account, auth_identity}]"'
```

Confirm xoxd and sulliwood have distinct `account_id_hash` values and that
neither collides with the canonical pre-state hash recorded in 2.1 (unless
canonical already holds one of them, per the decision point). Record this
JSON (already redacted) as `pre-state.json` in the evidence dir.

## 3. Arm 1 — keychain-only swap

1. Start a long-running Claude Code session as A (xoxd), using whatever
   config dir A normally uses, with a trivial persistent task that keeps the
   session open and produces periodic observable output (e.g. a long
   streaming conversation or a watch-style loop the operator can glance at).
   Record the UTC start timestamp.
2. Derive B's suffixed keychain service name from B's `CLAUDE_CONFIG_DIR`
   (the same derivation as `provider_schema.claudeKeychainService`: base +
   `-` + first 4 bytes of `sha256(config_dir_absolute)` as hex):

   ```bash
   bash -c '
   b_config_dir="/Users/jess/.local/share/oauth-mux/claude/sulliwood"
   b_suffix=$(printf "%s" "$b_config_dir" | shasum -a 256 | cut -c1-8)
   echo "Claude Code-credentials-${b_suffix}"
   '
   ```

3. Read B's credential JSON from that suffixed service (never print
   `accessToken`/`refreshToken` values to a log that leaves the operator's
   terminal):

   ```bash
   bash -c '
   b_service="Claude Code-credentials-<derived-suffix-from-step-2>"
   security find-generic-password -s "$b_service" -w -a "$(whoami)" \
     > /tmp/omux-e1-b-credential.json
   jq -r ".claudeAiOauth.expiresAt" /tmp/omux-e1-b-credential.json
   '
   ```

   Note the `expiresAt` value (13-digit epoch ms). Convert to a UTC
   wall-clock timestamp — this is the access-token expiry boundary to wait
   through during the observation loop, and the point at which a refresh
   attempt (if any) should occur and reveal which family rotates.

4. Atomic write into the canonical service (`-U` updates in place, matching
   the write convention already used in `src/secret.zig`):

   ```bash
   bash -c '
   security add-generic-password -U -s "Claude Code-credentials" -a "$(whoami)" \
     -w "$(cat /tmp/omux-e1-b-credential.json)"
   date -u +%Y-%m-%dT%H:%M:%SZ
   '
   ```

   Record the write's UTC timestamp precisely — this is T0 for the
   observation loop.

5. Observation loop. Log every check with a UTC timestamp:
   - T0+0s: is the live session still responding, no reprompt/restart?
   - T0+30s, T0+2m, T0+5m: issue a trivial next turn in the live session;
     does it succeed silently, error, or force a re-login prompt?
   - Continue checking at reasonable intervals until past B's `expiresAt`
     boundary from step 3.
   - At/after the expiry boundary: does the session trigger a refresh? If
     so, compare which store's refresh token changed (see step 6).
6. Refresh-family rotation check — compare token-prefix hashes between the
   canonical store and B's original suffixed store (never compares or prints
   raw token values):

   ```bash
   bash -c '
   b_service="Claude Code-credentials-<derived-suffix>"
   canon_rt_hash=$(security find-generic-password -s "Claude Code-credentials" -w -a "$(whoami)" \
     | jq -r ".claudeAiOauth.refreshToken" | shasum -a 256 | cut -c1-12)
   b_rt_hash=$(security find-generic-password -s "$b_service" -w -a "$(whoami)" \
     | jq -r ".claudeAiOauth.refreshToken" | shasum -a 256 | cut -c1-12)
   echo "canonical_rt_hash=${canon_rt_hash} b_suffixed_rt_hash=${b_rt_hash}"
   '
   ```

   If the hashes match post-refresh, the canonical write is the live head and
   B's original suffixed copy is now stale (needs re-sync before B returns to
   the warm pool — see section 6). If they diverge and the canonical hash
   changed to something new while B's suffixed copy stayed on the pre-swap
   value, the family rotated on the canonical side without updating B's
   store of record — also stale, same remediation.
7. Record the full timestamped observation log as `arm1-timeline.md` and a
   summary outcome (continuation yes/no, adoption timing classification,
   identity attribution, which family rotated, any 401s) as
   `arm1-outcome.md`.

## 4. Arm 2 — keychain + `~/.claude.json` `oauthAccount` swap

Same as Arm 1, plus swap the identity file, run against a fresh long-running
session (do not reuse Arm 1's session/state — start clean, re-run 2.3-2.5
verification if meaningful time has passed).

1. Back up `~/.claude.json` again immediately before the edit (separate from
   the section 2.4 shadow backup, so Arm 2 has its own restore point):

   ```bash
   bash -c 'cp ~/.claude.json ~/omux-e1-backups/claude-dot-json.pre-arm2-$(date -u +%Y%m%dT%H%M%SZ).json'
   ```

2. Extract B's `oauthAccount` object from B's own config-dir `.claude.json`
   and merge it into the canonical `~/.claude.json`, reviewing the diff
   before applying:

   ```bash
   bash -c '
   b_config_dir="/Users/jess/.local/share/oauth-mux/claude/sulliwood"
   b_oauth_account=$(jq -c ".oauthAccount" "${b_config_dir}/.claude.json")
   jq --argjson acct "$b_oauth_account" ".oauthAccount = \$acct" ~/.claude.json \
     > /tmp/omux-e1-claude-json-swapped.json
   diff <(jq -S . ~/.claude.json) <(jq -S . /tmp/omux-e1-claude-json-swapped.json)
   '
   ```

3. Only after reviewing the diff, apply it:

   ```bash
   bash -c 'cp /tmp/omux-e1-claude-json-swapped.json ~/.claude.json'
   date -u +%Y-%m-%dT%H:%M:%SZ
   ```

4. Repeat the keychain write from Arm 1 step 4 (or leave it in place if the
   arms run back-to-back with the same B credential still fresh).
5. **Key open question for this arm:** does the live session's identity
   surface (`/status` or equivalent) change immediately, on next turn, or not
   at all until process restart? Claude Code may hold `oauthAccount` in
   memory from process start. Explicitly record whether the file edit is
   observed mid-session at all — a "no observable effect" result is a valid,
   useful finding, not a failed arm.
6. Record `arm2-timeline.md` and `arm2-outcome.md` in the same shape as Arm 1.

## 5. Observables table

| Observable | How to measure |
|---|---|
| Session continuation | Watch the live session directly: no restart, no re-auth prompt, task keeps progressing after the swap |
| Adoption timing | Compare the swap write's UTC timestamp (Arm 1 step 4 / Arm 2 step 3) against the timestamp of the next successful/failed API call in the session; classify immediate / next-request / post-401 |
| Identity attribution | In-session identity surface (`/status` or equivalent) before and after the swap; corroborate with `oauth-mux accounts list --provider claude --json` re-run against the canonical service post-swap |
| Refresh-family rotation | Token-prefix sha comparison between canonical store and B's original suffixed store (Arm 1 step 6); repeat after waiting through B's `expiresAt` boundary |
| 401 storm on A's family | Watch for repeated auth failures tied to A's own suffixed-service credential in any other process still holding A's config dir (oauth-mux logs, `log show --predicate 'process == "claude"'`, or the session's own stderr) |

## 6. Abort/rollback

Run this to completion before ending the session, whether the arms
succeeded, failed, or were interrupted. Do not leave the canonical slot in an
experimental state across a session boundary.

1. Restore both shadow backups verbatim:

   ```bash
   bash -c '
   security add-generic-password -U -s "Claude Code-credentials" -a "$(whoami)" \
     -w "$(cat ~/omux-e1-backups/canonical-credentials.pre-<ts>.json)"
   cp ~/omux-e1-backups/claude-dot-json.pre-<ts>.json ~/.claude.json
   '
   ```

2. Verify canonical `accountUuid` matches the pre-state hash recorded in 2.1
   (hash-only comparison, never raw):

   ```bash
   bash -c 'printf "%s" "$(jq -r ".oauthAccount.accountUuid" ~/.claude.json)" \
     | shasum -a 256 | cut -c1-12'
   ```

3. Sanity-check with `claude auth status` (or the equivalent bare-CLI status
   command).
4. **Single-family-ownership check before re-admitting B to the warm pool.**
   The refresh-token family is single-use/rotating: whichever copy refreshed
   most recently is the live head, and the other copy is stale and will fail
   its next refresh. Compare token-prefix sha hashes between the canonical
   store and B's suffixed store (same recipe as Arm 1 step 6). If they
   diverge, treat the copy with the newer/only-valid `expiresAt` as the live
   head and re-derive B's suffixed-service copy from it before re-enabling
   proactive refresh — do not just flip the config flag back on with a stale
   copy in place, or the next keepalive tick will fail B's refresh (TIN-2113
   territory: single-use refresh-token family; family-revocation risk).
5. Only after the family-ownership check passes: flip
   `providers.claude.accounts.sulliwood.allow_proactive_refresh` back to
   `true`, `oauth-mux config validate`, and
   `launchctl kickstart -k gui/501/dev.xoxd.omux.keepalive` again.
6. If the operator must stop before completing rollback (interruption
   mid-arm), write an explicit `INCOMPLETE-ROLLBACK` marker file into a
   scratch location (not the evidence dir, not the repo) noting exactly
   which step was reached, so the next session does not assume the canonical
   slot is back to pre-state.

## 7. Evidence dir template

`docs/evidence/claude-hotswap-<UTCts>/`:

- `README.md` — narrative: the section 2.1 decision point and its
  resolution, UTC start/end, what passed, what failed, what is not claimed
  (mirroring the "What this shows" / "What this does not claim" split used
  in `docs/evidence/keepalive-warm-loop-20260703T171242Z/README.md`).
- `pre-state.json` — redacted `accounts list --json` output from section 2.5.
- `post-state.json` — redacted `accounts list --json` output after rollback,
  for comparison against `pre-state.json`.
- `arm1-timeline.md`, `arm1-outcome.md`
- `arm2-timeline.md`, `arm2-outcome.md`
- `backups-manifest.md` — operator-held backup **paths** and their sha256
  (of the file, not its content interpreted) for integrity tracking; never
  the backup files themselves.
- `verdict.md` — the single required line: "seamless continuation as B:
  yes / no / conditional", plus one paragraph of rationale tied directly to
  the observables table.
- `gitleaks-scan.log` — output of the repo-wide secrets scan, run before
  staging the evidence dir:

  ```bash
  bash -c 'just secrets-scan-dir'
  ```

  Gitleaks pattern coverage is defense in depth, not a guarantee against a
  raw Claude credential blob shape slipping through; manually re-read every
  file in the evidence dir for raw `accessToken`/`refreshToken` values, raw
  `accountUuid`, and raw email addresses before `git add`, regardless of
  scan result.

## 8. Risk register

1. **Dual-writer family revocation (TIN-2113).** If B stays in the warm pool
   while its credential also lives in the canonical slot, two writers can
   race the same single-use rotating refresh-token family and revoke each
   other. This is why section 2.3 (remove B from the warm pool for the
   window) is a precondition, not optional.
2. **In-memory token cache ambiguity.** Claude Code may read the access
   token once at process start and hold it in memory; an external swap may
   only be observed at the process's own next refresh or 401, not
   immediately. Arm 2 is partly designed to characterize this for the
   identity file as well as the credential.
3. **Statsig/org attribution mismatch.** A successful API-level continuation
   as B does not guarantee the Anthropic backend's usage panel, billing
   attribution, or telemetry also flip to B — those may be keyed on
   server-side session/device state outside this experiment's observation
   surface. Do not claim usage-panel attribution correctness beyond what was
   directly observed.
4. **Canonical-store contamination of `personal`.** `personal` is excluded
   from this experiment specifically because its credential may currently
   occupy the canonical store under test (see the section 2.1 decision
   point). Every write during the arms temporarily evicts whatever currently
   occupies that slot. This is why the decision point is mandatory,
   explicit, and recorded before Arm 1 starts.
5. **Operator-interrupt handling mid-arm.** If the operator must stop before
   the rollback in section 6 completes, the canonical slot is left in a
   non-pre-state condition. Section 6 step 6 requires an explicit
   incomplete-rollback marker rather than silently resuming later on the
   assumption that state is clean.
