# Codex Live Acceptance Checklist
Date: 2026-05-08
Status: operator checklist; subordinate to
`docs/spec/broker-mcp-contract-2026-05-03.md` and
`docs/spec/codex-live-quota-handoff-evidence-2026-05-08.md`.

## Purpose

The 2026-05-08 installed-runtime artifacts prove managed Codex resume/load
quota handoff from `codex:default` to `codex:max-2`. The 2026-05-09
installed-runtime artifacts add the stricter engineered managed-session shape:
an account returned successful `200` turns, reached provider-originated quota
exhaustion during brokered Codex traffic, and handed off to another credited
account without manual repair between quota event and fallback success.

## Required Entry Path

Only this entry path counts for live acceptance:

```bash
oauth-mux codex resume <session-id>
```

Requirements:

- `oauth-mux` resolves to an installed executable on PATH.
- The status artifact records `runtime_identity.binary_path`,
  `binary_source`, `binary_sha256`, `build_id`, `version`, `path_printed`,
  `command_spelling`, and `installed_local_mismatch_detected:false`.
- The operator does not pass a repo-local `./zig-out/bin/oauth-mux` path, a
  wrapper, or an arg-heavy dogfood helper.
- The operator does not repair the failure with logout/login/manual resume
  between quota event and fallback success.

## Closeable Evidence Shape

The status artifact must show all of the following in order:

1. `session_started` with `claim_level:"broker_owned"` and
   `session_authority:"isolated"` (the default `isolated_persistent` /
   home-is-store mode). A run that instead shows
   `session_authority:"canonical_bridge"` is the labeled legacy
   `shared_canonical` variant and is closeable only when the opt-in
   (`TINYLAND_CODEX_MUX_MODE=shared_canonical` or `--mux-mode
   shared_canonical`) is recorded with the evidence.
2. A normal `200` provider turn on account A before exhaustion.
3. Provider-originated quota evidence on account A:
   - `kind:"proxy_turn"`
   - `method:"POST"`
   - `path_kind:"responses"`
   - `status:429`
   - `classification:"quota_exhausted"`
   - `body_class:"usage_limit_reached"`
   - `delivered_to_codex:false`
4. Durable quota health for account A, observable in either status events or a
   subsequent route plan.
5. `proxy_post_swap_turn` or equivalent account-change evidence from account A
   to account B.
6. `proxy_same_turn_retry` from account A to account B with
   `dropped:"x-codex-turn-state"`.
7. A fallback `proxy_turn` on account B for the same request class with
   `status:200`.
8. No user-visible `usage_limit_reached` failure for the successful fallback
   turn.
9. Same managed Codex child process; no restart-shaped acceptance language.
10. Status summary verdict:
    `successful_live_quota_handoff`.

## Non-Closeable Evidence

Do not close the engineered in-session gate from:

- Synthetic smokes only.
- A repo-local or wrapper launch.
- A managed load/resume handoff where the selected login was already exhausted
  before meaningful session work began.
- Manual `codex login`, logout/login, manual resume, or account repair between
  quota event and continuation.
- Dashboard or API-credit evidence without subscription-backed Codex wire
  evidence.
- Generic `429` or `usage_not_included`; these are rate/tier states, not the
  ChatGPT subscription quota handoff path.

## Test Matrix

| Scenario | Setup | Expected result | Evidence value |
| --- | --- | --- | --- |
| Installed exhausted-login handoff | Sign into native Codex as a known exhausted ChatGPT account, then enter through installed `oauth-mux codex resume <id>` with one credited fallback | A returns `usage_limit_reached`; B returns `200`; no visible 429 | Managed load/resume proof. Already observed on 2026-05-08 |
| Engineered in-session exhaustion | Start A credited; run a long managed session until A reaches provider quota; keep B credited | Same process swaps A -> B and continues | Managed quota handoff proof. Observed on 2026-05-09 |
| Exhausted ChatGPT quota plus API credits | A has exhausted ChatGPT/Codex subscription quota but separate API credits remain | Codex subscription route still follows ChatGPT quota truth; API credits do not make A selectable for subscription-backed Codex | Prevents credit-dashboard false positives |
| Reset-window repair | A was quota-exhausted; reset window expires or plan changes | Diagnostic plan marks revalidation needed; spend-gated revalidation repairs A only after provider evidence | Durable health repair proof |
| Tier before fallback | A exhausted; B returns `usage_not_included`; C credited | B is marked `tier_insufficient`, then C handles the request | Typed rejection sequencing |
| All fallbacks exhausted | Every candidate is quota/rate/tier/auth blocked | Typed `quota_handoff_failed_no_account_selectable` with complete redacted rejection vector | Honest failure UX |
| Expired but refreshable fallback | B access token expired; B refresh token valid | Preflight/materialization refresh repairs B before selection or retry | Prevents false `NoAccountSelectable` |

## Current Scheduled Permutation

2026-05-09 operator quota data gave a concrete engineered-session setup:

- `codex:max-2`: low-weekly primary candidate after labeled user-mediated
  reauth.
- `codex:max-3`: high-capacity fallback candidate after labeled user-mediated
  reauth.
- `codex:max-1` and `codex:max-4`: weekly-exhausted reset-window candidates.

Observed outcome:

1. `max-2` and `max-3` were reauthed through labeled upstream Codex device
   login.
2. Installed `oauth-mux codex resume <session-id>` entered a managed frame.
3. The preserved artifact
   `docs/evidence/codex-engineered-quota-handoff-20260509/` shows successful
   `max-2` traffic, provider `usage_limit_reached`, same-turn retry to `max-3`,
   and fallback `status:200`.
4. `max-1` and `max-4` remain reset-window candidates for later repair proof.

## Commands

Summarize a status artifact:

```bash
oauth-mux codex status-latest --json
oauth-mux codex status-latest --status-file <status.ndjson> --json
python3 scripts/summarize-codex-status.py <status.ndjson> \
  --require-brokered --require-fallback-sequence
```

The installed-binary command is the operator path. The Python command is the
repo regression oracle.

Check diagnostic route state after a quota observation:

```bash
oauth-mux codex broker-session-plan \
  --profile codex-max \
  --capability codex-max \
  --json
```

Validate the preserved 2026-05-08 proof excerpt:

```bash
python3 scripts/summarize-codex-status.py \
  docs/evidence/codex-managed-quota-handoff-20260508/status-excerpt.ndjson \
  --require-brokered --require-fallback-sequence
```

## Tracker Guidance

- Managed load/resume quota handoff can cite
  `docs/evidence/codex-managed-quota-handoff-20260508/`.
- Engineered managed-session quota handoff can cite
  `docs/evidence/codex-engineered-quota-handoff-20260509/`.
- Same-thread continuity, mid-turn recovery, unmanaged `codex` hot-swap, and
  non-Codex harness behavior remain separate claims.
