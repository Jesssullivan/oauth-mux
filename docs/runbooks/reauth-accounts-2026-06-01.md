# Operator Runbook — Re-auth Codex Accounts + Add a 2nd Claude Account

Date: 2026-06-01. Status: operator runbook, grounded in live `oauth-mux accounts
list --json` state of 2026-06-01.

Update 2026-06-14: the keepalive implementation described here is now live. The
proactive refresh grant is flipped for Claude/Codex providers, accounts still
must opt in with `allow_proactive_refresh`, and the TIN-2113 shared-identity
guard excludes duplicate OAuth identities from the warm pool before any
proactive refresh can rotate a shared refresh-token family.

This runbook respects **mediation-not-control**
(`docs/spec/in-agent-reauth-handoff-contract-2026-05-14.md`): **oauth-mux scaffolds
config and emits handoffs; the OPERATOR runs every interactive login.** No step
here has an agent run `codex login`, `claude /login`, open a browser, write a
keychain, or perform provider calls.

Legend: **[AGENT-SAFE]** = read-only, or a broker-owned non-interactive scaffold —
an agent may run it. **[USER]** = interactive, human-mediated; the agent presents
the exact redacted command and waits. Never emit tokens, refresh tokens, keys,
auth headers, raw account ids, raw emails, session ids, or credential file
contents — masked hints only.

Contracts in force:
`docs/spec/account-enrollment-agent-contract-2026-05-01.md` (Visibility /
Admission / Mutation) and
`docs/spec/in-agent-reauth-handoff-contract-2026-05-14.md` (mediation only;
fresh-incognito per account; redaction).

---

## 0. Verified state snapshot (ground truth — do not re-derive)

| Slot | Email hint | account_id_hash | codex-max | codex-mini | Verdict |
|---|---|---|---|---|---|
| codex max-1 | `j***@sulliwood.org` | `38079d6acec6` | LIVE + selectable | LIVE | **Leave alone. Live but un-reauthable (#25737).** |
| codex max-2 | `j***@sulliwood.org` | `38079d6acec6` | dead:token_revoked | dead:token_revoked | **DUPLICATE of max-1. Decide per §1. Do NOT login-device.** |
| codex max-3 | `j***@columbari.us` | `c0dfbc44912c` | degraded:unknown_4xx | LIVE | **Probe, do NOT reauth (§2).** |
| claude personal | (keychain-backed) | — | auth-status live + selectable | — | Healthy. Add a 2nd account per §4. |

`account_id_hash` = `sha256_12hex` of the JWT `chatgpt_account_id` claim (verified
in `src/main.zig`). The hash `38079d6acec6` is **identical** across max-1 and
max-2 → the **same OpenAI account enrolled into two slots**, not a collision (a
48-bit truncation's birthday bound is ~16.7M values; a 3-account inventory cannot
collide by chance). This single fact drives §1.

---

## 1. Codex max-2 — DUPLICATE-IDENTITY DECISION (read before touching it)

**Finding:** max-2 (`38079d6acec6`, `j***@sulliwood.org`) is the **same OpenAI
account** as max-1, not a second account. Both routes are `token_revoked`, and the
account is the AAS-locked one (#25737). Its emitted handoff
`oauth-mux codex login-device max-2` is an **active hazard**.

**Single-account-revocation warning (load-bearing):** a ChatGPT OAuth account holds
**one live refresh chain** (single-use rotating refresh token; a second device
login mints a new chain and orphans the old one). Running `login-device` against
this same account is a **strict-loss** operation:

- Best case: it **fails at the #25737 phone-OTP wall** (the CLI OAuth path forces
  an SMS step-up to a stale number; browser sign-in is unaffected, but
  `login-device` uses the CLI OAuth surface) → no change.
- Worst case: it **succeeds, and revokes max-1's currently-live session** — the only
  live Codex-max route — with no recovery, because re-logging max-1 hits the same
  #25737 wall.

### Decide one of:

**(A) DROP / DISABLE max-2 — RECOMMENDED.** It is a duplicate of an AAS-locked
account; its dead state plus the live `login-device` handoff is a foot-gun.

1. **[AGENT-SAFE]** Stop the dangerous handoff from being surfaced:
   ```
   oauth-mux stay-afloat handoff ack --provider codex --account max-2 --json
   oauth-mux stay-afloat handoff clear --provider codex --account max-2 --json
   oauth-mux stay-afloat handoffs --json     # verify: no "login-device max-2" remains
   ```
2. **[USER]** Retire the slot (config-owner removal, NOT "remove by logging in"):
   remove the `codex:max-2` route from the active oauth-mux config and retire its
   per-account dir `~/.local/share/oauth-mux/codex/max-2/`. Then:
   ```
   oauth-mux accounts list --provider codex --json   # verify: max-2 gone/disabled; max-1 still codex-max LIVE+selectable
   ```
3. **Never** run `oauth-mux codex login-device max-2` against this identity.

**(B) RE-ENROLL max-2 as a GENUINELY DIFFERENT OpenAI account.** Valid only if a
*distinct* account exists (it must NOT reuse `j***@sulliwood.org`). This is a *new
enrollment*, not a repair.

1. **[AGENT-SAFE]** Plan and scaffold (mutating, non-interactive; does NOT run login):
   ```
   oauth-mux enroll plan codex --account max-2 --json
   oauth-mux enroll codex --account max-2 --confirm-enroll --json
   ```
   Scaffolds the oauth-mux-owned config + isolated `CODEX_HOME` at
   `~/.local/share/oauth-mux/codex/max-2/`, then returns the login as a next handoff.
2. **[USER]** Device login via the **mediated** surface (oauth-mux scopes the
   per-account `CODEX_HOME` for you — do not hand-set it):
   ```
   oauth-mux codex login-device max-2
   ```
   Complete the device code in a **fresh incognito window** signed into the
   *different* OpenAI account. `login-device` (device-code, not loopback) avoids
   Chrome/Workspace profile-cookie bleed-through — the bleed-through is exactly what
   produced this duplicate. (Only if you must bypass the broker, the raw form is
   `env CODEX_HOME=~/.local/share/oauth-mux/codex/max-2 codex login`, scoped to that
   one command per §5 — but prefer the mediated command, which guarantees the
   isolation for you.)
3. **[AGENT-SAFE]** Prove it is genuinely distinct before trusting it:
   ```
   oauth-mux accounts list --provider codex --json
   ```
   Assert max-2's new `account_id_hash` is **NOT** `38079d6acec6`. That one check
   catches a re-cloned duplicate.

**(C) LEAVE max-2 DEAD AS COLD STANDBY — REJECT.** A "standby" backed by the same
account is not redundancy: activating it (§1 worst case) destroys the primary. It
provides zero failover and leaves the revocation foot-gun armed. Choose (A) instead.

---

## 2. Codex max-3 (`j***@columbari.us`) — PROBE the codex-max 4xx, do NOT reauth

**Finding:** codex-mini is LIVE on max-3 → credentials/auth are valid. The
codex-max failure is `degraded:unknown_4xx` — a **capability/schema problem, not
auth-death**. Auth-death would surface as `401 auth_unauthorized`, which is
explicitly NOT reported. Reauth would risk the §1 revocation pattern for zero
benefit.

**[AGENT-SAFE]** Classify it with the exact emitted command:
```
oauth-mux probe --provider codex --account max-3 --capability codex-max --json
```

Interpret the redacted result by `status` + `body.error.type`:

| Probe result | Meaning | Remedy |
|---|---|---|
| `429` + `usage_not_included` → `tier_insufficient` | codex-max gated to a higher plan tier (most likely) | Plan/entitlement change. **Never reauth.** |
| `429` + `usage_limit_reached` (carries `resets_at`) | Quota exhausted | Transient — wait/backoff. **Never reauth.** |
| `403` / scope error body | Scope/forbidden | Fix scope mapping. **Never reauth.** |
| unmatched 4xx → `inspect_provider_schema` | Unrecognized 4xx (new error type or model-id/schema mismatch) | Fix schema/model-id mapping. **Never reauth.** |
| `401` `auth_unauthorized` | (not the reported state) | Only this would warrant reauth — not applicable. |

The probe is the whole action. Do not run any `codex login` / `login-device` for max-3.

---

## 3. Codex max-1 (`j***@sulliwood.org`, `38079d6acec6`) — LEAVE ALONE; it is critical

**Finding:** max-1 is the only un-reauthable live Codex-max route. If its session
lapses it is **permanently dead** — re-login hits the #25737 OTP wall, and any
login attempt also risks revoking it. Do **not** touch it interactively; do **not**
run `login-device max-1`.

**Keepalive guarantees now in force for max-1-style critical accounts:**

1. **Proactive refresh, treated as critical.** The warm loop refreshes opted-in
   accounts well before expiry (~75% of lifetime); sessions go stale after ~8 days
   without refresh, so keep max-1's chain hot continuously. The goal is to *never
   reach* a reactive/expired path.
2. **Serialize refresh per account; never concurrent.** Concurrent refreshes trigger
   `refresh_token_reused` / `token_revoked` — the same self-revocation as §1.
   Refresh is serialized by account and must not race the live `codex` CLI/app-server.
   The TIN-2039/TIN-2043/TIN-2073 lock path plus TIN-2113 shared-identity guard
   prevents both same-account races and known duplicate-identity warm attempts.
3. **Never-halt + escalation, not silent death.** The moment max-1's refresh starts
   failing or its remaining lifetime crosses a critical floor, emit a **redacted
   escalation handoff** that explicitly says: *"max-1 is un-reauthable — do NOT run
   `login-device` (revocation + #25737 OTP wall); human escalation only."* The
   auto-remediation path must NOT emit a `login-device` handoff for max-1.
4. **Refresh-only, never re-login.** The only safe machine action is rotating the
   *existing* refresh token. Recovery from a true death is human-escalation only
   (the #25737 fix or an account-policy change), never an automated re-login.

**[AGENT-SAFE]** Monitoring (read-only, no spend):
```
oauth-mux accounts list --provider codex --json
oauth-mux stay-afloat handoffs --json
oauth-mux doctor runtime --json
```

---

## 4. Add a 2nd Claude account (for cassette/keepalive proofing)

Maps to the verified enroll plan: **step1 inspect (agent-safe) → step2 scaffold
`CLAUDE_CONFIG_DIR` (mutating, non-interactive) → step3 user-mediated login → step4
prove auth-status.** The agent mediates; the OPERATOR runs the login. Claude is
**command-owned**: oauth-mux scaffolds the isolated config dir and hands off to the
Claude CLI, which owns the credential write — oauth-mux does not rewrite
Claude-owned state (`account-enrollment-agent-contract` Story B).

> **macOS keychain caveat (unverified assumption — confirm with an operator fixture
> before relying on it).** Claude Code on macOS stores OAuth creds in the encrypted
> login keychain (`personal` shows `secret_backend=keychain`; `~/.claude/.credentials.json`
> is absent for that reason). The keychain item *appears* to be a single shared
> generic-password (`service = "Claude Code-credentials"`) that may **not** vary per
> `CLAUDE_CONFIG_DIR` on macOS — if so, `CLAUDE_CONFIG_DIR` isolates filesystem state
> but not the keychain, and a second `/login` could overwrite the first account's
> token (the same single-token clobber that killed codex max-2). The repo's own
> `provider-proof-claude-command-auth` spec lists real keychain/operator fixtures as
> *remaining work*, so treat the keychain-collision behavior as **unproven**.
> **Practical mitigation until proven:** isolate `CLAUDE_CONFIG_DIR` per account AND
> **do not re-login the existing `personal` identity** — log in a genuinely distinct
> account. If an operator fixture later proves the keychain collides across config
> dirs, revisit with a file-based credential path; do not assume either way now.

### Step 1 — inspect **[AGENT-SAFE]** (read-only)
```
oauth-mux accounts list --provider claude --json
oauth-mux enroll plan claude --account <n> --json
```
`enroll plan` labels each step agent_safe / interactive / mutating /
spends_provider_calls. Read it before proceeding.

### Step 2 — scaffold config **[AGENT-SAFE]** (mutating, non-interactive; broker-owned; NO login)
```
oauth-mux enroll claude --account <n> --confirm-enroll --json
```
Scaffolds the oauth-mux-owned config + an isolated `CLAUDE_CONFIG_DIR` at
`~/.local/share/oauth-mux/claude/<acct>/`, then **returns the provider login as a
next handoff** (does not run it). oauth-mux does not write Claude-owned credentials.

### Step 3 — login **[USER]** (interactive — the OPERATOR runs this; the agent waits)
```
env CLAUDE_CONFIG_DIR=~/.local/share/oauth-mux/claude/<acct>/ claude /login
```
- Use a **fresh incognito/private browser context** and sign in with a **genuinely
  distinct** identity — do NOT re-login the existing `personal` identity (that would
  just overwrite it; the max-2 lesson applied to Claude).
- `CLAUDE_CONFIG_DIR` is set **only for this one command**; never export it globally
  or into a sibling account's environment.
- The agent does **not** execute this; it presents the exact redacted command and
  waits for operator-confirmed completion.

### Step 4 — prove auth-status **[AGENT-SAFE]** (redacted)
```
oauth-mux accounts list --provider claude --json     # expect auth-status live + selectable for <acct>
```
Then value-free checks (never `cat`, never `security ... -w`):
- Account #1 (`personal`) is **untouched** — its `accounts list` entry still
  live/selectable, proving no credential clobber.
- Refresh route evidence and mark the new account selectable **only after** evidence
  says so (handoff contract: refresh evidence, retry only after `selectable`).

The new account then becomes the source for cassette/keepalive proofing: its (once,
isolated) refresh feeds the cassette recorder/replayer (PR #357 / TIN-1823) for
deterministic offline proof of the adapter (#354) + scheduler (#355) — **default is
to hand-author the neutral cassette fixtures; live capture is the fail-closed
escape hatch only.**

---

## 5. CODEX_HOME isolation discipline (any raw `codex login`)

**Incident lesson:** a prior change made per-worktree `CODEX_HOME` the **default**
and broke `codex resume` across repos (session/sqlite/logs all live under
`CODEX_HOME`). The rule:

- **Shared `~/.codex` stays the default.** Per-account `CODEX_HOME` isolation is
  **explicit, opt-in, and per-command only**.
- **Prefer the mediated `oauth-mux codex login-device <acct>`** — it scopes the
  per-account `CODEX_HOME` for you. Only if you must use the raw CLI, set
  `CODEX_HOME` **inline for that one command**, pointing at that account's own dir:
  ```
  env CODEX_HOME=~/.local/share/oauth-mux/codex/<acct> codex login
  ```
- That login must write **only** to the per-account dir; it must **never** clobber
  `~/.codex` or sibling accounts (`max-1` / `max-3`).
- **Never export `CODEX_HOME` into a global shell** or leak it into another
  account's environment. One shell, one command, one account.

---

## 6. Quick decision summary

- **max-1:** leave alone; keepalive keeps it warm, serially, and escalates (never `login-device`).
- **max-2:** duplicate of max-1 → **(A) drop/disable (recommended)**; (B) re-enroll only on a truly different account (assert `account_id_hash != 38079d6acec6`); **never (C) cold standby**. Never `login-device max-2`.
- **max-3:** `oauth-mux probe --provider codex --account max-3 --capability codex-max --json` to classify; never reauth.
- **claude 2nd account:** enroll plan → `enroll --confirm-enroll` scaffold → `[USER] env CLAUDE_CONFIG_DIR=… claude /login` (fresh incognito, distinct identity) → prove via `accounts list --json`. Command-owned; isolate per account; do not re-login `personal`.
