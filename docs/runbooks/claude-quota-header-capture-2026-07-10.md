# Claude quota-header capture (TIN-2722)

Status: operator-gated lab runbook. **No live capture has happened yet — this
runbook and `scripts/capture-claude-quota-headers.sh` are the harness, built
ahead of the live session so the operator only has to review the protocol,
not build it under time pressure.**

This runbook drives the E2 evidence gate for
`docs/spec/model-quota-granularity-2026-07-03.md` §5 phase P1: a committed,
redacted `test/evidence/quota-observation/` fixture proving Anthropic's real
quota signals. It is the precondition for any Claude model-quota claim
(AGENTS.md gate) and for TIN-2400 P1. It does **not** implement P1's code
increment (capability declarations, classifier, failure rules) — that is a
separate PR that reads this fixture once it exists.

## Claim boundary (unchanged by this runbook)

"Credential keepalive" (shipped, proven — see
`docs/runbooks/claude-5-account-keepalive-dogfood-2026-07-03.md`) is not
"model-quota keepalive" (this design, gated behind this fixture). This
runbook produces evidence only. It does not grant a quota claim by itself;
the code increment listed in TIN-2722 does that, and only after this fixture
lands.

## Preconditions

- Operator present for the entire `--live` step. This spends real, tiny
  amounts of API usage on real accounts and reads real OAuth tokens from the
  macOS keychain.
- All five dogfood accounts (`xoxd`, `sulliwood`, `columbari`, `coye`,
  `lmux`) enrolled and credential-fresh. Confirm with:

  ```bash
  /Users/jess/.local/bin/oauth-mux accounts list --provider claude --json
  ```

  `personal` (canonical, unsuffixed keychain service) is never touched by
  this harness, even if selected.
- Spend approval: the operator has read and approved the honest-spend
  ladder table below (single-digit tokens per account, no more than one
  `no_spend`-then-`micro_spend` pass per account per session).
- `security`, `curl`, `python3` on PATH (macOS only — the harness refuses on
  non-Darwin hosts for `--live`).
- `gitleaks` and this repo's `just test-local` available for the post-redact
  review step.

## Honest-spend ladder

| Step | Channel | Shape | Spend | What a result (or its absence) proves |
|---|---|---|---|---|
| 1 | No-spend, `max_tokens:0` | `POST /v1/messages` with a valid model and `max_tokens:0` | **Zero** — provider rejects before generation (`invalid_request_error`) | Whether rate-limit headers appear on an ordinary validation 4xx at all |
| 2 | No-spend, unknown model | `POST /v1/messages` with `max_tokens:1` and a model id that does not exist | **Zero** — provider rejects on model lookup, before generation | Whether rate-limit headers appear on a 404/`not_found_error`; whether the error body carries a model-dimension hint |
| 3 | Micro-spend, fable-class | `POST /v1/messages`, `max_tokens:1`, fable-class model id (**placeholder — see open question**) | ≤ 1 output token + prompt tokens for a ~9-token user message | Real header names on a 200; live-Fable-serve confirmation for the account; model round-trip in the response body |
| 4 | Micro-spend, opus-class | Same shape, opus-class model id | Same order of magnitude | Same, for opus |
| 5 | Micro-spend, cheap/haiku-class | Same shape, haiku-class model id | Same order of magnitude | Same, for the cheapest tier — also the cheapest place to observe a real 429/`quota_exhausted` body shape if one account happens to be near a window boundary |

Steps 1-2 run before 3-5 for every account (the script's channel order is
fixed honest-spend-ladder order: no-spend first). Total spend per account
across one full pass: 0 tokens (steps 1-2) + at most a few output tokens and
~30 prompt tokens (steps 3-5) — single digits to low tens of tokens per
account, five accounts, one pass. Do not loop `--live` repeatedly "to be
sure"; one clean pass per account is the ladder.

### Rejected alternative: riding CLI traffic

TIN-2722 considered observing quota headers passively by riding the
operator's own `claude` CLI traffic (as `scripts/capture-codex-wire.sh` does
for Codex via mitmdump), which would be strictly lower-spend than the
micro-spend steps above. **Rejected for this cut**: there is no Claude wire
proxy today (`docs/spec/model-quota-granularity-2026-07-03.md` §2 row 3,
"Claude" column — no wire proxy, no 429/quota rule), and standing one up is
itself the net-new adapter work this fixture is meant to justify, not a
prerequisite for it. Recorded here explicitly so nobody reaches for a
man-in-the-middle capture (mitmproxy or otherwise) against Anthropic's API
without a separate, deliberate decision — that is a materially different
trust and ToS posture than direct operator-initiated requests.

### Open question: `anthropic-beta` header

No file in this repo documents whether Claude Code's own OAuth-authenticated
traffic sends an `anthropic-beta` header (or any value for it). This
runbook does not invent one. `scripts/capture-claude-quota-headers.sh`
leaves it unset by default and reads `OMUX_E2_ANTHROPIC_BETA` if the
operator wants to test a specific candidate value live. If the live capture
independently reveals (e.g. via a legitimate side channel, not by
proxying Claude Code itself, which is out of scope per the rejected
alternative above) that such a header is required, record the finding in
the fixture README and file a follow-up; do not silently bake in a guessed
value.

## Step by step

### 1. Dry-run review (no keychain access, no network calls)

```bash
./scripts/capture-claude-quota-headers.sh --dry-run
```

Read the full plan: every (account × channel) request that `--live` would
send, including the exact JSON bodies and the candidate model ids. Confirm:

- All five dogfood accounts appear, `personal` does not.
- Each account's derived `keychain_service` matches
  `provider_schema.zig`'s `claudeKeychainService` golden vectors where
  known (`xoxd` → `Claude Code-credentials-26ae8e92`, `sulliwood` →
  `Claude Code-credentials-cec7498b`).
- The `MODEL_ID_*` constants at the top of the script are still the
  operator's intended candidates. **They are placeholders** — correct them
  in the script before `--live` if research or the no-spend channel
  (channel 2, the unknown-model probe) suggests a better guess. In
  particular `MODEL_ID_FABLE` has no confirmed public Anthropic id
  anywhere in this repo; expect to correct it live.
- To scope to a subset while iterating: `--account xoxd --account
  sulliwood`.

### 2. Live capture (operator present)

```bash
export OMUX_E2_OPERATOR_ACK=yes
./scripts/capture-claude-quota-headers.sh --live
```

- Writes to a fresh `mktemp` directory outside the repo by default (printed
  at the end); override with `--out-dir DIR` or `OMUX_E2_OUT_DIR` if you
  want a stable path, but it must still resolve outside the repo — the
  script refuses otherwise.
- Per (account × channel): a `*-request-plan.json` (method/url/header
  names/body — no secrets, generated by the script, never by curl), a
  `*-response-headers.txt` (raw `curl -D` output — no `Authorization`
  request header ever appears here, since that's a request header and this
  dump is response-only), a `*-response-body.json`, and a `*-meta.json`
  (http status, timing, rate-limit-header presence/names, usage tokens
  parsed from the response).
- A run-level `SPEND-LEDGER.txt`: one row per request with account,
  channel, model requested, http status, `max_tokens` requested, tokens
  actually billed (from the response `usage` object when present), and
  whether rate-limit headers were present.
- If a keychain read fails for one account (e.g. not yet enrolled), the
  script warns and skips that account rather than aborting the whole run.
- Tokens are read into a `mktemp`'d header file (`chmod 600` immediately
  after creation) per account, consumed by `curl -H @file`, never placed in
  argv or echoed, and removed (best-effort secure-overwrite then unlink)
  via an `EXIT`/`INT`/`TERM` trap — including on interruption mid-run.

Watch the terminal output; each request logs `account=... channel=...
http=... ratelimit_headers=...` as it completes. If something looks wrong
(e.g. an account eating a 429 on step 1's `max_tokens:0` probe, which would
be a genuine and interesting finding, not a bug), let the whole pass finish
before deciding how to react — the ladder is designed to be safe to run to
completion.

### 3. Redact

```bash
./scripts/capture-claude-quota-headers.sh --redact "$RAW_OUT_DIR"
```

- Writes a redacted copy to a fresh `mktemp` directory outside the repo
  (printed at the end); override with `--redact-out DIR` or
  `OMUX_E2_REDACT_OUT`.
- Redaction rules (per TIN-2722's "fixture + redaction" section):
  - Header **names** and **numeric/timestamp values** are kept verbatim
    (this is the actual evidence: rate-limit remaining/reset/limit
    counters, `date`, `retry-after`, etc.).
  - Any header or JSON body field that looks like a request id,
    organization id, account id, user id, session id, or Cloudflare ray id
    is replaced with `sha256_12hex(value)` (the same convention as
    `src/identity_hash.zig`, e.g. `sha256_12hex("acct-test") ==
    "660d25a9d7ee"`).
  - `authorization`, `www-authenticate`, and `proxy-authenticate` header
    lines are stripped entirely (the latter two commonly echo the literal
    word "Bearer" in a 401 challenge, which carries no quota signal and
    would otherwise trip the forbidden-marker scan below for nothing).
  - The account-label directory name (`xoxd`, `sulliwood`, ...) is replaced
    with its `sha256_12hex` hash.
- The redact step runs its own forbidden-marker self-check (the same
  marker list as `src/fixture_redaction.zig`, kept in sync by hand) over
  its own output and **fails closed** (nonzero exit, no partial "trust me"
  output) if anything survives. This is a safety net, not the gate — the
  gate is step 4.

### 4. Manual review checklist (operator, before any commit)

- [ ] Skim every `*-response-headers.txt` and `*-response-body.json` in the
      redacted output by hand. Confirm nothing that looks like a live
      secret survived (the automated scans below are a backstop, not a
      substitute for eyes).
- [ ] Confirm the `SPEND-LEDGER.txt` in the redacted output accounts for
      every request the plan said it would send, with plausible token
      counts (single digits to low tens per account).
- [ ] Confirm at least one of: (a) real Anthropic rate-limit header names
      captured (even if the values are trivial), or (b) a documented,
      explicit absence of such headers on both 4xx and 200 responses.
      Absence is a valid, fixture-worthy result — do not re-run `--live`
      repeatedly chasing a positive signal.
- [ ] Confirm whether any response carries a model-dimension header or
      body field (the request/response `model` echo counts).
- [ ] Confirm whether any 429 body distinguishes a burst/window shape
      (`retry-after` seconds vs. an absolute reset timestamp vs. neither).
- [ ] Confirm each account's micro-spend channel either served the
      requested model or returned a documented failure — this is the
      "live Fable-serve confirmation per account" the TIN-2722 acceptance
      criterion asks for. A model substitution/downgrade in the response is
      itself a finding, not a bug.
- [ ] Write (or update) a `README.md` inside the promoted fixture directory
      with: UTC start/finish timestamps, the exact `MODEL_ID_*` values used
      (post-correction), the accounts covered, the full spend ledger, and
      an explicit "what this proves / what this does not prove" section
      using the allowed/forbidden language below.

### 5. gitleaks + fixture_redaction scan

Run both before staging anything:

```bash
gitleaks detect --no-git -s "$REDACTED_DIR"
```

Then copy the reviewed, redacted directory into
`test/evidence/quota-observation/claude-<UTCts>/` inside the repo and run
the repo's own committed secret-marker test over it:

```bash
just test-local
```

(`just test-local` runs `zig build test`, which — after this PR —
includes `src/fixture_redaction.zig`'s `"evidence captures contain no
obvious OAuth secrets"` test walking `test/evidence/` in addition to its
existing `test/fixtures/` walk.) This is **local-iteration validation
only**; the remote CI run on the PR is the actual completion proof, exactly
as for every other change in this repo.

### 6. Commit

```bash
git add test/evidence/quota-observation/claude-<UTCts>/
git commit
```

Never `git add -A`. Add only the specific promoted fixture path (plus any
doc/spec updates the fixture's findings motivate — those are separate,
reviewed commits, not bundled silently into the evidence commit).

## Evidence bar (TIN-2722 acceptance, verbatim)

> Committed fixture proving (a) real header names + model-dimension
> presence/absence, (b) window-vs-burst 429 shapes or their documented
> absence, (c) live Fable-serve confirmation per account, (d) spend ledger.
> **Absence of a signal is a valid result** — it locks the advisor's
> `unobserved` rendering and keeps the claim gate closed. Claim boundary
> unchanged: credential keepalive ≠ model-quota keepalive.

## Allowed language (once the fixture lands)

- "Committed, redacted Claude quota-header evidence (TIN-2722)"
- "Real Anthropic rate-limit header names observed" (only if true — see
  the review checklist)
- "Documented absence of a Claude quota signal on channel X" (equally a
  valid, citable result)

## Forbidden language

- "Claude quota keepalive" / "Claude model keepalive" (this fixture is
  evidence for a future gate, not the gate itself — the code increment in
  TIN-2722's "code increment after capture" section is a separate PR)
- "Fable/Opus quota routing proven"
- "Claude adapter parity"
- Any claim that a placeholder `MODEL_ID_*` value is confirmed before the
  live capture actually confirms it
