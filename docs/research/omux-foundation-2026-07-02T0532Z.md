# omux foundation — exploration packet (2026-07-02T0532Z)

Prompt: `prompts-enqueue/prompts/26-omux-oauth-broker-foundation.md` (97-line rework, merged
2026-07-02 via prompts-enqueue PR #8). Operator decision ledger item 12 applies: Level-3
stay-afloat evidence leads July; reauth lane (TIN-1805–1808) queues behind this work;
ffi-sdk + federation-packaging are formally parked.

This packet is the step-1 proof artifact. Every claim below was re-verified against the
working trees and Linear on 2026-07-02 (step-0 mandate), not carried from the prompt.

## Step-0 deltas — where the prompt's "Current reality" is stale at HEAD

| # | Prompt claim | Live truth (verified 2026-07-02) | Consequence |
|---|---|---|---|
| D1 | "the refresh **write** path (`broker_loader.zig refreshCodexAccountAuthFile`, ~:387) takes **no lock at all**" | The write path **does** take `repair_state.acquireRepairLockBlocking(provider, account)` at `src/broker_loader.zig:368`, re-reads auth under the lock (`refreshCodexAuthState`, early-return `.not_needed`), and additionally defers to a live session's identity flock (TIN-2043 block at `:386-409`). Landed in PR #351 (2026-06-01, "Serialize Codex auth refresh by account"). | Scope step 4 shrinks: the lock is wired; what is missing is the **exactly-once concurrency proof**, the bounded-timeout typed error, and the `credential_lock.zig` factor. |
| D2 | "TIN-1785 … not because a blocking primitive is missing … but because the refresh write path takes no lock" | Same as D1 — the stated *reason* for TIN-1785 being open is stale. TIN-1785 remains genuinely open (Backlog) for: dedicated module factor, `LockMode` knob API surface, bounded acquire timeout → `error.RefreshLockTimeout`, N-racer stub-endpoint test. | TIN-1785 needs a scope-correction comment, not silent closure. |
| D3 | Decision ledger item 12 orders "TIN-1517 → TIN-950 → TIN-951 (gates TIN-916)" as the July Level-3 lane | All three are recorded **Done** in Linear (TIN-1517 2026-05-19 via PR #271; TIN-950 2026-05-04 via PR #308/#309; TIN-951 2026-05-16). The ledger intent (fresh Level-3 *live* evidence in July) therefore needs **new evidence tickets or re-opens**, not status flips on closed work. | Recorded in Linear update; operator decides re-open vs new tickets. |
| D4 | "wave notes: several referenced PRs merged 2026-07-01" | In `oauth-mux` **nothing merged since PR #424 (2026-06-15)**; no branch touched since then; no open PRs. The 2026-07-01 merges were in `prompts-enqueue` (#6, #7, #8) and `omux.xoxd.ai` (dependabot #72). No wave-1 residue found in oauth-mux branches, PRs, or Linear comments (initiative has one comment, 2026-06-01). | Adopted: nothing to rescue; this session starts clean. |
| D5 | Prompt names `docs/decisions/…` -style stale docs | The stale docs live at `docs/spec/dual-writer-refresh-designation-2026-06-13.md:180` ("grant flip remains blocked") and `docs/spec/refresh-authority-adr-trace-2026-06-13.md:62` ("GRANT FLIP … BLOCKED"). The grant flip landed in PR #418 (2026-06-14). `docs/provider-repair-contracts.md` does not contain a "BLOCKED" grant-flip claim at HEAD (checked; no correction needed there). | Dated correction notes added in this PR (ledger correction pattern: dated note, no silent rewrite). |
| D6 | "Remove `oauth-mux/WORKSPACE.bazel`" (a file) | True, and **worse**: `.bazelrc` carries `common --noenable_bzlmod`, i.e. the bounded TIN-2105 Bazel surface runs in *legacy WORKSPACE mode* despite `MODULE.bazel`. Bzlmod-only means deleting the file **and** the flag. | Handled on the `jess/tin-2105-*` branch. |
| D7 | (implied) repo carries the standard contract set | `oauth-mux` has **no `tinyland.repo.json`** manifest; CI (`.github/workflows/ci.yml`) does not consume `ci-templates@v2.0.0`; `scripts/gloriousflywheel-bazel.sh` is a repo-local wrapper (house rule: source the canonical wrapper from `nix develop`/profile-tools, never vendor — verify whether this one counts as vendored drift). | Manifest added on the tin-2105 branch; ci-templates + wrapper-sourcing recorded as follow-up workstream. |
| D8 | "5 issues rotting In Review/In Progress since mid-June" | Confirmed and named: TIN-2059 (In Progress 2026-06-13), TIN-2045 (In Review 2026-06-12), TIN-1812 (In Review 2026-06-01), TIN-1811 (In Review 2026-06-01), TIN-2105 (In Review 2026-06-14). | Revival comments posted (see Linear lane). |

## Repo truth lane

- **`Jesssullivan/oauth-mux`** (runtime authority; local `~/git/oauth-mux`, main @ `ba7cdd2` PR #424).
  Pure Zig (`minimum_zig_version 0.14.0`, flake-pinned; local host zig is 0.15.2 — always build
  via `nix develop`). Version **0.1.13** (`build.zig.zon:3`). Entrypoint: `justfile`;
  remote-first validation (`just build|test` → `scripts/remote-validate.sh` GH-workflow
  dispatch; `just flywheel-zig-*` → bounded TIN-2105 Bazel/REAPI lane). AGENTS.md anchors the
  product on the broker contract (`docs/spec/broker-mcp-contract-2026-05-03.md`).
- **Bazel posture**: `MODULE.bazel` (module `oauth_mux` 0.1.13) + dependency-free genrule
  candidates tagged `gloriousflywheel-rbe-candidate` (`target-class=oauth-mux-zig-build-test`).
  Defects: stub `WORKSPACE.bazel` present, `--noenable_bzlmod` in `.bazelrc` (D6), no
  `tinyland.repo.json`, CI not on `ci-templates@v2.0.0` (D7). `.bazelrc`/`.bazelrc.flywheel`
  are endpoint-free (good).
- **Keepalive truth**: `oauth-mux keepalive` wired (`src/main.zig:274` dispatch; PR #417),
  `proactive_refresh` grant flipped for claude/codex builtins (PR #418, consent-gated on
  `allow_proactive_refresh`), shared-identity accounts excluded from the warm pool (PR #419).
  **No committed `docs/evidence/` warm-loop run exists** (`ls docs/evidence` shows four codex
  dirs, newest 20260612) — keepalive is *merged, not evidence-proven*.
- **Broker layer**: `credential/refresh` is still `notImpl` (`src/broker/methods.zig:49`);
  `surface/info` reports `credential_refresh:false` (`:97`). Serialization today lives in the
  *loader* path, not the broker method — TIN-1792/1793 remain real work.
- **TIN-1786 open in code**: `shouldPreserveChildAuth` (`src/adapters/codex/wire_proxy.zig:1673`)
  still preserves child auth on account-id equality; no `broker_is_sole_writer` gate.
- **`tinyland-inc/omux.xoxd.ai`** (static docs site; read-only this session): SvelteKit spoke;
  provider page enum is 3-valued (`live-proven | schema-modeled | planned`,
  `src/lib/content/providers.schema.ts:10`); `just regen-providers` regenerates
  `providers.json` from `oauth-mux/docs/spec/provider-probe-admission-matrix-2026-04-26.md`
  **plus curated status inside the site script** — i.e. site status is *not* keyed to the
  runtime `proof_status` field. Reconcile gap recorded (see proof DAG).
- **`Jesssullivan/homebrew-omux`** (packaging): published Formula on `main` is **0.1.13**
  (matches release v0.1.13). Local working clone sits on stale branch
  `codex/oauth-mux-0.1.11-checksums` (tracking branch gone) — clone hygiene, not a shipped-tap
  defect. npm lanes: `npm-publish.yml` + `npm-deprecate.yml` exist; npm is **RETIRED** as an
  install recommendation.

## Linear parity lane (queried 2026-07-02)

| Issue | State | Parity note |
|---|---|---|
| TIN-1785 CredentialLock | Backlog | Stale premise (D1/D2); remaining scope = module factor + timeout + exactly-once test |
| TIN-1786 shouldPreserveChildAuth flip | Backlog | Confirmed open in code |
| TIN-1792 surface/info flags + smoke | Backlog | Confirmed open (`credential_refresh:false`) |
| TIN-1793 contract freeze + incident closeout | Backlog | This branch starts it (dated corrections; full closeout blocked on TIN-1792) |
| TIN-2059 dual-writer refresh | In Progress (since 06-13) | Partial mechanism already at HEAD: identity-flock defer on the background write path (`broker_loader.zig:386-409`) = design-space option 1; freshness re-read under lock = option 2 precursor. Needs the written contract + engineered-race proof |
| TIN-2045 chooser resume | In Review (since 06-12) | Rotting; needs review closure |
| TIN-1811 / TIN-1812 never-halt selector | In Review (since 06-01) | Rotting; branch `tin-1811-cross-capability-degrade` exists on origin |
| TIN-2105 Zig REAPI target class | In Review (since 06-14) | Rotting; forced-proof dispatch lane merged (PR #421) but promotion evidence not recorded |
| TIN-2057 golden-metric keepalive | Todo (unstarted) | The 2×Claude+2×Codex acceptance; gated on live accounts (operator) |
| TIN-2047 loopback auth token | Todo | Owned here as a foundation primitive (GH #376) |
| TIN-2040 proxy perf pass | Todo | zig-core gap ticket |
| TIN-2051 age bech32 decode | Todo | fix-vs-remove decision required in-ticket before code |
| TIN-1517 / TIN-950 / TIN-951 | **Done** | D3 — ledger item 12's July lane needs fresh evidence tickets |

## History lane

- The refresh-race incident (`codex-refresh-token-race`, GH #336 / PR #337) produced the
  serialize/authority-split train that closed 2026-06-01→06-15 (PRs #351, #405–#424).
- Two prior burns define the dual-writer hazard class (from TIN-2059): sops-nix stale-auth
  re-materialization revoked a rotated RT system-wide; temp-home muxxing poisoned the
  canonical store.
- A prior wave-1 attempt at this prompt (2026-07-01/02) died to a rate limit **before leaving
  residue** (verified: no branches, no PRs, no stamped Linear comments).
- 2026-06-13 decision docs froze "grant flip BLOCKED" one day before PR #418 flipped it —
  the docs were never corrected (fixed in this PR with dated notes).

## Sibling/authority lane

- **GloriousFlywheel** owns cache/RBE; enrollment keystone CLOSED (fresh-repo proof run
  28294443457 green) but adoption is the open frontier; endpoints are env-authority only.
- **ci-templates@v2.0.0** owns CI shape; oauth-mux CI predates it (D7).
- **omux.xoxd.ai** owns docs/marketing rendering only — never runtime claims.
- **homebrew-omux** owns the brew lane; binary-only formula.
- **lab** owns fleet secrets (sops/age); no secret material may land here.

## Web/source lane (research appendix)

| Source | Accessed | Decision it informs |
|---|---|---|
| RFC 9700 (OAuth 2.0 Security BCP), rfc-editor.org/rfc/rfc9700.html | 2026-07-02 | §2.2.2: refresh tokens for public clients MUST be sender-constrained **or rotated** (§4.14) — omux's whole exactly-once discipline exists because rotation makes a double-spend *revoke the chain*; the exactly-once smoke is therefore the incident-class regression gate, not a nicety. §2.1.1: PKCE MUST for public clients + downgrade-attack mitigation — applies to the reauth loopback flow (queued lane). §2.1/RFC 8252 §7.3: exact-string matching except port on localhost loopback redirects — constrains the TIN-2047 per-session loopback token design (token must ride the path/header, not the redirect-URI match). |
| OpenAI TOS posture (standing house rule, re-affirmed in prompt) | 2026-07-02 | Codex evidence is `live_proven` but must never be framed as "unlimited"/"bypass"/"pooling"; provider matrix language below complies. |

## Boundary map (step-2 truth)

| Concern | Owner | Non-owners |
|---|---|---|
| Broker/OAuth runtime logic, locks, refresh, resume | `Jesssullivan/oauth-mux` | omux.xoxd.ai (renders only), homebrew-omux |
| Provider truth (proof_status) | `oauth-mux` `src/provider_schema.zig` + `docs/spec/provider-truth-matrix-2026-07-02.md` | the site's curated map must derive from it |
| Static docs/marketing | `tinyland-inc/omux.xoxd.ai` | must not overstate: 3-value enum maps from 6-value runtime truth |
| Packaging: brew | `Jesssullivan/homebrew-omux` (binary-only Formula) | |
| Packaging: tarballs/curl/rpm/deb/nix | `oauth-mux` release lane (`release.yml`, nfpm, flake) | npm RETIRED; no .app/.dmg/AppImage; systemd/launchd are user-wrapper templates only |
| Release notes/versioning | `oauth-mux` (`build.zig.zon` + `scripts/project-version.sh`) | |
| CI/cache/RBE substrate | GloriousFlywheel + ci-templates | never standalone runners, never baked endpoints |
| Secrets | lab (sops/age) + local keychain paths | never in any omux repo |

## Failure register

1. **Stale-doc drift** (BLOCKED claims outliving the flip by 18 days) → this PR adds dated
   corrections and the packet names doc-truth as a step gate.
2. **Marketing outrunning runtime** (site "live-proven" curated by hand) → provider truth
   matrix keyed to `proof_status` with proof links; site regen must consume it.
3. **"Merged ≠ proven"** (keepalive wired but no evidence dir) → keepalive stays
   *merged-not-proven* until a committed `docs/evidence/keepalive-warmloop-*/` run exists.
4. **Race-class regressions** (two burns + one incident) → exactly-once smoke as a
   permanent gate (`scripts/smoke-codex-refresh-exactly-once.sh`).
5. **Lock semantics trap** (found this session): the in-process holder registry in
   `repair_state.zig` (`acquireRepairLockWithMode`) is **process-re-entrant** — a second
   *thread* in the same process re-enters (`entry.count += 1`) instead of serializing. Two
   in-process writers (e.g. warm-loop tick + broker materialize in one daemon) are therefore
   NOT mutually excluded by the flock; only the freshness re-read narrows the window. This is
   a real TIN-2059 design input and is flagged in its Linear comment.

## Proof DAG (this session and next)

| Step | Linear | Proof artifact | Status 2026-07-02 |
|---|---|---|---|
| 1 Exploration packet | — | this file | landed (this PR) |
| 2 Boundary repair | TIN-1793 | AGENTS.md boundary section + this map | landed (this PR) |
| 3 GF/Bzlmod repair | TIN-2105 | WORKSPACE.bazel deleted + bzlmod-on + `tinyland.repo.json`; RBE executor evidence via `just flywheel-zig-test` | branch `jess/tin-2105-bzlmod-only-and-repo-manifest`; executor run needs runner env (parked evidence) |
| 4 CredentialLock exactly-once | TIN-1785 | `scripts/smoke-codex-refresh-exactly-once.sh` green locally; fails-by-construction against a no-lock write path | branch `jess/tin-1785-refresh-exactly-once-smoke` |
| 5 Refresh serialization | TIN-1792/1793/2059 | broker `credential/refresh` + flags + engineered dual-writer race | open (next session; hardest problem, In Progress) |
| 6 Child-auth flip + resume | TIN-1786/2045 | broker-owned-only unit test + chooser-resume test | open |
| 7 Typed seams / core split | zig-core epic | non-CLI consumer over the seam | open |
| 8 Provider truth ledger | adapter-maturation | `docs/spec/provider-truth-matrix-2026-07-02.md` (this PR) + site regen keyed to it | runtime side landed; site reconcile queued |
| 9 Release/package proof | release-packaging | dry-run install + broker smoke under GF validation | open (tap at 0.1.13 verified) |
