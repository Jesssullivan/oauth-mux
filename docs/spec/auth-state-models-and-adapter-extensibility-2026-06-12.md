# Auth-State Models and the Adapter Extensibility Claim (revision)

Status: DESIGNATED (operator decision, 2026-06-12 evening). Revises the
extensibility claims in `docs/adoption.md` ("a new provider should usually
start as data, not Zig") and `docs/onboarding.md` (provider-author story)
against the verified Claude credential ground truth (TIN-2060/TIN-2070) and
the codex home-is-store arc (TIN-1851). Companion to the harness-adapter
pattern (`docs/spec/harness-adapter-pattern-2026-05-03.md`) and the reauth
orchestrator designation (TIN-2064).

## The problem

The `ProviderDefinition` contract silently encodes ONE auth-state model —
"auth state is a file inside a relocatable directory" — via
`injection.config_dir_env` + `credential_filename` + `credential_template`
and the `replace_file` writeback capability. Codex fits this model exactly
(`$CODEX_HOME/auth.json`; the whole store relocates with the home). Claude
Code does not fit it at all, and Claude + Codex are the two largest harness
contenders: an extensibility story that can only express one of them is
overclaiming.

Verified live (TIN-2060, `provider-proof-claude-credential-store-2026-06-12.md`),
Claude Code on macOS has **three singleton layers** Codex has none of:

1. **OS-keystore singleton (credentials).** Credentials live in the login
   keychain — a global, user-scoped store the harness app ACL-owns — keyed
   by `Claude Code-credentials-<sha256(CLAUDE_CONFIG_DIR)[:8]>`. The
   config dir is the *key derivation input*, not the storage location.
   `.credentials.json` is never written; the declared
   `claude_def.injection.credential_filename`/`credential_template` are
   **dead fields on macOS**, and tmpdir credential injection cannot deliver
   credentials to the CLI there at all.
2. **Identity-file singleton (account identity).** Stable identity is
   `<CLAUDE_CONFIG_DIR>/.claude.json` → `oauthAccount.accountUuid` — a file
   *separate from* the credential, with no `ProviderDefinition` field to
   declare it.
3. **Browser-session singleton (consent).** The claude.com browser session
   bleeds across accounts during OAuth: the 2nd+ account's manual-paste
   code page never resolves in a browser carrying the 1st account's
   session. Per-account isolated browser contexts (incognito-first,
   ephemeral profile) are load-bearing for any mediated login (TIN-2071).

## The taxonomy (named models)

Adapter/extensibility claims and gates MUST name which model a provider
follows; "add a provider" means different work per model.

| Model | Anchor | Credential store | Account isolation | Refresh writeback | Mediated login hazard |
| --- | --- | --- | --- | --- | --- |
| **home-scoped-file** | codex | file(s) inside `$CONFIG_DIR_ENV` | relocate the directory | atomic file replace (+ field-preserving merge, TIN-2074) | device-code flow; no browser singleton |
| **os-keystore-singleton** | claude (macOS) | OS keychain item, key derived from config-dir path | distinct derived keys (structural, no clobber) | OS keystore write API (`security -U`, TIN-2070), ACL-mediated | browser-session bleed → isolated context per account (TIN-2071) |
| *(future)* os-keystore variants | Linux secret-tool, Windows DPAPI | platform keyring | per-key | platform API | per-provider |

A single provider may be **per-platform hybrid**: Claude on Linux is
likely home-scoped-file (`.credentials.json` — unproven, tracked) while
macOS is os-keystore-singleton. The model is a (provider, platform) fact,
not a provider fact.

## Revised claims

1. **"A new provider should usually start as data, not Zig" holds for
   home-scoped-file providers only.** For os-keystore-singleton providers,
   the JSON definition can declare parsing/probes/failure rules, but the
   credential store mechanics (key derivation, keystore write, identity
   file, browser isolation) currently require compiled support. The
   adoption/onboarding claims are scoped accordingly (this doc is the
   truth source they point to).
2. **The harness-adapter pattern claim stands, with a sharpened reading**:
   the adapter owns "the harness's native auth surface" — and for Claude
   that surface is the OS keystore + identity file + browser consent
   context, not a credential file. Adapter work for an
   os-keystore-singleton harness is necessarily larger than for a
   home-scoped-file harness; the pattern doc's effort framing inherits
   this taxonomy.
3. **`claude_def`'s injection block is documented as aspirational on
   macOS**: `credential_filename`/`credential_template` describe the
   (unproven) Linux file lane and the historical tmpdir mode. They MUST
   NOT be read as "how Claude credentials are delivered on macOS" — that
   is the keychain + `CLAUDE_CONFIG_DIR` pairing, end to end.

## Objectives (the extensibility goal, made falsifiable)

**Goal: one declarative contract that expresses BOTH anchor models well
enough that the golden-metric gates (TIN-2057, TIN-2077) run on schema +
small per-model engines, not per-provider forks.**

Schema extensions required (cut as TIN-2078; informs, does not block, the
#354 contract amendment):

1. `os_credential_store: ?OsCredentialStore` on `ProviderDefinition` —
   `keychain: { base_service, suffix: config_dir_sha256_8, account: local_user }`
   as the first variant. Today this derivation is hardcoded
   (`claudeKeychainService`, `applyClaudeKeychainDefaults`); the field
   makes it declarable and makes "which model is this provider on this
   platform" machine-readable.
2. `identity: { file, claims }` — e.g. `.claude.json` +
   `oauthAccount.accountUuid` — so identity-keyed health/stats/dedupe
   (#359/#360 lane) stop special-casing providers.
3. `reauth.browser_isolation: { incognito_first, ephemeral_profile }` —
   the TIN-2071 requirement as schema, enforced by the mediated-login flow
   rather than remembered by operators.
4. Injection-mode truth: `credential_template` usage is gated on the
   absence of an active `os_credential_store` for the (provider, platform);
   a definition that declares both states which platform uses which.

Non-goals: porting the keychain write to Linux/Windows (separate proofs),
collapsing the adapter layer (per the harness-adapter pattern, adapters
remain required for session lifecycle and signal observation).

## Consequences for the concurrent-sessions gates

The codex gate (TIN-1852, closed) proved home-scoped-file concurrency:
isolated homes, canonical store byte-stable. The Claude gate (TIN-2077)
must prove os-keystore-singleton concurrency, which is a *different*
theorem: two live sessions against one OS keystore (distinct derived
keys), one mediated reauth in an isolated browser context, the other
session undisturbed — no bleed, no lock stampede, byte-stable keychain
item for the untouched account. Passing both gates is what substantiates
the revised extensibility claim for the two anchor models.
