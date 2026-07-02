# Provider truth matrix (2026-07-02)

Single source of provider-support truth, keyed to the **runtime's** `proof_status` field
(`src/provider_schema.zig:5-8` + per-capability `proof_status`,
`CapabilityDefinition.proof_status` default `needs_operator_proof` at
`src/provider_schema.zig:203`). Marketing surfaces (omux.xoxd.ai) must *derive* from this
table, never curate ahead of it.

## The runtime enum (4 values, `src/provider_schema.zig:5-8`)

The runtime defines exactly four `proof_status` values:

| `proof_status` | Meaning | Evidence bar |
|---|---|---|
| `live_proven` | exercised end-to-end against a real account, evidence committed | dated `docs/evidence/` dir |
| `local_live_proven` | a *local* probe ran against real local state — proves the probe, **not** quota, tier, or a model call | probe output in a proof doc |
| `public_live_proven` | proven against a public, unauthenticated surface | probe output |
| `needs_operator_proof` | schema-modeled only; typed but never live-run | none yet (say so) |

## Matrix-level doc statuses (layered on top; NOT in the runtime enum)

This matrix additionally uses two doc-only statuses the runtime does not model:

| status | Meaning | Evidence bar |
|---|---|---|
| `planned` | named intent, no schema | — |
| `blocked` | a correctly-shaped, correctly-scoped attempt was refused by the provider (e.g. 400/403) | the dated refusal; a mis-shaped credential or mis-scoped token does **not** meet this bar and stays `needs_operator_proof` |

## Capability rows (verified against `src/provider_schema.zig` @ main `ba7cdd2`)

| Provider | Capability | proof_status | Proof anchor |
|---|---|---|---|
| Codex CLI (`codex_def`) | `codex-max` | **`live_proven`** | `src/provider_schema.zig:683`; evidence dirs `docs/evidence/codex-live-e2e-clean-lineage-20260612/`, `codex-concurrent-accounts-live-20260612/`, `codex-engineered-quota-handoff-20260509/`, `codex-managed-quota-handoff-20260508/` |
| Codex CLI | `codex-mini` | **`live_proven`** | `src/provider_schema.zig:710`; same evidence family |
| Claude Code (`claude_def`) | `auth-status` | `local_live_proven` | `src/provider_schema.zig:332`. Proves the local probe only — **no quota, tier, or model-call proof**; no harness adapter exists ("synthetic smoke only"); login remains vendor-CLI `claude /login` |
| MCP Server (`mcp_def`) | `resource-metadata` | `public_live_proven` | `src/provider_schema.zig:410` |
| MCP Server | `resource` | `needs_operator_proof` | default (no explicit status) |
| Vercel CLI | `identity` | `local_live_proven` | `src/provider_schema.zig:492` |
| GitHub CLI | `identity` | `local_live_proven` | `src/provider_schema.zig:509` |
| Linear | `identity-api-key` | `local_live_proven` | `src/provider_schema.zig:560` |
| Linear | `identity` (OAuth bearer) | `needs_operator_proof` | `docs/live-provider-qa.md:240-241`. Negative evidence 2026-05-01: HTTP 400 came from sending the *personal API key* as a bearer — a mis-shaped credential, not a provider refusal of OAuth bearer auth; no correctly-shaped OAuth bearer has ever been attempted, so the row "stays `needs_operator_proof`" |
| Figma REST API | `identity-pat` | `local_live_proven` | `src/provider_schema.zig:609` |
| Figma REST API | `identity` (OAuth bearer) | `needs_operator_proof` | `docs/spec/provider-proof-figma-rest-2026-05-01.md` ("Current Proof Status: `needs_operator_proof`"). Negative evidence 2026-05-01: HTTP 403 classified `degraded.scope_insufficient` on a mis-scoped token — a scope defect on the attempted token, not a provider refusal of OAuth bearer auth; no correctly-scoped OAuth bearer has ever been attempted |
| Figma REST API | `file-metadata-plan` | `needs_operator_proof` | default |
| FlakeHub / Determinate Nix | `status` | `local_live_proven` | `src/provider_schema.zig:664` |
| Gemini CLI | (all) | `needs_operator_proof` | schema-modeled only |
| Generic OAuth Provider | (template) | `needs_operator_proof` | definition template, never a support claim |

## Hard language rules

- **Codex is the only `live_proven` provider.** Heavy OpenAI TOS surface: never frame as
  "unlimited", "bypass", or "pooling". The claim is *continuity for accounts the user owns*.
- **No capability may be shown `live` from another capability's local proof.** Claude
  `auth-status` being `local_live_proven` does not make "Claude" a proven provider.
- `local_live_proven` must always carry its limitation sentence when rendered.

## Site reconcile contract (omux.xoxd.ai)

The site enum (`src/lib/content/providers.schema.ts:10`) is 3-valued. Canonical mapping:

| runtime | site |
|---|---|
| `live_proven` | `live-proven` |
| `local_live_proven`, `public_live_proven`, `needs_operator_proof` | `schema-modeled` (with the honest note) |
| `planned` | `planned` |
| `blocked` (matrix-level) | `schema-modeled` + the dated refusal note (never hidden). No row currently carries this status — the Linear and Figma OAuth-bearer rows are `needs_operator_proof` and must render as unproven/not-live, never as "blocked by provider" |

`scripts/regen-providers.mts` currently reads the 2026-04-26 probe-admission matrix plus a
curated status map **inside the site script** — the curated map must be replaced by/checked
against this table (follow-up recorded in Linear; the site never overrides runtime truth).
