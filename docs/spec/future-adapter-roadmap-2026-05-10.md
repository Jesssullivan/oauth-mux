# Future Adapter Roadmap

Date: 2026-05-10
Status: planning; subordinate to `docs/spec/broker-mcp-contract-2026-05-03.md`
and `docs/spec/harness-adapter-pattern-2026-05-03.md`.

## Rule

New adapters must consume the same broker/account contract. If a provider needs
a new state or auth shape, fix the shared model first; do not fork the product
claim per adapter.

## Adapter Proof Gates

Every adapter needs:

1. account discovery/inventory that redacts raw identity and token material;
2. named account labels that operators can map privately;
3. runtime doctor that distinguishes missing CLI, missing login, bad auth,
   quota/rate/tier failure, and local store errors;
4. diagnostic fixture tests for every typed state the adapter emits;
5. one positive live proof and one negative live or cassette proof before
   claiming capability support;
6. a documented current-process boundary: managed proxy, app-server protocol,
   native refresh hook, or prepared launch only.

## Roadmap Matrix

| Adapter | First proof target | Handoff shape to study | Main unknowns |
| --- | --- | --- | --- |
| Claude Code | isolated account-store `auth-status` | native CLI config-dir selection first; current-process handoff later only if a hook exists | subscription vs Console/API billing, quota text shape, account-store isolation |
| OMO / OpenCode frontends | route inventory and config/profile isolation | consume oauth-mux diagnostics or future MCP repair prompts first; prepared launch only until protocol evidence exists | whether the agent frontend exposes provider auth state, quota state, request proxy hooks, or reloadable credentials |
| Pi | account inventory and login-state doctor | likely prepared launch or HTTP/MCP proxy, pending protocol evidence | auth storage, quota signal shape, CLI/API boundary |
| opencode | config/profile isolation and command probe | prepared launch first; request proxy only if HTTP path is observable | provider plugin model, auth ownership, model/provider routing |
| Kimi | provider-schema proof and command/API probe | command adapter or HTTP proxy depending on available CLI/API | OAuth vs API key, quota/rate/tier error taxonomy |
| Figma | PAT/OAuth/resource-token identity probes | no stay-afloat claim until token/resource model is distinct | seat type, file/resource authorization, REST vs MCP bearer tokens |
| GitHub/Linear | existing provider-proof probes | provider-token fallback for API calls, not harness TUI | app token vs user token, installation permissions, rate limit classes |
| Vercel | auth/status and project-scope probe | command adapter first | team/project scoping, token refresh ownership |
| MCP HTTP resources | bearer/resource-token probe | per-request muxing through MCP transport | server auth schemes, resource-bound token semantics |

## Shared Account Labels

Use labels that encode role, not identity:

- `claude-pro-1`, `claude-max-1`, `claude-team-1`;
- `figma-full-1`, `figma-dev-1`, `figma-plan-1`, `figma-mcp-1`;
- `github-user-1`, `github-app-1`, `linear-user-1`;
- `kimi-paid-1`, `opencode-primary-1`, `pi-plus-1`.

Private email/account binding stays outside repo docs. Public evidence should
show only route labels, capability labels, typed state, and redacted proof
metadata.

## Do Not Claim

- Do not claim "provider supported" when only one capability is proven.
- Do not treat adjacent agent-control-plane route proof as oauth-mux
  stay-afloat support.
- Do not claim seamless handoff from a prepared launch.
- Do not claim quota fallback from auth fallback.
- Do not generalize API credits or unrelated model availability into
  subscription-backed harness quota.
- Do not claim a background daemon can hot-swap an unmanaged process without a
  provider/native hook, request proxy, or adapter-owned process boundary.

## Sequencing

1. Keep Codex as the reference adapter until its cassette and negative
   permutation matrix is stable.
2. Promote Claude next only for account-store isolation and `auth-status`;
   quota/fallback proof is a separate lane.
3. Promote Figma as a token/resource taxonomy proof, not as a harness
   stay-afloat proof.
4. Add OMO/OpenCode/Pi/Kimi only after provider docs or local CLI behavior
   identify concrete auth, quota, reload, and process-boundary states to model.
