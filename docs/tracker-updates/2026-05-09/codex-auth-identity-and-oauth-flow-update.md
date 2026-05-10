Codex route/account truth update, redacted:

- Fresh installed `oauth-mux route explain --profile codex-max --capability codex-max --json` currently reports `not_afloat`.
- `codex:max-2` and `codex:max-3` are recorded `auth_permanently_failed`.
- `codex:max-1` and `codex:max-4` remain quota-blocked reset-window candidates.
- Immediate next step is route-specific upstream CLI reauth:
  `oauth-mux codex login-device max-2` for the low-weekly primary, and
  `oauth-mux codex login-device max-3` for the high-capacity fallback.
- Re-run route explain after both handoffs. Use spend-gated
  `oauth-mux codex probe-all --capability codex-max --json` only if recorded
  health remains stale and the operator explicitly confirms spend.
- Account inventory is being extended with redacted Codex `auth_identity`
  metadata so agents can map named route stores to auth-bound accounts without
  reading auth files or printing raw email/account/token/path data.

The `/experimental` / Codex behavior-settings concern is already tracked by
GitHub #211. Current acceptance for that issue is config passthrough by default,
with only oauth-mux-owned proxy provider keys stripped or rejected.
