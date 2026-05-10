# Tracker Updates — 2026-05-09

Issue filed:

- `codex-config-overlay-issue.md`:
  <https://github.com/Jesssullivan/oauth-mux/issues/211>
- `codex-engineered-live-handoff-proof.md`: tracker-safe proof summary for
  the 2026-05-09 installed `oauth-mux codex resume` managed quota handoff.
  Posted to:
  - <https://github.com/Jesssullivan/oauth-mux/issues/177#issuecomment-4414105351>
  - <https://github.com/Jesssullivan/oauth-mux/issues/131#issuecomment-4414105521>

This tracks managed Codex config parity: preserving native Codex
`config.toml` behavior settings, including `/experimental` / `[features]`,
while oauth-mux owns only the proxy-provider override in the temporary managed
overlay.

Initial implementation landed locally after filing: the managed overlay reads
canonical config when present, preserves native behavior settings, removes only
oauth-mux-owned provider conflicts, appends the managed proxy provider, emits
redacted config-passthrough status, and has unit plus CLI-smoke coverage for
feature/experimental/MCP/approval settings.

Follow-up refinement: config authority is independent from session authority.
Managed config passthrough follows `OMUX_CODEX_CONFIG_HOME`, then parent
`CODEX_HOME`, then `~/.codex`; `--session-home` and
`--isolated-session-store` affect sessions, not native Codex behavior settings.

Second refinement: profile-scoped `model_provider` entries are stripped while
unrelated profile settings survive, and forwarded Codex `--config` / `-c`
attempts to override mux-owned provider keys fail before child spawn with a
redacted `config_passthrough_check` status event.

Live handoff update: the engineered low-weekly run produced the headline
managed Codex proof. The preserved redacted bundle is
`docs/evidence/codex-engineered-quota-handoff-20260509/`; it shows successful
primary-route traffic, provider-originated `usage_limit_reached`, same-request
retry to a distinct fallback route, and fallback `status:200`. Keep
same-thread continuity, mid-turn recovery, unmanaged daemon handoff, and
non-Codex providers as separate claims.
