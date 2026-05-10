Update after the 2026-05-08 installed-runtime dogfood:

Managed resume parity is now backed by a non-stale installed command path, not
only source tests or repo-local binaries. The latest proof entered through:

```bash
oauth-mux codex resume <id>
```

The status artifact recorded installed runtime identity, canonical session
authority, explicit resume preflight, provider-originated quota on
`codex:default`, and successful fallback traffic on `codex:max-2`.

Proof references:

- `docs/evidence/codex-managed-quota-handoff-20260508/status-excerpt.ndjson`
- `docs/evidence/codex-managed-quota-handoff-20260508/status-summary.json`
- `docs/spec/codex-live-quota-handoff-evidence-2026-05-08.md`

Recommended tracker state: close if #191 is specifically about managed resume
parity through the installed command path. Keep separate follow-up coverage for
chooser/`--last` UX if that is still desired.
