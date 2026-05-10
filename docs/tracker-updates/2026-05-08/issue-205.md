Update after the 2026-05-08 installed-runtime dogfood:

The stale/missing binary ambiguity that blocked dogfood earlier has been
addressed enough for the latest proof: the accepted run entered through the
bare installed command path:

```bash
oauth-mux codex resume <id>
```

The status artifact records runtime identity and command spelling, including
`binary_path`, `binary_source`, `build_id`, `version`, `command_spelling`, and
`installed_local_mismatch_detected:false`.

Proof references:

- `docs/evidence/codex-managed-quota-handoff-20260508/status-excerpt.ndjson`
- `docs/evidence/codex-managed-quota-handoff-20260508/status-summary.json`
- `docs/spec/codex-live-quota-handoff-evidence-2026-05-08.md`

Recommended tracker state: close if #205 is scoped to dogfood ambiguity between
stale installed `oauth-mux`, missing `./zig-out/bin/oauth-mux`, and raw
`codex resume`. Keep any package-manager PATH precedence polish as a separate
release/install issue.
