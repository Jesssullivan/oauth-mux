# Browser Account-Juggling Evidence (TIN-2720)

This directory is the committed, redacted evidence root for the browser/cookie-picker lane described in `docs/spec/stay-afloat-valet-and-browser-evidence-2026-07-09.md`.

The lane captures the user-visible Claude Code account-juggling path: browser account picker, usage/model surfaces, current singleton identity, intended switch, after identity, and active-harness outcome. Browser observations are evidence for operator assistance and product UX, not provider API contracts.

## Contract

Every promoted run must include:

- `manifest.json` with `schema_version: 1`, `evidence_kind: browser_account_juggling`, and `tracker: TIN-2720`.
- Account identities only as `sha256_12hex` values.
- Model/plan/quota observations as derived classifications with a `confidence` value and source.
- Explicit `provenance.provider_api_contract_claimed: false`.
- Explicit redaction booleans showing no cookie values, tokens, raw emails, raw account ids, PII screenshots, or raw page dumps were committed.

Allowed capture sources:

- `setup-browser-cookies` or equivalent operator-selected cookie picker, where the operator selects domains and the tool exposes domain names/counts only.
- `browse` / headed browser / CDP observations after cookies are imported.
- Operator notes that have been reduced to hashes, classifications, counts, and outcome labels.

Disallowed committed artifacts:

- Cookie values.
- Token values.
- Raw emails or raw account ids.
- Screenshots containing PII.
- Raw browser page dumps.
- Provider-control bypass notes or hidden spending probes.

## Current Fixture

`dry-run-20260711T050543Z/` is a schema/redaction dry run. It proves the manifest shape is parseable and redaction-scanned, but it is not a live browser proof and does not satisfy the full TIN-2720 acceptance by itself.
