# Native owner candidate artifact

R-N13 creates this separate, unshipped candidate epoch. The original artifact at
`integrations/codex-upstream` and its prepared source and receipts stay preserved.
No native support, installed behavior or seamless handoff follows from packaging.

Root staged `manifest.json`, the named product patch, `upstream-base.tar.gz`,
`binary-overlay.tar.gz`, `validation.json`, `validation-overlay.patch` and
`schema-import-receipt.json` under R-N13. Producer
`247e7ef5-8c34-458a-9c79-13e35cb1e6c3` packaged 164 reviewed changed files
against immutable official commit `00c972ed5d6ff6499317fd41b7f23605b8e6850d`.
The product patch SHA256 is
`2e5542c5f6a44e3a8dd38b4a4093d1735ff19771721b05fc51f55b475b1a8d46`.
Current validation records distinguish passing gates from pending gates;
packaging alone establishes no behavioral support. `:artifact_test` now joins
the default test graph and checks exact bytes and receipt binding.

`//integrations/codex-upstream:import_schema_bundle` copies exact stable public
JSON/TypeScript and stable/experimental compressed maps into the new development
checkout. It preserves unrelated files, rejects symlinks and untrusted roots,
performs no normalization or compression, and creates an exclusive private
receipt directory. Arguments are `--stable-dir`, `--experimental-dir`,
`--edited-checkout`, `--receipt-directory` and `--producer-invocation-id`.
The receipt directory contains an intent and `schema-import-receipt.json`;
a failed partial import is not a passing receipt.

The candidate verifier uses declared sibling `patch_io.py` runfiles to check
exact reconstruction, upstream pin, attribution and manifest/validation hashes.
Validation needs `artifact_status`, `native_support: false`, `upstream_commit`,
`artifact` (three artifact hashes and `reviewed_changed_files`), the existing
restoration `validation_environment` graph/overlay hashes, and `schema_import`
with `receipt_file: schema-import-receipt.json`, its `receipt_sha256` and the
actual `producer_invocation_id`. Every changed public schema must match an
imported file's hash and length. Unchanged imported files are receipt-bound;
they are outside the changed subset archive. Full restoration independently
checks the complete pinned Git tree, validation overlay and graph hashes.

This verifier contains no Rust source-text oracle. Current behavioral tests and
live version-bound owner gates retain their separate scopes. Earlier pass
counts must not be copied into this candidate's validation record.

Run both tools through the locked Nix/Bazel graph. Restoration uses
`//integrations/codex-owner-candidate:restore_source` with a new durable private
`--root` and the ordinary fetch/verify/prepare/verify-prepared phases. Its declared
data contains only this candidate; it cannot silently substitute the old one.
The new package's `:public_sources` must be explicitly included by the root
source archive because a parent glob stops at a nested Bazel package.
