# Native recovery candidate epoch

Omux owns this authentication adapter and its native integration contract. No
OpenAI-provided Omux hook is a prerequisite. Existing suitable extension points
may be used; an explicitly maintained application modification is also an
allowed delivery lane. This candidate is experimental and provides no evidence
of continuity support in unmodified Codex. Delivery qualification is tracked in
[the adapter delivery epoch](../codex-adapter-delivery/README.md).

The user's authorized native discovery and resume work uses this separate,
unshipped candidate. R-N13 governs mutation and receipt custody. Existing107/164
candidate artifacts, prepared sources, produced ELFs, runtime009 and source T2
remain preserved. This package has no staged artifact or passing receipt yet;
its BUILD anchors do not prove recovery, installation or native support.

Bootstrap a new durable source root using the immutable
`//integrations/codex-owner-candidate:restore_source` target's fetch, verify,
prepare and verify-prepared phases. Actual recovery edits belong only in that
new source. The proposed root is
`/srv/fast-local/jess/state/codex/omux-codex-native-recovery-development-20261004`;
the `source` directory is created by the declared restoration tool.

`:export_pristine_subset` declares the164 baseline artifact and exports original
pinned Git blobs from a verified mirror. Supply `--root`, a fresh exclusive
`--output-directory` and `--include-schema-originals`. The currently proposed
delta uses paths already covered by164, so no additional original is required.
New source/generated paths remain explicit `--new-file` inputs to
`//integrations/codex-upstream:refresh_artifact`; export does not select edited
checkout bytes. Exact schema producers and the schema importer remain separate
declared upstream/Omux targets.

The separate status epoch also declares six introduced stable schema paths:
JSON params/response for `OmuxOwnerAttachmentStatus`, and TypeScript
params/response, `OmuxOwnerAttachmentDisposition` and `OmuxOwnerNativeRef`.
They were observed in the saved stable output of SDK invocation
`2b4f062d-b216-4d31-a8d6-0cda7b9524cd`, whose overall batch was cancelled.
The experimental bundle contains only its compressed exports, as required by
the importer; these six paths are not expected in that tree. Readback establishes
path shape, not a passing producer, schema import, artifact or runtime receipt.
The [incident checkpoint](../../docs/agent-notes/2026-10-04-sess-omux-execution-incident.md)
retains its historical failure and hold. The [current provider-free continuation](../../docs/plans/omux-native-browser-continuation-2026-10-06.md)
resumes scoped work; this fresh candidate's production and installed gates remain
deferred until independently qualified inputs and fresh terminal receipts exist.
Obtain scoped producer evidence before import and packaging; never reuse the
cancelled batch as a successful SDK receipt. The refresh target selects these
new paths explicitly rather than handwritten schema bytes or broad globs.

Root stages a fresh manifest, product patch, base/overlay archives, validation
overlay, schema receipt and validation record only after their producers finish.
The new validation records actual counts, source/graph hashes and scoped checks;
it does not copy old pass counts. `:artifact_test` reuses the generic byte and
schema-receipt oracle against this package's own data. It is manual while staging
is incomplete; invoke it explicitly to prove this epoch.

After staging, `:restore_source --phase verify-prepared` binds the final complete
source and exact owned output links to this artifact. Use the actual new SDK
output base and `--bazel-configuration owner-linux-opt` when those links exist.
The new output root preserves the earlier fastbuild and optimized original ELFs.
Root owns the shared source archive, authority and proof scheduling.
