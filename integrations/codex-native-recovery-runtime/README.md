# Native recovery runtime epoch

This is an Omux-maintained application adapter delivery lane, not a vendor hook
waiting to be supplied. Modified application packaging is allowed when its exact
source, version, compatibility and support limits are declared. Unmodified Codex
continuity remains unsupported by the available evidence. See the separate
[adapter delivery epoch](../codex-adapter-delivery/README.md) for the next
source-only retirement repair and its remaining proof gates.

The user's authorized recovery work uses this separate, unshipped runtime data
anchor. R-N13 governs its mutation and receipt custody. It reuses the declared
runtime packaging implementation while fixing candidate inputs to
`integrations/codex-native-recovery-candidate`. Existing runtime009 and its
producer, installed P1 and source T2 receipts remain preserved. No produced
archive or passing runtime/installed receipt exists for this new package yet.

Run `:runtime_package` only through locked Nix/Bazel after the new candidate,
complete source receipt and actual selected CLI producer are ready. Supply
`--source-binary`, `--source-receipt`, `--producer-receipt` and a fresh private
`--output-directory`. The existing packaging contract retains1GiB original
streaming, explicit512MiB SDK backend,128MiB dependency limits, finite archive
bounds, source/profile equality and separate original/stripped/relocated hashes.
Every library and tool comes from the declared Nix inputs; no host lookup or SDK
execution participates in packaging.

Output filenames remain `codex-owner-runtime.tar.gz`, `runtime-manifest.json`
and `runtime-receipt.json`; their package directory distinguishes this epoch.
Keep a produced archive in a fresh owned operator output root outside Git.
Stage only publicly reviewable pinned manifest/receipt metadata after successful
production and verification. This fresh package's missing exports remain data
anchors; an outside-Git archive declaration requires its own reviewed input policy
and actual qualification before consumers can use it. Consumers must declare
this package's exact archive and tracked metadata together. Packaging proves
closed transformed bytes only; new installed discovery/resume behavior requires
fresh actual process/native-state predicates against these exact bytes.

`:public_sources` and the root public source archive exclude runtime payloads.
The [retained owner-runtime input policy](../codex-owner-runtime/README.md)
qualifies its existing pinned archive outside Git; it does not supply this fresh
recovery package's absent runtime or prove its source lineage. Fresh runtime
production, declaration/runfiles and installed gates require independent pins
and receipts. Historical archives and artifacts retain their separate custody
and digest references. No support or release claim follows from these anchors.
