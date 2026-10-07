# Candidate site tool input repository

Authority: October 5 authorized implementation, AGENTS.md and R-HOOK-CONVERGENCE-20261004. Sources: `tools/cached_site_repository.bzl` and `tools/cached_site_input_validator.py`. Root owns graph wiring and execution admission.

The repository accepts an explicit operator inventory path and expected SHA256 plus the already realized host bootstrap closure. It uses bootstrap Python only to validate digest, schema/claim boundaries, roots and complete references, then uses the existing guarded `nix_file_inventory.py` to enumerate candidate closure files. Candidate Node, PNPM and Chromium never execute during repository setup. All aliases must remain inside the declared immutable graph.

Generated public labels include the original inventory, candidate metadata, store paths, full closure, Node closure, browser closure and explicit Node/Chromium executable input paths. Candidate metadata explicitly records pending NAR and shared-selection qualification. This repository supplies declared files; it fabricates neither a Nix linkFarm nor a proof receipt. A separately admitted byte verifier and source-qualified mapping evaluator precede browser evidence.

Inputs can use attributes `inventory_path`, `inventory_sha256`, `bootstrap_closure`, or corresponding `OMUX_SITE_INVENTORY`, `OMUX_SITE_INVENTORY_SHA256`, `OMUX_BAZEL_BOOTSTRAP_CLOSURE`. Validator source/dependency and guarded enumerator labels must be declared by root. Operator paths remain external to product source. No module/BUILD changes, execution, imports or browser acceptance were performed by this workstream.

After root reported the prior epoch finished, the NAR serializer was isolated from system/user Nix configuration using a private HOME/config directory and empty NIX configuration/path variables. The source mapper explicitly selects empty configuration/overlays. These changes remain unrun until the next contained epoch.
