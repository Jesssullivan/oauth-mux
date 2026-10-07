# Tool custody for upstream Codex validation

The Omux runtime uses the default flake shell and locked Bazel 9.0.1. The separate
upstream Codex source checks use the audited Linux shell:

```sh
nix develop /path/to/oauth-mux#codex-upstream --command bazelisk build <upstream-targets>
nix develop /path/to/oauth-mux#codex-upstream --command bazelisk test <upstream-targets>
```

Run these commands in the upstream checkout, substituting this repository's path,
or enter this shell and then change to that checkout. The shell provides
Bazel 9.0.1 and a supplemental Bazel rc file. Its `--distdir` points to immutable
Nix fixed-output downloads matching the original upstream repository hashes;
its test `PATH` contains only the declared Nix shell tools. This preserves the
official upstream compiler archives, repository rules and target semantics.
`OMUX_CODEX_TOOL_ARCHIVES`, `OMUX_CODEX_BAZELRC` and `OMUX_CODEX_TEST_PATH` expose
those inputs for inspection.

[codex_upstream_archives.json](codex_upstream_archives.json) records the exact
URLs and SHA-256 digests observed in the x86_64 Linux validation graph: Rust
1.95.0 compiler, standard library, Cargo, Clippy and rustfmt; LLVM 22.1.8 compiler
and source archives plus its generator extras; bindgen, toml2json and the graph's
CPython interpreter, GNU 2.28 headers and Linux 6.17.13 UAPI headers. The flake
realizes all thirteen archives before entering
this dedicated shell. Its `codex-upstream-tool-archives` package exports the same
directory independently.

The owner candidate's explicit `//codex-rs/core:owner-linux` platform retains
the upstream GNU 2.28 ABI and selects the pinned Linux 6.17 header profile.
Select it with `--platforms=//codex-rs/core:owner-linux` for owner proof.
This is build input custody, not a running-kernel claim. Runtime checks require
the verified pidfs/namespace profile and refuse unsupported kernels; older
header profiles compile closed stubs. No host include directory is substituted.

This is an audited input set for that graph. Other platforms, optional nightly
toolchains and additional lint tools require their own entries before use.
Upstream `scripts/format.py` can fetch DotSlash tools independently of Bazel;
the distdir does not cover those downloads. Source dependencies and generated
tools retain the upstream locked Bazel graph as their authority. Providing the
archives does not establish a complete cold-cache, network-free upstream build,
an installed Codex runtime, or a live provider handoff proof.
