# Cached NAR byte-verification action

Authority: October 5 authorized implementation, runtime AGENTS.md and R-HOOK-CONVERGENCE-20261004. Sources: `tools/verify_cached_nars.py` and `tools/verify_cached_nars_test.py`. Root owns declared target wiring and execution.

Input contract: explicitly supplied cached inventory file, its expected exact-byte SHA256 and a pinned executable resolving into `/nix/store`. Each inventory row names an already present path with recorded NAR SHA256, NAR size and complete references. Before execution the helper validates the input digest, graph completeness, unique paths and aggregate expected byte budget. The fixed command is `nix --extra-experimental-features nix-command --store dummy:// nar dump-path PATH`; it never queries the daemon, resolves dependencies or realizes paths. No ambient PATH or Nix configuration is forwarded.

NAR output is streamed into SHA256 and a byte count, discarded immediately, and compared to registered metadata. Stderr is discarded. Bounds are 4,096 paths, 16 GiB aggregate NAR bytes, 120 seconds per path and 600 seconds overall. Every subprocess owns a process group and receives unconditional kill/wait cleanup, including interruption. Public failures contain no raw tool diagnostics. A success receipt binds the inventory SHA256 and reports byte verification, while explicitly leaving flake mapping and realization unproved.

Unit sources cover digest mismatch, graph gaps, excessive byte totals, NAR hash encodings, same-size corruption, truncation and claim boundaries. No executable, build or test was run by this workstream. Live cached inventory, pinned flake-to-tool mapping, actual NAR serialization and installed Chromium remain separate unrun gates until root executes their declared actions under containment.
