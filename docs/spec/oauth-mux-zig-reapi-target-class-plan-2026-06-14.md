# oauth-mux Zig REAPI Target-Class Plan

Status: Planning gate for TIN-2105, created 2026-06-14.

## Decision

`oauth-mux` is already remote-first for proof builds and tests through the
GloriousFlywheel Nix runner lanes. That is the current product validation
authority.

It is not yet countable Bazel REAPI remote execution:

- `oauth-mux` has no Bazel target graph.
- GloriousFlywheel toolchain coverage still lists Zig as absent.
- Cache hits, ARC runner placement, and GitHub Actions runner dispatch are not
  RBE evidence.

The next REAPI step is a bounded Zig target-class candidate, not a broad Bazel
migration.

## Vocabulary

```
developer laptop
  |
  | just build / just test / just check
  v
scripts/remote-validate.sh
  |
  | workflow_dispatch
  v
GloriousFlywheel tinyland-nix runner
  |
  | nix develop --command zig/just ...
  v
current oauth-mux proof

This is remote runner validation.
It is not Bazel remote execution.
```

```
Bazel client
  |
  | --remote_cache only
  v
remote cache / CAS
  |
  | cache hit returns prior outputs
  v
cache-backed build

This accelerates work.
It is not remote execution unless an executor runs an action.
```

```
Bazel client
  |
  | --remote_executor + --remote_cache
  | --remote_local_fallback=false
  | --spawn_strategy=remote
  v
GF REAPI cell
  |
  | Execute(action)
  v
remote worker process
  |
  | proof artifact:
  |   remote_processes > 0
  |   worker_image_digest
  |   force_execution=true
  v
countable RBE proof
```

## Current Authority

The current authoritative proof surfaces remain:

- `just build`
- `just test`
- `just check`
- `just e2e`
- `just remote-build`
- `just remote-test`
- `just remote-check`
- `just remote-e2e`
- `just remote-release-proof`

Those dispatch existing Zig/Just validation bodies onto the GloriousFlywheel
runner. They are the right default for PR readiness, release readiness, and
developer laptop offload until TIN-2105 lands.

## Candidate Target Class

Name: `oauth-mux-zig-build-test`

First bounded surface:

- `zig build test`
- `zig build`

Non-goals for the first candidate:

- broad Zig ecosystem claims;
- release publication authority;
- every cross-compile target;
- live provider tests;
- local dogfood install mutation;
- anything that reads real `~/.codex`, `~/.config`, Keychain, or enrolled
  account stores.

## Implementation Shape

Preferred first implementation:

1. Add a minimal Bazel graph that models only the bounded Zig proof target.
2. Use a genrule/shell wrapper around the existing Zig graph unless a stable
   `rules_zig` path is proven first.
3. Keep `.bazelrc` and `.bazelrc.flywheel` endpoint-free.
4. Use the GloriousFlywheel wrapper pattern:
   - `BAZEL_REMOTE_CACHE` from runtime environment;
   - `BAZEL_REMOTE_EXECUTOR` only in executor-backed mode;
   - `GF_BAZEL_SUBSTRATE_MODE=shared-cache-backed|executor-backed`;
   - `GF_BAZEL_REMOTE_UPLOAD=true` only for trusted lanes.
5. In executor-backed proof, require:
   - `--remote_local_fallback=false`;
   - `--spawn_strategy=remote`;
   - forced execution or nonce perturbation so the proof cannot be cache-only;
   - `remote_processes > 0`;
   - captured `worker_image_digest`;
   - no ambient secrets, account homes, or host-local state.

`rules_zig` remains a later decision. Prior Zig RBE research (TIN-1264) found
the current ecosystem too unstable to adopt as a broad dependency without a
maintenance decision.

## Promotion Gate

TIN-2105 is complete only when a forced GloriousFlywheel proof artifact cites:

- workflow run id;
- artifact id;
- target label;
- Bazel command;
- `remote_processes > 0`;
- `worker_image_digest`;
- executor endpoint attached;
- cache endpoint attached;
- `force_execution=true` or equivalent no-cache-hit proof;
- no local fallback.

Only after that proof should GloriousFlywheel target-class eligibility mention
`oauth-mux-zig-build-test`.

## Spoke Proof Dispatch

`oauth-mux` now has spoke-side helpers for the next proof gate:

```bash
just flywheel-zig-proof-dispatch --image-digest sha256:<gf-reapi-cell-digest>
just flywheel-zig-proof-verify <run-id> --image-digest sha256:<gf-reapi-cell-digest>
```

The dispatch helper calls GloriousFlywheel's `gf-reapi-cell-proof.yml` with:

- `consumer_repository=Jesssullivan/oauth-mux`
- `workspace_path=consumer-workspace`
- `target=//:zig_build_test`
- `bazel_command=build`
- `force_execution=true`
- `apply=true` for the Linux proof endpoint

The verifier helper delegates to GloriousFlywheel's
`download-gf-reapi-proof-artifact.sh` and requires forced execution,
`gloriousflywheel-rbe-linux-x86_64`, the expected target, and the expected
worker image digest when supplied.

These scripts are convenience wrappers only. The proof authority remains the
GloriousFlywheel artifact verifier and `proof-result.json`. Dispatching a
workflow, seeing a cache hit, or passing oauth-mux's normal hosted CI still
does not count as REAPI eligibility.

## Risk Controls

- Do not replace current Just/Nix remote proof lanes before the target class is
  proved.
- Do not put remote endpoints, credentials, cache upload authority, or auth
  headers in checked-in `.bazelrc`, workflow YAML defaults, docs examples, or
  Justfile defaults.
- Do not claim `oauth-mux` has Bazel RBE because it runs on `tinyland-nix`.
- Do not call a cache hit remote execution.
- Do not include live OAuth account stores in REAPI action inputs.

## Workstreams

| Step | Modules touched | Depends on |
| --- | --- | --- |
| Design contract | `docs/spec/` | - |
| Bazel candidate graph | repo root build metadata, `scripts/` | Design contract |
| GloriousFlywheel proof dispatch | GloriousFlywheel proof lane | Bazel candidate graph |
| Target-class promotion | GloriousFlywheel eligibility manifest | Successful forced proof |
| oauth-mux docs update | `docs/`, `AGENTS.md` if needed | Target-class promotion |

Sequential implementation is recommended for the first candidate. The work
crosses build metadata and proof authority, so parallel worktrees would mostly
increase merge and claim-drift risk.
