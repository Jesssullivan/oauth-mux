# oauth-mux Authority Map

This map separates immutable product intent, active unshipped design, shipped
truth, implementation, and evidence. GitHub #463 and Linear TIN-2057 track the
v0.2 program; trackers coordinate work but do not override repository authority.

## Authority Order

1. `AGENTS.md` - repository operating rules and authority order.
2. `docs/spec/broker-mcp-contract-2026-05-03.md` - immutable product anchor: a
   managed harness stays in the same process and hands off without prompting.
3. `docs/plans/oauth-mux-v0.2-full-broker-foss-program-2026-07-11.md` - active
   v0.2 design authority. It is future/unshipped until golden proof.
4. `docs/plans/oauth-mux-v0.2-deletion-ledger-2026-07-11.md` - normative removal
   order and preservation gates for the v0.2 reset.
5. `docs/security/omux-v0.2-threat-model-2026-07-11.md` - managed sidecar,
   credential, memory, local-state, evidence, and supply-chain boundaries.
6. `docs/spec/managed-harness-jsonrpc-v2.md` - generated, declaration-only
   process-adapter compatibility contract. Its methods remain unimplemented.
7. `docs/spec/codex-adapter-contract-2026-05-03.md` and
   `docs/spec/harness-session-authority-bridge-2026-05-05.md` - shipped Codex
   adapter/session constraints where they do not conflict with the v0.2 program.
8. `CHANGELOG.md`, release tags, and committed evidence - shipped claim truth.
   A plan can supersede direction but cannot retroactively broaden or erase it.
9. `justfile` - operator entrypoint and remote-proof authority.
10. `README.md` - public summary, subordinate to contracts and shipped evidence.
11. `build.zig.zon` plus the Zig release graph - the human-edited version and
   product/release-semantics authority.
12. Generated, checked `release-manifest.json` - the projection
    consumed by packaging, installers, Nix, Homebrew, Bazel, and
    GloriousFlywheel. Consumers may not duplicate its version or target graph.
13. `flake.nix`, packaging scripts, and `src/` - implementation subordinate to
    the release graph and shipped evidence.

## Evidence Rules

- `docs/evidence/` and `test/evidence/` are immutable claim-bounded records.
- Synthetic, schema-only, local, and live evidence remain distinct. A narrower
  artifact cannot satisfy a broader acceptance gate.
- Remote GloriousFlywheel lanes are required completion proof. Local checks are
  debugging or cheap documentation hygiene only.
- Current stable behavior is v0.1.15. v0.2 plans and prereleases remain unshipped
  until the program's golden gate passes.

## Superseded Inputs

The following are useful historical inputs but no longer active design
authority and are pending sequenced deletion under the ledger:

- `docs/spec/model-quota-granularity-2026-07-03.md`;
- `docs/spec/stay-afloat-valet-and-browser-evidence-2026-07-09.md`;
- `docs/spec/claude-managed-hotswap-experiment-2026-07-14.md`;
- runtime-daemon, supervisor/restart, prepared-fallback, federation, and FFI
  plans that conflict with the full-broker program.

When sources disagree, preserve shipped evidence, follow the immutable product
anchor, then apply the v0.2 program. Do not resolve conflict by claiming planned
behavior has shipped.
