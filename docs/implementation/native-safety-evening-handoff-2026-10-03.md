# Native safety evening handoff

Paused at the user's request for lunch and manual evening resumption. This handoff
preserves unfinished work; it does not complete the sprint or dispatch a future
job. The original five-hour checkpoint was `2026-10-03T15:07:56Z` and remains
historically partial. See the [checkpoint ledger](../../.goal/omux-native-safety-2026-10-03.json)
for execution state and [full evidence](native-safety-evidence-2026-10-03.md)
for exact successful, failed and unknown receipts.
The ledger's checkpoint status remains `in_progress` because acceptance is
unfinished; its separate execution state records the user-requested pause.

## Start here on resumption

1. Read this file, the checkpoint ledger, `AGENTS.md` and the
   [active reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md).
   This is a historical lunch checkpoint. Its resumption was completed by the
   saved evening sprint; the [current admission ledger](../../.goal/omux-native-admission-2026-10-04.json)
   owns the active goal. Retain the original checkpoint and the separate
   [weekend milestones](../../.goal/omux-weekend-2026-10-02.json).
2. Confirm the dirty runtime and SPA branches below. Do not reset, stash,
   overwrite or broadly commit the existing rewrite. No new interview is
   necessary for priority or host roles.
3. These lunch resumption priorities were superseded by the saved evening
   checkpoint and the [active admission sprint](../plans/omux-native-admission-sprint-2026-10-04.md).
   Begin with whole-snapshot admission while the GF-owned PZM lane is held.
   Reuse the existing
   workers rather than exceeding the authorized twelve GPT-6.1 Sol workers.
   All workers finished or froze their assigned code; no worker-owned host
   jobs remain. Check live sessions before dispatching new work.

## Product and scope

Ordinary applications launch normally. Supported integrations must preserve
the same process, native history, tools and approval authority during account
handoff. Never replay accepted work. Wrapper launch, restart and synthetic
admission are not the product success metric.

Codex stock native-hook/live proof remains missing. Browser production exports,
provider renewal/adoption/revoke, native installation/service/desktop promotion
and provider-backed continuity remain unfinished. No provider evaluation or
spending resource was supplied. Reliability targets exist, but achieved SLOs
and a staffed or contractual SLA are not claimed. Nothing was published.

PZM is the intended Darwin compiler host through the lab REAPI lane, currently
GF-held under `gf-core-adoption-orchestration`, TIN-2998/GF#1717, with
`startServices=false`. Neo is the teletype and an authorized read-only source for ASFW/FireWire, cmux and
Legalab patterns. Do not resume Neo compilation or use a manual PZM SSH compiler.
Sting and Yoga remain the named Linux hosts; Yoga's earlier SSH-trust gap was
not changed. Every project execution uses locked Nix through Bazel/Bazelisk;
Justfile examples are reference material, not restored Omux entrypoints.

## Workstreams and priorities

| Workstream | Current fact | Next work / custody |
| --- | --- | --- |
| PZM REAPI, external readiness gate | Endpoint-free Darwin profile and preceding exact closure/declared-input analysis receipts retain their scopes. PZM remains GF-held; separate Nix repair reports do not prove REAPI readiness. | GF owns release prerequisites and operator binding. Rebuild current-source analysis and verify registration/selected worker before any authorized remote-only dispatch; local admission work proceeds first. |
| Request and mutation authority | Durable bounded identity/idempotency fences and actual client/CLI reconciliation passed. TIN-5337 is Done only for its recorded bounded component. | Preserve fences, two-attempt budget and original operation IDs. Long-term ledger retirement and live adapter proof remain separate work. |
| Recovery and socket custody | SQLite-only rollback fence, strict XDG ownership and singleton gates passed. | TIN-5336/TIN-5335 remain broader In Progress. Full-user rollback and service/platform promotion are excluded. |
| Vault and installation | Current Linux local installed/relocation tests passed. Dedicated Sting passed earlier exact artifact; private macOS C Keychain driver passed. | TIN-5340 remains In Progress. PZM app/archive proof precedes installed Darwin/service/UI gates; personal vaults stay untouched. |
| Observability | Bounded typed observations and redacted health passed; no provider/source IO from health/export. | TIN-5342 remains In Progress. Availability denominators, durable measurements and achieved SLOs need separate evidence. |
| Reference and SPA | Source-derived bundle and five applicable SPA gates passed; no deployment. | Keep API/CLI/capability facts producer-derived. Regenerate only for actual public contract changes. |
| Tracker and claim review | NS5 and broader issue states/owners/dependencies/dates preserved. | `sprint_linear` owns append-only receipts/readbacks; no blanket Done or support promotion. |

## Execution inputs and exact receipts

The runtime checkout is `/srv/fast-local/jess/git/oauth-mux`, branch
`codex/omux-native-reset`, baseline `f5f83c1ad99c2920de6759791b327a99a02a2ec5`.
The SPA is `/srv/fast-local/jess/git/omux.xoxd.ai`, branch
`feature/native-account-custody-reference`. Both dirty workspaces are retained.
Git staging state also remains intact; the new source is experimental and unshipped.

Locked versions: Zig 0.17.0 and Omux's Bazel 9.0.1. Neo's inspected Legalab
consumer pins 9.2.0; do not attribute that version to Omux.

```sh
nix develop --ignore-environment --keep HOME --command bazelisk \
  --nosystem_rc --nohome_rc \
  --output_user_root=/srv/fast-local/jess/state/codex/omux-bazel9-native-proof-20261003 \
  test //... --keep_going --jobs=4 --test_output=errors
```

Final full test: `402bfcc8-0e1f-4725-9a08-806a69cc8f85`, 54 passed,
zero skipped/failing, nine fresh and 45 locally cached. Full build:
`133a5eb0-8d62-4199-a81b-5896c03486e0`, 96 targets passed.
Pause documentation gates `6788d3f5-72a4-4d73-84a4-938ed36f09bf` passed
both targets; runtime and SPA whitespace checks also passed.
Local current archive verification `60d57b35-8c2c-4a4e-b791-88665e7875c9`:
SHA256 `1c25304f169166ef04c71fc61c471b2c57d59f23a6bbad0b29b9c4976f46728d`,
59,741,056 bytes, 138 artifacts. Dedicated Sting's `0be0a6...` source and
`a49ad0...` artifact remain a separate prior epoch, not a remote receipt for
the new archive. Its current workspace was removed.

The exact matched Darwin execution closure is
`/nix/store/9k958iwyvk7cn5f7axdfg8a0j1s0nsa1-omux-bazel-closure`.
Offline resolution `98d7e583-d2e9-414c-8f7b-4ab90c97ae39` matches Neo
metadata `07635590-fc14-4fda-871a-6fd54d0fb8b1`: system `aarch64-darwin`,
SDK 14.4, native SHA256
`fdfeb78902a8fb28d2e7cff6c4516558c9b0b5e9c4b154b2981a49e561b25087`.
The [evidence](native-safety-evidence-2026-10-03.md) records full manifest,
store-path and registration hashes. This is identity metadata, not import or
worker readiness. Do not substitute either of the other discovered closures.

`@omux_host` owns declared Linux coordinator Nix/SSH/Python/Bash. These inputs
stay outside the application runtime. `OMUX_BAZEL_BOOTSTRAP_CLOSURE` selects
local repository setup; `OMUX_BAZEL_CLOSURE` selects the execution closure.
At the lunch-checkpoint epoch, local wrapper variables were absent under
`a0c6e539-874b-44c8-bfbf-d2d7b5614ea4`; other operator contexts were not tested.
These observations do not establish current route availability. Operator binding,
host transport and dispatch remain held pending GF's explicit release and
applicable authorization. Current-source analysis may verify declared Darwin
tools and submitted `nix_closure` properties, with no `@omux_host` tools in
product actions. Independent selected-worker evidence must establish actual
routing. Any subsequently authorized execution uses `--config=darwin-reapi` and
`--config=reapi-proof`, without local fallback and with one job. Record actual
action/cache provenance, artifact hash/bytes and cleanup separately.

The Bazel 9 launcher correction handles root `./` locations and external
runfiles aliases. Source review found a remaining generic limitation for future
compound arguments with overlapping declared filenames; current metadata
inputs are distinct plain locations. Keep that issue bounded until such an
argument is needed.

## Unknown custody and completed cleanup

Interrupted Neo proof `2acf30f9-a1df-4a57-9231-ad2ee195299e`, orchestration
`f56bfe97-7da6-4a5e-804c-a8880220d451`, exited locally 130. Remote graph,
artifact, log and `.run-U1ZLg7kn` cleanup remain unknown. The exact local SSH
scan `558961a5-b1d4-4a3d-b0bd-6f28c2ae2bfa` found no matching process and
sent no signals; it does not prove remote cleanup. No host jobs are claimed
active or clean from that observation.

The old Sting `faf6...` workspace remains unidentified after a bounded no-match
lookup. Do not adopt an arbitrary directory, extend identity guesses, delete
the purpose base or infer success. All four identified earlier Neo workspaces
were removed with exact receipts. Historical failures retain their original
cause, limit and unknown fields.

Three clean superseded worktrees were removed without force, preserving
branches and their unique commits: release hardening `fb76a558...`, redacted
route state `f3bd4d2...`, cassette `87d37c3...`. The runtime now has only the
active native-reset worktree; the SPA already had only its active worktree.
No stale public `.tmp`, `.bak` or `.orig` files were found. Historical doc
references remain inert; no active native-reference dangling links were found.

Operational follow-up remains: rotate the DNS API key previously exposed in
tool output by an inherited environment. No value is retained in this handoff
or repository. Subsequent proof invocations use a minimal inherited environment;
rotation was not performed.

Final pause bookkeeping and documentation checks are recorded in the
[checkpoint ledger](../../.goal/omux-native-safety-2026-10-03.json) and
[Linear receipt](../tracker-updates/native-safety-sprint-2026-10-03.md).
Evening resumption is manual; no timer or automatic dispatch was installed.
