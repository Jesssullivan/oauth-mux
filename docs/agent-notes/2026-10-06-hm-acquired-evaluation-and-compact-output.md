# Retained HM pair: evaluator and compact-output preparation

Authority: root's October 6 source-only assignment, repository `AGENTS.md`, R-N13.
Root applied the reviewed source/graph patch on October6 after native7b0b
became terminal. Modeled tests, actual compact packing and genuine evaluation
remain unrun for this source epoch.
The shared evaluator's 24 and acquired evaluator's 25 modeled methods passed
in root's bd16 epoch. They do not prove genuine Home Manager evaluation.

The reviewed source artifact is recorded as the source path
`docs/agent-notes/2026-10-06-hm-acquired-evaluation-source.patch`.
It defines `//tools:home_manager_retained_bundle_producer`,
`//tools:home_manager_acquired_evaluation` and separate retained-input/bundle
repositories, with no acquisition or artifact producer dependency. Every regular
source byte becomes an explicit data file; source directory and link records
remain inert in the complete inventory. Every artifact payload listed in its
manifest, plus `release-manifest.json` and `SHA256SUMS`, becomes a data file.
The one-time bundle producer derives regular inputs from declared runfile
aliases and inventory metadata, verifies them before and after packing, and
outputs one bundle plus its bounded receipt. Root then independently freezes
that output for a separate consumer. The genuine target declares only the
compact bundle/receipt, lock, five modules and tool closures. It reconstructs
readonly private roots and reuses the fresh tree/NAR/custody evaluator.
No retained host root appears in either target's argv or compact consumer
layout. No producer rebuild edge, alternate path, ambient input, provider,
daemon or fetch fallback is introduced. The revised artifact contains the
complete two-helper implementation, repository/BUILD declarations and 21
modeled bundle test methods. Independent security/declaration reviews cleared
the revised source proposal after Starlark corrections. Root applied it;
execution remains unrun. Source review cannot establish evaluation success.

## Selected acquisition and its failed wrapper

Root reported actual producer completion in 617.128 seconds in epoch
`e3b9e0bc-f473-49f5-be46-4f23e2776a1f`. The enclosing Bazel test then timed out
at 900 seconds while `test-setup.sh` enumerated roughly 95,000 undeclared output
nodes with per-file `stat` and `file` subprocesses. Controller/workload exits
remain **3/3**, descendants empty is **true**, and controller failure is null.
Raw controller receipt SHA256 is
`3356a5660fd73954d33253ec929957c4c47212036280de6c2a4de2ce6eb566f0`.
This is a failed Bazel test, separately containing a completed acquisition;
neither fact overwrites the other.

The retained physical root is fixed in the patch. Root independently selected
receipt SHA256
`9e9c04f6768b4ba7ac4023f54c5ae98c5a585da1642a3fca9c0c153d8a1c30eb`.
The actual 747-byte receipt names inventory SHA256
`30b2378513bd73a09ffccf3874190ea0e086c0dc3a5cf1668a761e593b5ddade`
and lock SHA256
`050163ea4edc9a50401bb320ac12626cc2aae68318f98fe6030fe1402b10437d`.
Inventory size reported by root is 8,389,707 bytes; ordinary inspection finds
57,112 regular records and three inert link records. The frozen source NARs are:

| Source | Revision | NAR | Bytes |
| --- | --- | --- | ---: |
| home-manager | `65258d5c65a250189fde2e35f490d15e064c4c62` | `sha256-Sxu1NLTD/Ern6hFGLlZmtKCSct3YQXZI/lls8RE1XeM=` | 7,125,936 |
| nixpkgs | `a9e6d84f9c2f9012f5fe7d964a7851352300e61a` | `sha256-WncT27+3BOkgTaJZLnCsf3LcYf9RXMuR9ONSN4rzQ7s=` | 206,239,824 |

`verify_acquired_pair()` requires an independently selected receipt SHA, the
matching lock/inventory, exact pins, and fresh physical byte/NAR/custody proof.
It has no producer-exit or controller-exit predicate. Independently validating
this retained failed-wrapper artifact is therefore permitted by its existing
contract. The wrapper failure must accompany resulting evidence explicitly.
The acquisition report is context, not replacement authority for actual bytes.

## Artifact selection and evaluator gates

The patch retains artifact receipt
`aa9c9f0c5808da597294b04d59f1e7111567145e1c3f2790fff07c5e670e2ae8`
for archive
`937936f3011ac4177bfa38ef808223103d6b72768a1d922e1c8982c7981fcc1c`.
Its physical root is copied verbatim from the existing integrated delivery
receipt. Its source remains caller-declared dirty development revision
`f5f83c1ad99c2920de6759791b327a99a02a2ec5`, full Qt, Linux x86_64.
Manifest SHA is
`144e8993c9604d9852cbd50a5d6eb9a0a2b1bff8591ebc81ca8b759adfd12b1d`;
artifact NAR is `sha256-/26p+DxGzgVYvB786/qezWrTb5CkJW6ApNuLE/BNSJA=`.
No current-source/release or compiled-source binding follows from this tuple.

Required declared executable input is raw
`@omux_eval_host//:executables/nix`, resolving to the existing native pin
`/nix/store/fphbr6vvc2fdmx02nkagnbx0nv04f709-nix-2.34.6/bin/nix`;
`@omux_eval_host//:all_tools` supplies its full locked closure. The current
Python test rule separately supplies its locked Python/Bash closure. Lab's
exact lock and all five listed Nix modules are explicit data. Each proposed
main and its imported Python sources are listed explicitly in the patch. No
unqualified native executable is selected.

Before applying, root must retain bounded nofollow regular-file qualification
of receipt/inventory/manifest metadata and exclusive custody during repository
setup. Starlark cannot establish all owner/mode/link-count predicates. The
repository rejects linked regular declarations and nonlocal source link targets;
it never resolves the three inert source link targets. The fresh action remains
the independent byte proof. No action may inherit the artifact producer's old
test success or treat metadata-only declaration as a NAR proof.

The proposed actions are manual, Linux x86_64, no-remote/no-cache, Bazel long,
standard contained PrivateNetwork with unchanged resource/mask/controller
policy and inherited `OMUX_EXECUTION_GUARD`. It invokes the existing offline
dummy-store evaluator with no builders, substituters or IFD. Its original
900-second inner deadline must enclose unpack, preparation, evaluation,
verification and owned cleanup. The unapplied core seam accepts the wrapper's
original absolute deadline and rejects expired/overlong/nonfinite values;
it does not start another 900 seconds after unpack. The
the subprocess keeps 60 seconds maximum work with its five-second cleanup
reserve inside that bound. No deadline increase is proposed. The evaluator's
private unpack/copy tree is removed before test completion and no source tree
is emitted as an undeclared output. Retained-input producer analysis/runfile
setup for 57,112 source inputs and consumer unpack/fsync cost still require
measurement under existing limits. Exact native executable pins currently
constrain execution to a qualified locked host closure; portable byte inputs
do not by themselves establish a ready RBE service or another host.

Success proves only `genuineModule`, `activationUnproved`, `bytesUnverified`,
`witnessScope`, `manifestBound` and `recordGenerated`, plus fresh before/after
byte and custody predicates. Generated activation bytes remain unrealized and
unverified; service activation, fleet delivery, native continuity, release
provenance and compiled-source binding remain unproved.

## Future fresh-acquisition compact-output correction (unimplemented)

Adding an archive beside the currently published directory does not solve
collection: the old directory remains under `TEST_UNDECLARED_OUTPUTS_DIR`.
The minimal producer correction must move its actual publication destination
under the existing private worker, publish one compact bundle to undeclared
outputs, then clean the worker's retained tree before returning. Keep the
existing four fsync workers, one writer, per-file fsync, all source/publication
NAR and custody checks, source600/overall1200 and enclosing action900/guard1200
limits unchanged. Remaining-time refusal must precede any new stage; source
deadlines must not be reset.

For future fresh acquisition, the exact proposed source seam in `run()` is:

```python
with private_worker(scratch_anchor) as worker:
    os.mkdir("publication", 0o700, dir_fd=worker.fd)
    with HeldDirectory(worker.path / "publication", parent_anchor=worker) as retained:
        report = produce(nix, ca, lock_bytes, locked, worker, retained)
        # NEW helper; must be implemented/reviewed/tested before applying.
        compact = pack_pair(retained.path / "home-manager-pair", lock_bytes,
                            report["receiptSha256"], output_anchor,
                            original_action_deadline)
```

This is a specification seam, not an executable patch: `pack_pair` and original
action-deadline plumbing are not implemented. `produce_held` currently selects
its 1200-second deadline internally; the new interface must receive one
start-selected bound clipped to the enclosing action with cleanup reserve.
Publication reports must identify the original private source location as
temporary and the bundle as the retained output, avoiding claims of persistent
source directories after worker cleanup.

Proposed helper API:

```python
pack_pair(pair_root, lock_bytes, trusted_receipt_sha256, output_parent, deadline)
unpack_pair(bundle_path, trusted_bundle_sha256, trusted_receipt_sha256,
            lock_bytes, private_parent, deadline)
```

The e3b9 one-time importer instead reads only declared file aliases from
`layout.json`, derives names from pinned inventory/manifest and retains each
input's alias, descriptor facts and before/after commitment. It must serialize
declared NAR nodes with a nofollow regular opener; it cannot discover additional
files from a retained host directory. Importer receipt verification preserves
the three inert source links and exact closed artifact file set.

Use a versioned, deterministic single regular-file format, for example
`OMUX-HM-PAIR-1\n`, followed by little-endian uint64 receipt length and exact
receipt bytes, uint64 inventory length and exact inventory bytes, uint64 artifact
receipt length and exact bytes, uint64 artifact descriptor length and exact
closed directory/regular-node metadata, then regular payloads in fixed
source-name and UTF-8 path order followed by artifact payloads. Sizes, executable bits,
directory names and link targets come only from the authenticated inventory;
links have no payload and are never followed. Artifact bytes reside in the
same bundle; genuine consumption has no retained artifact root dependency.
No general archive extraction,
PAX headers, duplicate paths, hardlinks, device files, implicit parent creation,
traversal or external link target is accepted. Receipt <=64 KiB, inventory
<=64 MiB, all existing node/depth/file/tree budgets and one original deadline
bound both helpers. Reject short data, growth and any trailing byte.

Packing holds the original nofollow root/descriptors and metadata witnesses,
independently verifies the pair before and after streaming all regular bytes,
computes a bundle SHA256/size, fsyncs a uniquely created private output file,
seals it readonly, then uses exact owned publication/readback. Its finite receipt
records original pair SHA and the compact bundle SHA/size plus the source
wrapper's actual failed or passing provenance. The old acquisition receipts
and failures are not rewritten. Repacking e3b9 is a separate fresh contained
action and must not claim to be a new source acquisition.

Unpacking independently authenticates the complete bundle SHA, pair receipt
and inventory binding before admitting evaluation. It creates an exclusive
0700 worker directory; validates every descriptor and parent; uses held
descriptor-relative O_NOFOLLOW/O_EXCL file writes with original per-file fsync
and modes; installs inert links without traversing them; seals directories
bottom-up; fsyncs and rechecks ownership before accepting the reconstructed
pair and artifact. Actual reconstructed NAR/custody verification remains mandatory before
and after evaluation. Cleanup follows only held ownership. The target declares
the bundle and its independently selected receipt,
five modules, exact lock and locked tool closures; no producer rebuild edge.
No reconstructed tree becomes an undeclared output. The wrapper must reserve
owned cleanup within its original enclosing deadline; it cannot reuse the
current `private_worker`'s fresh `monotonic()+60` restoration bound as an
extension. The reviewed one-time importer now proposes that cleanup/deadline
interface and materializer tests. Its application, contained regression gates,
actual compact packing and genuine consumer are still required. The future
fresh-acquisition publication seam above remains unimplemented.

This reduces Bazel's collector to a few regular files. Pack/unpack/cleanup cost
within the original action budget is an unmeasured gate; no timer expansion,
weakened durability or successful-evaluation claim is authorized by this note.
Required modeled tests cover exact roundtrip/NAR, inert links and ordering,
receipt/bundle drift, unsupported special files and escapes, short/trailing or
oversize data, ownership/replacement/close failures, original deadline expiry,
fd/worker cleanup and refusal to report success after failed publication.
