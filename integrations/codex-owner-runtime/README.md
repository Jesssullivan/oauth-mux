# Declared native owner runtime proof input

The user's authorized implementation and lane resume govern this separate,
unshipped runtime proof package. R-HOOK-CONVERGENCE-20261004 and R-N13 govern
execution and receipt custody. It preserves the 164-file source candidate and original produced
SDK ELF. Packaging does not execute Codex or prove installation, native
interoperation, provider continuity or shipped support.

Run `//integrations/codex-owner-runtime:runtime_package` only through locked
Nix/Bazel. The target declares the current candidate data, strip, patchelf,
coreutils search path, CA bundle and finite Nix runtime library inputs. Supply
`--source-binary` (canonical actual `//codex-rs/cli:codex` output),
`--source-receipt` (complete verify-prepared receipt), `--producer-receipt`
(explicit current executable byte receipt) and `--output-directory` (new private
durable epoch). Input import is an explicit operator run; its physical upstream
output does not become an Omux cacheable compile action by being copied.
The library filegroup is recorded by `:runtime_files_manifest` in a generated
finite JSON response file, with canonical runfiles keys and the exact library
runfiles included. No expanded library list enters an argv element. Its parser
rejects duplicate, absolute, traversing, malformed or over-budget selections;
the executable resolves keys only against its declared runfiles tree.

The producer JSON must contain `target: //codex-rs/cli:codex`,
`configuration` equal to `owner-linux-fastbuild` or `owner-linux-opt`,
`original_sha256`, `original_bytes`,
and the exact `candidate` fields described below at top level. These fields are
matched to the current candidate validation and complete source receipt.
Use a new producer receipt; never inherit the original candidate's counts.
It also supplies `current_compile_invocation_id`,
`current_source_verification_invocation_id` and `current_source_receipt_sha256`.
These identify the fresh selected-CLI build and source readback independently
of the immutable candidate validation's original receipt IDs.
The complete source receipt's `bazel_configuration` must exactly match the
producer's allowed configuration; the manifest and external receipt bind it
as `candidate.current_configuration`. Historical validation retains its
fastbuild compile/source IDs. An optimized selected-CLI build does not prove
that all eight historical production labels or their tests ran in opt mode.

The importer streams at most 1 GiB and records the original hash and length,
strips a private copy with `--strip-all`. This SDK proof package explicitly
selects a 512 MiB backend read/parser limit; the generic portable default,
libraries, loader and CA retain their 128 MiB limit. Declared library inputs
retain their 256 MiB aggregate bound. Published payloads are bounded at 512 MiB,
compressed archives at 256 MiB, and raw tar bytes at 512 MiB plus 16 MiB of
bounded metadata/overhead. The original interpreter must be exactly the GNU x86_64
standard `/lib64/ld-linux-x86-64.so.2` or an alias of a supplied declared loader.
Only byte-identical declared loader choices are eligible; no host loader is
opened. The copy's interpreter is first relocated to that selected input.
The unchanged portable resolver then selects and relocates every ELF dependency
from the declared library files. Missing or ambiguous dependencies refuse the
package. No host library search, `ldd`, Git, account, provider or key access is
part of this tool. Linker symbol/version compatibility remains an actual
execution gate; a closed ELF dependency graph does not prove it.

Outputs are `codex-owner-runtime.tar.gz`, `runtime-manifest.json` and
`runtime-receipt.json`, plus an intent. The archive contains only `bin/codex`,
`lib/codex/libexec/codex.bin`, its loader/libraries under `lib/codex/lib/`,
the CA bundle under `lib/codex/share/` and `runtime-manifest.json`. Its SDK
launcher clears loader overrides and selects only its private packaged closure.
Original, stripped and packaged executable hashes/lengths are distinct.
Fixed phase diagnostics and the private copy's post-strip byte count identify
packaging failures without emitting SDK/tool error content. Earlier failed
output epochs remain separate; changing the strip transformation does not
change the original produced ELF or alter the generic parser bound.
The measured larger SDK requires an explicit backend role budget, recorded as
the exact integer `backend_max_bytes: 536870912` in both `runtime` and
`executable`; the consumer requires those receipt-bound values. This bound
does not apply to any dependency or change generic Omux package policy.

The manifest has schema version 1, status `native-owner-runtime-proof-candidate`,
`native_support: false`, target `x86_64-linux`, and:

- `candidate`: upstream commit, patch/base/binary-overlay/validation hashes,
  complete source inventory hash, compile and source-verification invocation IDs,
  and the current selected build configuration.
- `executable`: original, stripped and packaged SHA-256 and byte counts.
- `runtime`: exact loader, sorted dependencies, backend interpreter and CA path.
- `files`: every payload path with its SHA-256, byte count and mode; the embedded
  manifest is excluded from this map and independently receipt-bound.
- Original declared runtime input inventory, loader relocation and tool/receipt
  hashes identify the transformation inputs independently of patched outputs.

The external receipt binds the archive hash/length and embedded manifest hash,
candidate and executable identities. A consumer declares both archive and
receipt as Bazel inputs. `read_runtime_bundle(archive_path, receipt_path)` and
`verify_runtime_files(payload, receipt)` return `(manifest, files)` only after
exact receipt, tar member, byte/mode, launcher and closed ELF checks. Returned
files include the embedded manifest (mode 0644); payload modes come from
`manifest.files`. Extraction must still use exclusive owned destinations.

The retained archive is an offline operator input outside Git; its 119,923,125
bytes exceed GitHub's ordinary Git object limit. The tracked manifest and receipt
remain immutable evidence. No LFS, download, upload or public artifact service is
part of this lane. The stable archive label aliases the explicitly selected
`@omux_codex_owner_runtime` repository, whose digest-named physical input leaf
contains only `codex-owner-runtime.tar.gz`.

Root first runs the declared `//tools:codex_owner_runtime_input_copy` precursor
against the original declared input, then independently selects its successful
fresh `TEST_UNDECLARED_OUTPUTS_DIR/<archive-sha256>` leaf. This copies and qualifies
retained bytes without moving/deleting the original or establishing new artifact
provenance. Its separate receipt is byte custody only, not native acceptance. Bazel seals the
undeclared-output tree and archive to exact mode 0555 after the action finishes;
A records the earlier private 0700 leaf / 0400 archive phase. Import admission
therefore captures fresh sealed identities and never treats pre-seal stat fields
as a post-seal identity witness. The guard admits only private 0700/0400 or
observed sealed 0555/0555 leaf/archive pairs and refuses any later change.

Later retained proof uses the execution guard's explicit
`--codex-owner-runtime-directory` selector for a finite standard offline label
set. The guard verifies canonical no-follow ownership, exact fixed hash/length,
tracked metadata and held-descriptor/named-path readbacks under the original
finite deadline. An absent or changed input refuses. Ambient environment never
selects this archive. The local repository declares one inert watched archive;
the fresh consumers still verify fixed receipt/member/ELF predicates.

`:runtime_inputs`, installed native interop/discovery, and retained legacy TUI
proof are manual explicit gates. Ordinary source archives/builds omit the retained
payload; missing operator inputs leave installed gates deferred/unrun. Run
`//tools:codex_owner_runtime_input_qualification` to qualify actual declaration
and byte custody before applicable installed targets. All invocations remain
locked Nix/Bazel under the guard. The legacy manifest read is bound to its tracked
receipt source package, not the operator archive's parent.

These input policy changes preserve runtime009 and every earlier epoch. They
do not replace installed-custody predicates, establish SDK/executable/source or
channel authority, enable native support, or prove same-process/provider handoff.
The fresh recovery lane requires its own independently pinned archive/evidence.

The installed fixture uses ordinary native app-server APIs with no model or tool
turn. Its version-bound empty-history probe requires the exact `list_turns`
rejection for a newly created paginated thread. It then initializes genuine
native metadata with one `thread/name/set` call and a fixed nonpersonal fixture
label before the full `includeTurns` read. This tests native persistence through
its supported API; it never seeds SQL, constructs a rollout, or changes history
mode. Positive proof still requires unchanged native name, thread/session,
rollout path, inode and bytes across acknowledged removal, plus native SQL and
sealed Omux retirement inspection after their respective clean shutdowns.
This fixture initialization is not a product setup requirement or a proof of
accepted user turns, native resume, provider handoff or stock support.
