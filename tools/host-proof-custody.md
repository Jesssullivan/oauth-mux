# Explicit host proof tools

Current execution status (October 5, 2026): `//tools:host_probe` remains the
read-only host readiness probe. `//tools:deployed_fixture` and the legacy host
graph worker fail closed with `unsupported-execution-capability` before source
transfer, SSH transport, Nix bootstrap, custody mutation or graph launch. This
includes historical diagnosis, cleanup and recovery recipes: their bootstrap
also lacks verified aggregate containment. Generic permission, a process group,
or a caller timeout does not establish that capability.

Local execution uses the declared execution guard and its verified,
bootstrap-inclusive aggregate memory/process limits, exclusive ownership,
deadline, cancellation and descendant cleanup. Remote execution remains held
until an equivalent declared lane is implemented and verified; this is a missing
execution capability, not an additional user approval requirement. The current
guard scope is recorded in the [integrated delivery plan](../docs/plans/omux-integrated-delivery-sprint-2026-10-05.md)
and implemented by [execution_guard.py](execution_guard.py).

The remainder of this document records historical custody design and receipt
interpretation. It is not current operator guidance to dispatch those recipes.
Historical receipts and the parsing helpers retain their original scope.

## Historical custody design

`//tools:host_probe` and `//tools:deployed_fixture` were manual Bazel run targets.
Ordinary tests never contact a host. The SSH executable and its transitive
closure come from the locked Nix flake. Operator host addresses, identities,
agent access and existing host trust remain in the operator's SSH configuration.
The tools do not enroll a host key, forward an agent, print SSH configuration,
or read authentication material.

Direct SSH graph recipes are limited to the named Linux hosts. Darwin
compilation and vault tests use PZM through the declared REAPI action graph;
the former `darwin-build` and `darwin-vault` SSH recipes are rejected before
source transfer or execution. Neo remains the teletype and read-only recipe
source, with the separately authorized fixed historical diagnosis and cleanup
operations below. Historical Darwin receipts retain their original scope.

Readiness checks report only platform, architecture, Nix/store availability and
bounded failure categories. Absence of a literal Host stanza does not prevent a
probe: existing Include files, DNS and normal SSH resolution still apply.

On Linux the locked GSSAPI OpenSSH variant recognizes distro GSSAPI policy.
The current operator's public distro policy also names two ML-KEM/NIST hybrids
absent from that release. A temporary private derived configuration replaces
that affected KEX list with the already-permitted, PQ-first subset
`mlkem768x25519-sha256,curve25519-sha256`. Every other system line is preserved;
the existing user configuration is included first and remains authoritative.
No source configuration or global host configuration is modified.

Derivation permits only bounded, root-owned, publicly readable, nonwritable
system SSH/crypto-policy files. It rejects recursive includes, paths outside
public policy roots and unexpected symlinks. The one explicit symlink exception
is the public DEFAULT crypto-policy file installed by this distro. A missing
subset or a relative KEX modifier fails closed. The pure policy tests exercise
the narrowing and preservation predicates without contacting any host.

The deployed runner accepts a declared public-source gzip archive, verifies
its root graph files, rejects traversal, private-state directories, repeated
members, symlinks and special entries, and bounds compressed/extracted bytes.
It stages a private durable user-state child with separate XDG state and
runtime paths. Linux uses `${XDG_STATE_HOME:-$HOME/.local/state}/omux-proof`;
Darwin uses `$HOME/Library/Application Support/OmuxProof`. The base and child
must already have private ownership/mode, or be created privately. Existing
ancestors must be non-symlink directories owned by root or the current user,
without group/world write access. Unsafe existing directories are rejected,
never chmod-adopted. A pinned isolated Python validator repeats the metadata
checks before graph execution. Existing HOME remains intact. It removes the
staging directory on shell exit. On Linux it runs the selected fixed graph
entrypoint through `nix develop --command ... bazelisk` on that host. Darwin
diagnosis and cleanup use the declared interpreter and bounded custody helpers,
and exit before the graph worker invocation.
The host Bazel invocation uses batch mode and a workspace-private output user
root, so orchestration leaves no resident Bazel server or personal Bazel cache.
It reads the source `.bazelrc` and disables unrelated home/system Bazel rc files.
The resolved existing Nix bootstrap binary starts with a minimal environment:
actual HOME, explicit private XDG paths and public system bootstrap PATH.
The resulting locked development shell uses `--ignore-environment` and keeps
only HOME and those private XDG paths. Operator SSH policy/trust and normal
HOME/system Nix configuration stay under operator authority. Ambient proxy,
provider, Nix override and agent variables do not enter the remote graph.
Recognized bootstrap/graph phase markers stream as bounded metadata; compiler
output remains private until the bounded redacted failure receipt. The fixed
worker additionally reports repository mapping, loading/analysis, completed
analysis, active action execution and graph completion; these stage markers
are operational observations, not platform acceptance proof.
After Nix bootstrap the original shell computes remaining caller allowance,
subtracting bootstrap elapsed time, a one-second rounding margin and twenty
seconds for completion/cleanup. Backward or exhausted elapsed values fail
closed. A private single-writer FIFO carries the bounded budget; EOF tells the
worker its custodian exited. The worker uses one monotonic deadline, terminates
only its own Bazel process group on expiry, custodian loss or handled signal,
and preserves the exclusive no-follow0600 private graph log and full SHA.
Transport failures retain the observed phase names and observation timestamps.
The flake explicitly supplies the same locked JDK used by Bazel, so disabling
system rc files does not fall back to an undeclared machine Java installation.

The Nix repository enumerates finite input paths rather than recursively
globbing SDK framework aliases. Declared aliases remain usable; ancestor cycles
are omitted. Symlink traversal must stay inside the declared immutable closure
at every hop. The exact `systemd-260.1` and `systemd-minimal-260.1`
`lib/environment.d/99-environment.conf` aliases with literal target
`../../../../../etc/environment` are operator configuration, excluded without
reading their targets and recorded in the generated inventory. Near matches and
other undeclared targets fail closed.

The local SSH deadline bounds the whole caller. After Nix environment
realization, the remote graph receives the remaining original caller allowance
with completion and cleanup reserves. Nix bootstrap is bounded by the caller;
abrupt transport termination is not proof of immediate remote cleanup.
Report that distinction if the transport deadline expires. Do not broaden a
successful graph build into an installed, GUI, service-registration, provider
or native continuity claim.

Receipts identify the source archive hash, proof UUID, target, phase and exit
codes. A completed graph additionally returns its full private build-log hash
and bounded redacted public-source compiler diagnostics before cleanup. Native
installation proof must use a frozen source archive and its dedicated graph
entrypoint. A mutable initial archive may warm tool custody and find compile
failures, but does not establish a frozen acceptance result.

Successful Linux package and installed-custody recipes return the
SHA256 and byte count of their fixed declared archive output. The runner checks
that its resolved regular file remains under the private Bazel output root.
Receipts accept only bounded enum OS/architecture metadata and numeric kernel
releases; kernel workstation suffixes, hostnames and user paths are excluded.
A cleanup receipt is required for success. The installed-custody target proves
its stated installation predicates; it does not establish native continuity.
The inert provenance parser retains support for historical Darwin bundle
receipts; it does not expose a current Darwin SSH execution recipe.

The manual `darwin-cleanup` mode is restricted to Neo and the explicitly
observed failed staging children `.run-nUi7wZna` (proof
`14ccacec-4922-486d-a95f-4332d4f531bb`) and `.run-UVJycRK3` (proof
`3ddc3001-8494-4fb1-bfdb-4f3676d15684`) and `.run-tIFiJDX7` (proof
`e5d3e5f5-7872-4249-926b-de7db20d9632`, after its exact log was verified and
read), and `.run-s9jRDq9y` (proof
`22412e51-546a-4379-bef2-9b164c552e46`). The fixed name/proof pairs are the
entire historical repair authority. It first checks existing HOME,
base and child metadata, then stages fresh declared public source and realizes
the locked Nix interpreter. Its worker uses the same remaining-budget FIFO,
no-follow directory descriptors and inode checks. It may add owner write/search
permission only to admitted, current-user, nonshared real directories inside
that child; it never chmods files or follows SDK/store symlinks. Receipt counters
and the repair summary hash describe cleanup metadata, not a full content log.
Successful repair does not change the original failed graph result or the
unknown disposition of any other historical staging directory.

Normal staging cleanup uses the same descriptor walker for only the current
custodian-created workspace. Before source transfer, an exclusive private marker
records its proof UUID and device/inode. The pinned worker checks that identity,
marker custody and private directory custody before removing anything. Its
monotonic cleanup deadline is the remaining original caller allowance minus
three seconds for final completion. The pinned worker samples its admission
anchor before ready publication or FIFO waiting and records the proof-bound
deadline from that earlier anchor, the single remaining budget and the existing
twenty-second reserve. Waiting never resets or extends either graph or caller
deadline. Private authority and deadline markers survive ordinary-entry removal
until final root removal. The opaque current workspace basename is streamed
before bootstrap and retained even on caller expiry. Once
Nix is launched, failed or unavailable declared cleanup never falls back to
recursive shell removal; a surviving workspace is reported as cleanup failed.
Future receipts retain the current cleanup outcome and static failure category.
Rejected cleanup predicates additionally return fixed rejection codes, bounded
partial directory/entry/repair counts and a failure-summary hash. Optional
metadata is limited to numeric permission mode, current/root/other ownership
class, depth and fixed subtree/entry-kind labels. These describe attempted
progress and rejection, never successful removal or the original failure cause.
The finite per-walk ceiling is8,000,000 entries, with depth128 unchanged. This
replaces the earlier2,000,000 ceiling only after an actual SDK build workspace
crossed it; historical rejection receipts retain their original limit. Caller
and monotonic deadlines still apply independently. Private authority reads open
nonblocking before rejecting nonregular files, so a substituted FIFO cannot
block admission.
The original category for proof `e5d3e5f5-7872-4249-926b-de7db20d9632` was not
retained and cannot be inferred from its build log.

The manual `darwin-diagnose` recipe reads only `.run-tIFiJDX7/build.log`, bound
to that proof and SHA256
`8537f74eaf4a9b6913a8721cdaf8dfa3d9d9c640213e19346729e53bb836a346`.
It executes fresh public source, never the failed workspace's source. The
no-follow log descriptor must be an owned0600 single-link regular file no larger
than128MiB; its complete hash and stable inode/metadata are checked before
output. Only fixed public library/framework candidates and immutable SDK14.4
relative identities from bounded unresolved-dependency diagnostic blocks may
leave the host. These are diagnostic candidates, not declarations of inputs or
proof of a fix. Raw lines, operator paths and ambient environment are excluded.

`linux-recover` is restricted to the failed Sting proof
`faf6e1f4-a9c9-4dad-9947-1b9424a6c844`. It inspects at most32 top-level entries
of the admitted purpose-specific proof base. Only owned0700 no-follow directories
are candidates; private bounded authority markers or owned0600 single-link logs
may establish the fixed proof or full recorded log SHA256
`16a33002b13ba56e2f390ab0903c135294398973ba18fdc621243ec11323aff2`.
Log reads are limited to128MiB per file and256MiB in aggregate. A unique exact
match is required before the existing descriptor walker can remove that child;
absence, duplicate matches and custody rejection fail closed. No source
subtree or unrelated user directories are searched.
After the original marker/log predicate failed, one final content predicate is
authorized: the59741174-byte production archive with SHA256
`a49ad024d06d6864097007e4d1c7c0729e9415c830c2cc1427c92680d3e6aa5a` at
the fixed declared release target beneath the candidate's private Bazel output
root. Its output-base directory uses the recorded recipe's canonical physical
workspace MD5 layout; every static path component is opened without following
links and checked for current ownership, nonshared permissions and stable
identity. The artifact must be an owned, single-link regular file with the
exact length and complete hash. These reads share the same aggregate bound.
Artifact authority establishes content and custody, not independent proof of
the failed operation UUID or source epoch. No alternate layouts or recursive
fallback are permitted.
