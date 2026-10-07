# Yoga toolbar permission proof proposal

Status: source-only implementation checkpoint, October 5, 2026. The user selected
Yoga's local Wayland desktop and authorized operator participation for actual
toolbar permission handling. The fixed proof target and local guard interfaces
are implemented in source and reviewed. Scoped modeled support checks have
passed; target build, current Yoga seat/closure qualification and actual toolbar
execution remain unproved. No Yoga provider access, login or live consent proof
is established. The interfaces below are not commands ready for dispatch.

Authority: [AGENTS.md](../AGENTS.md), the
[native account-lifecycle reset](../docs/plans/omux-native-account-lifecycle-reset-2026-10-02.md),
and [host execution custody](../tools/host-proof-custody.md). The passed
[installed Chromium recovery receipt](../docs/tracker-updates/integrated-delivery-chromium-2026-10-05.json)
has `toolbarConsentProved: false`; this proposal cannot change that historical
scope. Browser automation remains a test driver, outside product architecture.

## Four acceptance predicates

1. In a newly created private denial profile on `about:blank`, the operator
   opens Omux through Chromium's actual toolbar action. The shipped checkbox
   starts unchecked and Connect is disabled. The operator checks the checkbox,
   clicks Connect, sees Chromium's permission prompt, and denies it. Optional
   cookies/provider permissions remain absent. No browser source, native source
   mutation, account, or grant is created.
2. In a separate newly created private approval profile on `about:blank`, the
   operator performs the same toolbar/checkbox/Connect actions and approves
   Chromium's prompt. The only optional permission additions are `cookies` and
   `https://github.com/*`; the other declared provider origins remain absent.
   The real popup/background command then refuses with `open_provider_tab`.
   Source metadata, source mutation journal, accounts, and grants remain empty.
3. The runner terminates and waits for its approval browser, then relaunches
   that exact profile with the same qualified runtime and extension artifact.
   Permission readback retains exactly those optional additions. The operator
   reopens the actual toolbar popup: consent starts unchecked and Connect
   disabled; the source is disconnected, identity unverified, grant and
   capability unproven. No source/account/grant is created during startup.
4. Network confinement remains verified throughout both cases and restart.
   Cleanup removes only this proof's marked profiles/private state and verifies
   the owned process aggregate is empty. A timeout, missing operator response,
   unexpected origin, invalid custody, or incomplete cleanup fails the proof.

Only one provider origin is selected to avoid broad consent. This permission
request needs no provider tab: the shipped popup requests optional permissions
before its background command, and `BrowserService.context()` rejects
`about:blank` before querying cookie stores. Production adapters keep exports
blocked. This proves permission handling and persistence across restart, not
provider-context enrollment, identity, usable authority, or continuity.

Chrome requires `permissions.request()` inside a user gesture, and may silently
restore previously accepted permissions. Separate fresh profiles avoid regrant
history obscuring the prompt.
[Chrome permissions contract](https://developer.chrome.com/docs/extensions/reference/api/permissions)

The approval-profile restart in predicate 3 tests optional-permission persistence
in the same private browser profile. Its case name `reload` means reopening the
toolbar after that restart. It does not rebuild/stage a development generation,
manually reload an unpacked extension, or restart the development daemon.
Those development operations and DEVLOOP acceptance require their own evidence;
this permission proof cannot close DEVLOOP.

## Entry point and declared input contract

The local-on-Yoga target `//delivery:yoga_toolbar_consent_proof` is declared in
[BUILD.bazel](BUILD.bazel) as a manual, uncached, local Python run target using
locked Nix tools and eleven fixed artifact/runtime arguments. Its build and
execution are not yet proved. It must not run in ordinary tests or launch
another build/test. No remote dispatcher recipe is active; the historical
host dispatcher remains held and is not this lane's execution route.

Inputs must include:

- Frozen public source receipt and source/archive SHA256; development Linux
  bundle and keyed Chromium extension SHA256; expected channel, extension ID,
  extension version, and installed daemon/native-host hashes.
- The existing qualified Chromium runtime authority and exact NAR/reference
  inventory, including Node/Python/D-Bus/Secret Service dependencies and the
  display tools. Reuse `browser_runtime_authority.py` validation, including
  registered root-link topology and execution-mask requirements. A display
  dependency added to the closure needs its own declared qualification.
- A hash-bound operator session selection, scoped to Yoga, with explicit
  display protocol and selected local display endpoint. These are private
  operator inputs, not public source, receipt contents, ambient SSH variables,
  or shell fragments. Specify how the operator sees and controls the isolated
  browser; do not infer it from the SSH login.
- Verified remote containment capability: fixed aggregate memory, swap,
  process, CPU and elapsed limits; exclusive ownership; cancellation; retained
  custody; and descendant cleanup on the local Yoga seat. Require an
  already-realized exact closure and locked tools, with no Nix realization,
  Bazelisk resolution or remote bootstrap in this lane.
- Verified private network confinement with no provider route. A private
  network namespace exposing no external interfaces is preferred; DNS/proxy
  flags are not network authority. Chromium and its children belong to the
  same confined aggregate; observer transport is a private local socket/pipe.

The manual budget proposal is 20 minutes total, including preparation and
cleanup: at most five minutes per denial/approval interaction, three minutes
for restart/readbacks, and two minutes reserved for cancellation/cleanup.
Unused time remains within the original total; prompts and reconnects cannot
reset it. Operator absence fails categorically rather than prompting forever.

## Visible session and isolation

The operator confirmed a local Wayland desktop on Yoga. The implemented adapter
admits one exact qualified Wayland socket, with current inode/device and live
same-UID server PID/peer credentials. Root's coordinator must bind that socket
to an admitted private location beyond the existing runtime-directory mask;
the browser receives an absolute `WAYLAND_DISPLAY` and
`--ozone-platform=wayland`, with its own private `XDG_RUNTIME_DIR`. No personal
session bus or profile is admitted. No X11/Xauthority adapter is implemented.
Never adopt ambient display variables, broad runtime-directory bind mounts,
personal Chromium profiles, or global host configuration changes.

The current installed-browser guard masks `/run/user/<uid>` and the fixture
clears display variables. A visible lane therefore needs its own reviewed,
finite display-access contract; it cannot silently relax that profile. The exact
socket binding, operator-owned compositor custody, and qualified coordinator
remain required inputs. The compositor is never a fixture cleanup target.
Chromium sandbox and existing runtime pins remain enabled.

## Runner and observer behavior

Create two marked private profile children under proof-owned state, preserving
the operator's HOME and fleet-managed registrations. Give each its own private
native-host registration. Both profiles and the approval-profile restart share
one fixture-private daemon, D-Bus/Secret Service session and synthetic-free
database; empty authority is checked across every case. Run the exact installed native host directly; if a
test recorder is used, its authority must explicitly permit only health and
reject every browser source mutation. Do not reuse the recovery recorder's
synthetic connect allowlist as consent evidence.

Keep the real extension popup, background sender checks, production adapters,
and BrowserService unchanged. Observe the action popup through target discovery
and read-only DOM/API readbacks; the driver never calls Connect, source commands,
permission requests/removals, `action.openPopup()`, CDP permission-grant APIs,
synthetic clicks, or evaluation with injected user activation. It never seeds
source metadata, cookies, storage, or grants. UI events can be observed without
replacing production handlers. A browser's trusted-event/activation flag alone
does not establish human participation: retain separate operator categorical
attestation that the toolbar, checkbox, Connect and browser dialog were used.

Programmatic `chrome.action.openPopup()` is available for the pinned browser
and could support a separate action-container test, but it does not prove a
human toolbar click. The existing extension-tab sender rejection stays intact.
[Chrome action contract](https://developer.chrome.com/docs/extensions/reference/api/action)

Record only fixed phase/outcome enums, elapsed integers, source/artifact/runtime
digests, extension/version/channel, optional-permission set comparisons, empty
source/account/grant predicates, restart completion, and cleanup predicates.
Keep endpoint paths, desktop environment, usernames, raw native frames, cookie
values, account identifiers, screenshots and raw exception text out of public
evidence. Permission approval attestation does not authorize provider access.

Success requires the observed real denial/approval outcomes and operator
attestation together. Never infer a shown prompt solely from a granted bit.
If Chromium closes the popup during the permission dialog, the observer must
retain and report the categorical outcome safely; it must not script a second
Connect to compensate or invent an unobserved UI result.

## Existing host paths and required wiring

`//tools:host_probe -- --host yoga` is the reusable bounded readiness entrypoint;
its SSH policy preserves existing trust, BatchMode and no agent forwarding.
It reports platform/Nix/store capability, not display or containment readiness.
Reuse `ssh_policy.operator_config` for any later admitted fixed-host transport.

`host_closure_transfer.py` has a fixed Darwin closure and Neo/PZM transport
contract. It cannot transfer the Linux Chromium closure to Yoga without a
separate exact declared input contract. The local development-generation
selector also does not establish remote runtime custody or transfer authority.

`deployed_fixture.py` and `host_graph.py` currently return
`unsupported-execution-capability` before transfer/bootstrap. Their documented
remote containment hold remains valid despite authorized operator participation.
Do not dispatch historical recipes or add a free-form SSH launcher around them.
Remote dispatch remains held. Root can separately wire and qualify the following
operator-local implementation after exact runtime/artifact availability and
local aggregate/display custody have been established on Yoga.

## Implemented source checkpoint and root wiring

The new `yoga_toolbar_consent.py` runner installs the exact development bundle
with existing private-install helpers, extracts the keyed extension, creates
private D-Bus/Secret Service and daemon custody, and launches the passive
`yoga_toolbar_observer.mjs` for denial, approval, and approval-profile restart.
`yoga_toolbar_native_recorder.py` wraps the declared existing recorder
implementation to forward only strict health requests; every other request is
categorically journalled and rejected without retaining its values. The shared
`yoga_toolbar_contract.py` supplies strict session, limits, display, private-file
and human-attestation validators. `test_yoga_toolbar_consent.py` covers boundary
refusals without launching a browser. Root's epoch `1dd828ad` passed the original
19 methods; the subsequent runner boundary suite reached twenty-seven methods.
These modeled checks did not launch a browser or establish toolbar consent.

Source declarations and remaining delivery boundaries:

- `//delivery:yoga_toolbar_consent_test`: declared Python test with runner, contract, native
  wrapper, and existing `chromium_native_recorder.py` sources; no browser or host
  access, no fixture main execution.
- `//delivery:yoga_toolbar_consent_proof`: declared manual local Python run target, with
  runner, contract, `browser_runtime_authority.py`, `test_installed_chromium.py`,
  `test_installed_custody.py`, `install.py`, `pack.py`, and `portable.py` as sources.
  Existing installed helpers are imported for runtime/custody only; their main
  fixtures are never run. Declare keyed development extension, development Linux
  archive, qualified browser authority/closure, Node closure, locked private
  D-Bus/keyring tools, passive observer, native wrapper, and existing recorder
  implementation as data. This target is operator-local only.
- `yoga_toolbar_attest.py` remains a source helper, not an active standalone
  proof route. Local guard integration must carry bounded operator statements
  through its owned event channel; no second build or uncontained command is
  admitted during the proof.

Runner arguments are named declared inputs: `--bundle`, `--extension`,
`--chromium`, `--node`, `--observer`, `--dbus-session`, `--dbus-daemon`, `--keyring`,
`--runtime-authority`, `--recorder`, `--recorder-implementation`, followed by
private operator/coordinator inputs `--visible-session`,
`--visible-session-sha256`, and `--attestation-dir`. Missing visible-session input
refuses before launch. Do not expose the internal `--inside` option as a recipe.

The private session JSON's exact v1 scope is `yoga-operator-local-toolbar-v1`.
Its fields are `schemaVersion`, `scope`, `hostAlias` (`yoga`), `proofId` (UUID4),
`operatorAccess` (`local-console`), `deadlineMonotonicNs` (one original deadline,
at most 20 minutes ahead), `coordinator`, `display`, and `inputSha256`.
`coordinator` contains live `pid`, exact `/sys/fs/cgroup/...` `cgroupPath`, and
`device`/`inode`. The observer verifies same aggregate membership, effective
4GiB-or-smaller memory/zero-swap/512-or-fewer tasks/two-CPU-or-smaller limits,
no effective capabilities, no-new-privileges, and loopback-only networking.
`display` contains only `adapter` (`qualified-wayland-unix`), `socketPath`,
`socketDevice`, `socketInode`, and `serverPid`. `inputSha256` contains exactly the
eleven input names shown above with underscores replacing argument hyphens.
All files and digests must match the selected graph/runtime tuple. Session file
and attestation files are single-link, owned 0600 regular files; their directory
is owned 0700 with a 0600 `proof-id` file containing the exact UUID without a
newline. No previous case attestation may exist when the outer runner starts.
Input hashing opens direct regular files with no-follow/nonblocking descriptors,
checks the size ceiling before reading, inherits the original deadline with a
12-second per-hash ceiling, and compares final descriptor and path witnesses
including nanosecond modification/change times. Control CLI stdout is capped
while streaming through the owned-group custodian; no whole-response collection
precedes that cap. Reserved deadlines are validated as bounded future integers
before selector allocation and again before child launch; hashing rechecks the
deadline after final identity checks before returning a digest.

When progress says `await-toolbar`, the operator opens the real toolbar popup
and selects GitHub, keeping consent unchecked until `await-human-decision`.
They then check consent, click Connect and deny/approve the actual Chrome prompt.
For reload they only reopen the toolbar and select GitHub. After each observed
case, the runner allows at most one minute for the separate manual attestation:
`--attestation-dir <private selection> --proof-id <proof UUID> --case denial`
plus `--observed toolbar-checkbox-connect-prompt-denied`; approval uses
`toolbar-checkbox-connect-prompt-approved`, and reload uses
`toolbar-reopened-without-request`. These are statements the operator supplies
only after seeing the actions; the fixture never creates them automatically.

The runner emits categorical `yoga-toolbar-local-observations`, with
`aggregateCleanupJoinRequired: true`. It does not claim overall completion.
Root's independently qualified coordinator must join source/artifact/session
bindings, the three operator statements, observed predicates, temporary-profile
removal, deadline/cancellation disposition, and a final empty aggregate after
the runner exits. Human permission consent remains separate from verified
identity/grant claims. Remote transfer/execution remains unimplemented and held.
The coordinator must also supply the declared human-event/attestation channel;
recording a statement during the live proof must not launch a second uncontained
or nested build. Socket source-to-private-destination bind custody is verified
by the coordinator before/after binding; the fixture verifies the presented
destination and peer identity. Host HOME remains masked; admitted source,
runfiles, session receipt and operator files must be staged outside that mask.

## Local Yoga guard source checkpoint

**Reviewed source implementation; live execution unproved.** The user selected Yoga's local Wayland desktop and operator
participation. The support modules and modeled tests do not establish a qualified
Yoga seat, visible execution, or toolbar consent. Track installed-browser proof
in [TIN-5442](https://linear.app/tinyland/issue/TIN-5442) and shared installation
and onboarding in [TIN-2063](https://linear.app/tinyland/issue/TIN-2063).

The twelve coordinator methods passed in epoch
`e006d56c-36c8-44af-b71e-a2040132ef53`, separately from the five display-binding
methods and twenty-seven runner boundary methods. These are modeled predicates;
the [durable execution notes](../docs/agent-notes/2026-10-05-sess-omux-integrated-delivery.md)
retain their scope. They do not qualify aggregate limits, mounts, a compositor,
operator interaction, or browser acceptance on Yoga.

In epoch `c5d684a2-f030-4939-808e-ed7711a3033c`, the scoped Yoga profile twelve,
display twelve, input qualification eleven and coordinator fourteen modeled
methods passed. The whole batch failed with controller/workload 3 because the
launcher fixture had two errors; this is not a whole-batch success. After its
fixture correction, epoch `bd412392-ef5a-4cc4-88f0-1e6affbe47c0` logged passing
launcher, installed-core, documentation and source-capture targets, but its
controller/workload receipt is 125 with tests unadmitted and
`descendants_empty: false`. Those log results and its archive are not promoted.
Later owned inspection found the recorded unit/process aggregate absent; it
does not repair that receipt. Root's latest pre-epoch admission refusal leaves
execution idle. Actual target build, Yoga seat and toolbar gates remain open.

Use the existing sole [execution guard](../tools/execution_guard.py), its
[finite profile selector](../tools/guard_dependency_profile.py), and
[system mask policy](../tools/system_mask_policy.py). The source integration adds one local-only
`yoga-toolbar` profile admitting exactly `run
//delivery:yoga_toolbar_consent_proof` through the system manager. The fixed
manual target declares the selected artifacts, qualified runtime, observer
and health-only recorder. Do not add a recipe to the held legacy host dispatcher
or start a second bootstrap, nested build, arbitrary SSH command, Nix realization,
or Bazelisk download. Remote distribution and execution remain separate,
unimplemented qualification work.

Before creating an epoch directory, cache, workload, or transient unit, reject
missing or mismatched local-seat qualification, host/boot identity, same-user
local-console selection, realized registered inputs, exact input digests,
compositor witness, or operator event channel. A private hash-bound receipt must
select the intended Yoga seat; ambient hostnames and SSH aliases do not establish
that selection. Recheck current compositor socket ownership, device/inode,
same-user peer credentials, live PID and start ticks. Validate selectors and the
original monotonic deadline before filesystem walks. Reuse the
[display-binding helper](../tools/yoga_display_binding.py) and
[coordinator support](../tools/yoga_operator_coordinator.py); factor shared
read-only channel validation for preallocation rather than duplicate its policy.

After these prerequisites, take the existing execution lock and hold a marked,
private 0700 proof directory under `/srv`. Keep the original twenty-minute
deadline, including preparation and cleanup. Bind only the witnessed Wayland
socket to that directory's `wayland.sock`. Preserve the existing `/run`, Nix,
privilege-secret, Bluetooth and environment masks; add verified personal-HOME
concealment. Source, runfiles, session and operator files must remain outside
the concealed HOME. Keep private D-Bus/Secret Service custody, Chromium sandbox,
`PrivateNetwork=yes`, and live loopback-only/no-external-route verification.

Before releasing `go`, the held worker must inspect the destination inside its
mount namespace. The supervisor must reinspect the source outside the `/run`
mask and compare both snapshots with the original witness. Verify the effective
singleton read-only bind, all masks, HOME/bus denial, aggregate cgroup limits,
network observations and current input bytes. A property request or prior
receipt alone is insufficient. Only then write the private session using the
worker PID and measured cgroup identity, and release the fixed runner.

The sole guard creates and retains the operator channel: a duplicated,
non-inheritable read-only anonymous pipe with pinned device/inode, same-user
0600 FIFO metadata and exact procfs `pipe:[inode]` identity. No named FIFO or
caller-selected replacement descriptor is admitted. Accept at most three ordered
categorical statements, each at most 2048 bytes, with bounded waits inside the
original deadline. The operator supplies statements after the indicated real UI
actions; the channel never issues browser actions. This replaces any need to
launch a separate attestation command during the proof. Keep endpoint paths,
PIDs and session data private. Cancellation targets only the verified owned
aggregate; never signal the compositor.

Injected refusal tests must establish that invalid seat/boot/UID, unrealized or
changed inputs, unsafe socket selectors, named/wrong-end/replaced channels and
expired deadlines cause no epoch/cache/unit allocation. At admission, missing
masks, additional binds, replaced socket/PID, personal HOME or bus visibility,
external routes, incorrect limits or changed digests must prevent `go`. Event
tests must reject oversized, partial, duplicated, out-of-order and replayed
statements. Cleanup must refuse success for foreign ownership, nonempty
descendants, cancellation or deadline expiry. Join measured browser outcomes,
operator statements and final empty aggregate only after runner exit; coordinator
support alone always keeps `toolbarConsentProved: false`.

Finite labels, schemas, pins and injected test results are source facts.
Current seat/socket identity, effective mounts and limits, actual input bytes,
human actions, browser readbacks and cleanup are live observations requiring
separate retained evidence. Current missing facts are the qualified local Yoga
seat, realized exact tool/artifact closure, live mount/network/aggregate
capabilities, selected compositor endpoint, private `/srv` placement and bounded
local operator event ingress.

## Reviewed operator preparation contract

The local guard interface is implemented and reviewed in source; live
qualification remains pending. It accepts existing locked controller tool/closure
selectors plus `--profile yoga-toolbar`, `--manager system`,
`--state-dir <private physical /srv root>`,
`--yoga-qualification <private 0600 /srv receipt>`,
`--yoga-qualification-sha256 <independently selected SHA256>`, and
`--yoga-deadline-monotonic-ns <original future integer>`, followed by exactly
`-- run //delivery:yoga_toolbar_consent_proof`. This is an interface contract,
not a dispatch instruction: its build, live qualification and proof run remain
unproved. It rejects caller-supplied payload arguments and cache, site, SDK or
acquisition inputs. It does not expose an operator-descriptor flag.

Prepare the private qualification receipt against
[guard_yoga_profile.py](../tools/guard_yoga_profile.py), scope
`yoga-local-guard-qualification-v1`. Select the intended host machine/boot hashes,
UID, active local Wayland logind seat and exact local console terminal; proof
UUID and original deadline; physical source root, graph hash and eight runner
source digests; compositor source socket and six-field snapshot; eleven direct
physical input paths and digests; and controller tools with independently
selected inventory/NAR proof paths and digests. No token, cookie, login, personal
profile, session-bus address or provider data belongs in this receipt. The guard
rechecks its current observations before allocating the proof root.

The compositor source selector is exactly
`/run/user/<same UID>/wayland-<one to three digits>`. The future proof directory
is `<state-dir>/<proof UUID>`; its socket is `wayland.sock`. Keep state,
qualification, physical source, runfiles and operator/session files outside the
concealed HOME and under admitted physical `/srv` paths. Runtime input files
may also use qualified physical Nix store paths. The display helper pins the
original socket with a held descriptor and checks current inode and PID start
ticks; only an exact singleton read-only bind with no writable binds is accepted.

The worker, not the caller, appends `--visible-session <proof root>/session.json`,
`--visible-session-sha256 <guard-produced SHA256>`, and
`--attestation-dir <proof root>` to the eleven declared runner arguments. The
selected local console supplies one newline-terminated JSON statement per
completed case with exactly `proofId`, `case` and `observed`; use the denial,
approval and reload categorical values already specified above, in that order.
The guard owns the anonymous pipe and writes the private categorical attestation
files. No separate attestation target or remote command is part of this lane.

The input/display/launcher/guard interfaces are reviewed source implementation;
the scoped results above do not establish live Yoga qualification. Earlier five
display and twenty-seven runner methods, and the twelve
coordinator methods in `e006d56c`, retain their original tested scope; they do not
automatically validate these new integration changes or a live Yoga seat.
