# Omux browser sources

The Chromium and Firefox extensions connect authorized browser sources to the
per-user Omux daemon through the native host `ai.xoxd.omux`. The popup requests
access to one selected provider at a time. Browser provenance identifies a source;
the daemon verifies provider identity before activating an imported grant.

This is an unshipped foundation. Production account imports remain disabled until
provider acquisition schemas have verified evidence. The ZIP/XPI artifacts are
unsigned; browser installation, signing and live continuity have separate proof
requirements. Registering the native host does not activate provider exports.

## Browser conduit and application integration are separate

The intended browser flow is: authorize one provider/context, acquire only its
reviewed fields, send them through the local native host, independently verify
identity and purpose in the daemon, then persist eligible authority encrypted
under the OS-vault wrapping key. Browser read consent does not authorize API
calls, transfer refresh ownership or make browser-bound credentials portable.
Account routing belongs to the daemon; same-process request handoff additionally
requires a verified application adapter. Omux owns that adapter's authentication
contract and implementation; no vendor-provided Omux hook is assumed. The browser
conduit and the application adapter are separate implementation workstreams.
Current Codex candidates are experimental; unmodified Codex continuity is unproved.

The current popup can connect, reconcile and disconnect source metadata. All
production adapters have empty acquisition field lists and
`blocked_pending_schema_proof`; the background service has no production page
storage reader. Only explicit test fixtures acquire synthetic capsules. Typed
page observations and usable production grants remain provider-specific work.

## Development and delivery checkpoint

The [recorded reset evidence](../docs/implementation/native-reset-evidence-2026-10-02.md)
contains 28 passing extension scenarios and produced unsigned ZIP/XPI artifacts,
plus 41 passing native-host setup fixtures. Those receipts do not establish
installation in a real browser profile. No new execution is inferred from this
documentation update. The
[integrated implementation plan](../docs/plans/omux-integrated-delivery-sprint-2026-10-05.md)
ratifies delivery under bounded execution after the
[Sting execution incident](../docs/agent-notes/2026-10-04-sess-omux-execution-incident.md).
The initial pure guard pass and supervisor cleanup exit 125 remain historical
receipts. Later bounded epochs qualified specific guard/mask, cancellation and
output-cap predicates; see the [root receipt](../docs/agent-notes/2026-10-05-sess-omux-integrated-delivery.md)
and [tracker checkpoint readbacks](../docs/tracker-updates/integrated-delivery-2026-10-05.md).
These scoped results establish neither actual browser execution nor a universal
same-user security boundary.

Later epoch `c8f63b83-f9cb-4233-a01c-5d1e6f30f33d` passed
`//delivery:installed_chromium_test` on Chrome/147.0.7727.116 in a private
profile with the exact keyed development extension and native host. It proved
health, permission refusal and synthetic pending-operation recovery across
browser restart and context disconnect, with empty descendants. The
[browser tuple](../docs/tracker-updates/integrated-delivery-chromium-2026-10-05.json)
retains its artifact and source bindings. Human toolbar consent, provider
acquisition, committed daemon mutation with lost-reply recovery and the complete
browser gate remain open. Firefox installed proof and signed distribution also
remain separate.

| Surface | Exists | Remaining delivery work |
| --- | --- | --- |
| Chromium/Firefox extension | Shared modules and unsigned archives; exact Chromium development install and synthetic recovery receipt | Human consent, provider acquisition, complete browser lifecycle and Firefox installed proof |
| Local native host | Explicit registration/removal, exact installed Linux setup/channel predicates and private-profile Chromium transport | Fleet activation and complete user setup/consent proof |
| Provider acquisition | Declared optional origins and a synthetic test adapter | Reviewed fields, context/identity/purpose verification and exact live proof |
| Distribution | Pinned development identity, unsigned archives and locally validated SPA metadata | Signing/store submissions, update compatibility and published downloads |

Extension archives are separate Bazel outputs; the main Omux bundle includes the
native-host executable but does not bundle or automatically install the browser
extension. The explicit registration workflow below remains necessary today.
For the ratified fleet lane, Home Manager owns exact-ID host manifests and
services; the imperative host tool must not replace those managed files. Shared
native UI/CLI setup reports readiness and required declarative changes. The new
fleet and setup interfaces have source and Nix harness evidence; epoch `9fd5966e`
passed module-harness evaluation without activation. Later
[installed Linux setup/channel predicates](../docs/tracker-updates/integrated-delivery-installed-setup-2026-10-05.json)
and the private-profile Chromium receipt have their own exact scope; actual
fleet activation and human browser consent remain unproved. Follow
[TIN-5442](https://linear.app/tinyland/issue/TIN-5442) for installed-browser
lifecycle and [TIN-5443](https://linear.app/tinyland/issue/TIN-5443) for updates.

Ratified development route: keep first-party source here
under `extensions/`, with no separately maintained vendor copy in the SPA. Build
through the locked Nix/Bazel graph, then load the artifact's root manifest from a
stable local development directory in a dedicated profile. Chromium uses
[Load unpacked](https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world#load-an-unpacked-extension).
Firefox supports [temporary installation](https://extensionworkshop.com/documentation/develop/temporary-installation-in-firefox/),
which is removed on browser restart and does not reproduce every signed-install
permission behavior. Bind native registration to the actual installed extension
ID. Channel-specific archive and handshake source now separates release
`ai.xoxd.omux` / default instance from development `ai.xoxd.omux.dev` / dev
instance. The declared `//extensions:chromium_dev_package` consumes a fixed
development public key, now pinned at `chromium/development.public-key` after
the declared generation action in epoch `afcddb75-5a42-45ec-b9cd-cf0b3da7df32`.
The public key establishes an unpacked development identity, not a signing
credential. Epoch `05d7c7e7-29c7-4c24-8099-eb56ac766025` produced the unsigned
development archive and derived metadata with extension identity
`bggghdafplhajiailkafeihemlalagmm`; the overall epoch failed other targets.
That production does not prove browser installation. Release/development
coexistence and mismatch refusal still require installed proof.

### Mandatory wire-1 channel boundary

Every wire-version-1 browser request, including `browser.health`, carries typed
`params.provenance.channel`: exactly `release` or `development`. The extension
sets its own channel from its packaged identity/configuration; callers and popup
inputs cannot select another channel. A missing or unknown channel is refused,
and a valid channel targeting the other instance is refused. There is no implicit
release default. Older unsigned, unshipped extension/host/daemon combinations
that omit this field require matching component updates; retaining wire version
1 does not make those combinations compatible.

The native host checks this channel against its selected daemon instance before
forwarding the request. The daemon independently validates it before any browser
mutation or production-schema-proof refusal accounting. Host validation does not
replace daemon validation. The development host/instance accepts `development`,
and the release host/instance accepts `release`.

The extension performs a `browser.health` compatibility preflight on the same
native messaging port that will carry the operation. The response must identify
wire protocol version, channel and applicable capabilities before the operation
is sent. This checks compatibility with that port's peer; health and client-
supplied provenance do not establish browser principal identity or confer account
authority. Exact-ID registration, local transport boundaries and independent
provider identity verification retain their separate obligations. These are
source-level contracts; actual browser installation, cross-channel refusal and
same-port behavior require their own installed receipts. Effects of browser port
closure or extension uninstall on acquired authority remain unproved; neither
event is evidence that Disconnect or upstream revocation completed.

The ratified development documentation destination is `/extensions/dev` in the
separate `omux.xoxd.ai` SPA. Its exact local import/render/archive gate passed in
epoch `b62de355-e8e5-4c26-a3f6-e4bb8e370f3b`; the
[SPA tuple](../docs/tracker-updates/integrated-delivery-spa-2026-10-05.json)
binds the imported manifest, extension ZIP and unpublished site archive. The page
displays caller-declared source provenance, artifact/manifest digests and protocol
limits, with unsigned, unpublished and unproved qualifiers. No public development
download or deployment is established. Later runtime changes do not update that
selected snapshot or inherit its proof. The website receives no credentials and
loads no extension code.

Persistent user delivery should use the Chrome Web Store and Mozilla-signed
Firefox packages (AMO-listed or signed unlisted beta). Chrome's ordinary external
installation on macOS requires a Web Store update source; Linux has additional
self-hosted options, not yet implemented here. See
[Chrome distribution](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
and [Firefox signing/distribution](https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/).
Signing and publication are separate authorized operations. Any future signing,
staging or checking tools must be pinned and invoked through Bazel.

## Build and check

```bash
nix develop --command bazelisk build //extensions:chromium_package //extensions:firefox_package
nix develop --command bazelisk test //extensions:tests //extensions:host_setup_test
```

For the pinned Chromium development identity, explicitly build
`//extensions:chromium_dev_package` and `//delivery:chromium_dev_metadata`.
Metadata additionally requires `--define=OMUX_SOURCE_COMMIT=<full commit>` and
`--define=OMUX_SOURCE_DIRTY=true|false` selected for the actual input worktree.
The outputs are `bazel-bin/extensions/chromium_dev_package.zip` and
`bazel-bin/delivery/chromium_dev_metadata.json`. Review their exact bytes before
staging or selecting a SPA import; provenance fields are caller declarations.

The release-channel artifacts are `bazel-bin/extensions/chromium_package.zip` and
`bazel-bin/extensions/firefox_package.xpi`. Each contains a root `manifest.json`
and shared modules. Tests use synthetic browser APIs and verify package contents;
they do not establish live browser or application handoff support.

The unsigned local Firefox development artifact is
`//extensions:firefox_dev_package`, producing
`bazel-bin/extensions/firefox_dev_package.xpi`. It retains the release permission
scope and uses the existing exact development identity
`browser-sources-dev@omux.xoxd.ai`, channel `development`, instance `dev` and host
`ai.xoxd.omux.dev`. Register that exact ID with `//extensions:host_setup` using
`--browser firefox --channel development`, the installed development host alias
and an explicit destination ending in `ai.xoxd.omux.dev.json`. Runtime launch
validation admits the Firefox ID for its selected instance only. The release
identity remains `browser-sources@omux.xoxd.ai` / `ai.xoxd.omux` / default.
This package supplies no signing or store identity and does not establish Firefox
installation, consent, account acquisition or fleet activation. Chromium remains
the first installed-browser proof lane; Firefox temporary installation and future
Mozilla-signed delivery retain their separate requirements.

## Register the native host

Use a stable, installed executable or alias named `omux-native-host`. Its absolute
path must remain executable outside Bazel; a temporary Bazel/runfiles path cannot
serve as a durable browser registration. Its target and directory chain must be
owned by the current user or the system and protected from other users' writes.
Safe file aliases are supported; directory symlinks and alias targets containing
parent-directory traversal (`..`) are rejected.

For Chromium, supply the installed extension's exact 32-character ID, using
lowercase letters `a` through `p`. Chrome and Chromium use the same host manifest
format. For Firefox, use the ID declared in its extension manifest:
`browser-sources@omux.xoxd.ai`.

Choose an absolute destination ending in `ai.xoxd.omux.json` in the browser's
existing, user-owned native messaging directory. Symlink components and writable
directory chains are rejected; standard system-owned sticky temporary directories
are allowed above private test/install directories. Verify the directory used by
your browser/profile. These are usual user-level locations:

| Platform | Browser | Directory |
| --- | --- | --- |
| Linux | Chrome | `${XDG_CONFIG_HOME:-$HOME/.config}/google-chrome/NativeMessagingHosts` |
| Linux | Chromium | `${XDG_CONFIG_HOME:-$HOME/.config}/chromium/NativeMessagingHosts` |
| Linux | Firefox | `~/.mozilla/native-messaging-hosts` |
| macOS | Chrome | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts` |
| macOS | Chromium | `~/Library/Application Support/Chromium/NativeMessagingHosts` |
| macOS | Firefox | `~/Library/Application Support/Mozilla/NativeMessagingHosts` |

Browser profile overrides can change discovery paths. Consult the browser's
[Chrome/Chromium native messaging documentation](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location)
or [Firefox native manifest documentation](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_manifests#manifest_location).
Omux setup uses explicit destinations; system-wide registration is outside this
per-user workflow.

Replace the example values, then inspect the generated JSON before installation:

```bash
omux_extension_id='replace-with-installed-32-letter-a-p-id'
omux_native_host='/absolute/path/to/installed/omux-native-host'
omux_host_manifest='/absolute/path/to/browser/NativeMessagingHosts/ai.xoxd.omux.json'

nix develop --command bazelisk run //extensions:host_setup -- emit \
  --browser chromium --extension-id "$omux_extension_id" \
  --binary "$omux_native_host"

nix develop --command bazelisk run //extensions:host_setup -- install \
  --browser chromium --extension-id "$omux_extension_id" \
  --binary "$omux_native_host" --manifest "$omux_host_manifest"
```

`emit` is the default operation and only prints manifest JSON. For Firefox, use
`--browser firefox --extension-id browser-sources@omux.xoxd.ai` and its selected
destination. The generator emits one exact allowed origin/extension ID.

Installation creates the manifest and an ownership receipt at
`<manifest>.omux-owner.json`. The receipt binds the selected browser, extension
and binary to the manifest content hash, owner/group, permissions and file
device/inode. Repeating the exact owned installation is idempotent; an unrelated,
changed or unowned existing file is preserved and the operation fails.

## Disconnect and remove

The popup's **Disconnect** source implementation now selects one authorized
provider/context and refuses ambiguous context selection. It records pending
disconnect for retry after a lost host response and releases optional access
only when no authorized contexts still need it. Disconnect ends that source's
acquisition authority and removes source-retained secrets; independently valid
grants and native history retain their own authority. Browser disappearance uses
detachment semantics. The C8 Chromium tuple above covers synthetic pending
recovery and context disconnect; human consent, production authority transitions
and committed daemon mutation with lost-reply recovery remain unproved.
Removing host registration is a separate action.
Use the exact browser, extension ID, binary and destination from installation:

```bash
nix develop --command bazelisk run //extensions:host_setup -- remove \
  --browser chromium --extension-id "$omux_extension_id" \
  --binary "$omux_native_host" --manifest "$omux_host_manifest"
```

Removal verifies the owned manifest/receipt pair before deleting either file.
Changed contents, replacement files, ownership/permission changes or mismatched
arguments stop removal. Keep the receipt beside the manifest until removal.
The browser directory, executable and daemon lifecycle are managed separately.
The setup tool coordinates its own operations with a lock; it cannot guarantee
atomicity against unrelated processes running as the same user.

### Local release-channel coexistence evaluation

`//extensions:chromium_release_evaluation_package` is a local, unsigned and
unpublished evaluation archive of the release-channel extension source. Its
distinct public-only identity was generated in contained Bazel epoch
`9d9710c8-8a71-459d-813d-f558b7f88ed7` using the locked OpenSSL tool. Private
material existed only in an anonymous pipe and was discarded; the retained
`chromium/evaluation-release.public-key` supplies no signing authority.

This archive lets isolated fixtures join actual release/default runtime hosts
to a distinct extension origin while development remains independently pinned.
It does not assign the eventual Chrome Web Store identity or change the normal
`//extensions:chromium_package`. Installation, store signing and persistent
distribution keep their separate proof and delivery requirements.
