# Chromium installed transport lane — source prepared, execution unrun

Authority: user Chromium-first delivery direction; `AGENTS.md`; native lifecycle
architecture SSOT; R-N12 advisory diagnostics and R-N13 durable receipts. Tracker:
[TIN-5442](https://linear.app/tinyland/issue/TIN-5442) installed Chromium connection,
context disconnect and development/release separation; provider acquisition remains
[TIN-2720](https://linear.app/tinyland/issue/TIN-2720).

`delivery/test_installed_browser.py` exercises the genuine installed native host,
daemon and private Secret Service, without a browser. Its successful run would
prove synthetic transport/source metadata predicates only.

`delivery/test_installed_chromium.py` and `delivery/chromium_transport.mjs` prepare
the next lane: a genuine Chromium process loads the unchanged development archive,
discovers the exact pinned extension service worker, opens the shipped extension
popup page for CDP inspection, calls the extension's shipped
`requestNativeHealth` and `sendNativeRequest` modules, and proves synthetic source
connect/reconcile/disconnect/reconnect. A full browser restart keeps the same new
private profile, extension ID and synthetic storage handle. The daemon snapshot
must contain one connected source, zero accounts and zero grants; sealed custody
and owned installation removal are checked separately.

These are test harness operations through CDP, not product browser automation.
They bypass popup consent and provider acquisition deliberately. They do not prove
manual Load Unpacked UX, Home Manager activation, consent, browser-bound authority,
verified provider identity, usable grants, renewal or seamless application handoff.
The fixture never requests cookie/host permission or opens a provider page.

Official support checked through read-only documentation on 2026-10-05:

- [Chrome DevRel announcement](https://groups.google.com/a/chromium.org/g/chromium-extensions/c/1-g8EFx2BBY/m/S0ET5wPjCAAJ)
  says Chrome-branded builds removed `--load-extension` starting in Chrome 137;
  Chromium and Chrome for Testing retain that switch.
- [Chrome extension end-to-end testing](https://developer.chrome.com/docs/extensions/how-to/test/end-to-end-testing)
  documents loading extension packages, new headless mode, stable extension IDs
  and inspection from extension execution contexts.
- [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
  documents exact extension origins, stdio framing, and user-level manifests in
  `NativeMessagingHosts/` under the selected user-data directory. This fixture
  registers only the development host below its fresh private profile.
- [Chromium CDP pipe implementation](https://chromium.googlesource.com/chromium/src/+/main/content/browser/devtools/devtools_pipe_handler.cc)
  is the primary implementation reference for the pipe harness. Version-bound
  compatibility must still be demonstrated by the declared test.

The local site repository's `tools/offline-site-roots.json` records Chromium
147.0.7727.116 at
`/nix/store/b5chknh5501v96xipynfdyfxjvn55jbw-chromium-147.0.7727.116`.
That package directory was inspected and exists. The same manifest explicitly
marks its missing site closure unresolved. Directory existence is not transitive
closure verification, Bazel input declaration or browser runtime proof.

Required integration before execution:

1. Export a dedicated browser closure inventory/registration from the locked Nix
   authority. The site flake models this as `closureInfo` over Chromium, Bash and
   coreutils. Either select Chromium under Omux's own locked flake and update the
   exact fixture version, or explicitly import and verify the existing site's
   pinned closure. Never copy an executable path into PATH as sufficient proof.
2. Declare browser closure contents and inventory as Bazel test inputs. Keep the
   potentially large browser closure separate from the ordinary runtime/tool
   graph. A browser executable label must refer to that declared closure.
3. Wire `//delivery:installed_chromium_test` with Python sources
   `test_installed_chromium.py`, `test_installed_custody.py`, `install.py`, `pack.py`
   and `portable.py`; data includes `chromium_transport.mjs`, release archive,
   `//extensions:chromium_dev_package`, declared Chromium/Node executables,
   browser inventory and the same three private D-Bus/keyring tools as
   `//delivery:installed_custody_test`. Linux-only; Bazel long timeout.
4. Argument order: bundle, development extension archive, Chromium executable,
   Node executable, CDP harness, dbus-run-session, dbus-daemon, keyring-daemon,
   browser closure store-paths inventory.
5. Execute only through the root-owned bounded Nix/Bazel lab lane after inputs
   and containment are established. No package downloads or provider calls.

The harness uses a CDP pipe rather than a debugging listener. Browser requests
are routed to an unused loopback proxy and DNS is disabled; only internal browser
contexts are inspected. Chromium's sandbox is not disabled. All child processes
inherit a unique private fixture process group. The outer wrapper has a deadline
and kills only that owned group, including browser/native-host descendants, on
completion or failure. Root containment must verify descendant cleanup; an
elapsed deadline never closes the acceptance gate.

Source preparation did not execute Chromium, Node, tests, generators, builds,
package installation or closure checks. No provider data or personal profiles
were opened. No installed-browser claim is established yet.
