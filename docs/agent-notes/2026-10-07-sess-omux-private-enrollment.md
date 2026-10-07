# Private second-account enrollment implementation

Authority: user-authorized real-account Omux work, AGENTS.md,
R-HOOK-CONVERGENCE-20261004 and R-N13. Root owns this signed branch and
remains the sole execution coordinator. The Original index/worktree is not staged.

This branch is isolated from the running native-build worktree. It implements
device-only native OAuth enrollment into a fresh private profile, a private Qt
code dialog and local Wayland portal transport to Yoga. Codes remain in private
pipes and process memory; only fixed status and opaque profile handles enter
diagnostics. Device setup does not claim identity verification, live continuity,
stock support or refresh-writer adoption.

Source nouns: `delivery/native_account_login{,_guarded}.py`,
`tools/guard_codex_login_profile.py`,
`tools/codex_retained_device_api_qualification.py`,
`tools/native_enrollment_repository.bzl`, `tools/yoga_portal_{carrier,worker}.py`,
and `clients/linux/device_code_dialog.{h,cpp}`.

Qualification order: offline guard/helper/carrier/Qt models; actual retained009
full-runtime device API version/schema qualification; actual Yoga dialog and
Qt closure plus current Wayland seat qualification; guarded device login and
operator consent; independent daemon identity and encrypted-custody verification.
All executions use locked Nix/Bazel under unchanged aggregate containment.
No provider calls or desktop actions have occurred on this branch.

Tracks: TIN-5338/TIN-5421 native integration, TIN-1818/TIN-1798 account
enrollment, TIN-2063 installation. Tracker facts remain in the Original
`docs/tracker-updates/live-account-proof-2026-10-07.json` until this source is
qualified and reconciled. Completion never follows merely from a schema.

R-N12 per-command hook alternative: advisory hooks are bypassed only for this
owned signed commit; no global hooks or remotes are changed. Source and commit
readbacks and actual declared checks supply the traceable alternative.

Initial source `14bf849234a9d00fc4e962ac2c9afc47898feac6` ran thirteen
declared targets in `5b07a804-8fda-4a6b-8b11-98c0c86946db`, with nine
passing and four failing; exit3, descendants empty and no controller failure.
The guard, existing live/retained/dependency/SSH contracts, wrapper and actual
offscreen Qt display/EOF/cancellation passed. Refused targets were document
classification and three fixture defects: an escaped literal instead of a
control newline, BytesIO lacking the modeled descriptor, and cleanup expecting
termination despite modeled graceful exit. Corrections retain production
predicates; cleanup now genuinely models timeout followed by owned termination.
The document is classified in authority.json. Yoga uses its recorded remote
account rather than assuming that the local username matches. These corrections
are unverified until their next declared invocation completes.
