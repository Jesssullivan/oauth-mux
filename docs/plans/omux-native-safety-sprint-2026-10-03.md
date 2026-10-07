# Omux native safety implementation sprint

Status: active implementation checkpoint, experimental and unshipped.
Start `2026-10-03T10:07:56Z` (06:07:56 EDT); five-hour checkpoint
`2026-10-03T15:07:56Z` (11:07:56 EDT). The active umbrella goal and
[checkpoint ledger](../../.goal/omux-native-safety-2026-10-03.json) record this
bounded push. They do not dispatch future work. The previous ratification
receipts and weekend objectives retain their original scope and dates.

## Interview and product scope

The user selected daemon and native continuity safety first, named neo/pzm as
Darwin environments and sting/yoga as Linux environments, and selected installed
platform proof where available. The [active reset](omux-native-account-lifecycle-reset-2026-10-02.md),
[charter](../product/charter.md), [support gates](../product/support-and-completeness.md)
and [authority map](../authority-map.md) remain design authority. Twelve parallel
GPT-6.1 Sol workers implement and review bounded changes; the root integrates
the graph and evidence.

The user's October 3 host-role correction assigns compilation to PZM through
the lab's existing Bazel REAPI lane. Neo is the teletype and a read-only source
for ASFW/FireWire, cmux and related Darwin consumer patterns, including their
Justfile dispatch recipes. Omux executions continue through locked Nix+Bazel;
reading a dispatch recipe does not restore Just as an Omux build entrypoint.
The original five-hour checkpoint and its partial result remain unchanged.

The outcome remains ordinary application launch with compatible same-process
continuity. Native history, tools and approval authority stay with the
application. Accepted work is never replayed. Code, fixtures, private real-vault
proof, installed artifacts and live provider continuity have distinct receipts.
No provider evaluation accounts or spending budget were supplied. Codex stock
hook availability and live continuity remain missing gates; this sprint does
not ship a fork or enable browser credential exports.

## Acceptance work

| Work | Required predicate | Tracker |
| --- | --- | --- |
| Request authority | Mandatory unique request ID pins application/session/binding/demand. A durable two-attempt budget survives lease expiry and restart. Accepted/completed/abandoned/unknown work cannot reacquire. Exact report duplicates acknowledge without another transition. | TIN-5337; NAC-004, NAC-008, NAC-009 |
| Mutation authority | Stable operation IDs and expected revisions precede side effects. Intent is keyed and canonicalized; completed redacted results survive lost replies and restart. Uncertain external actions remain indeterminate. Clients query status without submitting a new identity. | TIN-5337; REL-007 |
| Backup recovery | Independent authenticated installation/sequence/nonce authority reserves before SQLite commit. SQLite-only restore cannot reactivate forgotten accounts or older generations while the independent authority survives. Missing or mismatched authority and unsupported legacy migration fail closed. Full-user rollback is outside this boundary. | TIN-5336; LC-04, LC-05, LC-07, REL-004 |
| Runtime custody | Supplied Linux runtime paths are private, validated and never silently replaced; absence uses the explicit state/run fallback. Daemon and thin clients agree on the installation-specific socket. The persistent singleton fences different runtime selections and existing legacy locks. | TIN-5335; LC-11, SC-02 |
| Observation | Local health/export initiates no provider or source work. Fixed typed observations have bounded denominators, latency histograms and honest in-memory coverage. No measured availability or contractual SLA is inferred. | TIN-5342; REL-009, REL-010 |
| Platform proof | Exercise isolated genuine Secret Service and private Keychain where executable tooling and host access permit. Installed proof names the exact host/artifact/action predicates; unavailable resources get observed blockers and next actions. | TIN-5340, TIN-2723, TIN-2830; SC-01, SC-02, SC-08 |

The bounded request and mutation ledgers refuse new admission when full; they
never silently evict replay authority. Authenticated long-term retirement needs
a separate contract before reliable long-lived operation can be claimed.

## Execution and evidence

All builds, tests, generators, packages and host tooling execute through locked
Nix and declared Bazel actions. Local execution is the default. Host probes use
strict existing SSH trust and operator authorization; transferred source comes
from the explicit public-source archive, excluding Git and personal state.
Vault tests use disposable private buses/keyrings or a named temporary Keychain.
No personal auth stores or default user services are changed.

The [implementation receipt](../implementation/native-safety-evidence-2026-10-03.md)
records actual actions and limits. The [Linear receipt](../tracker-updates/native-safety-sprint-2026-10-03.md)
records the distinct NS5 milestone and issue changes; tracker percentages cannot
substitute for proof. Generated reference facts and the SPA reconcile only with
the real source producer. No deadline passage promotes support or publication.
