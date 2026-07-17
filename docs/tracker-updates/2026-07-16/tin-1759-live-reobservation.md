# TIN-1759 — live launchd exposure re-observed unchanged (2026-07-16)

Posted 2026-07-16. Read-only re-observation on the dogfood host: the
resident keepalive LaunchAgent's inherited environment still carries the
plaintext secret values first audited 2026-07-13 (order of thirty direct
secret-bearing variables alongside their `*_FILE` pointer siblings; same
exposure class, same containment gap). No containment change has activated
since the audit; the drafted narrowing (lab PR #814) remains un-activated.
No service mutation, restart, or rotation was performed — activation,
restart, live value-free proof, and rotate-last remain operator actions in
that order.

Consequence unchanged: `R-TIN-1759` stays closed and continues to block
every Stage-4+ action in the v0.2 evaluation ladder (installed candidate,
resident mutation, installed dogfood), and also blocks fixing the known
resident-binary version skew (TIN-2723): the LaunchAgent still runs the
v0.1.14 binary while the PATH winner is v0.1.15 — `doctor` warns
`resident_sha_differs_and_version_older`, and the restart that would fix it
is exactly the mutation this gate forbids.

References: Linear TIN-1759, TIN-2723; ladder §5 (`R-TIN-1759`), §9 Stage 4.
