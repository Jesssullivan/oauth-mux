---
title: Standard Secret Service setup and actual native build limit
date: 2026-10-07
status: active
summary: Source-reviewed OS-mediated unlock avoids guessing a sudo factor; platform proof remains pending.
refs:
  - TIN-2063
  - TIN-5338
  - TIN-1818
  - https://github.com/Jesssullivan/oauth-mux/pull/535
  - https://github.com/Jesssullivan/oauth-mux/pull/536
---

Authority: user-authorized normal OS unlock via Lab SOPs and the explicit
instruction to check Neo; repository AGENTS.md; R-N11/R-N12/R-N13.
The original five-hour checkpoint was missed and the full objective is incomplete.

## Source composition and OS boundary

The separate standard-vault branch starts at signed resident I10
`15facb976ae43ce1729e56de817f864064869351`. Root applied reviewed metadata
proposal SHA256 `c057135d02ba54970f73cc42a74c6c29e144f9013c267d79ea701668e64f0b1d`
and standard carrier proposal SHA256
`9e15d5f7b0c9d06d8843fbc45cfa672fc086cb5e520727442f5a78a2f95ba218`.
Independent review of the actual composition found no static blocker or drift.

Version two authenticates the actual local bus peer and the existing unique
service owners by UID, PID and stable process start. It performs no executable
inspection as service-role authority. Version one's executable/factor contract
remains unchanged. The standard namespace contains only the existing user bus;
it does not expose SOPS material or a proprietary keyring control socket.

The new metadata action reads the existing default alias and Locked property.
Unlock uses the pinned unique service owner and standard Unlock/Prompt protocol.
The opaque collection path travels through a bounded private pipe rather than
argv or public output. Prompt completion is bound to sender/object/result, with
120-second prompt and original aggregate deadlines; cancellation remains explicit.
Neither action starts a provider, reads collection items or secrets, creates a
collection, writes a wrapping key, activates Omux, or invokes an account provider.

Helper-connection unlock is distinct from resident custody. Independent Locked
readback may remain true; actual resident readiness must be checked separately.
The standard path requires no assumed mapping from sudo to keyring credentials.

Required new tests: `//delivery:resident_standard_vault_models` and
`//tools:guard_resident_standard_vault_test`, alongside the existing vault,
enrollment and execution regression targets. These tests and actual new metadata,
Unlock/Prompt and resident custody readback are unrun at this source checkpoint.
Earlier I10 tests cannot qualify this changed graph.

## Actual native outcome

Frozen N4 `b332f596c711e45a7fea4ebcdae559f543cc3816` qualification/CLI attempt
six, aggregate eight, ended in epoch `5a973300-9c1b-49b1-99ff-8460317eaeba`.
Receipt SHA256 `12543b3f84d6db2fd4c70074248da87627f5666df14c783f281ab7bc5f2013c0`:
guard exit 125, workload exit 9, `preservation-failed`, descendants empty,
controller failure null. Source/export after-cleanup verification is false and
phase-two transition after-cleanup verification is null.

Independent exact-unit readback showed `Result=oom-kill`, MemoryPeak 4294967296,
MainPID zero, empty ControlGroup and failed/inactive workload. The frozen 4 GiB
bound held; no broader host or process-tree observation is implied. The guard's
cleanup ownership remains unproved, rather than being upgraded by this note.
Schema attempt seven, fresh packaging and native/live proof remain held. No retry,
counter reset, cap change or source/cache mutation is authorized by this receipt.

Zero accounts are durably retained. Actual owned inactive package replacement
remains the existing installed proof. Ordinary native resume, accepted live
history, two-account same-process handoff, browser consent, Darwin, unmodified
Codex support and achieved reliability targets remain unproved.
