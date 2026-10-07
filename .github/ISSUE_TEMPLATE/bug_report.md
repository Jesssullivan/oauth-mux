---
name: Bug report
about: Report a version-scoped Omux failure with redacted evidence
title: "[bug] "
labels: bug
assignees: ""
---

## Expected and observed behavior

Describe the normal application command, native version/hook and affected
operation. State whether the report concerns historical v0.1.15 or the
experimental native reset. Include artifact digest/revision, OS/architecture,
install source, daemon availability and the specific capability involved.

## Local evidence

For the experimental checkout, these metadata reads use the declared graph:

```bash
nix develop --command bazelisk run //:omux -- version
nix develop --command bazelisk run //:omux -- status
nix develop --command bazelisk run //:omux -- accounts
```

Scrub labels, paths, handles and identifiers before sharing. A snapshot is not a
live support claim; include the bounded reproduction and typed error. A timed-out
mutation may have completed: reconcile state before retrying it.

## Acceptance and scope

Link the applicable user-story/support/native-contract ID from docs/README.md.
Identify lost process/session/tool authority, a routine handoff prompt, unsafe
replay, custody failure or missing capability explicitly.

Do not paste credentials, cookies, OTPs, raw account IDs, emails, provider bodies,
prompts, transcript contents or PII screenshots. Never use a paid provider call
as an implicit diagnostic.
