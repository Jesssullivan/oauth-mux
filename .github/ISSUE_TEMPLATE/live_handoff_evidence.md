---
name: Live handoff evidence
about: Share redacted evidence for a quota/auth handoff or failed handoff
title: "[evidence] "
labels: evidence
assignees: ""
---

## Scenario

- provider/harness:
- route labels involved:
- command used:
- expected handoff:
- observed result:

## Status summary

Paste redacted status summary output:

```bash
oauth-mux codex status-latest --json
```

If using a saved artifact:

```bash
oauth-mux codex status-latest --status-file <redacted-status.ndjson> --json
```

## Claim boundary

Check all that apply:

- [ ] provider-originated quota event observed
- [ ] auth failure observed
- [ ] fallback route returned success
- [ ] user-visible failure occurred
- [ ] same-thread continuity is being claimed
- [ ] unmanaged daemon hot-swap is being claimed

## Privacy check

Do not paste raw tokens, refresh tokens, account ids, emails, credential paths,
session ids, prompt text, or assistant transcript content.
