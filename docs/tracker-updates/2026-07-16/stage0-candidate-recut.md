# Stage 0 — candidate record re-cut at current main (2026-07-16)

The evaluation ladder's baseline table
(`docs/runbooks/omux-v0.2-evaluation-ladder-2026-07-14.md` §2) froze
`c4622f8` as the authored-from candidate. Main has since advanced four
commits (#478, #479, #480, #481). Per ladder §6, a green run on an ancestor
is stale; this note re-cuts the Stage 0 record at today's head so downstream
work cites current truth.

## Sanitized candidate record

| Field | Value |
| --- | --- |
| Source commit | `bc59ca1b3f7d84049d023c0364247a8ecbb51bb5` |
| Source tree | `7c47282987345fd42147619807663c1dd2c44423` |
| Declared version | none (v0.2 unshipped; stable remains v0.1.15) |
| Release fields (§6) | deferred to the pre-Stage-2 record, as the ladder allows |
| PR CI / Public Source / GF proof | green at merge for #477–#481; exact-head run records live in GitHub #463 merge-proof comments (2026-07-14) |

## Gate states (all closed; recorded, not inferred)

`O-OWNERSHIP`, `S-PROVIDER-SPEND`, `R-TIN-1759`, `L-TIN-2077`,
`P-PROMOTION` — all closed. No enrollment, install, service mutation,
provider call, or live continuity action is authorized by this record.

## Claim boundary

- TIN-2057 remains exactly **0/11**. This record earns no golden row and is
  not Stage 1/2/3 evidence.
- The managed-Claude adapter on this candidate is a unit-tested library only:
  its five modules are imported solely by the test root and are not reachable
  from any CLI verb; real upstream forwarding is compile-disabled.
- Ladder §6 still applies forward: any product/test/release/redaction code
  change after this commit changes the candidate. The authoritative pre-Stage-2
  candidate record (with complete release fields) must be re-cut after the
  last code-changing PR of the current increment train, and Stage 2 dispatch
  must cite that record, not this one.

References: Linear TIN-2057, TIN-1829, TIN-2047; GitHub `#463`, `#477`–`#481`.
