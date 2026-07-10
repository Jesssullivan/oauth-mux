# Wiring `oauth-mux status --json` advice into a Claude Code statusLine (2026-07-09)

Status: operator runbook. Docs-only; no runtime code in this change.
Trackers: Linear TIN-2061, TIN-2719.

Claude Code supports a `statusLine` command in `settings.json`: an
operator-supplied shell command whose stdout becomes the status line rendered
at the bottom of every session. This runbook shows how to point that command
at `oauth-mux status --json` so the status line surfaces the valet advisor's
current read on Claude account/class health, once that advice is exposed.

## Caveat: this lands with PR2, not today

As of this writing, `oauth-mux status --json` emits only `version` and a
`providers` map (`{kind, accounts}` counts) — see `runStatus` in
`src/main.zig` (~:443). The pure advisor core that computes per-class
`ClassSummary` / `Suggestion` / `wait_until` data (`src/quota/advise.zig`)
merged in TIN-2719 M0 PR1 (#449), but **nothing wires that advisor into the
CLI's `status --json` output yet**. That wiring is TIN-2719 M0 PR2. Treat
everything below the field-shape example as the target shape, not a shape you
can `jq` against today — **the advice block lands with PR2** (not merged as
of 2026-07-09). Until PR2 merges, `oauth-mux status --json` will not contain
an `"advice"` key and the jq one-liner below will emit `null`/empty for that
field.

The anticipated shape is inferred directly from the merged `Advice` /
`ClassSummary` / `Suggestion` structs in `src/quota/advise.zig` (~:105-135);
exact JSON key names are PR2's call and may shift slightly on landing —
confirm against the actual PR2 diff before depending on this in a script you
run unattended.

## Anticipated `status --json` advice shape

```json
{
  "version": "0.1.14",
  "providers": { "claude": { "kind": "claude", "accounts": 5 } },
  "advice": {
    "claude": {
      "classes": [
        { "provider": "claude", "class": "fable", "status": "available", "usage_pct": 42, "resets_at": null, "provenance": "inferred" },
        { "provider": "claude", "class": "opus",  "status": "waiting",   "usage_pct": 97, "resets_at": 1783718400000, "provenance": "inferred" }
      ],
      "suggestion": { "provider": "claude", "account": "sulliwood", "class": "fable", "reason": "credential-ready and quota-available with exact class parity", "provenance": "inferred" },
      "wait_until": null
    }
  }
}
```

Field notes (from `src/quota/advise.zig`):

- `status` is `bucket.EffectiveStatus`: one of `available`, `waiting`,
  `tier_blocked`, `plan_gated` (`src/quota/bucket.zig` ~:350).
- `provenance` is one of `unobserved`, `assumed`, `inferred`, `proven`
  (declaration order is confidence rank; a class with no HealthStore row at
  all is `unobserved`, never silently `assumed`).
- `suggestion` is `null` when no account can be honestly recommended for the
  demand; `wait_until` (epoch ms) is then set to the earliest known recovery
  instant across waiting candidates, or `null` if nothing recoverable is
  known.

## The jq one-liner

Once PR2 lands, this renders a single-line summary for whichever class you
care about (`fable` in this example — swap for `opus`/`sonnet`/`haiku`):

```bash
oauth-mux status --json | jq -r '
  .advice.claude as $a
  | ($a.classes[] | select(.class=="fable")) as $c
  | "claude: " + $c.status
    + " → " + ($a.suggestion.account // "none")
    + " (" + $c.provenance + ")"
'
```

Example output once real advice data is present:

```text
claude: available → sulliwood (inferred)
```

or, when every account for the class is waiting:

```text
claude: waiting → none (inferred)
```

Before PR2 merges, run this against today's `status --json` output and expect
a `jq` error (`.advice` is `null`, `.advice.claude` errors on member access of
`null`) — that is expected, not a bug in the one-liner. Guard it defensively
if you want a graceful "not yet available" line in the interim:

```bash
oauth-mux status --json | jq -r '
  if .advice == null then "claude: advice not available (upgrade oauth-mux)"
  else
    (.advice.claude) as $a
    | ($a.classes[] | select(.class=="fable")) as $c
    | "claude: " + $c.status + " → " + ($a.suggestion.account // "none") + " (" + $c.provenance + ")"
  end
'
```

## `settings.json` statusLine stanza

Claude Code reads `statusLine` from `settings.json` (project `.claude/` or
user-level `~/.claude/settings.json`):

```json
{
  "statusLine": {
    "type": "command",
    "command": "oauth-mux status --json | jq -r 'if .advice == null then \"claude: advice not available\" else (.advice.claude) as $a | ($a.classes[] | select(.class==\"fable\")) as $c | \"claude: \" + $c.status + \" \\u2192 \" + ($a.suggestion.account // \"none\") + \" (\" + $c.provenance + \")\" end'",
    "padding": 0
  }
}
```

Notes:

- `oauth-mux` must be on `PATH` for the shell the statusLine command runs
  under (same constraint as any other statusLine command that shells out).
- `→` is escaped as `→` in the JSON string above because it sits inside
  a `settings.json` string literal; you can also just use `->` if you'd
  rather not deal with the escape.
- Claude Code invokes the statusLine command frequently (roughly once per
  render tick). `oauth-mux status --json` today only reads local config +
  the HealthStore file — no network call — so it should be cheap enough for
  this cadence once PR2 lands, but this runbook does not benchmark it.

## Reserved: a future compact `status --statusline` renderer

This runbook's jq pipeline is a reasonable bridge, but jq-in-a-JSON-string is
fragile to maintain (quoting, the `→` escape, drift if PR2's key names
change). A cleaner long-term shape is a dedicated
`oauth-mux status --statusline [--class <class>]` renderer that emits the
one-line summary directly — no `jq` dependency, no JSON re-parsing, a stable
CLI-owned output contract instead of a hand-maintained downstream query. That
renderer does not exist yet and is not scoped to any open PR as of this
writing; this section only reserves the name so a future implementation
doesn't have to re-litigate the shape from scratch. If you build it, prefer
matching the line format already established by this runbook's jq one-liner
(`"claude: <status> → <account|none> (<provenance>)"`) so dashboards and
muscle memory built against the jq bridge keep working after the cutover.
