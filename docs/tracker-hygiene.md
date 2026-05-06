# Tracker Hygiene

Use the GitHub/Linear connectors for tracker reads and writes when their
installation has the required permissions. If the GitHub Apps connector returns
`403 Resource not accessible by integration` for an issue or PR comment, use the
local `gh` fallback instead of dropping the tracker update.

```bash
scripts/github-tracker-comment.sh ISSUE path/to/body.md
```

For stdin:

```bash
printf '%s\n' 'tracker update body' | scripts/github-tracker-comment.sh ISSUE -
```

The script refuses empty bodies and obvious bearer/JWT/API-key/PAT-shaped
strings before posting. That guard is not a substitute for manually reviewing
redacted live evidence, status artifacts, and cassette snippets before putting
them in a public tracker.

If `GH_TOKEN` or `GITHUB_TOKEN` points at a stale token but local keyring auth is
valid, force `gh` to use the keyring:

```bash
scripts/github-tracker-comment.sh --ignore-env-token ISSUE path/to/body.md
```

Dry-run the auth and body checks without posting:

```bash
scripts/github-tracker-comment.sh --dry-run ISSUE path/to/body.md
```

Tracked limitation: GitHub #198.
