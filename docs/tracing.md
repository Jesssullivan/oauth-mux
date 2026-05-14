# oauth-mux Tracing

`oauth-mux` can emit redacted JSONL trace events for route, auth, runtime, and
native Codex command decisions. Tracing is off by default.

Enable it with one global flag:

```bash
OMUX_TRACE=1 oauth-mux codex preflight --profile codex-max --capability codex-max --json
```

By default, events are appended to:

```text
$OMUX_STATE_DIR/trace.ndjson
```

If `OMUX_STATE_DIR` is unset, the normal oauth-mux state directory is used. To
send traces to a specific file:

```bash
OMUX_TRACE=1 \
OMUX_TRACE_FILE=/tmp/oauth-mux-trace.ndjson \
oauth-mux route explain --profile codex-max --capability codex-max --json
```

For external trace correlation, callers may provide:

```bash
OMUX_TRACE_ID=11111111111111111111111111111111
OMUX_SPAN_ID=2222222222222222
OMUX_PARENT_SPAN_ID=3333333333333333
```

Each event uses schema `oauth-mux.trace.v1` and includes:

- `ts_unix_ms`
- `name`
- `severity`
- `trace_id`
- `span_id`
- `parent_span_id`
- `attributes`
- `redaction`

The first traced decisions are:

- `health.normalize`: persisted transient provider degradation recovered for
  route selection after its retry window expires.
- `route.evaluate`: no-spend route runtime, liveness, action, and selectability.
- `codex.native_binary.resolve`: native Codex binary resolution without printing
  absolute paths.
- `codex.native_command.spawn` and `codex.native_command.exit`: explicit
  oauth-mux-managed Codex admin commands without printing `CODEX_HOME`.
- `codex.shim.pass_through`: installed `codex` shim admin-command pass-through
  without route election or native binary path output.

Trace output must not include OAuth token bytes, raw provider account ids, raw
Codex session ids, or local auth/config file paths. Attach `trace.ndjson` to a
support issue only after confirming it was produced by the current version and
does not include local shell output from other tools.
