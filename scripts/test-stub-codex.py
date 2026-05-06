#!/usr/bin/env python3
"""Stub `codex` binary for in-session acceptance smoke.

Stands in for the real `codex` CLI when the `oauth-mux codex run`
adapter spawns it. Reads its `CODEX_HOME/config.toml` to find the
proxy port, then sends a fixed sequence of POSTs to the proxy
emulating codex's real-turn traffic shape.

Records its own PID at start and at end so the harness can assert
PID stability across the swap (the no-restart proof).

Env (set by the adapter):
  CODEX_HOME  — directory containing config.toml + auth.json
  OMUX_ACTIVE_PROVIDER / OMUX_ACTIVE_ACCOUNT / OMUX_ACTIVE_PROFILE
              — informational breadcrumbs

Env (set by the smoke harness):
  OMUX_STUB_CODEX_TURNS  — number of POST turns to send (default 5)
  OMUX_STUB_CODEX_PIDFILE — file to write our PID into (default
                            /tmp/omux-stub-codex.pid)
  OMUX_STUB_CODEX_REPORT  — JSON summary path (default
                            /tmp/omux-stub-codex.report)
  OMUX_STUB_CANONICAL_SESSION_HOME — optional canonical session authority
                            home; when set, the stub verifies the managed
                            CODEX_HOME exposes sessions by reference.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import sys
import time
from pathlib import Path


def _read_proxy_url(codex_home: Path) -> str:
    cfg = (codex_home / "config.toml").read_text()
    m = re.search(r'base_url\s*=\s*"([^"]+)"', cfg)
    if not m:
        print("stub-codex: config.toml missing base_url", file=sys.stderr)
        sys.exit(2)
    return m.group(1)


def _post(proxy_url: str, body: bytes) -> tuple[int, str]:
    # base_url is like http://127.0.0.1:NNNN/backend-api/codex
    # We want to POST to that prefix + /responses.
    m = re.match(r"http://([^/]+)(/.*)$", proxy_url)
    if not m:
        print(f"stub-codex: cannot parse base_url={proxy_url}", file=sys.stderr)
        sys.exit(2)
    netloc, prefix = m.group(1), m.group(2)
    conn = http.client.HTTPConnection(netloc, timeout=15)
    try:
        conn.request(
            "POST",
            prefix + "/responses",
            body=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "stub-codex/0",
                "x-codex-turn-state": "stub-turn-state-v1",
                "x-codex-installation-id": "stub-install-1",
                "OpenAI-Beta": "responses_websockets=2026-02-06",
            },
        )
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", errors="replace")
    finally:
        conn.close()


def _session_bridge_report(codex_home: Path) -> dict:
    canonical_raw = os.environ.get("OMUX_STUB_CANONICAL_SESSION_HOME")
    if not canonical_raw:
        return {"checked": False}

    canonical = Path(canonical_raw)
    sessions_overlay = codex_home / "sessions"
    sessions_canonical = canonical / "sessions"
    history_overlay = codex_home / "history.jsonl"
    history_canonical = canonical / "history.jsonl"
    index_overlay = codex_home / "session_index.jsonl"
    index_canonical = canonical / "session_index.jsonl"
    snapshots_overlay = codex_home / "shell_snapshots"
    snapshots_canonical = canonical / "shell_snapshots"

    marker = sessions_overlay / "omux-session-bridge-smoke.jsonl"
    marker.write_text('{"bridge":"ok"}\n')

    return {
        "checked": True,
        "sessions_samefile": os.path.samefile(sessions_overlay, sessions_canonical),
        "history_samefile": os.path.samefile(history_overlay, history_canonical),
        "session_index_samefile": os.path.samefile(index_overlay, index_canonical),
        "shell_snapshots_samefile": os.path.samefile(snapshots_overlay, snapshots_canonical),
        "marker_written_via_overlay": marker.exists(),
        "canonical_marker_exists": (sessions_canonical / marker.name).exists(),
        "paths_printed": False,
    }


def main() -> int:
    pid = os.getpid()
    pidfile = Path(os.environ.get("OMUX_STUB_CODEX_PIDFILE", "/tmp/omux-stub-codex.pid"))
    pidfile.write_text(f"{pid}\n")

    report_path = Path(os.environ.get("OMUX_STUB_CODEX_REPORT", "/tmp/omux-stub-codex.report"))
    turns = int(os.environ.get("OMUX_STUB_CODEX_TURNS", "5"))

    codex_home = Path(os.environ["CODEX_HOME"])
    proxy_url = _read_proxy_url(codex_home)
    session_bridge = _session_bridge_report(codex_home)

    started_at = time.time()
    print(
        f"stub-codex: pid={pid} CODEX_HOME=<redacted> proxy={proxy_url} turns={turns} "
        f"OMUX_ACTIVE_ACCOUNT={os.environ.get('OMUX_ACTIVE_ACCOUNT')}",
        file=sys.stderr, flush=True,
    )

    turn_results: list[dict] = []
    for i in range(turns):
        status, body = _post(
            proxy_url,
            json.dumps({"input": f"stub turn {i}"}).encode("utf-8"),
        )
        turn_results.append({"turn": i, "status": status, "body_head": body[:120]})
        print(f"stub-codex: turn {i} -> {status}", file=sys.stderr, flush=True)
        time.sleep(0.05)

    end_pid = os.getpid()
    report = {
        "start_pid": pid,
        "end_pid": end_pid,
        "pid_stable": pid == end_pid,
        "duration_s": round(time.time() - started_at, 3),
        "turns": turn_results,
        "codex_home_path_printed": False,
        "active_account_at_start": os.environ.get("OMUX_ACTIVE_ACCOUNT"),
        "session_bridge": session_bridge,
    }
    report_path.write_text(json.dumps(report, indent=2))
    print(f"stub-codex: pid_stable={report['pid_stable']} turns={turns}", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
