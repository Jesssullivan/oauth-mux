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
  OMUX_STUB_CODEX_ENDPOINTS — optional comma-separated endpoint suffixes for
                            each POST turn, relative to the managed base URL
                            (default "responses"). The last endpoint is reused
                            when turns exceed entries.
  OMUX_STUB_CODEX_PIDFILE — file to write our PID into (default
                            /tmp/omux-stub-codex.pid)
  OMUX_STUB_CODEX_REPORT  — JSON summary path (default
                            /tmp/omux-stub-codex.report)
  OMUX_STUB_CANONICAL_SESSION_HOME — optional canonical session authority
                            home; when set, the stub verifies the managed
                            CODEX_HOME exposes sessions by reference.
  OMUX_STUB_CODEX_CHATGPT_ACCOUNT_ID — optional ChatGPT-Account-ID header
                            to send on every proxy request.
  OMUX_STUB_CODEX_AUTH_TOKENS — optional comma-separated bearer tokens to
                            send through Authorization, one per turn. The
                            last token is reused when turns exceed entries.
  OMUX_STUB_APPEND_SESSION — optional path relative to CODEX_HOME to append
                            a redacted marker to. Used by resume smokes to
                            prove the managed session authority receives
                            child writes.
  OMUX_STUB_REWRITE_AUTH_JSON — optional auth.json contents to write inside
                            CODEX_HOME before sending turns. Used to emulate
                            Codex persisting refreshed ChatGPT tokens in the
                            managed overlay.
  OMUX_STUB_CODEX_TURN_DELAY_MS — optional delay between turns (default 50).
  OMUX_STUB_CODEX_BODY_BYTES — optional approximate JSON request body size for
                            each POST turn. Used to force proxy->upstream
                            request writes across multiple socket writes.
  OMUX_STUB_CODEX_MODEL — exact public model carried by each synthetic turn
                            (default "gpt-5.3-codex").
  OMUX_STUB_CODEX_DISCONNECT_TURNS — optional comma-separated turn indexes that
                            should send the request then close the proxy socket
                            before reading the streamed response.
  OMUX_STUB_CODEX_PARTIAL_STALL_MS — optional millisecond hold for a deliberately
                            incomplete request before normal turns. Used to prove
                            the proxy loop is not pinned by a half-open local socket.
  OMUX_STUB_CODEX_WEBSOCKET_PROBE — optional "1" to send a Codex-shaped
                            WebSocket upgrade GET before normal POST turns.
  OMUX_STUB_CODEX_WEBSOCKET_RST_PROBE — optional "1" to send an additional
                            WebSocket upgrade GET and reset the socket before
                            reading the managed proxy's response.
  OMUX_STUB_CODEX_FAIL_MODE — optional startup failure mode. "sqlite_locked"
                            emits Codex's sqlite lock startup error and exits 1.
  The report records argv after the stub binary so CLI forwarding smokes can
  assert `oauth-mux codex ...` command shape without provider traffic.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import struct
import sys
import threading
import time
from pathlib import Path


def _read_proxy_url(codex_home: Path) -> str:
    cfg = (codex_home / "config.toml").read_text()
    m = re.search(r'openai_base_url\s*=\s*"([^"]+)"', cfg)
    if not m:
        m = re.search(r'base_url\s*=\s*"([^"]+)"', cfg)
    if not m:
        print("stub-codex: config.toml missing proxy base URL", file=sys.stderr)
        sys.exit(2)
    return m.group(1)


def _config_report(codex_home: Path) -> dict:
    cfg = (codex_home / "config.toml").read_text()
    return {
        "checked": True,
        "native_provider_namespace": 'model_provider = "openai"' in cfg,
        "proxy_base_url_present": 'openai_base_url = "http://127.0.0.1:' in cfg
        and "/backend-api" in cfg,
        "shadow_mux_provider_absent": 'model_provider = "oauth_mux_openai"' not in cfg
        and "[model_providers.oauth_mux_openai]" not in cfg,
        "config_layout_root_partitioned": cfg.find('model_provider = "openai"') < cfg.find("[tui.model_availability_nux]")
        if "[tui.model_availability_nux]" in cfg
        else True,
        "user_feature_apps": "apps = true" in cfg,
        "user_feature_memories": "memories = true" in cfg,
        "user_feature_multi_agent": "multi_agent = true" in cfg,
        "managed_feature_terminal_resize_reflow": "terminal_resize_reflow = true" in cfg
        or "features.terminal_resize_reflow = true" in cfg,
        "managed_feature_external_migration": "external_migration = true" in cfg
        or "features.external_migration = true" in cfg,
        "managed_feature_goals": "goals = true" in cfg or "features.goals = true" in cfg,
        "managed_feature_prevent_idle_sleep": "prevent_idle_sleep = true" in cfg
        or "features.prevent_idle_sleep = true" in cfg,
        "user_experimental_legacy": "experimental_legacy_flag = true" in cfg,
        "user_tui_model_availability_nux": "[tui.model_availability_nux]" in cfg and '"gpt-5.5" = 2' in cfg,
        "user_mcp_server": "[mcp_servers.design]" in cfg,
        "stdio_mcp_remote_fields_absent": "https://figma.invalid/mcp" not in cfg
        and "FIGMA_ACCESS_TOKEN" not in cfg,
        "http_mcp_remote_fields_preserved": "[mcp_servers.linear]" in cfg
        and "https://mcp.linear.app/mcp" in cfg
        and "LINEAR_API_KEY" in cfg,
        "user_approval_policy": 'approval_policy = "on-request"' in cfg,
        "user_sandbox_mode": 'sandbox_mode = "workspace-write"' in cfg,
        "profile_model_provider_absent": 'model_provider = "profile_provider"' not in cfg,
        "stale_mux_provider_absent": "https://stale.invalid" not in cfg,
        "path_printed": False,
    }


def _auth_token_for_turn(turn: int) -> str | None:
    raw = os.environ.get("OMUX_STUB_CODEX_AUTH_TOKENS", "")
    if not raw:
        return None
    tokens = [part for part in raw.split(",") if part]
    if not tokens:
        return None
    return tokens[min(turn, len(tokens) - 1)]


def _disconnect_turns() -> set[int]:
    raw = os.environ.get("OMUX_STUB_CODEX_DISCONNECT_TURNS", "")
    turns: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        turns.add(int(part))
    return turns


def _endpoint_for_turn(turn: int) -> str:
    raw = os.environ.get("OMUX_STUB_CODEX_ENDPOINTS", "")
    endpoints = [part.strip().lstrip("/") for part in raw.split(",") if part.strip()]
    if not endpoints:
        return "responses"
    return endpoints[min(turn, len(endpoints) - 1)]


def _payload_for_turn(turn: int) -> bytes:
    target_bytes = int(os.environ.get("OMUX_STUB_CODEX_BODY_BYTES", "0"))
    model = os.environ.get("OMUX_STUB_CODEX_MODEL", "gpt-5.3-codex")
    if target_bytes <= 0:
        return json.dumps({"model": model, "input": f"stub turn {turn}"}).encode("utf-8")

    payload = {"model": model, "input": f"stub turn {turn}", "padding": ""}
    base_len = len(json.dumps(payload).encode("utf-8"))
    if target_bytes > base_len:
        payload["padding"] = "x" * (target_bytes - base_len)
    return json.dumps(payload).encode("utf-8")


def _path_for_turn(prefix: str, turn: int) -> tuple[str, str]:
    endpoint = _endpoint_for_turn(turn)
    return f"{prefix}/{endpoint}", endpoint


def _request_parts(proxy_url: str, body: bytes, turn: int) -> tuple[str, bytes]:
    m = re.match(r"http://([^/]+)(/.*)$", proxy_url)
    if not m:
        print(f"stub-codex: cannot parse base_url={proxy_url}", file=sys.stderr)
        sys.exit(2)
    netloc, prefix = m.group(1), m.group(2)
    path, _ = _path_for_turn(prefix, turn)
    headers = [
        f"POST {path} HTTP/1.1",
        f"Host: {netloc}",
        "Content-Type: application/json",
        "User-Agent: stub-codex/0",
        "x-codex-turn-state: stub-turn-state-v1",
        "x-codex-installation-id: stub-install-1",
        "OpenAI-Beta: responses_websockets=2026-02-06",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    account_id = os.environ.get("OMUX_STUB_CODEX_CHATGPT_ACCOUNT_ID")
    auth_token = _auth_token_for_turn(turn)
    if account_id:
        headers.append(f"ChatGPT-Account-ID: {account_id}")
    if auth_token:
        headers.append(f"Authorization: Bearer {auth_token}")
    request = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body
    return netloc, request


def _post(proxy_url: str, body: bytes, turn: int) -> tuple[int, str]:
    # base_url is like http://127.0.0.1:NNNN/backend-api/codex
    # We want to POST to that prefix + /responses.
    m = re.match(r"http://([^/]+)(/.*)$", proxy_url)
    if not m:
        print(f"stub-codex: cannot parse base_url={proxy_url}", file=sys.stderr)
        sys.exit(2)
    netloc, prefix = m.group(1), m.group(2)
    path, _ = _path_for_turn(prefix, turn)
    conn = http.client.HTTPConnection(netloc, timeout=15)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "stub-codex/0",
        "x-codex-turn-state": "stub-turn-state-v1",
        "x-codex-installation-id": "stub-install-1",
        "OpenAI-Beta": "responses_websockets=2026-02-06",
    }
    account_id = os.environ.get("OMUX_STUB_CODEX_CHATGPT_ACCOUNT_ID")
    auth_token = _auth_token_for_turn(turn)
    if account_id:
        headers["ChatGPT-Account-ID"] = account_id
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    try:
        conn.request(
            "POST",
            path,
            body=body,
            headers=headers,
        )
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", errors="replace")
    finally:
        conn.close()


def _post_and_disconnect(proxy_url: str, body: bytes, turn: int) -> tuple[int, str]:
    netloc, request = _request_parts(proxy_url, body, turn)
    host, port_s = netloc.rsplit(":", 1)
    sock = socket.create_connection((host, int(port_s)), timeout=15)
    try:
        sock.sendall(request)
        linger = struct.pack("ii", 1, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
    finally:
        sock.close()
    return 0, "client_disconnected_before_response"


def _start_partial_stall(proxy_url: str, hold_ms: int) -> dict:
    if hold_ms <= 0:
        return {"enabled": False}
    m = re.match(r"http://([^/]+)(/.*)$", proxy_url)
    if not m:
        print(f"stub-codex: cannot parse base_url={proxy_url}", file=sys.stderr)
        sys.exit(2)
    netloc, prefix = m.group(1), m.group(2)
    host, port_s = netloc.rsplit(":", 1)
    sock = socket.create_connection((host, int(port_s)), timeout=15)
    partial = (
        f"POST {prefix}/responses HTTP/1.1\r\n"
        f"Host: {netloc}\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 2\r\n"
    ).encode("utf-8")
    sock.sendall(partial)

    def close_later() -> None:
        time.sleep(hold_ms / 1000)
        sock.close()

    threading.Thread(target=close_later, daemon=True).start()
    return {"enabled": True, "hold_ms": hold_ms}


def _websocket_probe(proxy_url: str) -> dict:
    if os.environ.get("OMUX_STUB_CODEX_WEBSOCKET_PROBE") != "1":
        return {"checked": False}

    m = re.match(r"http://([^/]+)(/.*)$", proxy_url)
    if not m:
        print(f"stub-codex: cannot parse base_url={proxy_url}", file=sys.stderr)
        sys.exit(2)
    netloc, prefix = m.group(1), m.group(2)
    def run_get(label: str, headers: dict, suffix: str = "/responses") -> dict:
        conn = http.client.HTTPConnection(netloc, timeout=15)
        try:
            conn.request("GET", prefix + suffix, headers=headers)
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", errors="replace")
            return {
                "label": label,
                "status": resp.status,
                "body_has_unsupported_transport": "oauth_mux_unsupported_transport" in body,
                "path_printed": False,
                "token_material_printed": False,
            }
        finally:
            conn.close()

    def run_get_and_rst(label: str, headers: dict) -> dict:
        host, port_s = netloc.rsplit(":", 1)
        sock = socket.create_connection((host, int(port_s)), timeout=15)
        try:
            lines = [
                f"GET {prefix}/responses HTTP/1.1",
                f"Host: {netloc}",
            ]
            lines.extend(f"{name}: {value}" for name, value in headers.items())
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8"))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        finally:
            sock.close()
        time.sleep(0.05)
        return {
            "label": label,
            "status": 0,
            "body_has_unsupported_transport": False,
            "client_closed_before_response": True,
            "path_printed": False,
            "token_material_printed": False,
        }

    websocket_headers = {
        "Connection": "keep-alive, Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version": "13",
        "User-Agent": "stub-codex/0",
        "x-codex-installation-id": "stub-install-1",
        "OpenAI-Beta": "responses_websockets=2026-02-06",
    }
    account_id = os.environ.get("OMUX_STUB_CODEX_CHATGPT_ACCOUNT_ID")
    auth_token = _auth_token_for_turn(0)
    if account_id:
        websocket_headers["ChatGPT-Account-ID"] = account_id
    if auth_token:
        websocket_headers["Authorization"] = f"Bearer {auth_token}"

    beta_only_headers = {
        "User-Agent": "stub-codex/0",
        "x-codex-installation-id": "stub-install-1",
        "OpenAI-Beta": "responses_websockets=2026-02-06",
    }
    if account_id:
        beta_only_headers["ChatGPT-Account-ID"] = account_id
    if auth_token:
        beta_only_headers["Authorization"] = f"Bearer {auth_token}"

    variants = [
        run_get("websocket_upgrade", websocket_headers),
        run_get("responses_get_beta_only", beta_only_headers),
    ]
    extra_suffix = os.environ.get("OMUX_STUB_CODEX_WEBSOCKET_EXTRA_SUFFIX")
    if extra_suffix:
        if not extra_suffix.startswith("/"):
            extra_suffix = "/" + extra_suffix
        variants.append(run_get("websocket_upgrade_extra_suffix", websocket_headers, extra_suffix))
    if os.environ.get("OMUX_STUB_CODEX_WEBSOCKET_RST_PROBE") == "1":
        variants.append(run_get_and_rst("websocket_upgrade_rst", websocket_headers))
    primary = variants[0]
    return {
        "checked": True,
        "status": primary["status"],
        "body_has_unsupported_transport": primary["body_has_unsupported_transport"],
        "path_printed": False,
        "token_material_printed": False,
        "variants": variants,
    }


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
    state_overlay = codex_home / "state_5.sqlite"
    state_canonical = canonical / "state_5.sqlite"
    wal_overlay = codex_home / "state_5.sqlite-wal"
    wal_canonical = canonical / "state_5.sqlite-wal"
    shm_overlay = codex_home / "state_5.sqlite-shm"
    shm_canonical = canonical / "state_5.sqlite-shm"
    logs_overlay = codex_home / "logs_2.sqlite"
    logs_canonical = canonical / "logs_2.sqlite"
    logs_wal_overlay = codex_home / "logs_2.sqlite-wal"
    logs_wal_canonical = canonical / "logs_2.sqlite-wal"
    logs_shm_overlay = codex_home / "logs_2.sqlite-shm"
    logs_shm_canonical = canonical / "logs_2.sqlite-shm"
    sqlite_home_raw = os.environ.get("CODEX_SQLITE_HOME")
    sqlite_home = Path(sqlite_home_raw) if sqlite_home_raw else None

    marker = sessions_overlay / "omux-session-bridge-smoke.jsonl"
    marker.write_text('{"bridge":"ok"}\n')

    return {
        "checked": True,
        "sessions_samefile": os.path.samefile(sessions_overlay, sessions_canonical),
        "history_samefile": os.path.samefile(history_overlay, history_canonical),
        "session_index_samefile": os.path.samefile(index_overlay, index_canonical),
        "shell_snapshots_samefile": os.path.samefile(snapshots_overlay, snapshots_canonical),
        "state_db_samefile": state_canonical.exists() and os.path.samefile(state_overlay, state_canonical),
        "state_db_wal_samefile": wal_canonical.exists() and os.path.samefile(wal_overlay, wal_canonical),
        "state_db_shm_samefile": (not shm_canonical.exists()) or os.path.samefile(shm_overlay, shm_canonical),
        "logs_db_samefile": logs_canonical.exists() and os.path.samefile(logs_overlay, logs_canonical),
        "logs_db_wal_samefile": logs_wal_canonical.exists() and os.path.samefile(logs_wal_overlay, logs_wal_canonical),
        "logs_db_shm_samefile": (not logs_shm_canonical.exists()) or os.path.samefile(logs_shm_overlay, logs_shm_canonical),
        "sqlite_home_env_set": sqlite_home is not None,
        "sqlite_home_samefile": sqlite_home is not None and os.path.samefile(sqlite_home, canonical),
        "sqlite_home_path_printed": False,
        "marker_written_via_overlay": marker.exists(),
        "canonical_marker_exists": (sessions_canonical / marker.name).exists(),
        "paths_printed": False,
    }


def _append_session_marker(codex_home: Path) -> dict:
    rel = os.environ.get("OMUX_STUB_APPEND_SESSION")
    if not rel:
        return {"checked": False}
    target = codex_home / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"stub_resume_write": True, "argv_len": len(sys.argv) - 1}) + "\n")
    return {
        "checked": True,
        "path_printed": False,
    }


def _sqlite_env_report() -> dict:
    return {
        "codex_sqlite_home_env_set": bool(os.environ.get("CODEX_SQLITE_HOME")),
        "path_printed": False,
    }


def _rewrite_auth_json(codex_home: Path) -> dict:
    contents = os.environ.get("OMUX_STUB_REWRITE_AUTH_JSON")
    if contents is None:
        return {"checked": False}
    (codex_home / "auth.json").write_text(contents, encoding="utf-8")
    return {
        "checked": True,
        "written": True,
        "token_material_printed": False,
        "path_printed": False,
    }


def main() -> int:
    pid = os.getpid()
    pidfile = Path(os.environ.get("OMUX_STUB_CODEX_PIDFILE", "/tmp/omux-stub-codex.pid"))
    pidfile.write_text(f"{pid}\n")

    report_path = Path(os.environ.get("OMUX_STUB_CODEX_REPORT", "/tmp/omux-stub-codex.report"))
    turns = int(os.environ.get("OMUX_STUB_CODEX_TURNS", "5"))
    turn_delay_ms = int(os.environ.get("OMUX_STUB_CODEX_TURN_DELAY_MS", "50"))

    codex_home = Path(os.environ["CODEX_HOME"])
    if os.environ.get("OMUX_STUB_CODEX_FAIL_MODE") == "sqlite_locked":
        state_path = codex_home / "state_5.sqlite"
        print("Codex couldn't start because another Codex process is using its local data.", file=sys.stderr)
        print("Quit any other copies of Codex that may still be running, then try again.", file=sys.stderr)
        print("Technical details:", file=sys.stderr)
        print(f"  Location: {state_path}", file=sys.stderr)
        print(
            f"  Cause: failed to initialize state runtime at {codex_home}: error returned from database: (code: 5) database is locked",
            file=sys.stderr,
        )
        print(
            f"ERROR: failed to initialize sqlite state db at {state_path}: failed to initialize state runtime at {codex_home}: error returned from database: (code: 5) database is locked",
            file=sys.stderr,
        )
        return 1

    proxy_url = _read_proxy_url(codex_home)
    config_report = _config_report(codex_home)
    session_bridge = _session_bridge_report(codex_home)
    session_append = _append_session_marker(codex_home)
    sqlite_env = _sqlite_env_report()
    auth_rewrite = _rewrite_auth_json(codex_home)
    websocket_probe = _websocket_probe(proxy_url)
    partial_stall = _start_partial_stall(
        proxy_url,
        int(os.environ.get("OMUX_STUB_CODEX_PARTIAL_STALL_MS", "0")),
    )

    started_at = time.time()
    print(
        f"stub-codex: pid={pid} CODEX_HOME=<redacted> proxy={proxy_url} turns={turns} "
        f"OMUX_ACTIVE_ACCOUNT={os.environ.get('OMUX_ACTIVE_ACCOUNT')}",
        file=sys.stderr, flush=True,
    )

    turn_results: list[dict] = []
    disconnect_turns = _disconnect_turns()
    for i in range(turns):
        payload = _payload_for_turn(i)
        endpoint = _endpoint_for_turn(i)
        if i in disconnect_turns:
            status, body = _post_and_disconnect(proxy_url, payload, i)
        else:
            status, body = _post(proxy_url, payload, i)
        turn_results.append({
            "turn": i,
            "endpoint": endpoint,
            "status": status,
            "payload_bytes": len(payload),
            "response_bytes": len(body.encode("utf-8")),
            "body_head": body[:120],
        })
        print(f"stub-codex: turn {i} -> {status}", file=sys.stderr, flush=True)
        time.sleep(turn_delay_ms / 1000)

    end_pid = os.getpid()
    report = {
        "argv": sys.argv[1:],
        "start_pid": pid,
        "end_pid": end_pid,
        "pid_stable": pid == end_pid,
        "duration_s": round(time.time() - started_at, 3),
        "turns": turn_results,
        "codex_home_path_printed": False,
        "active_account_at_start": os.environ.get("OMUX_ACTIVE_ACCOUNT"),
        "managed_frame_id_present": bool(os.environ.get("OMUX_MANAGED_FRAME_ID")),
        "claim_level": os.environ.get("OMUX_CLAIM_LEVEL"),
        "status_file_present": bool(os.environ.get("OMUX_STATUS_FILE")),
        "config": config_report,
        "session_bridge": session_bridge,
        "session_append": session_append,
        "sqlite_env": sqlite_env,
        "auth_rewrite": auth_rewrite,
        "websocket_probe": websocket_probe,
        "partial_stall": partial_stall,
    }
    report_path.write_text(json.dumps(report, indent=2))
    print(f"stub-codex: pid_stable={report['pid_stable']} turns={turns}", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
