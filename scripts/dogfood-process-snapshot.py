#!/usr/bin/env python3
"""Read-only agent process fanout snapshot for oauth-mux dogfood sessions."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    import resource
except ImportError:  # pragma: no cover - unavailable on some non-Unix targets.
    resource = None  # type: ignore[assignment]


AGENT_NAMES = {"codex", "claude", "claude-code", "claude_code"}
ROOT_NAMES = AGENT_NAMES | {"oauth-mux"}
LIVE_CLAIM_FD_SOFT_LIMIT_PCT = 70.0
HELPER_RE = re.compile(
    r"(mcp|figma-console|serena|language-server|node|npm|npx|bun|uvx|"
    r"playwright|puppeteer|chrome-devtools)",
    re.IGNORECASE,
)
LIVE_VALIDATION_RE = re.compile(
    r"(mitmdump|capture-codex-wire|gh\s+run\s+watch|nix\s+build\s+\.#checks)",
    re.IGNORECASE,
)
SECRET_REDACTIONS = [
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s'\"]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1<redacted>"),
    (re.compile(r"(?i)((?:access|refresh|id)_token[=:\s]+)[^\s,'\"]+"), r"\1<redacted>"),
    (re.compile(r"(?i)((?:api[_-]?key|token)[=:\s]+)[^\s,'\"]+"), r"\1<redacted>"),
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def redact(value: str) -> str:
    result = value
    for pattern, replacement in SECRET_REDACTIONS:
        result = pattern.sub(replacement, result)
    home = os.environ.get("HOME")
    if home:
        result = result.replace(home, "~")
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        result = result.replace(tmpdir.rstrip("/"), "<tmp>")
    result = re.sub(r"/private/tmp/[^\s'\"]+", "<tmp>", result)
    result = re.sub(r"/tmp/[^\s'\"]+", "<tmp>", result)
    result = re.sub(r"/private/var/folders/[^\s'\"]+", "<tmp>", result)
    result = re.sub(r"/var/folders/[^\s'\"]+", "<tmp>", result)
    return result


def run_command(argv: list[str]) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(argv, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except OSError as exc:
        return 126, "", str(exc)


def command_name(command: str) -> str:
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    if not parts:
        return ""
    return os.path.basename(parts[0])


def parse_etime(value: str) -> int | None:
    # ps etime formats: [[dd-]hh:]mm:ss
    try:
        days = 0
        rest = value
        if "-" in rest:
            day_s, rest = rest.split("-", 1)
            days = int(day_s)
        parts = [int(part) for part in rest.split(":")]
        if len(parts) == 2:
            hours = 0
            minutes, seconds = parts
        elif len(parts) == 3:
            hours, minutes, seconds = parts
        else:
            return None
        return (((days * 24) + hours) * 60 + minutes) * 60 + seconds
    except ValueError:
        return None


def parse_ps() -> tuple[list[dict[str, Any]], list[str]]:
    code, stdout, stderr = run_command(["ps", "-axo", "pid=,ppid=,pcpu=,rss=,etime=,command="])
    warnings: list[str] = []
    if code != 0:
        warnings.append(f"ps failed with status {code}: {redact(stderr.strip())}")
        return [], warnings

    rows: list[dict[str, Any]] = []
    this_pid = os.getpid()
    for line in stdout.splitlines():
        parts = line.strip().split(None, 5)
        if len(parts) < 6:
            continue
        pid_s, ppid_s, cpu_s, rss_s, etime_s, command = parts
        try:
            pid = int(pid_s)
            ppid = int(ppid_s)
            cpu = float(cpu_s)
            rss_kib = int(rss_s)
        except ValueError:
            continue
        if pid == this_pid:
            continue
        rows.append(
            {
                "pid": pid,
                "ppid": ppid,
                "command_name": command_name(command),
                "command": redact(command),
                "cpu_pct": cpu,
                "rss_kib": rss_kib,
                "rss_mib": round(rss_kib / 1024, 1),
                "elapsed": etime_s,
                "elapsed_seconds": parse_etime(etime_s),
            }
        )
    return rows, warnings


def parse_lsof() -> tuple[dict[int, list[str]], list[str]]:
    code, stdout, stderr = run_command(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"])
    warnings: list[str] = []
    listeners: dict[int, list[str]] = {}
    if code != 0:
        message = stderr.strip() or "no listening TCP processes visible"
        warnings.append(f"lsof listen scan unavailable: {redact(message)}")
        return listeners, warnings

    current_pid: int | None = None
    for line in stdout.splitlines():
        if not line:
            continue
        tag = line[0]
        value = line[1:]
        if tag == "p":
            try:
                current_pid = int(value)
            except ValueError:
                current_pid = None
        elif tag == "n" and current_pid is not None:
            listeners.setdefault(current_pid, []).append(redact(value))
    return listeners, warnings


def nofile_limit_snapshot() -> dict[str, Any]:
    if resource is None:
        return {
            "available": False,
            "soft": None,
            "hard": None,
            "hard_label": "unknown",
        }
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    hard_is_unlimited = hard == resource.RLIM_INFINITY
    return {
        "available": True,
        "soft": soft,
        "hard": None if hard_is_unlimited else hard,
        "hard_label": "unlimited" if hard_is_unlimited else str(hard),
    }


def parse_fd_counts(pids: list[int]) -> tuple[dict[int, int], list[str]]:
    warnings: list[str] = []
    counts: dict[int, int] = {}
    if not pids:
        return counts, warnings

    chunk_size = 80
    for start in range(0, len(pids), chunk_size):
        chunk = pids[start : start + chunk_size]
        code, stdout, stderr = run_command(["lsof", "-nP", "-F", "pf", "-p", ",".join(str(pid) for pid in chunk)])
        if code != 0 and not stdout:
            warnings.append(f"lsof fd-count scan unavailable for pid chunk: {redact(stderr.strip())}")
            continue
        current_pid: int | None = None
        for line in stdout.splitlines():
            if not line:
                continue
            tag = line[0]
            value = line[1:]
            if tag == "p":
                try:
                    current_pid = int(value)
                    counts.setdefault(current_pid, 0)
                except ValueError:
                    current_pid = None
            elif tag == "f" and current_pid is not None and is_numeric_fd_tag(value):
                counts[current_pid] = counts.get(current_pid, 0) + 1
    return counts, warnings


def is_numeric_fd_tag(value: str) -> bool:
    return bool(value and value[0].isdigit())


def fd_soft_limit_pct(fd_count: int, soft_limit: Any) -> float | None:
    if not isinstance(soft_limit, int) or soft_limit <= 0:
        return None
    return round((fd_count / soft_limit) * 100, 1)


def is_agent_process(proc: dict[str, Any]) -> bool:
    name = proc["command_name"].lower()
    if name in AGENT_NAMES:
        return True
    command = proc["command"].lower()
    return any(f"/{agent}" in command or f" {agent} " in command for agent in AGENT_NAMES)


def is_helper_process(proc: dict[str, Any]) -> bool:
    return bool(HELPER_RE.search(proc["command"]))


def is_root_process(proc: dict[str, Any]) -> bool:
    name = proc["command_name"].lower()
    if name in ROOT_NAMES:
        return True
    command = proc["command"].lower()
    return any(f"/{root}" in command or f" {root} " in command for root in ROOT_NAMES)


def is_oauth_mux_process(proc: dict[str, Any]) -> bool:
    command = proc["command"].lower()
    return proc["command_name"].lower() == "oauth-mux" or "/oauth-mux" in command or " oauth-mux " in command


def is_codex_process(proc: dict[str, Any]) -> bool:
    if is_oauth_mux_process(proc):
        return False
    command = proc["command"].lower()
    return proc["command_name"].lower() == "codex" or "/codex" in command or " codex " in command


def is_claude_process(proc: dict[str, Any]) -> bool:
    command = proc["command"].lower()
    return proc["command_name"].lower() in {"claude", "claude-code", "claude_code"} or " claude" in command


def is_live_validation_process(proc: dict[str, Any]) -> bool:
    return bool(LIVE_VALIDATION_RE.search(proc["command"]))


def descendants(pid: int, children: dict[int, list[int]]) -> list[int]:
    result: list[int] = []
    stack = list(children.get(pid, []))
    while stack:
        child = stack.pop()
        result.append(child)
        stack.extend(children.get(child, []))
    return result


def has_ancestor(
    pid: int,
    by_pid: dict[int, dict[str, Any]],
    predicate: Any,
) -> bool:
    current = by_pid.get(pid)
    seen: set[int] = set()
    while current is not None:
        ppid = current["ppid"]
        if ppid in seen:
            return False
        seen.add(ppid)
        parent = by_pid.get(ppid)
        if parent is None:
            return False
        if predicate(parent):
            return True
        current = parent
    return False


def current_invocation_ancestor_pids(by_pid: dict[int, dict[str, Any]], start_ppid: int | None = None) -> set[int]:
    ancestors: set[int] = set()
    current_pid = os.getppid() if start_ppid is None else start_ppid
    while current_pid > 0 and current_pid not in ancestors:
        current = by_pid.get(current_pid)
        if current is None:
            break
        ancestors.add(current_pid)
        current_pid = current["ppid"]
    return ancestors


def depth_first_tree(pid: int, children: dict[int, list[int]], by_pid: dict[int, dict[str, Any]], depth: int = 0) -> list[dict[str, Any]]:
    proc = by_pid.get(pid)
    if proc is None:
        return []
    node = dict(proc)
    node["depth"] = depth
    rows = [node]
    for child in sorted(children.get(pid, [])):
        rows.extend(depth_first_tree(child, children, by_pid, depth + 1))
    return rows


def listener_ports(names: list[str]) -> list[str]:
    ports: list[str] = []
    for name in names:
        match = re.search(r":(\d+)(?:\s|\(|$)", name)
        if match:
            ports.append(match.group(1))
    return ports


def gate_reason(reason: str, count: int | None = None, detail: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {"reason": reason}
    if count is not None:
        row["count"] = count
    if detail is not None:
        row["detail"] = detail
    return row


def build_evidence_gate(
    process_summary: dict[str, Any],
    fd_summary: dict[str, Any],
    warnings: list[str],
    orphan_listener_candidates: list[dict[str, Any]],
    duplicate_helper_groups: list[dict[str, Any]],
    accumulated_sessions: list[dict[str, Any]],
    live_validation_processes: list[dict[str, Any]],
) -> dict[str, Any]:
    blocking_reasons: list[dict[str, Any]] = []
    caution_reasons: list[dict[str, Any]] = []

    if warnings:
        blocking_reasons.append(gate_reason("snapshot_warnings_present", len(warnings)))

    active_codex_mux = int(process_summary["active_codex_or_oauth_mux_processes"])
    if active_codex_mux:
        blocking_reasons.append(
            gate_reason(
                "active_oauth_mux_or_codex_processes",
                active_codex_mux,
                "close or explicitly account for active managed/native Codex sessions before live claims",
            )
        )

    if orphan_listener_candidates:
        blocking_reasons.append(
            gate_reason(
                "orphan_listener_candidates",
                len(orphan_listener_candidates),
                "collect a second snapshot or close known-idle helper sessions before live claims",
            )
        )

    if live_validation_processes:
        blocking_reasons.append(
            gate_reason(
                "live_validation_processes_running",
                len(live_validation_processes),
                "wait for capture/watch/build processes to finish before using evidence",
            )
        )

    max_fd_pct = fd_summary.get("max_fd_soft_limit_pct")
    if isinstance(max_fd_pct, (int, float)) and max_fd_pct >= LIVE_CLAIM_FD_SOFT_LIMIT_PCT:
        blocking_reasons.append(
            gate_reason(
                "fd_pressure_high",
                detail=f"max visible fd usage is {max_fd_pct}% of the collector soft limit; threshold is {LIVE_CLAIM_FD_SOFT_LIMIT_PCT}%",
            )
        )

    if accumulated_sessions:
        caution_reasons.append(
            gate_reason(
                "accumulated_sessions_visible",
                len(accumulated_sessions),
                "old visible agent sessions may be normal, but must be classified before broad claims",
            )
        )

    if duplicate_helper_groups:
        caution_reasons.append(
            gate_reason(
                "duplicate_helper_groups_visible",
                len(duplicate_helper_groups),
                "duplicate helper signatures may be normal MCP fanout, but need classification before broad claims",
            )
        )

    clean = not blocking_reasons and not caution_reasons
    return {
        "process_fd_clean_baseline": clean,
        "unannotated_live_claims_admitted": clean,
        "quota_cassette_claims_admitted": clean,
        "local_release_validation_admitted": True,
        "requires_operator_annotation": not clean,
        "fd_soft_limit_pct_threshold": LIVE_CLAIM_FD_SOFT_LIMIT_PCT,
        "blocking_reasons": blocking_reasons,
        "caution_reasons": caution_reasons,
        "next_actions": [
            "close or account for active Codex/oauth-mux sessions",
            "raise the fd soft limit or reduce helper fanout when fd pressure is high",
            "collect a second snapshot before calling process state clean",
            "do not kill processes automatically; get explicit operator approval",
        ] if not clean else [],
    }


def process_review_row(proc: dict[str, Any]) -> dict[str, Any]:
    return {
        "pid": proc.get("pid"),
        "ppid": proc.get("ppid"),
        "command_name": proc.get("command_name"),
        "role": proc.get("role"),
        "elapsed": proc.get("elapsed"),
        "elapsed_seconds": proc.get("elapsed_seconds"),
        "rss_mib": proc.get("rss_mib"),
        "cpu_pct": proc.get("cpu_pct"),
        "fd_count": proc.get("fd_count"),
        "listener_ports": proc.get("listener_ports", []),
    }


def build_safe_cleanup(
    evidence_gate: dict[str, Any],
    active_codex_or_oauth_mux_processes: list[dict[str, Any]],
    orphan_listener_candidates: list[dict[str, Any]],
    live_validation_processes: list[dict[str, Any]],
    fd_summary: dict[str, Any],
) -> dict[str, Any]:
    high_fd_processes = [
        proc
        for proc in fd_summary.get("top_processes", [])
        if isinstance(proc.get("fd_soft_limit_pct"), (int, float))
        and proc["fd_soft_limit_pct"] >= LIVE_CLAIM_FD_SOFT_LIMIT_PCT
    ]
    return {
        "automation_may_kill": False,
        "requires_operator_approval": True,
        "claim_blocking": not evidence_gate.get("process_fd_clean_baseline", False),
        "review_groups": {
            "active_codex_or_oauth_mux_processes": [
                process_review_row(proc) for proc in active_codex_or_oauth_mux_processes
            ],
            "orphan_listener_candidates": [
                process_review_row(proc) for proc in orphan_listener_candidates
            ],
            "live_validation_processes": [
                process_review_row(proc) for proc in live_validation_processes
            ],
            "high_fd_processes": high_fd_processes,
        },
        "guidance": [
            "Do not kill active Codex or Claude sessions from this report.",
            "Close old shells or agent sessions manually when their work is complete.",
            "Prefer the normal shell/session exit path before any PID-level action.",
            "Collect a second snapshot after cleanup before treating process/fd state as clean.",
            "Only collect a leak bug after repeated snapshots show unexplained RSS growth for the same PID.",
        ],
    }


def build_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    processes, ps_warnings = parse_ps()
    listeners, lsof_warnings = parse_lsof()
    fd_target_pids = [
        proc["pid"]
        for proc in processes
        if is_root_process(proc) or is_helper_process(proc)
    ]
    fd_counts, fd_warnings = parse_fd_counts(fd_target_pids)
    warnings = ps_warnings + lsof_warnings + fd_warnings

    by_pid = {proc["pid"]: proc for proc in processes}
    children: dict[int, list[int]] = {}
    for proc in processes:
        children.setdefault(proc["ppid"], []).append(proc["pid"])

    for pid, proc in by_pid.items():
        proc["listeners"] = listeners.get(pid, [])
        proc["listener_ports"] = listener_ports(proc["listeners"])
        proc["fd_count"] = fd_counts.get(pid)
        proc["is_agent"] = is_agent_process(proc)
        proc["is_helper"] = is_helper_process(proc)
        proc["is_oauth_mux"] = is_oauth_mux_process(proc)
        proc["is_codex"] = is_codex_process(proc)
        proc["is_claude"] = is_claude_process(proc)
        proc["role"] = "oauth_mux_parent" if proc["is_oauth_mux"] else "agent_parent" if proc["is_agent"] else "helper" if proc["is_helper"] else "other"

    root_candidates = {proc["pid"] for proc in processes if is_root_process(proc)}
    nested_roots = set()
    for pid in root_candidates:
        nested_roots.update(set(descendants(pid, children)).intersection(root_candidates))
    root_pids = sorted(root_candidates - nested_roots)

    for pid, proc in by_pid.items():
        if proc["is_codex"] and has_ancestor(pid, by_pid, is_oauth_mux_process):
            proc["role"] = "managed_codex_child"
        elif proc["is_codex"]:
            proc["role"] = "native_codex"
        elif proc["is_claude"]:
            proc["role"] = "native_claude"

    trees: list[dict[str, Any]] = []
    covered: set[int] = set()
    for root_pid in root_pids:
        tree_rows = depth_first_tree(root_pid, children, by_pid)
        tree_pids = {row["pid"] for row in tree_rows}
        covered.update(tree_pids)
        helper_count = sum(1 for row in tree_rows if row["is_helper"])
        root = by_pid[root_pid]
        tree_listeners = [
            {"pid": row["pid"], "command_name": row["command_name"], "listeners": row["listeners"]}
            for row in tree_rows
            if row["listeners"]
        ]
        trees.append(
            {
                "root": root,
                "child_count": max(len(tree_rows) - 1, 0),
                "helper_count": helper_count,
                "total_rss_kib": sum(row["rss_kib"] for row in tree_rows),
                "total_rss_mib": round(sum(row["rss_kib"] for row in tree_rows) / 1024, 1),
                "total_cpu_pct": round(sum(row["cpu_pct"] for row in tree_rows), 1),
                "listeners": tree_listeners,
                "processes": tree_rows,
            }
        )

    orphan_listener_candidates = []
    for pid, names in sorted(listeners.items()):
        proc = by_pid.get(pid)
        if proc is None or pid in covered:
            continue
        if proc["is_helper"] or HELPER_RE.search(" ".join(names)):
            orphan_listener_candidates.append(
                {
                    "pid": pid,
                    "ppid": proc["ppid"],
                    "command_name": proc["command_name"],
                    "role": proc["role"],
                    "command": proc["command"],
                    "rss_kib": proc["rss_kib"],
                    "rss_mib": proc["rss_mib"],
                    "cpu_pct": proc["cpu_pct"],
                    "fd_count": proc["fd_count"],
                    "elapsed": proc["elapsed"],
                    "elapsed_seconds": proc["elapsed_seconds"],
                    "listeners": names,
                    "listener_ports": listener_ports(names),
                }
            )

    helper_groups: dict[str, list[dict[str, Any]]] = {}
    for proc in processes:
        if not proc["is_helper"]:
            continue
        signature = proc["command_name"] or proc["command"].split(" ", 1)[0]
        if signature in {"sh", "bash", "zsh"}:
            signature = proc["command"][:120]
        helper_groups.setdefault(signature, []).append(proc)
    duplicate_helper_groups = [
        {
            "signature": signature,
            "count": len(group),
            "pids": [proc["pid"] for proc in group],
            "total_rss_mib": round(sum(proc["rss_kib"] for proc in group) / 1024, 1),
        }
        for signature, group in sorted(helper_groups.items())
        if len(group) > 1
    ]
    current_ancestor_pids = current_invocation_ancestor_pids(by_pid)
    ignored_current_invocation_live_validation_processes = [
        {
            "pid": proc["pid"],
            "ppid": proc["ppid"],
            "command_name": proc["command_name"],
            "role": proc["role"],
            "command": proc["command"],
            "elapsed": proc["elapsed"],
            "elapsed_seconds": proc["elapsed_seconds"],
        }
        for proc in processes
        if proc["pid"] in current_ancestor_pids and is_live_validation_process(proc)
    ]
    live_validation_processes = [
        {
            "pid": proc["pid"],
            "ppid": proc["ppid"],
            "command_name": proc["command_name"],
            "role": proc["role"],
            "command": proc["command"],
            "elapsed": proc["elapsed"],
            "elapsed_seconds": proc["elapsed_seconds"],
        }
        for proc in processes
        if proc["pid"] not in current_ancestor_pids and is_live_validation_process(proc)
    ]

    accumulated_sessions = [
        {
            "pid": tree["root"]["pid"],
            "command_name": tree["root"]["command_name"],
            "elapsed": tree["root"]["elapsed"],
            "elapsed_seconds": tree["root"]["elapsed_seconds"],
            "rss_mib": tree["root"]["rss_mib"],
            "cpu_pct": tree["root"]["cpu_pct"],
        }
        for tree in trees
        if (tree["root"]["elapsed_seconds"] or 0) >= args.accumulated_seconds
    ]
    oauth_mux_processes = [proc for proc in processes if proc["is_oauth_mux"]]
    codex_processes = [proc for proc in processes if proc["is_codex"]]
    active_codex_or_oauth_mux_processes = [
        proc for proc in processes if proc["is_oauth_mux"] or proc["is_codex"]
    ]
    claude_processes = [proc for proc in processes if proc["is_claude"]]
    managed_codex_children = [proc for proc in codex_processes if proc["role"] == "managed_codex_child"]
    unmanaged_codex_processes = [proc for proc in codex_processes if proc["role"] == "native_codex"]
    fd_rows = [proc for proc in processes if proc.get("fd_count") is not None]
    fd_limit = nofile_limit_snapshot()
    soft_limit = fd_limit.get("soft")
    top_fd_processes = []
    for proc in sorted(fd_rows, key=lambda row: (row.get("fd_count") or 0), reverse=True)[:10]:
        fd_count = proc.get("fd_count") or 0
        top_fd_processes.append(
            {
                "pid": proc["pid"],
                "ppid": proc["ppid"],
                "command_name": proc["command_name"],
                "role": proc["role"],
                "fd_count": fd_count,
                "fd_soft_limit_pct": fd_soft_limit_pct(fd_count, soft_limit),
            }
        )
    max_fd_count = top_fd_processes[0]["fd_count"] if top_fd_processes else None
    fd_summary = {
        "visible_fd_process_count": len(fd_rows),
        "fd_soft_limit_basis": "collector_process_nofile_soft_limit",
        "max_fd_count": max_fd_count,
        "max_fd_soft_limit_pct": fd_soft_limit_pct(max_fd_count, soft_limit) if isinstance(max_fd_count, int) else None,
        "top_processes": top_fd_processes,
    }
    process_summary = {
        "oauth_mux_processes": len(oauth_mux_processes),
        "codex_processes": len(codex_processes),
        "active_codex_or_oauth_mux_processes": len(active_codex_or_oauth_mux_processes),
        "claude_processes": len(claude_processes),
        "managed_codex_children": len(managed_codex_children),
        "unmanaged_codex_processes": len(unmanaged_codex_processes),
        "ambiguous_processes": len(orphan_listener_candidates),
    }
    evidence_gate = build_evidence_gate(
        process_summary,
        fd_summary,
        warnings,
        orphan_listener_candidates,
        duplicate_helper_groups,
        accumulated_sessions,
        live_validation_processes,
    )

    return {
        "kind": "dogfood_process_snapshot",
        "mode": "agent_process_fanout_snapshot",
        "schema_version": 2,
        "collected_at": utc_now(),
        "host": os.uname().nodename,
        "pid": os.getpid(),
        "scope": "agent_process_fanout",
        "spends_provider_calls": False,
        "mutates_user_config": False,
        "mutates_route_health": False,
        "mutates_processes": False,
        "kills_processes": False,
        "sleeps": False,
        "foreground_sleep": False,
        "resource_limits": {
            "nofile": fd_limit,
        },
        "tag": args.tag,
        "thresholds": {
            "accumulated_seconds": args.accumulated_seconds,
            "rss_growth_kib": args.rss_growth_kib,
            "rss_growth_pct": args.rss_growth_pct,
        },
        "summary": {
            "process_count": len(processes),
            "agent_tree_count": len(trees),
            "orphan_listener_candidate_count": len(orphan_listener_candidates),
            "duplicate_helper_group_count": len(duplicate_helper_groups),
            "accumulated_session_count": len(accumulated_sessions),
            "live_validation_process_count": len(live_validation_processes),
            "ignored_current_invocation_live_validation_process_count": len(ignored_current_invocation_live_validation_processes),
            "heap_leak_proven": False,
            "heap_leak_evidence": "single snapshot only; compare two snapshots before calling this a leak",
        },
        "process_summary": process_summary,
        "fd_summary": fd_summary,
        "evidence_gate": evidence_gate,
        "claim": {
            "current_process_hotswap": False,
            "unmanaged_tui_hotswap": False,
            "per_request_muxing": False,
        },
        "agent_trees": trees,
        "orphan_listener_candidates": orphan_listener_candidates,
        "duplicate_helper_groups": duplicate_helper_groups,
        "live_validation_processes": live_validation_processes,
        "ignored_current_invocation_live_validation_processes": ignored_current_invocation_live_validation_processes,
        "accumulated_sessions": accumulated_sessions,
        "safe_cleanup": build_safe_cleanup(
            evidence_gate,
            active_codex_or_oauth_mux_processes,
            orphan_listener_candidates,
            live_validation_processes,
            fd_summary,
        ),
        "warnings": warnings,
    }


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def compare_snapshots(base: dict[str, Any], current: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    base_procs: dict[int, dict[str, Any]] = {}
    for tree in base.get("agent_trees", []):
        for proc in tree.get("processes", []):
            base_procs[int(proc["pid"])] = proc
    for proc in base.get("orphan_listener_candidates", []):
        base_procs[int(proc["pid"])] = proc

    current_procs: dict[int, dict[str, Any]] = {}
    for tree in current.get("agent_trees", []):
        for proc in tree.get("processes", []):
            current_procs[int(proc["pid"])] = proc
    for proc in current.get("orphan_listener_candidates", []):
        current_procs[int(proc["pid"])] = proc

    stable: list[dict[str, Any]] = []
    growth: list[dict[str, Any]] = []
    disappeared: list[dict[str, Any]] = []
    appeared: list[dict[str, Any]] = []

    for pid, before in sorted(base_procs.items()):
        after = current_procs.get(pid)
        if after is None:
            disappeared.append({"pid": pid, "command_name": before.get("command_name"), "before_elapsed": before.get("elapsed")})
            continue
        rss_delta = int(after["rss_kib"]) - int(before["rss_kib"])
        before_rss = max(int(before["rss_kib"]), 1)
        pct = (rss_delta / before_rss) * 100
        row = {
            "pid": pid,
            "command_name": after.get("command_name"),
            "rss_delta_kib": rss_delta,
            "rss_delta_mib": round(rss_delta / 1024, 1),
            "rss_delta_pct": round(pct, 1),
            "before_rss_mib": before.get("rss_mib"),
            "after_rss_mib": after.get("rss_mib"),
            "before_elapsed": before.get("elapsed"),
            "after_elapsed": after.get("elapsed"),
            "command": after.get("command"),
        }
        if rss_delta >= args.rss_growth_kib and pct >= args.rss_growth_pct:
            growth.append(row)
        else:
            stable.append(row)

    for pid, after in sorted(current_procs.items()):
        if pid not in base_procs:
            appeared.append({"pid": pid, "command_name": after.get("command_name"), "rss_mib": after.get("rss_mib"), "elapsed": after.get("elapsed")})

    return {
        "kind": "dogfood_process_snapshot_comparison",
        "mode": "agent_process_fanout_comparison",
        "schema_version": 1,
        "compared_at": utc_now(),
        "spends_provider_calls": False,
        "mutates_user_config": False,
        "mutates_route_health": False,
        "mutates_processes": False,
        "kills_processes": False,
        "sleeps": False,
        "foreground_sleep": False,
        "baseline_collected_at": base.get("collected_at"),
        "current_collected_at": current.get("collected_at"),
        "thresholds": {
            "rss_growth_kib": args.rss_growth_kib,
            "rss_growth_pct": args.rss_growth_pct,
        },
        "summary": {
            "same_pid_count": len(stable) + len(growth),
            "suspected_rss_growth_count": len(growth),
            "stable_or_explained_count": len(stable),
            "appeared_count": len(appeared),
            "disappeared_count": len(disappeared),
            "heap_leak_proven": False,
            "classification": "suspected_rss_growth" if growth else "stable_or_session_churn",
        },
        "suspected_rss_growth": growth,
        "stable_or_explained": stable,
        "appeared": appeared,
        "disappeared": disappeared,
        "safe_cleanup": {
            "automation_may_kill": False,
            "requires_operator_approval": True,
        },
    }


def render_snapshot_md(snapshot: dict[str, Any]) -> str:
    lines = [
        "# Dogfood Process Fanout Snapshot",
        "",
        f"Collected: {snapshot['collected_at']}",
        f"Host: {snapshot['host']}",
        "",
        "This report is observational only. It does not spend provider calls, mutate oauth-mux state, sleep in the foreground, or kill processes.",
        "",
        "## Summary",
        "",
    ]
    for key, value in snapshot["summary"].items():
        lines.append(f"- `{key}`: {value}")
    gate = snapshot.get("evidence_gate", {})
    lines.extend(["", "## Evidence Gate", ""])
    for key in (
        "process_fd_clean_baseline",
        "unannotated_live_claims_admitted",
        "quota_cassette_claims_admitted",
        "local_release_validation_admitted",
        "requires_operator_annotation",
        "fd_soft_limit_pct_threshold",
    ):
        if key in gate:
            lines.append(f"- `{key}`: {gate[key]}")
    if gate.get("blocking_reasons"):
        lines.extend(["", "Blocking reasons:"])
        for item in gate["blocking_reasons"]:
            detail = f" - {item['detail']}" if item.get("detail") else ""
            count = f" ({item['count']})" if "count" in item else ""
            lines.append(f"- `{item['reason']}`{count}{detail}")
    if gate.get("caution_reasons"):
        lines.extend(["", "Caution reasons:"])
        for item in gate["caution_reasons"]:
            detail = f" - {item['detail']}" if item.get("detail") else ""
            count = f" ({item['count']})" if "count" in item else ""
            lines.append(f"- `{item['reason']}`{count}{detail}")
    lines.append("")
    lines.append("## Process Summary")
    lines.append("")
    for key, value in snapshot["process_summary"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Resource Limits", ""])
    nofile = snapshot["resource_limits"]["nofile"]
    lines.append(f"- `nofile.available`: {nofile['available']}")
    lines.append(f"- `nofile.soft`: {nofile['soft']}")
    lines.append(f"- `nofile.hard`: {nofile['hard_label']}")
    lines.extend(["", "## File Descriptor Summary", ""])
    for key, value in snapshot["fd_summary"].items():
        if key != "top_processes":
            lines.append(f"- `{key}`: {value}")
    if snapshot["fd_summary"]["top_processes"]:
        lines.extend(["", "| pid | ppid | role | command | fd count | fd soft limit pct |"])
        lines.append("| ---: | ---: | --- | --- | ---: | ---: |")
        for proc in snapshot["fd_summary"]["top_processes"]:
            lines.append(
                f"| {proc['pid']} | {proc['ppid']} | `{proc['role']}` | `{proc['command_name']}` | "
                f"{proc['fd_count']} | {proc['fd_soft_limit_pct']} |"
            )
    if snapshot.get("warnings"):
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in snapshot["warnings"])

    lines.extend(["", "## Agent Process Trees", ""])
    if not snapshot["agent_trees"]:
        lines.append("No Codex or Claude parent processes were visible to this user.")
    for tree in snapshot["agent_trees"]:
        root = tree["root"]
        lines.extend(
            [
                f"### `{root['command_name']}` pid `{root['pid']}`",
                "",
                f"- elapsed: `{root['elapsed']}`",
                f"- root RSS: `{root['rss_mib']} MiB`",
                f"- tree RSS: `{tree['total_rss_mib']} MiB`",
                f"- tree CPU: `{tree['total_cpu_pct']}%`",
                f"- child count: `{tree['child_count']}`",
                f"- helper count: `{tree['helper_count']}`",
                "",
                "| depth | pid | ppid | role | cpu | rss MiB | elapsed | listeners | fd count | command |",
                "| ---: | ---: | ---: | --- | ---: | ---: | --- | --- | ---: | --- |",
            ]
        )
        for proc in tree["processes"]:
            listeners = ", ".join(proc["listener_ports"]) if proc["listener_ports"] else ""
            command = proc["command"].replace("|", "\\|")
            fd_count = proc["fd_count"] if proc.get("fd_count") is not None else ""
            lines.append(
                f"| {proc['depth']} | {proc['pid']} | {proc['ppid']} | `{proc['role']}` | {proc['cpu_pct']} | "
                f"{proc['rss_mib']} | {proc['elapsed']} | {listeners} | {fd_count} | `{command}` |"
            )
        lines.append("")

    lines.extend(["## Orphan Listener Candidates", ""])
    if not snapshot["orphan_listener_candidates"]:
        lines.append("No helper/listener candidates were visible outside the agent trees.")
    else:
        lines.append("| pid | ppid | role | cpu | rss MiB | elapsed | listeners | fd count | command |")
        lines.append("| ---: | ---: | --- | ---: | ---: | --- | --- | ---: | --- |")
        for proc in snapshot["orphan_listener_candidates"]:
            listeners = ", ".join(proc["listener_ports"]) if proc["listener_ports"] else ", ".join(proc["listeners"])
            command = proc["command"].replace("|", "\\|")
            fd_count = proc["fd_count"] if proc.get("fd_count") is not None else ""
            lines.append(
                f"| {proc['pid']} | {proc['ppid']} | `{proc.get('role', 'helper')}` | {proc['cpu_pct']} | {proc['rss_mib']} | "
                f"{proc['elapsed']} | {listeners} | {fd_count} | `{command}` |"
            )

    lines.extend(["", "## Duplicate Helper Groups", ""])
    if not snapshot["duplicate_helper_groups"]:
        lines.append("No duplicate helper groups were detected by command signature.")
    else:
        for group in snapshot["duplicate_helper_groups"]:
            lines.append(
                f"- `{group['signature']}`: {group['count']} processes, "
                f"{group['total_rss_mib']} MiB total RSS, pids `{group['pids']}`"
            )

    lines.extend(
        [
            "",
            "## Safe Cleanup Rules",
            "",
            "- Do not kill processes from this report automatically.",
            "- Leave active shells/sessions alone while work is in progress.",
            "- Close old shells or agent sessions manually after confirming they are idle.",
            "- File a real leak bug only after repeated snapshots show unexplained RSS growth for the same PID.",
            "",
        ]
    )
    return "\n".join(lines)


def render_comparison_md(comparison: dict[str, Any]) -> str:
    lines = [
        "# Dogfood Process Fanout Comparison",
        "",
        f"Compared: {comparison['compared_at']}",
        f"Baseline: {comparison.get('baseline_collected_at')}",
        f"Current: {comparison.get('current_collected_at')}",
        "",
        "## Summary",
        "",
    ]
    for key, value in comparison["summary"].items():
        lines.append(f"- `{key}`: {value}")

    lines.extend(["", "## Suspected RSS Growth", ""])
    if not comparison["suspected_rss_growth"]:
        lines.append("No same-PID RSS growth crossed the configured threshold.")
    else:
        lines.append("| pid | command | delta MiB | delta % | before | after |")
        lines.append("| ---: | --- | ---: | ---: | ---: | ---: |")
        for row in comparison["suspected_rss_growth"]:
            lines.append(
                f"| {row['pid']} | `{row['command_name']}` | {row['rss_delta_mib']} | "
                f"{row['rss_delta_pct']} | {row['before_rss_mib']} | {row['after_rss_mib']} |"
            )

    lines.extend(["", "## Session Churn", ""])
    lines.append(f"- appeared: `{comparison['summary']['appeared_count']}`")
    lines.append(f"- disappeared: `{comparison['summary']['disappeared_count']}`")
    lines.extend(["", "Automation still must not kill any listed process without explicit operator approval.", ""])
    return "\n".join(lines)


def write_artifacts(payload: dict[str, Any], markdown: str, out_dir: Path, prefix: str) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tag = payload.get("tag")
    suffix = f"-{tag}" if tag else ""
    json_path = out_dir / f"{prefix}-{stamp}{suffix}.json"
    md_path = out_dir / f"{prefix}-{stamp}{suffix}.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(markdown, encoding="utf-8")
    return json_path, md_path


def schedule_followup(args: argparse.Namespace, baseline_path: Path, out_dir: Path) -> int:
    log_path = out_dir / f"process-followup-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.log"
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--followup-after-seconds",
        str(args.schedule_followup_seconds),
        "--followup-baseline",
        str(baseline_path),
        "--out",
        str(out_dir),
        "--tag",
        "followup",
        "--rss-growth-kib",
        str(args.rss_growth_kib),
        "--rss-growth-pct",
        str(args.rss_growth_pct),
    ]
    log = log_path.open("ab")
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    return proc.pid


def followup_mode(args: argparse.Namespace) -> int:
    # This sleep is intentionally in a detached/background follow-up process.
    time.sleep(args.followup_after_seconds)
    snapshot = build_snapshot(args)
    markdown = render_snapshot_md(snapshot)
    out_dir = Path(args.out)
    current_json, current_md = write_artifacts(snapshot, markdown, out_dir, "process-snapshot")
    baseline = load_json(Path(args.followup_baseline))
    comparison = compare_snapshots(baseline, snapshot, args)
    comp_md = render_comparison_md(comparison)
    comp_json, comp_md_path = write_artifacts(comparison, comp_md, out_dir, "process-comparison")
    print(f"follow-up snapshot: {current_json}")
    print(f"follow-up report:   {current_md}")
    print(f"comparison json:    {comp_json}")
    print(f"comparison report:  {comp_md_path}")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print JSON to stdout instead of Markdown")
    parser.add_argument("--out", help="write JSON and Markdown artifacts to this directory")
    parser.add_argument("--tag", help="short label to add to written artifact names")
    parser.add_argument("--compare", nargs=2, metavar=("BASELINE_JSON", "CURRENT_JSON"), help="compare two snapshot JSON files")
    parser.add_argument("--require-clean", action="store_true", help="exit nonzero unless process/fd evidence is clean")
    parser.add_argument(
        "--require-gate",
        choices=[
            "process_fd_clean_baseline",
            "unannotated_live_claims_admitted",
            "quota_cassette_claims_admitted",
            "local_release_validation_admitted",
        ],
        help="exit nonzero unless the named evidence gate is admitted",
    )
    parser.add_argument("--schedule-followup-seconds", type=int, help="after writing --out artifacts, schedule a background follow-up snapshot")
    parser.add_argument("--accumulated-seconds", type=int, default=4 * 60 * 60, help="elapsed time threshold for accumulated-session classification")
    parser.add_argument("--rss-growth-kib", type=int, default=64 * 1024, help="minimum same-PID RSS growth for comparison suspicion")
    parser.add_argument("--rss-growth-pct", type=float, default=25.0, help="minimum same-PID RSS percent growth for comparison suspicion")
    parser.add_argument("--followup-after-seconds", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--followup-baseline", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.schedule_followup_seconds is not None and args.schedule_followup_seconds <= 0:
        parser.error("--schedule-followup-seconds must be positive")
    if args.schedule_followup_seconds is not None and not args.out:
        parser.error("--schedule-followup-seconds requires --out")
    if args.followup_after_seconds is not None and not args.followup_baseline:
        parser.error("--followup-after-seconds requires --followup-baseline")
    if args.compare and (args.require_clean or args.require_gate):
        parser.error("--require-clean/--require-gate apply only to snapshots, not comparisons")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    if args.followup_after_seconds is not None:
        return followup_mode(args)

    if args.compare:
        baseline = load_json(Path(args.compare[0]))
        current = load_json(Path(args.compare[1]))
        payload = compare_snapshots(baseline, current, args)
        markdown = render_comparison_md(payload)
        prefix = "process-comparison"
    else:
        payload = build_snapshot(args)
        markdown = render_snapshot_md(payload)
        prefix = "process-snapshot"

    written_json: Path | None = None
    if args.out:
        written_json, written_md = write_artifacts(payload, markdown, Path(args.out), prefix)
        print(f"wrote json:   {written_json}", file=sys.stderr)
        print(f"wrote report: {written_md}", file=sys.stderr)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(markdown)

    if args.schedule_followup_seconds is not None:
        assert written_json is not None
        pid = schedule_followup(args, written_json, Path(args.out))
        print(
            f"scheduled background follow-up pid {pid} after {args.schedule_followup_seconds}s; "
            "no foreground sleep is running",
            file=sys.stderr,
        )

    if not args.compare:
        gate = payload.get("evidence_gate", {})
        required_gate = args.require_gate or ("process_fd_clean_baseline" if args.require_clean else None)
        if required_gate is not None and gate.get(required_gate) is not True:
            reasons = gate.get("blocking_reasons", []) + gate.get("caution_reasons", [])
            reason_text = ", ".join(str(item.get("reason")) for item in reasons) or "gate_not_admitted"
            print(f"process/fd evidence gate failed: {required_gate}: {reason_text}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
