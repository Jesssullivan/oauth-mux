#!/usr/bin/env python3
"""Exactly-once refresh race proof (TIN-1785 acceptance).

Scope: covers the broker materialize arm
(`broker_loader.refreshCodexAccountAuthFile`), cross-process; the pipeline
attemptRefresh arm and in-process threading are covered by
`src/keepalive/refresh_race_tests.zig` (TIN-2059 gate).

N concurrent broker processes materialize the SAME stale codex account whose
provider definition points at a local stub token endpoint. The per-
`provider:account` blocking flock on the refresh write path
(`broker_loader.zig refreshCodexAccountAuthFile`, landed PR #351) plus the
under-lock freshness re-read must collapse N racing refreshes into exactly one
token-endpoint call; the N-1 losers re-read the rotated store and return the
fresh token without spending a refresh token. The stub provider definition
declares `identity_claim_path` like production codex does
(`src/provider_schema.zig` codex_def), so each refresh also exercises the
TIN-2043 identity flock behind the account flock — the production lock
composition, account-flock THEN identity-flock.

Why this matters: OAuth refresh-token rotation is single-use (RFC 9700
section 2.2.2 / 4.14) — a raced double-refresh revokes the sibling chain. That
is the codex-refresh-token-race incident (GH #336 / PR #337). This test is the
regression gate: against a no-lock write path (the pre-#351 shape), all N
racers POST the same refresh token and the stub answers `invalid_grant` for
every replay, failing the run.

Assertions:
  1. the stub token endpoint is hit EXACTLY once;
  2. no replayed refresh token is ever presented (single-use enforced by stub);
  3. all N materialize calls succeed and agree on the rotated access token;
  4. the auth store ends holding the rotated refresh token (no stale
     writeback);
  5. contention actually occurred: >=2 materialize sends were observed before
     the single refresh response fired. A run that is otherwise green but
     never contended (pathological spawn skew) is RETRIED up to
     CONTENTION_RETRIES times, and only goes red if contention can never be
     established — a green without contention proves nothing about the lock.

Usage: test-refresh-exactly-once.py --bin zig-out/bin/oauth-mux [--racers 4]
Env:   RACER_TIMEOUT_S (default 60) — per-run racer deadline; a run that
       exceeds it is treated as wedged, its brokers are killed, and the
       script exits 1 promptly (racer threads are daemonic so a blocked
       stdout read can never hang interpreter shutdown).
"""

import argparse
import base64
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

RACER_TIMEOUT_S = float(os.environ.get("RACER_TIMEOUT_S", "60"))
ENDPOINT_LATENCY_S = 0.4  # widen the race window: losers must queue on the flock
CONTENTION_RETRIES = 3  # full-run retries when contention cannot be observed

# id_token payload used by the existing broker smoke: plan_type=pro, fedramp.
ID_TOKEN = (
    "h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJw"
    "cm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s"
)


def jwt_with_exp(exp: int) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    return f"h.{payload}.s"


class TokenEndpoint(http.server.BaseHTTPRequestHandler):
    lock = threading.Lock()
    hits = 0
    replays = 0
    valid_rt = "RT-0"
    rotated_rt = "RT-1"
    rotated_at: str = ""  # rotated access token, filled in per run
    first_response_at = None  # monotonic clock when the single 200 fired

    def do_POST(self):  # noqa: N802 (stdlib naming)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()
        form = dict(
            pair.split("=", 1) for pair in body.split("&") if "=" in pair
        )
        presented = form.get("refresh_token", "")
        time.sleep(ENDPOINT_LATENCY_S)
        cls = type(self)
        with cls.lock:
            cls.hits += 1
            if presented == cls.valid_rt:
                # single-use rotation: consume RT-0, issue RT-1
                cls.valid_rt = "__consumed__"
                payload = {
                    "access_token": cls.rotated_at,
                    "refresh_token": cls.rotated_rt,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
                out = json.dumps(payload).encode()
                if cls.first_response_at is None:
                    cls.first_response_at = time.monotonic()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
                return
            # replayed / unknown RT: the real provider revokes the chain here.
            cls.replays += 1
            out = json.dumps({"error": "invalid_grant"}).encode()
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    def log_message(self, *_args):
        pass


def rpc(proc, request):
    proc.stdin.write((json.dumps(request) + "\n").encode())
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("broker closed stdout mid-conversation")
    return json.loads(line)


def racer(bin_path, env, results, procs, send_times, stderr_dir, idx):
    stderr_path = os.path.join(stderr_dir, f"racer-{idx}.stderr.log")
    with open(stderr_path, "wb") as errf:
        proc = subprocess.Popen(
            [bin_path, "mcp", "--profile", "codex-max", "--capability", "codex-max"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errf,
            env=env,
        )
    procs[idx] = proc  # main() kills stragglers on a wedged run
    try:
        r = rpc(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "surface/handshake",
            "params": {"adapter": "race-smoke", "adapter_version": "0",
                       "harness_target": "codex", "session_pid": os.getpid()},
        })
        sid = r["result"]["session_id"]
        r = rpc(proc, {
            "jsonrpc": "2.0", "id": 2, "method": "account/select",
            "params": {"session_id": sid, "profile": "codex-max",
                       "capability": "codex-max"},
        })
        handle = r["result"]["credential_handle"]
        send_times[idx] = time.monotonic()  # contention proof: materialize send
        r = rpc(proc, {
            "jsonrpc": "2.0", "id": 3, "method": "credential/materialize",
            "params": {"session_id": sid, "credential_handle": handle,
                       "shape": "chatgpt_auth_tokens"},
        })
        results[idx] = r
    except Exception as e:  # noqa: BLE001 - report, main() asserts
        results[idx] = {"driver_error": str(e)}
    finally:
        try:
            proc.stdin.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def dump_racer_stderr(tmp):
    for name in sorted(os.listdir(tmp)):
        if not (name.startswith("racer-") and name.endswith(".stderr.log")):
            continue
        path = os.path.join(tmp, name)
        try:
            with open(path, "rb") as f:
                data = f.read().decode(errors="replace").strip()
        except OSError:
            continue
        if data:
            print(f"  --- {name} ---", file=sys.stderr)
            for line in data.splitlines():
                print(f"    {line}", file=sys.stderr)


def run_once(args):
    """One full race run. Returns (failures, sends_before_response, tmp)."""
    now = int(time.time())
    TokenEndpoint.hits = 0
    TokenEndpoint.replays = 0
    TokenEndpoint.valid_rt = "RT-0"
    TokenEndpoint.first_response_at = None
    TokenEndpoint.rotated_at = jwt_with_exp(now + 3600)
    stale_at = jwt_with_exp(now - 100)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), TokenEndpoint)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    tmp = tempfile.mkdtemp(prefix="omux-exactly-once.")
    acct_dir = os.path.join(tmp, "acct")
    state_dir = os.path.join(tmp, "state")
    runtime_dir = os.path.join(tmp, "runtime")
    for d in (acct_dir, state_dir, runtime_dir):
        os.makedirs(d, exist_ok=True)

    auth_path = os.path.join(acct_dir, "auth.json")
    with open(auth_path, "w") as f:
        json.dump({
            "OPENAI_API_KEY": None,
            "tokens": {
                "id_token": ID_TOKEN,
                "access_token": stale_at,
                "refresh_token": "RT-0",
                "account_id": "acc-race-1",
            },
            "auth_mode": "Chatgpt",
        }, f)

    with open(os.path.join(state_dir, "health.json"), "w") as f:
        json.dump({
            "version": 2,
            "accounts": [{
                "key": "codex:race-1#codex-max",
                "liveness": {"state": "live", "availability": "available"},
                "last_probe_hint_class": "none",
                "last_probe_decision": "use_this",
            }],
        }, f)

    config_path = os.path.join(tmp, "config.json")
    with open(config_path, "w") as f:
        json.dump({
            "version": 1,
            "provider_definitions": {
                "codex-test": {
                    "name": "codex-test",
                    # The locked-lineage boundary refuses undeclared refresh
                    # authority before endpoint submission. Match production
                    # Codex's explicit OAuth refresh grant.
                    "repair": {
                        "owner": "upstream_cli_login",
                        "proactive_refresh": "oauth_refresh_token",
                    },
                    "auth": {
                        "token_endpoint": f"http://127.0.0.1:{port}/token",
                        "client_id": "race-client",
                    },
                    # Production codex declares identity_claim_path
                    # (src/provider_schema.zig codex_def); without it the
                    # TIN-2043 identity-flock arm is silently skipped and the
                    # smoke only exercises the account flock.
                    "credential": {
                        "access_token_path": "tokens.access_token",
                        "refresh_token_path": "tokens.refresh_token",
                        "identity_claim_path": "tokens.account_id",
                    },
                },
            },
            "providers": {
                "codex": {
                    "kind": "codex-test",
                    "accounts": {
                        "race-1": {
                            "priority": 10,
                            "config_dir": acct_dir,
                            "secret": {"backend": "file", "path": auth_path},
                        },
                    },
                },
            },
            "profiles": {
                "codex-max": {"providers": ["codex:race-1#codex-max"]},
            },
        }, f)

    env = dict(os.environ)
    env.update({
        "OMUX_CONFIG": config_path,
        "OMUX_STATE_DIR": state_dir,
        "OMUX_RUNTIME_DIR": runtime_dir,
    })

    results = [None] * args.racers
    procs = [None] * args.racers
    send_times = [None] * args.racers
    # daemon=True: a racer blocked in proc.stdout.readline() against a wedged
    # broker must never hang interpreter shutdown after sys.exit(1).
    threads = [
        threading.Thread(
            target=racer,
            args=(args.bin, env, results, procs, send_times, tmp, i),
            daemon=True,
        )
        for i in range(args.racers)
    ]
    for t in threads:
        t.start()
    deadline = time.time() + RACER_TIMEOUT_S
    for t in threads:
        t.join(timeout=max(0.1, deadline - time.time()))
    server.shutdown()
    server.server_close()

    failures = []
    if any(t.is_alive() for t in threads):
        failures.append("racer timed out (possible deadlock on the account flock)")
    # Kill straggler brokers: unblocks any racer stuck in readline() and
    # guarantees a wedged run exits promptly instead of leaking processes.
    for p in procs:
        if p is not None and p.poll() is None:
            p.kill()

    tokens = set()
    for i, r in enumerate(results):
        if r is None:
            failures.append(f"racer {i}: no result")
        elif "driver_error" in r:
            failures.append(f"racer {i}: driver error: {r['driver_error']}")
        elif "error" in r:
            failures.append(f"racer {i}: rpc error: {r['error']}")
        else:
            res = r.get("result", {})
            if res.get("shape") != "chatgpt_auth_tokens":
                failures.append(f"racer {i}: bad shape {res.get('shape')}")
            tokens.add(res.get("access_token"))

    if TokenEndpoint.hits != 1:
        failures.append(
            f"token endpoint hit {TokenEndpoint.hits} times (expected exactly 1)"
        )
    if TokenEndpoint.replays != 0:
        failures.append(
            f"{TokenEndpoint.replays} refresh-token replays — double-spend! "
            "(a real provider revokes the chain here)"
        )
    if not failures and tokens != {TokenEndpoint.rotated_at}:
        failures.append(f"racers disagree on the rotated access token: {tokens}")

    try:
        with open(auth_path) as f:
            final_auth = json.load(f)
    except (OSError, ValueError):
        final_auth = {}
    final_rt = final_auth.get("tokens", {}).get("refresh_token")
    if final_rt != TokenEndpoint.rotated_rt:
        failures.append(
            f"auth store holds refresh_token={final_rt!r} (expected rotated "
            f"{TokenEndpoint.rotated_rt!r}) — stale writeback"
        )

    resp_at = TokenEndpoint.first_response_at
    sends_before = 0
    if resp_at is not None:
        sends_before = sum(
            1 for t in send_times if t is not None and t < resp_at
        )
    return failures, sends_before, tmp


def fail(failures, tmp):
    print("smoke-codex-refresh-exactly-once: FAIL", file=sys.stderr)
    for f_ in failures:
        print(f"  ✗ {f_}", file=sys.stderr)
    dump_racer_stderr(tmp)
    print(f"  diagnostics kept at {tmp}", file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--racers", type=int, default=4)
    args = ap.parse_args()

    for attempt in range(1, CONTENTION_RETRIES + 1):
        failures, sends_before, tmp = run_once(args)
        if failures:
            fail(failures, tmp)
        if sends_before >= 2:
            print(f"  ✓ {args.racers} concurrent materializers, exactly 1 refresh POST")
            print(
                f"  ✓ contention established: {sends_before}/{args.racers} "
                "materialize sends observed before the refresh response fired"
            )
            print("  ✓ no refresh-token replay (single-use rotation preserved)")
            print("  ✓ all racers returned the rotated access token")
            print("  ✓ auth store holds the rotated refresh token")
            shutil.rmtree(tmp, ignore_errors=True)
            return
        # Green but uncontended: a pathological spawn skew serialized the
        # racers, so the run proves nothing about the lock. Retry.
        print(
            f"  ~ contention not established ({sends_before} materialize "
            f"send(s) before the refresh response; need >=2) — "
            f"retry {attempt}/{CONTENTION_RETRIES}"
        )
        if attempt < CONTENTION_RETRIES:
            shutil.rmtree(tmp, ignore_errors=True)

    fail(
        [
            f"contention could not be established in {CONTENTION_RETRIES} "
            "runs (>=2 materialize sends before the refresh response never "
            "observed) — the exactly-once result is vacuous without a race"
        ],
        tmp,
    )


if __name__ == "__main__":
    main()
