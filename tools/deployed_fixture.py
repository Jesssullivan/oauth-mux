"""Historical host receipts; remote execution lacks verified aggregate containment."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
import signal
import re
import subprocess
import sys
import tarfile
import threading
import uuid

from host_probe import HOSTS
from ssh_policy import operator_config
from host_cleanup import KNOWN_REPAIRS, KNOWN_DIAGNOSTIC, REJECTION_CODES, STING_RECOVERY_PROOF, MAX_ENTRIES


def phase_marker(line):
    return {"phase=nix-bootstrap\n": "nix-bootstrap", "phase=declared-bazel-graph\n": "declared-bazel-graph", **{"phase=" + phase + "\n": phase for phase in ["repository-mapping", "loading-analysis", "analysis-complete", "action-execution", "graph-complete", "private-staging-repair"]}}.get(line)


def cleanup_rejection_fields(output, prefix):
    fields = {}
    code = re.search(r"^" + prefix + r"-rejection-code=([a-z-]+)$", output, re.MULTILINE)
    if code:
        if code.group(1) not in REJECTION_CODES:
            raise ValueError("unknown cleanup rejection code")
        fields["rejection_code"] = code.group(1)
    metadata = re.search(r"^" + prefix + r"-metadata=(.{1,512})$", output, re.MULTILINE)
    if metadata:
        value = json.loads(metadata.group(1))
        if (not isinstance(value, dict) or not {"depth", "scope", "entry_kind"} <= set(value) or set(value) - {"depth", "scope", "entry_kind", "mode", "owner_class", "match_count", "candidate_count"}
                or type(value["depth"]) is not int or not 0 <= value["depth"] <= 129
                or value["scope"] not in {"workspace", "source", "state", "runtime"}
                or value["entry_kind"] not in {"_tmp", "tmp", "sandbox", "server", "external", "other"}
                or ("mode" in value and (type(value["mode"]) is not int or not 0 <= value["mode"] <= 4095))
                or ("owner_class" in value and value["owner_class"] not in {"current", "root", "other"})
                or any(name in value and (type(value[name]) is not int or not 0 <= value[name] <= 32) for name in ["match_count", "candidate_count"])):
            raise ValueError("cleanup metadata rejected")
        fields["rejection_metadata"] = value
    for name in ["directories", "entries", "repaired-directories"]:
        count = re.search(r"^" + prefix + "-" + name + r"=(\d{1,7})$", output, re.MULTILINE)
        if count:
            if int(count.group(1)) > MAX_ENTRIES + 1:
                raise ValueError("cleanup partial count exceeds bound")
            fields[name.replace("-", "_")] = int(count.group(1))
    digest = re.search(r"^" + prefix + r"-summary-sha256=([a-f0-9]{64})$", output, re.MULTILINE)
    if digest:
        fields["summary_sha256"] = digest.group(1)
    return fields


def transport(command, payload, timeout, progress, workspace_callback=None):
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    def terminate():
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    stream = proc.stdout
    proc.stdout = None
    captured = bytearray()
    overflow = []
    failures = []
    def collect():
        try:
            while True:
                line = stream.readline(4097)
                if not line:
                    break
                if len(captured) + len(line) > 65536:
                    overflow.append(True)
                    terminate()
                    break
                captured.extend(line)
                phase = phase_marker(line.decode("utf-8", errors="replace"))
                if phase:
                    progress(phase)
                workspace = re.fullmatch(r"proof-workspace=(\.run-[A-Za-z0-9]{8})\n", line.decode("ascii", errors="replace"))
                if workspace and workspace_callback is not None:
                    workspace_callback(workspace.group(1))
        except Exception:
            failures.append(True)
            terminate()
        finally:
            try:
                stream.close()
            except Exception:
                failures.append(True)
                terminate()
    reader = threading.Thread(target=collect, daemon=True)
    reader.start()
    handlers = {}
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            handlers[signum] = signal.signal(signum, interrupted)
    try:
        _, stderr = proc.communicate(payload, timeout=timeout)
    except BaseException:
        terminate()
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            for pipe in (proc.stdin, proc.stderr):
                if pipe is not None:
                    pipe.close()
        reader.join(5)
        raise
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
    reader.join(5)
    if overflow or failures or reader.is_alive():
        terminate()
        raise ValueError("bounded proof output rejected")
    return subprocess.CompletedProcess(command, proc.returncode, bytes(captured), stderr)

# Linux graph entrypoints and fixed historical Darwin custody operations.
# Darwin compilation and vault tests use the separately configured PZM REAPI lane.
TARGETS = {
    "linux-recover": ("Linux", "recover", "//tools:deployed_fixture"),
    "darwin-diagnose": ("Darwin", "diagnose", "//tools:deployed_fixture"),
    "darwin-cleanup": ("Darwin", "cleanup", "//tools:deployed_fixture"),
    "linux-package": ("Linux", "build", "//delivery:release_archive"),
    "linux-vault": ("Linux", "test", "//:vault_realproof"),
    "linux-installed": ("Linux", "test", "//delivery:installed_custody_test"),
}


def public_graph_diagnostics(output):
    diagnostics = []
    for line in output.splitlines():
        match = re.search(r"(?:src|clients|tools|delivery)/[^\s:]+(?::\d+){1,2}:.*(?:error:|ERROR:)", line)
        if not match:
            match = re.search(r"(?:ERROR|FATAL|error|fatal error|ValueError|RuntimeError|AssertionError|FileNotFoundError):.*", line)
        if not match:
            match = re.search(r"(?:clang|ld|dyld|curl|bash|sh|zsh):.*", line)
        if not match:
            continue
        line = match.group(0)
        if re.search(r"(?i)token|password|secret|cookie|authorization|credential|private.key", line):
            continue
        line = re.sub(r"(?<![\w])/[^\s'\"]+", "[absolute-path]", line)
        line = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[redacted-address]", line)
        line = re.sub(r"(['\"])[^'\"]{80,}\1", "[redacted-long-value]", line)
        diagnostics.append(line[:1024])
    return diagnostics[:8]


def provenance_fields(output, recipe, successful=True):
    """Accept only bounded data emitted for this recipe's fixed artifact."""
    fields = {}
    recognized = {"artifact-kind", "artifact-sha256", "artifact-bytes", "host-os", "host-arch",
                  "host-kernel", "host-product-release", "host-os-family", "omux-version", "cleanup"}
    for line in output.splitlines():
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name not in recognized:
            continue
        if name in fields or len(value) > 128:
            raise ValueError("duplicate or oversized proof provenance")
        fields[name] = value
    result = {}
    for name, allowed in {
        "host-os": {"Linux", "Darwin"}, "host-arch": {"x86_64", "aarch64", "arm64"},
        "cleanup": {"removed", "failed"},
        "host-os-family": {"linux", "darwin", "nixos", "ubuntu", "debian", "fedora", "arch", "alpine",
                           "opensuse", "opensuse-tumbleweed", "rhel", "centos", "rocky", "almalinux", "linuxmint"},
    }.items():
        if name in fields:
            if fields[name] not in allowed:
                raise ValueError("unrecognized proof provenance enum")
            result[name.replace("-", "_")] = fields[name]
    for name in ["host-kernel", "host-product-release"]:
        if name in fields:
            # Emit the numeric release only; custom kernel suffixes may identify
            # a workstation. Keep vendor/build detail out of shared receipts.
            if not re.fullmatch(r"\d+(?:\.\d+){0,3}", fields[name]):
                raise ValueError("unsafe host release metadata")
            result[name.replace("-", "_")] = fields[name]
    if "omux-version" in fields:
        if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.+-]{1,48})?", fields["omux-version"]):
            raise ValueError("unsafe Omux product version metadata")
        result["omux_version"] = fields["omux-version"]
    required = successful and recipe in {"linux-installed", "linux-package", "darwin-build"}
    present = {name for name in fields if name.startswith("artifact-")}
    if present or required:
        expected = "darwin-zip" if recipe == "darwin-build" else "linux-tar-gz"
        if present != {"artifact-kind", "artifact-sha256", "artifact-bytes"} or fields["artifact-kind"] != expected:
            raise ValueError("missing or unrecognized declared artifact provenance")
        if not re.fullmatch(r"[a-f0-9]{64}", fields["artifact-sha256"]):
            raise ValueError("malformed declared artifact digest")
        if not re.fullmatch(r"[1-9]\d{0,9}", fields["artifact-bytes"]) or int(fields["artifact-bytes"]) > 512 * 1024 * 1024:
            raise ValueError("declared artifact exceeds byte bound")
        result["artifact"] = {"kind": expected, "sha256": fields["artifact-sha256"], "bytes": int(fields["artifact-bytes"])}
    return result


def bootstrap_diagnostics(output):
    excerpts = []
    for line in output.splitlines():
        if not re.match(r"\s*(?:error:|(?:bash|sh|zsh|nix|tar):|>.*(?:error:|clang:|ld:|No such file|not found|unsupported|failed))", line):
            continue
        if re.search(r"(?i)token|password|secret|cookie|authorization|credential|private.key", line):
            continue
        line = re.sub(r"/nix/store/[a-z0-9]{32}-([A-Za-z0-9.+_-]{1,96}\.drv)", r"[public-derivation:\1]", line)
        line = re.sub(r"/[^\s'\"]+", "[absolute-path]", line)
        line = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[redacted-address]", line)
        line = re.sub(r"(['\"])[^'\"]{80,}\1", "[redacted-long-value]", line)
        excerpts.append(line[:1024])
    return excerpts[:8]


def public_archive(path):
    with open(path, "rb") as source:
        payload = source.read(256 * 1024 * 1024 + 1)
    if len(payload) > 256 * 1024 * 1024:
        raise ValueError("public source archive exceeds bounded transfer size")
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        names = set()
        total_size = 0
        for member in archive:
            parts = member.name.split("/")
            if (len(names) >= 10000 or len(member.name) > 4096
                    or any(character in member.name for character in ["\n", "\r", "\x00"])
                    or member.name.startswith("/") or ".." in parts
                    or member.issym() or member.islnk() or not (member.isfile() or member.isdir())):
                raise ValueError("public source archive contains unsafe extraction entry")
            if any(part in {".git", ".ssh", ".netrc", ".codex", ".claude", "auth.json", "credentials.json"}
                   or part.startswith(".env") for part in parts):
                raise ValueError("public source archive includes private state")
            name = member.name.removeprefix("./")
            if name in names:
                raise ValueError("public source archive repeats an extraction path")
            total_size += member.size
            if total_size > 512 * 1024 * 1024:
                raise ValueError("public source archive exceeds bounded extraction size")
            names.add(name)
        if not {"flake.nix", "flake.lock", "MODULE.bazel", "BUILD.bazel"}.issubset(names):
            raise ValueError("archive must contain the declared repository graph at its root")
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh", required=True)
    parser.add_argument("--source-archive", required=True)
    parser.add_argument("--host", choices=HOSTS, required=True)
    parser.add_argument("--recipe", choices=TARGETS, required=True)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--cleanup-workspace", choices=[*KNOWN_REPAIRS, KNOWN_DIAGNOSTIC[0]])
    args = parser.parse_args()
    print(json.dumps({"host_alias": args.host, "recipe": args.recipe,
                      "passed": False, "gate": "unsupported-execution-capability",
                      "reason": "remote Nix bootstrap and descendants have no verified aggregate containment",
                      "claim": "no remote operation attempted"}, sort_keys=True))
    return 2
    expected, verb, target = TARGETS[args.recipe]
    if (args.recipe in {"darwin-cleanup", "darwin-diagnose"}) != bool(args.cleanup_workspace) or (args.cleanup_workspace and args.host != "neo") or (args.recipe == "darwin-diagnose" and args.cleanup_workspace != KNOWN_DIAGNOSTIC[0]) or (args.recipe == "darwin-cleanup" and args.cleanup_workspace not in KNOWN_REPAIRS):
        parser.error("cleanup is restricted to the explicitly authorized Neo workspace")
    if args.recipe == "linux-recover" and args.host != "sting":
        parser.error("recovery is restricted to the explicitly recorded Sting proof")
    if HOSTS[args.host] != expected or not 30 <= args.timeout <= 3600:
        parser.error("recipe must match host platform and timeout must be 30..3600 seconds")
    result = {"host_alias": args.host, "recipe": args.recipe, "passed": False,
              "target": target, "proof_id": str(uuid.uuid4()),
              "claim": "fixed declared target predicates; no live continuity proof", "observed_phases": [], "phase_observations": []}
    if args.recipe == "darwin-cleanup":
        result["claim"] = "exact private staging cleanup; no runtime platform proof"
        result["cleanup_workspace"] = args.cleanup_workspace
    def observe(phase):
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if phase not in result["observed_phases"]:
            result["observed_phases"].append(phase)
            result["phase_observations"].append({"phase": phase, "observed_at": timestamp})
        result["last_observed_phase"] = phase
        result["last_phase_observed_at"] = timestamp
        print(json.dumps({"host_alias": args.host, "proof_id": result["proof_id"], "source_sha256": result["source_sha256"], "phase": phase, "observed_at": timestamp, "progress": True}, sort_keys=True), flush=True)
    def observe_workspace(name):
        if "proof_workspace" in result:
            raise ValueError("duplicate current workspace authority")
        result["proof_workspace"] = name
        print(json.dumps({"host_alias": args.host, "proof_id": result["proof_id"], "source_sha256": result["source_sha256"], "proof_workspace": name, "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "progress": True}, sort_keys=True), flush=True)
    try:
        payload = public_archive(args.source_archive)
        result["source_sha256"] = hashlib.sha256(payload).hexdigest()
        command = """set -eu
umask 077
omux_started=$SECONDS
test "$(uname -s)" = PLATFORM
command -v nix >/dev/null
omux_uid=$(id -u)
omux_safe_dir() {
  test -d "$1" && test ! -L "$1" || return 3
  case PLATFORM in
    Linux) omux_metadata=$(stat -c "%u:%a" "$1") ;;
    Darwin) omux_metadata=$(stat -f "%u:%Lp" "$1") ;;
  esac
  omux_owner=${omux_metadata%%:*}; omux_mode=${omux_metadata#*:}
  case "$omux_owner:$omux_mode" in *[!0-9:]*|:*) return 3 ;; esac
  test "$omux_owner" = "$omux_uid" || test "$omux_owner" = 0 || return 3
  test "$((8#$omux_mode & 8#022))" -eq 0 || return 3
}
case PLATFORM in
  Linux) omux_base="${XDG_STATE_HOME:-$HOME/.local/state}/omux-proof" ;;
  Darwin) omux_base="$HOME/Library/Application Support/OmuxProof" ;;
esac
case "$HOME:$omux_base" in *'
'*) exit 3 ;; esac
omux_cr=$(printf "\\r")
case "$HOME:$omux_base" in *"$omux_cr"*) exit 3 ;; esac
case "$omux_base" in /*) ;; *) exit 3 ;; esac
case "$omux_base" in *//*|*/../*|*/./*|*/..|*/.) exit 3 ;; esac
omux_safe_dir / || exit 3
case "$HOME" in /*) ;; *) exit 3 ;; esac
case "$HOME" in *//*|*/../*|*/./*|*/..|*/.) exit 3 ;; esac
omux_rest=${HOME#/}; omux_walk=/
while test -n "$omux_rest"; do
  omux_component=${omux_rest%%/*}
  case "$omux_component" in ""|.|..) exit 3 ;; esac
  if test "$omux_component" = "$omux_rest"; then omux_rest=""; else omux_rest=${omux_rest#*/}; fi
  omux_walk="${omux_walk%/}/$omux_component"
  omux_safe_dir "$omux_walk" || exit 3
done
test "$omux_owner" = "$omux_uid" || exit 3
if test RECIPE = darwin-cleanup; then test -d "$omux_base" && test ! -L "$omux_base" || exit 3; fi
omux_rest=${omux_base#/}; omux_walk=/
while test -n "$omux_rest"; do
  omux_component=${omux_rest%%/*}
  case "$omux_component" in ""|.|..) exit 3 ;; esac
  if test "$omux_component" = "$omux_rest"; then omux_rest=""; else omux_rest=${omux_rest#*/}; fi
  omux_walk="${omux_walk%/}/$omux_component"
  if test ! -e "$omux_walk" && test ! -L "$omux_walk"; then mkdir "$omux_walk"; fi
  omux_safe_dir "$omux_walk" || exit 3
done
test "$omux_owner" = "$omux_uid" && test "$omux_mode" = 700 || exit 3
if test RECIPE = darwin-cleanup && { test -e "$omux_base/REPAIRNAME" || test -L "$omux_base/REPAIRNAME"; }; then
  omux_safe_dir "$omux_base/REPAIRNAME" || exit 3
  test "$omux_owner" = "$omux_uid" && test "$omux_mode" = 700 || exit 3
fi
omux_workspace=$(mktemp -d "$omux_base/.run-XXXXXXXX")
case PLATFORM in
  Linux) omux_identity=$(stat -c "%d:%i" "$omux_workspace") ;;
  Darwin) omux_identity=$(stat -f "%d:%i" "$omux_workspace") ;;
esac
omux_budget_open=0
omux_nix_pid=""
omux_declared_cleanup=0
omux_cleanup() {
  omux_exit=$1
  trap - EXIT HUP INT TERM
  if test "$omux_budget_open" = 1; then exec 4>&-; fi
  if test -n "$omux_nix_pid"; then
    omux_wait_started=$SECONDS
    while kill -0 "$omux_nix_pid" 2>/dev/null && test "$((SECONDS - omux_wait_started))" -lt 10; do sleep 0.1; done
    if kill -0 "$omux_nix_pid" 2>/dev/null; then kill -TERM "$omux_nix_pid" 2>/dev/null || :; fi
  fi
  if test ! -e "$omux_workspace" && test ! -L "$omux_workspace"; then printf "cleanup=removed\\n";
  elif test "$omux_declared_cleanup" = 1; then printf "cleanup=failed\\n"; omux_exit=1;
  elif rm -rf "$omux_workspace"; then printf "cleanup=removed\\n"; else printf "cleanup=failed\\n"; omux_exit=1; fi
  exit "$omux_exit"
}
trap 'omux_cleanup $?' EXIT
trap 'exit 130' HUP INT TERM
(set -C; printf "%s:%s\\n" PROOFID "$omux_identity" > "$omux_workspace/current.authority") || exit 3
printf "proof-workspace=%s\\n" "${omux_workspace##*/}"
mkdir "$omux_workspace/source" "$omux_workspace/state" "$omux_workspace/runtime"
tar -xzf - -C "$omux_workspace/source"
cd "$omux_workspace/source"
export XDG_CONFIG_HOME="$omux_workspace/state/config" XDG_DATA_HOME="$omux_workspace/state/data"
export XDG_CACHE_HOME="$omux_workspace/state/cache" XDG_STATE_HOME="$omux_workspace/state/state"
export XDG_RUNTIME_DIR="$omux_workspace/runtime"
unset SSH_AUTH_SOCK DBUS_SESSION_BUS_ADDRESS CODEX_HOME CLAUDE_CONFIG_DIR
mkfifo -m 600 "$omux_workspace/graph.deadline"
omux_nix_status=0
printf "phase=nix-bootstrap\\n"
omux_nix=$(command -v nix)
case "$omux_nix" in /*) ;; *) exit 3 ;; esac
omux_declared_cleanup=1
# R-N13: remote bootstrap uses the same explicit evaluation-cache policy as local proof.
env -i HOME="$HOME" XDG_CONFIG_HOME="$XDG_CONFIG_HOME" XDG_DATA_HOME="$XDG_DATA_HOME" XDG_CACHE_HOME="$XDG_CACHE_HOME" XDG_STATE_HOME="$XDG_STATE_HOME" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" PATH=/usr/bin:/bin:/usr/sbin:/sbin "$omux_nix" --option eval-cache false develop --ignore-environment --keep HOME --keep XDG_CONFIG_HOME --keep XDG_DATA_HOME --keep XDG_CACHE_HOME --keep XDG_STATE_HOME --keep XDG_RUNTIME_DIR --command bash -c '
omux_status=0
python3 -I -S tools/host_workspace.py --workspace "$5" --base "$7" --platform PLATFORM || exit 3
omux_python=$(command -v python3)
omux_cleanup_helper="$PWD/tools/host_cleanup.py"
omux_current_base="$7"
omux_current_workspace="$5"
omux_current_cleanup() {
  omux_saved=$?
  trap - EXIT HUP INT TERM
  cd "$omux_current_base" || exit 3
  "$omux_python" -I -S "$omux_cleanup_helper" --current --base "$omux_current_base" --workspace "$omux_current_workspace" --proof-id PROOFID || omux_saved=3
  exit "$omux_saved"
}
(set -C; printf "admitted\\n" > "$5/cleanup.admitted") || exit 3
trap omux_current_cleanup EXIT
trap "exit 130" HUP INT TERM
if test "$6" = darwin-cleanup || test "$6" = darwin-diagnose || test "$6" = linux-recover; then
  python3 -I -S tools/host_cleanup.py DIAGFLAG --base "$7" --workspace REPAIRNAME --repair-proof REPAIRPROOF --custodian "$5" --custodian-proof PROOFID --total "$1"
  exit $?
fi
printf "phase=declared-bazel-graph\\n"
printf "host-os=%s\\n" "$(uname -s)"
printf "host-arch=%s\\n" "$(uname -m)"
omux_kernel=$(uname -r)
omux_kernel=${omux_kernel%%-*}
case "$omux_kernel" in *[!0-9.]*|"") ;; *) printf "host-kernel=%s\\n" "$omux_kernel" ;; esac
python3 -I -S tools/host_graph.py --recipe "$6" --bazelisk "$(command -v bazelisk)" --output-root "$5/bazel" --log "$4" --budget-pipe "$5/graph.deadline" --total "$1" --proof-id PROOFID || omux_status=$?
if [ "$omux_status" -eq 0 ]; then
  omux_artifact=""
  case "$6" in
    linux-installed|linux-package) omux_artifact=bazel-bin/delivery/release_archive.tar.gz; omux_kind=linux-tar-gz ;;
  esac
  if [ -n "$omux_artifact" ]; then
    omux_resolved=$(realpath "$omux_artifact")
    case "$omux_resolved" in "$5"/bazel/*) ;; *) exit 3 ;; esac
    test -f "$omux_resolved" && test ! -L "$omux_resolved" || exit 3
    printf "artifact-kind=%s\\n" "$omux_kind"
    printf "artifact-sha256="; sha256sum "$omux_resolved" | cut -d " " -f 1
    printf "artifact-bytes="; wc -c < "$omux_resolved" | tr -d " "
  fi
fi
omux_bytes=0
while IFS= read -r omux_line; do
  case "$omux_line" in
    *error:*|*ERROR:*|*FATAL:*|*ValueError:*|*RuntimeError:*|*AssertionError:*|*FileNotFoundError:*|*clang:*|*ld:*)
      if [ "${#omux_line}" -le 1024 ]; then
        omux_bytes=$((omux_bytes + ${#omux_line} + 1))
        if [ "$omux_bytes" -gt 8192 ]; then break; fi
        printf "%s\\n" "$omux_line"
      fi
      ;;
  esac
done < "$4"
exit "$omux_status"
' omux-graph TOTAL VERB TARGET "$omux_workspace/build.log" "$omux_workspace" RECIPE "$omux_base" &
omux_nix_pid=$!
while kill -0 "$omux_nix_pid" 2>/dev/null && test ! -f "$omux_workspace/graph.ready"; do sleep 0.1; done
if test -f "$omux_workspace/graph.ready" && test ! -L "$omux_workspace/graph.ready"; then
  case PLATFORM in
    Linux) omux_marker=$(stat -c "%u:%a:%h:%s" "$omux_workspace/graph.ready") ;;
    Darwin) omux_marker=$(stat -f "%u:%Lp:%l:%z" "$omux_workspace/graph.ready") ;;
  esac
  test "$omux_marker" = "$omux_uid:600:1:6" || exit 3
  exec 4> "$omux_workspace/graph.deadline"
  omux_budget_open=1
  omux_elapsed=$((SECONDS - omux_started))
  test "$omux_elapsed" -ge 0 && test "$omux_elapsed" -le TOTAL || exit 3
  omux_remaining=$((TOTAL - 21 - omux_elapsed))
  test "$omux_remaining" -ge 1 || exit 3
  printf "%s\\n" "$omux_remaining" >&4
fi
wait "$omux_nix_pid" || omux_nix_status=$?
exit "$omux_nix_status"
""".replace("PLATFORM", expected).replace("VERB", verb).replace("TARGET", target).replace("TOTAL", str(args.timeout)).replace("RECIPE", args.recipe).replace("REPAIRNAME", "receipt-sting-faf6" if args.recipe == "linux-recover" else args.cleanup_workspace or ".run-nUi7wZna").replace("REPAIRPROOF", STING_RECOVERY_PROOF if args.recipe == "linux-recover" else KNOWN_DIAGNOSTIC[1] if args.recipe == "darwin-diagnose" else KNOWN_REPAIRS.get(args.cleanup_workspace, KNOWN_REPAIRS[".run-nUi7wZna"])).replace("DIAGFLAG", "--recover-sting" if args.recipe == "linux-recover" else "--diagnose" if args.recipe == "darwin-diagnose" else "").replace("PROOFID", result["proof_id"])
        with operator_config() as config_options:
            proc = transport(
            [args.ssh, *config_options, "-oBatchMode=yes", "-oConnectTimeout=10", "-oConnectionAttempts=1",
             "-oStrictHostKeyChecking=yes", "-oForwardAgent=no", "-oClearAllForwardings=yes",
             args.host, command], payload, args.timeout,
             observe, observe_workspace,
            )
        output = proc.stdout.decode("utf-8", errors="replace")
        workspaces = re.findall(r"^proof-workspace=(\.run-[A-Za-z0-9]{8})$", output, re.MULTILINE)
        if len(workspaces) == 1:
            result["proof_workspace"] = workspaces[0]
        elif workspaces:
            raise ValueError("duplicate proof workspace receipt")
        current_error = re.search(r"^current-cleanup-error=(deadline|custodian-or-signal|custody|permissions|not-empty|symlink|missing|storage|filesystem)$", output, re.MULTILINE)
        if current_error:
            result["current_cleanup_error"] = current_error.group(1)
        current_outcome = re.search(r"^current-cleanup=(removed|absent|failed)$", output, re.MULTILINE)
        if current_outcome:
            result["current_cleanup_result"] = current_outcome.group(1)
        result.update({"current_cleanup_" + name: value for name, value in cleanup_rejection_fields(output, "current-cleanup").items()})
        result["observed_phases"] = list(dict.fromkeys(phase for line in output.splitlines(keepends=True) if (phase := phase_marker(line))))
        status = re.search(r"^graph-exit=(\d{1,3})$", output, re.MULTILINE)
        digest = re.search(r"^log-sha256=([a-f0-9]{64})$", output, re.MULTILINE)
        result["remote_exit_code"] = proc.returncode
        result["phase"] = "declared-bazel-graph" if status else "host-stage-or-nix-bootstrap"
        if status:
            result["graph_exit_code"] = int(status.group(1))
        if digest:
            result["log_sha256"] = digest.group(1)
        result["passed"] = (proc.returncode == 0 and status is not None
                            and status.group(1) == "0" and digest is not None)
        result.update(provenance_fields(output, args.recipe, result["passed"]))
        result["passed"] = result["passed"] and result.get("cleanup") == "removed" and result.get("host_os") == expected
        result["gate"] = "passed" if result["passed"] else "remote declared graph or host bootstrap failed"
        diagnostics = public_graph_diagnostics(output)
        if diagnostics:
            result["public_graph_diagnostics_redacted"] = diagnostics
        if args.recipe in {"darwin-cleanup", "linux-recover"}:
            if args.recipe == "linux-recover":
                recovered = re.findall(r"^recovered-workspace=(\.run-[A-Za-z0-9]{8})$", output, re.MULTILINE)
                if len(recovered) > 1:
                    raise ValueError("duplicate recovery workspace receipt")
                if recovered:
                    result["recovered_workspace"] = recovered[0]
                authority = re.findall(r"^recovery-authority=(proof-marker|recorded-log-hash|recorded-artifact-hash)$", output, re.MULTILINE)
                if len(authority) > 1:
                    raise ValueError("duplicate recovery content authority")
                if authority:
                    result["recovery_authority"] = authority[0]
                result["recovery_receipt_scope_proof_id"] = STING_RECOVERY_PROOF
                result["claim"] = "unique authorized content and custody staging recovery; no runtime or source epoch proof"
            result.update({"repair_" + name: value for name, value in cleanup_rejection_fields(output, "repair").items()})
            repair = re.search(r"^repair-result=(removed|absent|failed)$", output, re.MULTILINE)
            repair_hash = re.search(r"^repair-summary-sha256=([a-f0-9]{64})$", output, re.MULTILINE)
            repair_error = re.search(r"^repair-error=(deadline|custodian-or-signal|custody|permissions|not-empty|symlink|missing|storage|filesystem)$", output, re.MULTILINE)
            if repair:
                result["repair_result"] = repair.group(1)
            if repair_hash:
                result["repair_summary_sha256"] = repair_hash.group(1)
            if repair_error:
                result["repair_error"] = repair_error.group(1)
            for name in ["directories", "entries", "repaired-directories"]:
                count = re.search(r"^repair-" + name + r"=(\d{1,7})$", output, re.MULTILINE)
                if count:
                    result["repair_" + name.replace("-", "_")] = int(count.group(1))
            result["passed"] = proc.returncode == 0 and repair is not None and repair.group(1) in {"removed", "absent"} and repair_hash is not None and result.get("cleanup") == "removed"
            if args.recipe == "linux-recover":
                result["passed"] = result["passed"] and "recovered_workspace" in result and "recovery_authority" in result
            result["gate"] = "exact staging repair passed" if result["passed"] else "exact staging repair failed"
        if args.recipe == "darwin-diagnose":
            summaries = re.findall(r"^diagnostic-summary=(.{1,8192})$", output, re.MULTILINE)
            summary = json.loads(summaries[0]) if len(summaries) == 1 else None
            if summary is not None:
                if (not isinstance(summary, dict) or set(summary) != {"proof_id", "log_sha256", "identities", "categories"}
                        or summary["proof_id"] != KNOWN_DIAGNOSTIC[1] or summary["log_sha256"] != KNOWN_DIAGNOSTIC[2]
                        or not isinstance(summary["identities"], list) or len(summary["identities"]) > 32
                        or any(not isinstance(item, str) or len(item) > 300 or not re.fullmatch(r"(?:library|framework|sdk-relative):[A-Za-z0-9_./+\-]+", item) or ".." in item.split("/") for item in summary["identities"])
                        or summary["categories"] not in [[], ["unresolved-dependency"]]):
                    raise ValueError("diagnostic summary rejected")
                result["dependency_diagnostic_candidates"] = summary
            result["claim"] = "exact private public-build-log diagnostics; no platform proof"
            result["passed"] = proc.returncode == 0 and summary is not None and result.get("cleanup") == "removed"
            result["gate"] = "exact diagnostics collected" if result["passed"] else "exact diagnostics failed"
        if not status:
            result["bootstrap_log_sha256"] = hashlib.sha256(proc.stderr).hexdigest()
            diagnostic = proc.stderr.decode("utf-8", errors="replace").lower()
            for needle, category in [
                ("experimental nix feature", "Nix experimental features unavailable"),
                ("could not resolve", "public Nix source hostname resolution failed"),
                ("permission denied", "host workspace or Nix permissions rejected"),
                ("unfree", "locked SDK/tool license policy gate"),
                ("attribute", "locked Nix expression attribute error"),
                ("syntax", "host shell or Nix source syntax rejected"),
                ("command not found", "host bootstrap utility unavailable"),
                ("not found", "host bootstrap input unavailable"),
                ("no such file", "host bootstrap input unavailable"),
            ]:
                if needle in diagnostic:
                    result["bootstrap_failure"] = category
                    break
            excerpts = bootstrap_diagnostics(proc.stderr.decode("utf-8", errors="replace"))
            if excerpts:
                result["bootstrap_diagnostics_redacted"] = excerpts
    except subprocess.TimeoutExpired:
        result["gate"] = "caller deadline expired; remote cleanup unknown"
        result["cleanup"] = "unknown"
        result["phase"] = result.get("last_observed_phase", "transport")
    except KeyboardInterrupt:
        result["gate"] = "caller canceled; remote cleanup unknown"
        result["cleanup"] = "unknown"
        result["phase"] = result.get("last_observed_phase", "transport")
    except (OSError, ValueError, tarfile.TarError):
        result["gate"] = "archive custody rejected, transport unavailable, or bounded execution expired"
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
