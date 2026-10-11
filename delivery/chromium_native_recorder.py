"""Test-only bounded stdio observer for synthetic Chromium source requests.

The private fixture copies this declared source into an executable with its
declared Python interpreter. It forwards unchanged frames to one hash-bound
installed native host. Only synthetic request IDs/methods/source IDs and opaque
operation/revision/generation metadata enter the private journal. Frames, native
replies and diagnostics are never printed. One fixed synthetic Connect loses
only its accepted reply; this fault is not part of the attended health proof.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys

MAX_FRAME = 4096
MAX_JOURNAL = 16384
MAX_RECORDS = 64
SOURCE = "installed-chromium-synthetic-context"
STATIC_IDS = {"chromium-health-first", "chromium-health-restart", "chromium-health-historical", "chromium-service-health"}
SOURCE_IDS = {"chromium-lost-connect", "chromium-exact-retry", "chromium-changed-intent",
              "chromium-stale-removal", "chromium-new-connect", "chromium-removal-retry",
              "chromium-final-removal", "chromium-outcome-before", "chromium-outcome-committed",
              "chromium-outcome-unchanged", "chromium-outcome-removed", "chromium-outcome-new",
              "chromium-outcome-after-replay", "chromium-outcome-final"}
OPERATIONS = {"chromium-original-operation", "chromium-new-operation",
              "chromium-stale-removal-operation", "chromium-final-removal-operation"}
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


def require(condition):
    if not condition:
        raise ValueError("synthetic_recorder_boundary")


def private_file(value, *, executable=False):
    path = Path(value)
    require(path.is_absolute() and str(path.resolve(strict=True)) == value)
    information = path.lstat()
    require(stat.S_ISREG(information.st_mode) and information.st_uid == os.getuid()
            and information.st_nlink == 1 and not information.st_mode & 0o022)
    if executable:
        require(information.st_mode & 0o111)
    return path


def read_frame(stream, *, eof=False):
    header = stream.read(4)
    if eof and header == b"":
        return None
    require(len(header) == 4)
    length = int.from_bytes(header, "little")
    require(0 < length <= MAX_FRAME)
    payload = stream.read(length)
    require(len(payload) == length)
    return header + payload


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("synthetic_recorder_json_constant")


def authority_number(value, *, positive=False):
    require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value)
            and int(value) <= 18446744073709551615 and (not positive or int(value) > 0))


def project(frame, identity):
    message = json.loads(frame[4:], object_pairs_hook=unique_fields, parse_constant=invalid_constant)
    require(type(message) is dict and set(message) == {"version", "id", "method", "params"}
            and type(message["version"]) is int and message["version"] == 1)
    identifier, method, params = message["id"], message["method"], message["params"]
    require(type(identifier) is str and method in {"browser.health", "browser.connect", "browser.connectOutcome", "browser.disconnect"}
            and type(params) is dict)
    require(params.get("provenance") == {"browser": "chromium", "extensionId": identity,
                                         "channel": "development"})
    source = None
    if method == "browser.health":
        require(set(params) == {"provenance"} and (identifier in STATIC_IDS or UUID.fullmatch(identifier)))
    else:
        base = {"sourceId", "adapter", "origin", "provenance", "operationId"}
        required = base | ({"expectedRevision"} if method != "browser.connectOutcome" else set())
        if method == "browser.disconnect":
            required |= {"expectedGeneration"}
        require(required <= set(params) <= required | {"expectedRevision"}
                and params["sourceId"] == SOURCE and params["adapter"] == "github"
                and params["origin"] == "https://github.com")
        require(identifier in SOURCE_IDS or UUID.fullmatch(identifier))
        operation = params["operationId"]
        require(type(operation) is str and (operation in OPERATIONS or UUID.fullmatch(operation))
                and operation != identifier)
        if "expectedRevision" in params:
            authority_number(params["expectedRevision"])
        if "expectedGeneration" in params:
            authority_number(params["expectedGeneration"], positive=True)
        source = params["sourceId"]
        if method == "browser.connect":
            require(identifier in {"chromium-lost-connect", "chromium-exact-retry", "chromium-changed-intent", "chromium-new-connect"}
                    and operation in {"chromium-original-operation", "chromium-new-operation"})
    return {"id": identifier, "method": method, "sourceId": source,
            **{name: params[name] for name in ("operationId", "expectedRevision", "expectedGeneration") if name in params}}


def suppress_reply(frame, response):
    request = json.loads(frame[4:], object_pairs_hook=unique_fields, parse_constant=invalid_constant)
    if request.get("method") != "browser.connect" or request.get("id") != "chromium-lost-connect":
        return False
    reply = json.loads(response[4:], object_pairs_hook=unique_fields, parse_constant=invalid_constant)
    # Refusals are forwarded. Only a validated committed original ACK is lost;
    # the daemon still executes the unchanged real request, not a mock outcome.
    if "error" in reply:
        return False
    require(set(reply) == {"version", "id", "result"} and type(reply["version"]) is int
            and reply["version"] == 1 and reply["id"] == request["id"])
    result = reply["result"]
    require(type(result) is dict and set(result) == {"accepted", "source_id", "operation_id", "revision", "generation"}
            and result["accepted"] is True and result["source_id"] == SOURCE
            and result["operation_id"] == request["params"]["operationId"])
    authority_number(result["revision"], positive=True)
    authority_number(result["generation"], positive=True)
    require(int(result["revision"]) == int(request["params"]["expectedRevision"]) + 1)
    return True


def append(journal, record):
    encoded = json.dumps(record, separators=(",", ":")).encode("ascii") + b"\n"
    require(len(encoded) <= 512)
    descriptor = os.open(journal, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        information = os.fstat(descriptor)
        require(stat.S_ISREG(information.st_mode) and information.st_uid == os.getuid()
                and stat.S_IMODE(information.st_mode) == 0o600 and information.st_nlink == 1
                and information.st_size + len(encoded) <= MAX_JOURNAL)
        previous = os.read(descriptor, MAX_JOURNAL + 1)
        require(len(previous) <= MAX_JOURNAL and previous.count(b"\n") < MAX_RECORDS)
        require(os.write(descriptor, encoded) == len(encoded))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def deadline(signum, frame):
    raise TimeoutError("synthetic_recorder_deadline")


def main():
    require(os.environ.get("OMUX_ISOLATED_VAULT_PROOF") == "private-bus-private-xdg"
            and os.environ.get("OMUX_INSTANCE") == "dev" and len(sys.argv) == 2)
    configuration = private_file(os.environ["OMUX_CHROMIUM_RECORDER_CONFIG"])
    require(configuration.stat().st_size <= 4096)
    settings = json.loads(configuration.read_bytes())
    require(type(settings) is dict and set(settings) ==
            {"nativeHost", "nativeHostSha256", "journal", "extensionId"})
    identity = settings["extensionId"]
    require(type(identity) is str and re.fullmatch(r"[a-p]{32}", identity)
            and sys.argv[1] == "chrome-extension://" + identity + "/")
    host = private_file(settings["nativeHost"], executable=True)
    launcher = private_file(str(Path(sys.argv[0]).absolute()), executable=True)
    require(host.name == "omux-native-host" and host.parent.name == "bin"
            and not os.path.samefile(host, launcher) and not os.path.samefile(host, __file__)
            and host.stat().st_size <= 262144
            and hashlib.sha256(host.read_bytes()).hexdigest() == settings["nativeHostSha256"])
    journal = private_file(settings["journal"])
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(15)
    process = None
    try:
        process = subprocess.Popen([str(host), sys.argv[1]], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        for index in range(8):
            frame = read_frame(sys.stdin.buffer, eof=True)
            if frame is None:
                process.stdin.close()
                return 0 if process.wait(timeout=2) == 0 else 1
            record = project(frame, identity)
            append(journal, record)
            process.stdin.write(frame)
            process.stdin.flush()
            response = read_frame(process.stdout)
            if suppress_reply(frame, response):
                # Closing the transport is a reply fault, never cancellation.
                return 0
            sys.stdout.buffer.write(response)
            sys.stdout.buffer.flush()
        raise ValueError("synthetic_recorder_frame_limit")
    finally:
        signal.alarm(0)
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Never copy exception text, native output or frames to diagnostics.
        print("synthetic Chromium recorder refused", file=sys.stderr)
        sys.exit(1)
