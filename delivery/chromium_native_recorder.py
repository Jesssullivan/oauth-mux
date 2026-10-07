"""Test-only bounded stdio observer for synthetic Chromium source requests.

The private fixture copies this declared source into an executable with its
declared Python interpreter. It forwards unchanged frames to one hash-bound
installed native host. Only synthetic request IDs/methods/source IDs enter the
private journal; frames, native replies and diagnostics are never printed.
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
STATIC_IDS = {"chromium-health-first", "chromium-health-restart", "chromium-service-health"}
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


def project(frame, identity):
    message = json.loads(frame[4:], object_pairs_hook=unique_fields, parse_constant=invalid_constant)
    require(type(message) is dict and set(message) == {"version", "id", "method", "params"}
            and type(message["version"]) is int and message["version"] == 1)
    identifier, method, params = message["id"], message["method"], message["params"]
    require(type(identifier) is str and method in {"browser.health", "browser.connect", "browser.disconnect"}
            and type(params) is dict)
    require(params.get("provenance") == {"browser": "chromium", "extensionId": identity,
                                         "channel": "development"})
    source = None
    if method == "browser.health":
        require(set(params) == {"provenance"} and (identifier in STATIC_IDS or UUID.fullmatch(identifier)))
    else:
        require(set(params) == {"sourceId", "adapter", "origin", "provenance"}
                and params["sourceId"] == SOURCE and params["adapter"] == "github"
                and params["origin"] == "https://github.com")
        source = params["sourceId"]
        if method == "browser.connect":
            require(identifier == "chromium-recovery-connect")
        if method == "browser.disconnect":
            require(UUID.fullmatch(identifier))
    return {"id": identifier, "method": method, "sourceId": source}


def append(journal, record):
    encoded = json.dumps(record, separators=(",", ":")).encode("ascii") + b"\n"
    require(len(encoded) <= 256)
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
