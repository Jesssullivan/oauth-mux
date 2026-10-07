"""Private failure projection for one owned CLI invocation; never an RPC outcome."""
import errno
import json
import subprocess

PREFIX = b"OMUX_RUN_CLI_FAILURE_V1"
MAX_RECORD = 192
STAGES = ("launch", "input", "capture", "wait", "process", "json", "result")
FAILURES = ("os-busy", "os-permission", "os-missing", "os-memory", "os-pipe",
            "os-limit", "os-interrupted", "os-other", "timeout", "json",
            "output-bound", "stream-deadline", "process-predicate",
            "result-predicate", "other")
EXITS = ("exit-unobserved", "exit-zero", "exit-positive", "exit-signal", "exit-unavailable")
STDOUT = ("stdout-empty", "stdout-nonempty", "stdout-unavailable")
STDERR = ("stderr-empty", "stderr-nonempty", "stderr-unavailable")
CHOICES = (STAGES, FAILURES, EXITS, STDOUT, STDERR)
PREDICATES = {
    "installed CLI output exceeded its bound": "output-bound",
    "installed CLI deadline exceeded": "stream-deadline",
    "installed CLI predicate failed": "process-predicate",
    "installed CLI response rejected": "result-predicate",
}
ERRNOS = {
    errno.EAGAIN: "os-busy",
    errno.EACCES: "os-permission", errno.EPERM: "os-permission",
    errno.ENOENT: "os-missing",
    errno.ENOMEM: "os-memory",
    errno.EPIPE: "os-pipe",
    errno.EMFILE: "os-limit", errno.ENFILE: "os-limit",
    errno.EINTR: "os-interrupted",
}


def failure_kind(error):
    # Type/errno and exact static predicate messages only; never str/repr(error).
    if isinstance(error, subprocess.TimeoutExpired):
        return "timeout"
    if isinstance(error, OSError):
        return ERRNOS.get(error.errno, "os-other") if type(error.errno) is int else "os-other"
    if isinstance(error, json.JSONDecodeError):
        return "json"
    if (isinstance(error, ValueError) and len(error.args) == 1
            and type(error.args[0]) is str):
        return PREDICATES.get(error.args[0], "other")
    return "other"


def stream_kind(data, name):
    if type(data) not in (bytes, bytearray):
        return name + "-unavailable"
    return name + ("-nonempty" if data else "-empty")


def record(stage, error, returncode, output, diagnostics):
    if stage not in STAGES:
        raise ValueError("CLI failure stage rejected")
    code = ("exit-unobserved" if returncode is None else
            "exit-unavailable" if type(returncode) is not int else
            "exit-zero" if returncode == 0 else
            "exit-positive" if returncode > 0 else "exit-signal")
    fields = (stage, failure_kind(error), code, stream_kind(output, "stdout"),
              stream_kind(diagnostics, "stderr"))
    data = PREFIX + b"/" + "/".join(fields).encode("ascii") + b"\n"
    parse_record(data)
    return data


def parse_record(data):
    if (type(data) is not bytes or len(data) > MAX_RECORD
            or not data.endswith(b"\n") or data.count(b"\n") != 1):
        raise ValueError("CLI failure record rejected")
    fields = data[:-1].split(b"/")
    if len(fields) != 6 or fields[0] != PREFIX:
        raise ValueError("CLI failure record rejected")
    for field, allowed in zip(fields[1:], CHOICES):
        if field not in tuple(value.encode("ascii") for value in allowed):
            raise ValueError("CLI failure record rejected")
    return data


def notify(observer, stage, error, returncode, output, diagnostics):
    """Optional observation cannot replace the operation's failure or cleanup.

    Only finite bytes reach the callback. Failure to classify/deliver is a
    missing diagnostic, never successful acceptance or a different exception.
    Catch BaseException deliberately: diagnostic cancellation/exit must not
    overwrite the original operation exception already being propagated.
    """
    if observer is None:
        return
    try:
        observer(record(stage, error, returncode, output, diagnostics))
    except BaseException:
        return
