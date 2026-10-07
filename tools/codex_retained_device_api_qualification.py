"""Retained009 provider-free device schema qualification; declared Bazel only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

import codex_owner_runtime_input as retained
import guard_owner_runtime_input as custody
sys.path.insert(0, str(Path(__file__).parent.parent / "delivery"))
import codex_runtime_selection as selection

BACKEND_SHA = "0b82d7f1535ab98ca2854dad0ac908912c9df56f29bb70c664e18e9956dc4a3f"
BACKEND_BYTES = 318579008
LOADER_SHA = "1640ec4d1cfcc3c19430b368cbbb057c5652eac340ecba12cf9dfbe2c3769d07"
PRODUCER_SHA = "545727183aa4e361eb1967fa3599dd30e5fd38a78f68dad9fec74793f8f713ee"
SOURCE_SHA = "e3c6d45bc93119ddf1da8bee6e02de3c7c3a3bbe52bb6d2664eb4b7b3d7b5273"
SCHEMA_NAMES = ("ClientRequest.json", "v2/LoginAccountParams.json", "v2/LoginAccountResponse.json")
DEADLINE = None
PHASE = "admission"
PHASES = ("admission", "archive", "output", "nativeversion", "schemageneration", "schemavalidation", "finalseal")

def phase(name):
    global PHASE
    require(name in PHASES)
    PHASE = name
    print("OMUX_RETAINED_DEVICE_API_PHASE_" + name.upper(), file=sys.stderr, flush=True)

def wire_schema(value):
    # Generated annotation titles differ between standalone and embedded schemas.
    # Preserve every validation keyword, including unknown future keywords.
    if isinstance(value, dict):
        return {key: wire_schema(item) for key, item in value.items()
            if key not in ("title", "description", "$comment")}
    if isinstance(value, list):
        return [wire_schema(item) for item in value]
    return value

def require(value):
    if not value:
        raise ValueError("retained-device-api-qualification-refused")

def tick():
    require(time.monotonic() < DEADLINE)

def sha(value):
    return hashlib.sha256(value).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()

def read_fd(fd, maximum):
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        and info.st_nlink == 1 and not info.st_mode & 0o022 and 0 < info.st_size <= maximum)
    os.lseek(fd, 0, os.SEEK_SET)
    blocks, total = [], 0
    while True:
        tick()
        block = os.read(fd, min(1024 * 1024, maximum-total+1))
        if not block:
            break
        total += len(block)
        require(total <= maximum)
        blocks.append(block)
    require(retained.identity(os.fstat(fd)) == retained.identity(info) and total == info.st_size)
    return b"".join(blocks)

def member(root, name):
    parts = name.split("/")
    require(parts and all(p not in ("", ".", "..") for p in parts))
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)

def write(path, value, mode):
    tick()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        for offset in range(0, len(value), 1024 * 1024):
            tick()
            retained.write_all(fd, value[offset:offset+1024*1024])
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)

def inventory(root, expected):
    observed = set()
    expected_dirs = {"."}
    for name in expected:
        expected_dirs.update(str(parent) for parent in Path(name).parents)
    observed_dirs = set()
    for directory, children, names in os.walk(root, followlinks=False):
        tick()
        relative_dir = str(Path(directory).relative_to(root))
        require(relative_dir in expected_dirs)
        observed_dirs.add(relative_dir)
        require(stat.S_IMODE(os.lstat(directory).st_mode) == 0o555)
        for child in children:
            require(stat.S_ISDIR(os.lstat(Path(directory)/child).st_mode))
        for name in names:
            relative = str((Path(directory)/name).relative_to(root))
            require(relative in expected)
            row = expected[relative]
            fd = member(root, relative)
            try:
                raw = read_fd(fd, row["bytes"])
                require(len(raw) == row["bytes"] and sha(raw) == row["sha256"]
                    and stat.S_IMODE(os.fstat(fd).st_mode) == row["mode"])
            finally:
                os.close(fd)
            observed.add(relative)
    require(observed == set(expected) and observed_dirs == expected_dirs)

def seal(root):
    for directory, _, _ in os.walk(root, topdown=False, followlinks=False):
        os.chmod(directory, 0o555)

def native(loader_fd, backend_fd, library_path, arguments, environment, directory):
    tick()
    command = ["/proc/self/fd/" + str(loader_fd), "--library-path", str(library_path),
        "--argv0", "codex", "/proc/self/fd/" + str(backend_fd), *arguments]
    process = subprocess.Popen(command, pass_fds=(loader_fd, backend_fd), cwd=directory,
        env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, umask=0o077)
    pidfd = None
    try:
        pidfd = os.pidfd_open(process.pid)
        until = min(DEADLINE-30, time.monotonic()+120)
        captured = {process.stdout.fileno(): bytearray(), process.stderr.fileno(): bytearray()}
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                tick()
                require(time.monotonic() < until)
                for key, _ in selector.select(min(0.1, max(0, until-time.monotonic()))):
                    block = os.read(key.fd, 8192)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        captured[key.fd].extend(block)
                        require(sum(map(len, captured.values())) <= 65536)
        require(process.wait(timeout=max(0.1, min(5, until-time.monotonic()))) == 0)
        return bytes(captured[process.stdout.fileno()]), bytes(captured[process.stderr.fileno()])
    finally:
        if process.poll() is None:
            if pidfd is not None:
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            else:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if pidfd is not None:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                else:
                    process.kill()
                process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()
        if pidfd is not None:
            os.close(pidfd)

def device_branch(value):
    rows = [row for row in value["oneOf"]
        if row.get("properties", {}).get("type", {}).get("enum") == ["chatgptDeviceCode"]]
    require(len(rows) == 1 and rows[0].get("type") == "object")
    return rows[0]

def schema_contract(values):
    request, response = device_branch(values[SCHEMA_NAMES[1]]), device_branch(values[SCHEMA_NAMES[2]])
    require(set(request["properties"]) == {"type"} and request["required"] == ["type"])
    fields = {"type", "loginId", "verificationUrl", "userCode"}
    require(set(response["properties"]) == fields and set(response["required"]) == fields)
    require(all(response["properties"][key].get("type") == "string"
        for key in fields))
    envelopes = [row for row in values[SCHEMA_NAMES[0]]["oneOf"]
        if row.get("properties", {}).get("method", {}).get("enum") == ["account/login/start"]]
    require(len(envelopes) == 1 and set(envelopes[0]["required"]) == {"id", "method", "params"}
        and envelopes[0]["properties"]["params"] == {"$ref": "#/definitions/LoginAccountParams"})
    embedded = device_branch(values[SCHEMA_NAMES[0]]["definitions"]["LoginAccountParams"])
    require(set(embedded["properties"]) == {"type"}
        and embedded["required"] == ["type"]
        and wire_schema(embedded) == wire_schema(request))
    return {"method": "account/login/start", "request": request, "response": response,
        "provider_invocation": False}

def main():
    global DEADLINE
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    phase("admission")
    require(os.environ.get("OMUX_EXECUTION_GUARD") and os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"))
    DEADLINE = time.monotonic()+600
    until_ns = time.monotonic_ns()+600*10**9
    archive_path = args.archive.resolve(strict=True)
    admitted = custody.Admission(archive_path.parent, args.manifest, args.receipt, Path.cwd(), until_ns)
    try:
        phase("archive")
        archive = read_fd(admitted.archive_fd, retained.ARCHIVE_BYTES)
        manifest_fd, receipt_fd = retained.open_declared(args.manifest), retained.open_declared(args.receipt)
        try:
            manifest_raw = read_fd(manifest_fd, retained.MAX_METADATA)
            receipt_raw = read_fd(receipt_fd, retained.MAX_METADATA)
        finally:
            os.close(manifest_fd)
            os.close(receipt_fd)
        qualified = selection.qualify_runtime(archive, manifest_raw, receipt_raw,
            expected_source_receipt_sha256=SOURCE_SHA, expected_producer_receipt_sha256=PRODUCER_SHA)
        manifest, files = selection.runtime.verify_runtime_files(archive, json.loads(receipt_raw))
        require(len(manifest["files"]) == 10 and len(files) == 11
            and files.pop("runtime-manifest.json") == manifest_raw
            and sha(files[selection.runtime.BACKEND]) == BACKEND_SHA
            and len(files[selection.runtime.BACKEND]) == BACKEND_BYTES
            and sha(files[selection.LOADER]) == LOADER_SHA)
        phase("output")
        outputs = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in outputs.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
                info = os.fstat(parent)
                require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022)
            require(os.fstat(parent).st_uid == os.getuid())
        finally:
            os.close(parent)
        root = outputs/BACKEND_SHA
        root.mkdir(mode=0o700)
        runtime = root/"runtime"
        runtime.mkdir(mode=0o700)
        rows = {}
        for name, raw in files.items():
            mode = 0o555 if manifest["files"][name]["mode"] == 0o755 else 0o444
            write(runtime/name, raw, mode)
            rows[name] = {"sha256": sha(raw), "bytes": len(raw), "mode": mode}
        write(root/"codex", files[selection.runtime.BACKEND], 0o555)
        seal(runtime)
        inventory(runtime, rows)
        backend, loader = member(root, "codex"), member(runtime, selection.LOADER)
        try:
            with tempfile.TemporaryDirectory(prefix=".device-api-", dir=outputs) as scratch:
                scratch = Path(scratch)
                for name in ("home", "codex", "tmp", "cache", "config", "data", "state", "run", "schemas"):
                    (scratch/name).mkdir(mode=0o700)
                environment = {"HOME": str(scratch/"home"), "CODEX_HOME": str(scratch/"codex"),
                    "TMPDIR": str(scratch/"tmp"), "XDG_CACHE_HOME": str(scratch/"cache"),
                    "XDG_CONFIG_HOME": str(scratch/"config"), "XDG_DATA_HOME": str(scratch/"data"),
                    "XDG_STATE_HOME": str(scratch/"state"), "XDG_RUNTIME_DIR": str(scratch/"run"), "PATH": "/nonexistent",
                    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "RUST_LOG": "off",
                    "SSL_CERT_FILE": str(runtime/selection.runtime.CA)}
                phase("nativeversion")
                version, diagnostics = native(loader, backend, runtime/"lib/codex/lib", ["--version"],
                    environment, scratch)
                require(re.fullmatch(rb"codex-cli [0-9][0-9A-Za-z.+_-]{0,127}\n", version))
                phase("schemageneration")
                _, schema_diagnostics = native(loader, backend, runtime/"lib/codex/lib",
                    ["app-server", "generate-json-schema", "--out", str(scratch/"schemas")], environment, scratch)
                phase("schemavalidation")
                values, schema_rows = {}, {}
                for name in SCHEMA_NAMES:
                    fd = member(scratch/"schemas", name)
                    try:
                        raw = read_fd(fd, 8*1024*1024)
                    finally:
                        os.close(fd)
                    values[name] = json.loads(raw, object_pairs_hook=selection.runtime.unique_object)
                    schema_rows[name] = {"sha256": sha(raw), "bytes": len(raw)}
                api = schema_contract(values)
        finally:
            os.close(backend)
            os.close(loader)
        phase("finalseal")
        inventory(runtime, rows)
        fd = member(root, "codex")
        try:
            require(sha(read_fd(fd, BACKEND_BYTES)) == BACKEND_SHA)
        finally:
            os.close(fd)
        admitted.recheck()
        report = {"schema_version": 1, "kind": "omux-retained-device-api-qualification-v1",
            "status": "provider-free-device-api-qualified", "upstream_commit": manifest["candidate"]["upstream_commit"],
            "patch_sha256": manifest["candidate"]["patch_sha256"], "archive_sha256": retained.ARCHIVE_SHA,
            "archive_bytes": retained.ARCHIVE_BYTES, "manifest_sha256": retained.MANIFEST_SHA,
            "source_receipt_sha256": SOURCE_SHA, "producer_receipt_sha256": PRODUCER_SHA,
            "backend_sha256": BACKEND_SHA, "backend_bytes": BACKEND_BYTES,
            "loader_sha256": LOADER_SHA, "version": version.decode().strip(),
            "runtime_inventory": rows, "runtime_inventory_sha256": sha(encoded(rows)),
            "artifact_selection_sha256": qualified["selection_sha256"],
            "device_api": api, "generated_schema_inventory": schema_rows,
            "diagnostics": [{"bytes": len(value), "sha256": sha(value)} for value in (diagnostics, schema_diagnostics)],
            "native_support": False, "text_continuity": False, "provider_evaluation": False,
            "authority": ["R-HOOK-CONVERGENCE-20261004", "R-N13"]}
        report_raw = encoded(report)
        write(root/".qualification.pending", report_raw, 0o444)
        seal(root)
        expected_output = {"codex": {"sha256": BACKEND_SHA, "bytes": BACKEND_BYTES, "mode": 0o555},
            ".qualification.pending": {"sha256": sha(report_raw), "bytes": len(report_raw), "mode": 0o444},
            **{"runtime/"+name: row for name, row in rows.items()}}
        inventory(root, expected_output)
        admitted.recheck()
        rootfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require(set(os.listdir(rootfd)) == {"codex", "runtime", ".qualification.pending"})
            os.fchmod(rootfd, 0o700)
            os.rename(".qualification.pending", "native-source-receipt.json", src_dir_fd=rootfd, dst_dir_fd=rootfd)
            os.fchmod(rootfd, 0o555)
            os.fsync(rootfd)
        finally:
            os.close(rootfd)
        print("OMUX_RETAINED_DEVICE_API_QUALIFICATION_OK")
    finally:
        admitted.close()

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("OMUX_RETAINED_DEVICE_API_QUALIFICATION_REFUSED_PHASE_" + PHASE.upper(), file=sys.stderr)
        sys.exit(125)
