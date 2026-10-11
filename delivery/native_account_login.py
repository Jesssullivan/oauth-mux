"""Opt-in native OAuth setup; fresh native profile, private URI UI, no token export.

R-N13. Device setup requires independently qualified retained device API bytes.
No account inspection, provider call, native launch or live proof occurs on import.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import urllib.parse
import uuid

MAX_FRAME = 64 * 1024
MAX_OUTPUT = 1024 * 1024
MAX_URI = 8192

class Refusal(Exception):
    pass

def require(condition, reason):
    if not condition:
        raise Refusal(reason)

def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, "native_duplicate_field")
        result[key] = value
    return result

def metadata_input(fd, until):
    old_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    os.set_blocking(fd, False)
    result = bytearray()
    try:
        while time.monotonic() < until:
            ready, _, _ = select.select([fd], [], [], min(0.2, max(0, until - time.monotonic())))
            if not ready:
                continue
            try:
                chunk = os.read(fd, 8193 - len(result))
            except BlockingIOError:
                continue
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            require(len(result) <= 8192, "configuration_bound")
        raise Refusal("metadata_input_deadline")
    finally:
        fcntl.fcntl(fd, fcntl.F_SETFL, old_flags)

def write_private(fd, payload, until, reason):
    old_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    os.set_blocking(fd, False)
    offset = 0
    try:
        while offset < len(payload) and time.monotonic() < until:
            _, ready, _ = select.select([], [fd], [], min(0.2, max(0, until - time.monotonic())))
            if not ready:
                continue
            try:
                count = os.write(fd, payload[offset:])
            except BlockingIOError:
                continue
            require(count > 0, reason)
            offset += count
        require(offset == len(payload), reason)
    finally:
        fcntl.fcntl(fd, fcntl.F_SETFL, old_flags)

def configuration(raw):
    require(len(raw) <= 8192, "configuration_bound")
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError):
        raise Refusal("configuration_invalid") from None
    require(type(value) is dict and set(value) == {
        "authorize_provider_login", "no_cancel_build_qualified", "native_sha256",
        "source_receipt_sha256", "state_parent", "private_ui_fd", "deadline_seconds"}, "configuration_invalid")
    require(value["authorize_provider_login"] is True, "provider_login_not_authorized")
    require(value["no_cancel_build_qualified"] is True, "no_cancel_build_required")
    for name in ("native_sha256", "source_receipt_sha256"):
        digest = value[name]
        require(type(digest) is str and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest), "input_pin_invalid")
    require(type(value["private_ui_fd"]) is int and value["private_ui_fd"] >= 3, "private_ui_required")
    require(type(value["deadline_seconds"]) is int and 1 <= value["deadline_seconds"] <= 900, "deadline_invalid")
    parent = value["state_parent"]
    require(type(parent) is str and parent.startswith("/") and parent == os.path.normpath(parent) and ".." not in Path(parent).parts, "state_parent_invalid")
    return value

def hold_input(path, expected, maximum, executable=False):
    # Runfile links resolve to a declared physical input, never an auth path.
    selected = Path(path).resolve(strict=True)
    fd = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
                and not before.st_mode & 0o022 and 0 < before.st_size <= maximum, "declared_input_custody")
        if executable:
            require(before.st_mode & 0o100, "native_not_executable")
            require(selected.parent.name == expected, "native_registry_pin_differs")
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(fd, min(65536, before.st_size - offset), offset)
            require(bool(chunk), "declared_input_changed")
            offset += len(chunk)
            digest.update(chunk)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, name) == getattr(after, name) for name in fields)
                and not os.pread(fd, 1, offset) and digest.hexdigest() == expected, "declared_input_pin_differs")
        return fd
    except BaseException:
        os.close(fd)
        raise

def private_ui(fd):
    info = os.fstat(fd)
    identity = (info.st_dev, info.st_ino)
    require(info.st_uid == os.getuid() and all(identity != (os.fstat(other).st_dev, os.fstat(other).st_ino)
            for other in (0, 1, 2)), "private_ui_required")
    require(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR), "private_ui_required")
    require(stat.S_ISFIFO(info.st_mode) or stat.S_ISSOCK(info.st_mode) or os.isatty(fd), "private_ui_required")
    if stat.S_ISSOCK(info.st_mode):
        with socket.socket(fileno=os.dup(fd)) as channel:
            require(channel.family == socket.AF_UNIX, "private_ui_local_only")
            _, uid, _ = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == os.getuid(), "private_ui_peer_mismatch")
    return os.dup(fd)

def profile(parent):
    # Descriptor traversal never follows a source symlink or scans personal state.
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in Path(parent).parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            require(info.st_uid in (0, os.getuid()) and (not info.st_mode & 0o022 or sticky), "state_parent_custody")
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "state_parent_private_required")
        handle = uuid.uuid4().hex
        name = "native-login-" + handle
        os.mkdir(name, 0o700, dir_fd=fd)
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            info = os.fstat(child)
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "profile_custody")
            os.fsync(fd)
            return handle, Path(parent) / name, child
        except BaseException:
            os.close(child)
            raise
    finally:
        os.close(fd)

def authorization_url(value):
    require(type(value) is str and 0 < len(value.encode()) <= MAX_URI and not any(ord(c) < 0x21 or ord(c) == 0x7f for c in value), "native_uri_invalid")
    try:
        uri = urllib.parse.urlsplit(value)
        query = urllib.parse.parse_qs(uri.query, strict_parsing=True)
        redirect = urllib.parse.urlsplit(query["redirect_uri"][0])
    except (ValueError, KeyError):
        raise Refusal("native_uri_invalid") from None
    require(uri.scheme == "https" and uri.netloc == "auth.openai.com" and uri.path == "/oauth/authorize" and not uri.fragment, "native_uri_invalid")
    require(len(query["redirect_uri"]) == 1 and redirect.scheme == "http" and redirect.hostname == "localhost"
            and redirect.port in (1455, 1457) and redirect.path == "/auth/callback"
            and not redirect.query and not redirect.fragment and not redirect.username, "native_callback_invalid")
    return value.encode() + b"\n"

class Native:
    def __init__(self, fd, environment, directory, *, loader_fd=None, library_path=None):
        require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "native_pidfd_required")
        self.pidfd = None
        self.selector = None
        self.buffer = bytearray()
        self.total = 0
        self.closed = False
        arguments = ["codex", "-c", 'cli_auth_credentials_store="file"',
            "app-server", "--listen", "stdio://", "--strict-config"]
        executable, inherited = "/proc/self/fd/" + str(fd), (fd,)
        if loader_fd is not None:
            require(type(loader_fd) is int and loader_fd >= 3 and type(library_path) is str
                and library_path.startswith("/") and library_path == os.path.normpath(library_path)
                and not any(c.isspace() or c in ":\\\\\x00" for c in library_path)
                and ".." not in Path(library_path).parts, "qualified_loader_contract_required")
            loader = os.fstat(loader_fd)
            require(stat.S_ISREG(loader.st_mode) and loader.st_uid in (0,os.getuid())
                and not loader.st_mode & 0o022 and loader.st_mode & 0o100
                and loader.st_nlink == 1, "qualified_loader_custody_required")
            executable = "/proc/self/fd/" + str(loader_fd)
            arguments = [executable, "--library-path", library_path, "--argv0", "codex",
                "/proc/self/fd/" + str(fd), *arguments[1:]]
            inherited = (fd,loader_fd)
        else:
            require(library_path is None, "qualified_loader_contract_required")
        self.process = subprocess.Popen(arguments, executable=executable,
            pass_fds=inherited, cwd=directory, env=environment, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, umask=0o077)
        try:
            print(json.dumps({"scope": "omux-native-login-owned-child-v1",
                "owned_native_pid": self.process.pid}, sort_keys=True), flush=True)
            self.pidfd = os.pidfd_open(self.process.pid)
            self.selector = selectors.DefaultSelector()
            self.selector.register(self.process.stdout, selectors.EVENT_READ)
            os.set_blocking(self.process.stdout.fileno(), False)
        except BaseException:
            try:
                self.close()
            except Exception:
                raise Refusal("native_cleanup_failed") from None
            raise Refusal("native_initialization_failed") from None

    def send(self, method, params, identifier=None, until=None):
        require(until is not None, "native_send_deadline_required")
        value = {"method": method, "params": params}
        if identifier is not None:
            value["id"] = identifier
        encoded = json.dumps(value, separators=(",", ":")).encode() + b"\n"
        require(len(encoded) <= MAX_FRAME, "native_request_bound")
        write_private(self.process.stdin.fileno(), encoded, until, "native_send_deadline")

    def receive(self, until):
        while time.monotonic() < until:
            if b"\n" in self.buffer:
                line, _, remaining = self.buffer.partition(b"\n")
                self.buffer = bytearray(remaining)
                try:
                    value = json.loads(line, object_pairs_hook=unique_object)
                except (ValueError, UnicodeError):
                    raise Refusal("native_envelope_invalid") from None
                require(type(value) is dict, "native_envelope_invalid")
                return value
            require(self.process.poll() is None, "native_exited")
            for key, _ in self.selector.select(min(0.2, max(0, until - time.monotonic()))):
                chunk = os.read(key.fd, 8192)
                require(bool(chunk), "native_eof")
                self.total += len(chunk)
                require(self.total <= MAX_OUTPUT, "native_output_bound")
                self.buffer.extend(chunk)
                require(len(self.buffer) <= MAX_FRAME, "native_frame_bound")
        raise Refusal("operator_consent_deadline")

    def result(self, identifier, until):
        for _ in range(128):
            value = self.receive(until)
            if value.get("id") == identifier:
                require("error" not in value and type(value.get("result")) is dict, "native_rpc_refused")
                return value["result"]
            require("id" not in value, "native_unexpected_request")
        raise Refusal("native_notification_bound")

    def close(self):
        if self.closed:
            return
        self.closed = True
        failure = None
        try:
            self.process.stdin.close()
        except BrokenPipeError:
            pass
        except BaseException as error:
            failure = error
        reaped = False
        try:
            self.process.wait(timeout=5)
            reaped = True
        except subprocess.TimeoutExpired:
            pass
        except BaseException as error:
            failure = failure or error
        if not reaped:
            for sig in (signal.SIGTERM,signal.SIGKILL):
                try:
                    if self.pidfd is not None:
                        signal.pidfd_send_signal(self.pidfd,sig)
                    elif self.process.poll() is None:
                        self.process.terminate() if sig == signal.SIGTERM else self.process.kill()
                except ProcessLookupError:
                    pass
                except BaseException as error:
                    failure = failure or error
                try:
                    self.process.wait(timeout=5)
                    reaped = True
                    break
                except subprocess.TimeoutExpired:
                    pass
                except BaseException as error:
                    failure = failure or error
        if not reaped:
            failure = failure or Refusal("native_cleanup_failed")
        for cleanup in (
                lambda: self.buffer.__setitem__(slice(None),b"\x00"*len(self.buffer)),
                lambda: self.selector.close() if self.selector is not None else None,
                self.process.stdout.close):
            try:
                cleanup()
            except BaseException as error:
                failure = failure or error
        pidfd,self.pidfd = self.pidfd,None
        if pidfd is not None:
            try:
                os.close(pidfd)
            except BaseException as error:
                failure = failure or error
        if failure is not None:
            raise Refusal("native_cleanup_failed") from None

def login(native, ui, until):
    native.send("initialize", {"clientInfo": {"name": "omux-native-enrollment", "title": None, "version": "1"},
        "capabilities": {"experimentalApi": False, "requestAttestation": False}}, 1, until=min(until, time.monotonic() + 30))
    native.result(1, min(until, time.monotonic() + 30))
    native.send("initialized", {}, until=min(until, time.monotonic() + 30))
    native.send("account/login/start", {"type": "chatgpt"}, 2, until=min(until, time.monotonic() + 30))
    started = native.result(2, min(until, time.monotonic() + 30))
    require(started.get("type") == "chatgpt" and type(started.get("loginId")) is str, "native_login_invalid")
    payload = authorization_url(started.get("authUrl"))
    # Only the operator's explicitly held private UI channel gets the native URI.
    write_private(ui, payload, until, "private_ui_deadline")
    for _ in range(256):
        value = native.receive(until)
        require("id" not in value, "native_unexpected_request")
        if value.get("method") == "account/login/completed":
            params = value.get("params")
            require(type(params) is dict and params.get("loginId") == started["loginId"], "native_login_mismatch")
            require(params.get("success") is True, "native_login_failed")
            return
    raise Refusal("native_notification_bound")

def device_prompt(started):
    require(started.get("type") == "chatgptDeviceCode" and type(started.get("loginId")) is str,
        "native_device_login_invalid")
    verification = started.get("verificationUrl")
    code = started.get("userCode")
    require(verification == "https://auth.openai.com/codex/device", "native_device_uri_invalid")
    require(type(code) is str and 0 < len(code) <= 128 and all(0x21 <= ord(c) < 0x7f for c in code),
        "native_device_code_invalid")
    return json.dumps({"verification_url": verification, "user_code": code}, sort_keys=True,
        separators=(",", ":")).encode() + b"\n"


def device_login(native, ui, until, healthy=None):
    require(healthy is None or healthy(), "private_ui_transport_unavailable")
    native.send("initialize", {"clientInfo": {"name": "omux-native-enrollment", "title": None, "version": "1"},
        "capabilities": {"experimentalApi": False, "requestAttestation": False}}, 1, until=min(until, time.monotonic() + 30))
    native.result(1, min(until, time.monotonic() + 30))
    native.send("initialized", {}, until=min(until, time.monotonic() + 30))
    require(healthy is None or healthy(), "private_ui_transport_unavailable")
    native.send("account/login/start", {"type": "chatgptDeviceCode"}, 2, until=min(until, time.monotonic() + 30))
    started = native.result(2, min(until, time.monotonic() + 30))
    payload = device_prompt(started)
    require(healthy is None or healthy(), "private_ui_transport_unavailable")
    # URL + one-time code only enter the internally held private native UI pipe.
    write_private(ui, payload, until, "private_ui_deadline")
    payload = None
    seen = 0
    while seen < 256 and time.monotonic() < until:
        require(healthy is None or healthy(), "private_ui_transport_unavailable")
        try:
            value = native.receive(min(until, time.monotonic() + .25) if healthy else until)
        except Refusal as error:
            if healthy and str(error) == "operator_consent_deadline" and time.monotonic() < until:
                continue
            raise
        seen += 1
        require("id" not in value, "native_unexpected_request")
        if value.get("method") == "account/login/completed":
            params = value.get("params")
            require(type(params) is dict and params.get("loginId") == started["loginId"], "native_login_mismatch")
            require(params.get("success") is True, "native_login_failed")
            return
    raise Refusal("operator_consent_deadline" if time.monotonic() >= until else "native_notification_bound")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", required=True)
    parser.add_argument("--source-receipt", required=True)
    args = parser.parse_args()
    config = configuration(metadata_input(sys.stdin.fileno(), time.monotonic() + 30))
    native_fd = receipt_fd = ui = root_fd = None
    native = None
    try:
        native_fd = hold_input(args.codex, config["native_sha256"], 600 * 1024 * 1024, True)
        receipt_fd = hold_input(args.source_receipt, config["source_receipt_sha256"], 16 * 1024 * 1024)
        ui = private_ui(config["private_ui_fd"])
        handle, root, root_fd = profile(config["state_parent"])
        print(json.dumps({"scope": "omux-native-login-started-v1", "profile_handle": handle,
            "identity_verified": False, "native_support": False}, sort_keys=True), flush=True)
        environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/nonexistent",
            "CODEX_HOME": str(root), "RUST_LOG": "off"}
        for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"):
            child = name.lower()
            os.mkdir(child, 0o700, dir_fd=root_fd)
            environment[name] = str(root / child)
        until = time.monotonic() + config["deadline_seconds"]
        native = Native(native_fd, environment, root)
        login(native, ui, until)
        auth = os.stat("auth.json", dir_fd=root_fd, follow_symlinks=False)
        require(stat.S_ISREG(auth.st_mode) and auth.st_uid == os.getuid() and stat.S_IMODE(auth.st_mode) == 0o600 and auth.st_nlink == 1, "native_auth_custody")
        native.close()
        native = None
        print(json.dumps({"scope": "omux-native-login-v1", "profile_handle": handle,
            "native_login_completed": True, "identity_verified": False, "renewal_owner": "native",
            "native_support": False}, sort_keys=True))
        return 0
    finally:
        if native is not None:
            native.close()
        for fd in (native_fd, receipt_fd, ui, root_fd):
            if fd is not None:
                os.close(fd)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refusal as failure:
        print(json.dumps({"scope": "omux-native-login-refused-v1", "reason": str(failure)}), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('{"scope":"omux-native-login-refused-v1","reason":"setup_action_failed"}', file=sys.stderr)
        sys.exit(1)
