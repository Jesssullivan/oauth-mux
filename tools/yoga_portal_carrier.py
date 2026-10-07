"""One owned SSH lifetime carries a private native device frame and desktop UI.

Construct inside the declared Bazel RUN target; no FD survives Bazel by assumption.
The root guard separately joins selected remote inputs to real qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import shlex
import signal
import socket
import stat
import subprocess
import threading
import time

from ssh_policy import operator_config
from yoga_controller_delivery import KnownHostAuthority, KNOWN_HOSTS_SOURCE
import yoga_executable_qualification as qualification
import yoga_portal_worker as worker

MAX_OUTPUT = 16384


def require(value, reason):
    if not value:
        raise worker.Refusal(reason)


def write_fd(fd, data, until, stop=None):
    old = os.get_blocking(fd)
    os.set_blocking(fd, False)
    try:
        offset = 0
        while offset < len(data) and time.monotonic() < until:
            require(stop is None or not stop.is_set(), "ssh_private_channel_stopped")
            _, ready, _ = select.select([], [fd], [], min(.2, max(0,until-time.monotonic())))
            if not ready:
                continue
            try:
                count = os.write(fd, data[offset:])
            except BlockingIOError:
                continue
            require(count > 0, "ssh_private_channel_closed")
            offset += count
        require(offset == len(data), "ssh_private_channel_deadline")
    finally:
        os.set_blocking(fd, old)


def ui_selection(ui):
    require(type(ui) is dict and set(ui) == {"host_alias", "ssh_path", "ssh_sha256", "known_hosts_path", "remote",
        "qualification_path", "qualification_sha256", "ssh_auth_socket"}, "ui_selection_invalid")
    require(ui["host_alias"] == "yoga" and ui["ssh_path"] == qualification.SSH
        and type(ui["ssh_sha256"]) is str and qualification.SHA.fullmatch(ui["ssh_sha256"]), "ssh_input_pin_invalid")
    require(type(ui["known_hosts_path"]) is str and str(Path(ui["known_hosts_path"]).resolve(strict=True)) == KNOWN_HOSTS_SOURCE, "fixed_host_key_authority_required")
    selected_agent = ui["ssh_auth_socket"]
    require(selected_agent is None or type(selected_agent) is str and selected_agent.startswith("/")
        and str(Path(selected_agent)) == selected_agent and ".." not in Path(selected_agent).parts,
        "ssh_agent_selector_invalid")
    remote = dict(ui["remote"])
    remote["deadline_seconds"] = 1
    # Schema is shared, but controller UID may differ from authorized Yoga UID.
    require(type(remote.get("uid")) is int and remote["uid"] > 0, "remote_seat_selector_invalid")
    fields = {"python_path", "python_sha256", "gio_path", "gio_sha256", "uid", "machine_id_sha256", "boot_id_sha256",
        "wayland_socket", "wayland_device", "wayland_inode", "closure_qualified", "seat_qualified", "deadline_seconds",
        "dialog_path", "dialog_sha256", "qt_platform_plugin", "qt_platform_plugin_sha256"}
    require(set(remote) == fields and remote["closure_qualified"] is True and remote["seat_qualified"] is True, "remote_qualification_required")
    for name in ("python_sha256", "gio_sha256", "machine_id_sha256", "boot_id_sha256", "dialog_sha256", "qt_platform_plugin_sha256"):
        require(type(remote[name]) is str and worker.SHA.fullmatch(remote[name]), "remote_input_pin_invalid")
    for name in ("python_path", "gio_path", "qt_platform_plugin"):
        require(type(remote[name]) is str and worker.STORE.fullmatch(remote[name])
            and ".." not in Path(remote[name]).parts, "remote_input_selector_invalid")
    require(type(remote["dialog_path"]) is str and remote["dialog_path"].startswith("/")
        and str(Path(remote["dialog_path"])) == remote["dialog_path"] and ".." not in Path(remote["dialog_path"]).parts,"remote_dialog_selector_invalid")
    require(type(remote["wayland_socket"]) is str and re.fullmatch(r"/run/user/"+str(remote["uid"])+r"/wayland-[0-9]{1,3}",remote["wayland_socket"]), "remote_seat_selector_invalid")
    for name in ("wayland_device", "wayland_inode"):
        require(type(remote[name]) is int and remote[name] > 0, "remote_seat_selector_invalid")
    return ui


def qualified_join(ui):
    # Outer guard establishes the issuer/closure/seat evidence join separately.
    # Here hold exact raw metadata and compare its selected tuple, never infer
    # qualification from caller booleans or bytes hashing successfully.
    require(ui["qualification_path"] == "/omux-native-login/ui-qualification.json"
        and type(ui["qualification_sha256"]) is str and worker.SHA.fullmatch(ui["qualification_sha256"]), "ui_qualification_selector_invalid")
    fd = os.open(ui["qualification_path"],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) in (0o400,0o600)
            and before.st_nlink == 1 and 0 < before.st_size <= 32768,"ui_qualification_custody")
        data = os.pread(fd,before.st_size+1,0)
        witness = lambda s: (s.st_dev,s.st_ino,s.st_uid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(len(data) == before.st_size and hashlib.sha256(data).hexdigest() == ui["qualification_sha256"]
            and witness(before) == witness(os.fstat(fd)) == witness(os.stat(ui["qualification_path"],follow_symlinks=False)),"ui_qualification_changed")
        receipt = json.loads(data,object_pairs_hook=worker.unique)
        require(type(receipt) is dict and set(receipt) == {"schema_version","scope","host_alias","remote","controller_ssh",
            "closure_receipt_sha256","seat_receipt_sha256"}
            and type(receipt["schema_version"]) is int and receipt["schema_version"] == 1
            and receipt["scope"] == "omux-native-login-ui-qualification-v1" and receipt["host_alias"] == "yoga"
            and receipt["remote"] == ui["remote"] and receipt["controller_ssh"] == {"path":ui["ssh_path"],"sha256":ui["ssh_sha256"]}
            and all(type(receipt[name]) is str and worker.SHA.fullmatch(receipt[name])
                for name in ("closure_receipt_sha256","seat_receipt_sha256")),"ui_qualification_join_invalid")
    finally:
        os.close(fd)


def ssh_arguments(ui, options, known_hosts_options, remote_command):
    """Device flow creates no forwarding listeners, mux, TTY or shared cancel."""
    return [ui["ssh_path"], *known_hosts_options, *options,
        "-T", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oConnectTimeout=10",
        "-oConnectionAttempts=1", "-oServerAliveInterval=5", "-oServerAliveCountMax=2",
        "-oControlMaster=no", "-oControlPath=none", "-oControlPersist=no",
        "-oClearAllForwardings=yes", "-oForwardAgent=no",
        "-oForwardX11=no", "-oPermitLocalCommand=no", "-oRemoteCommand=none",
        "-oProxyCommand=none", "-oProxyJump=none", "-oHostName=100.104.152.110",
        "-l", "jsullivan2",
        "yoga", remote_command]


def remote_command(python, source):
    # Existing authenticated SSH host shell is the bootstrap authority. Clear
    # loader/module/opener inputs before the independently pinned Python exec.
    return ("unset LD_PRELOAD LD_LIBRARY_PATH PYTHONHOME PYTHONPATH GIO_EXTRA_MODULES GIO_MODULE_DIR "
        "GI_TYPELIB_PATH DBUS_SESSION_BUS_ADDRESS DBUS_SYSTEM_BUS_ADDRESS BASH_ENV ENV DISPLAY WAYLAND_DISPLAY; "
        "exec "+shlex.quote(python)+" -I -S -c "+shlex.quote(source))


class YogaPortalCarrier:
    def __init__(self, ui, until, worker_path):
        self.ui = ui_selection(ui)
        require(type(until) in (int,float) and 0 < until-time.monotonic() <= 900, "ui_deadline_invalid")
        self.until, self.worker_path = until, Path(worker_path)
        self.process = self.pidfd = self.reader = self.writer = None
        self.hosts = self.policy = self.thread = None
        self.requested = threading.Event()
        self.stopping = threading.Event()
        self.failure = None
        self.closed = False

    def remote_result(self, scope, stop=None):
        data = worker.read_line(self.process.stdout.fileno(), min(self.until,time.monotonic()+30),MAX_OUTPUT,stop=stop)
        try:
            value = json.loads(data,object_pairs_hook=worker.unique)
        except (ValueError,UnicodeError):
            raise worker.Refusal("ssh_remote_metadata_invalid") from None
        require(type(value) is dict and value.get("scope") == scope, "ssh_remote_metadata_invalid")
        return value

    def open(self):
        require(self.process is None and not self.closed, "ui_carrier_already_started")
        require(hasattr(os,"pidfd_open") and hasattr(signal,"pidfd_send_signal"), "ssh_pidfd_required")
        try:
            qualified_join(self.ui)
            qualification.executable_hash(self.ui["ssh_path"],int(self.until*10**9),self.ui["ssh_sha256"])
            self.hosts = KnownHostAuthority(self.ui["known_hosts_path"],self.until)
            self.policy = operator_config(include_user=False)
            options = self.policy.__enter__()
            source = self.worker_path.read_bytes()
            require(0 < len(source) <= 65536 and b"\0" not in source, "declared_worker_bound")
            command = remote_command(self.ui["remote"]["python_path"],source.decode("utf8"))
            environment = {"HOME":os.environ["HOME"]} if "HOME" in os.environ else {}
            if self.ui["ssh_auth_socket"] is not None:
                environment["SSH_AUTH_SOCK"] = "/omux-native-login/ssh-agent.sock"
                info = os.stat(environment["SSH_AUTH_SOCK"],follow_symlinks=False)
                require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(), "authorized_ssh_agent_unavailable")
                with socket.socket(socket.AF_UNIX) as channel:
                    channel.settimeout(5)
                    channel.connect(environment["SSH_AUTH_SOCK"])
                    import struct
                    _,uid,_ = struct.unpack("3i",channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    require(uid == os.getuid(),"authorized_ssh_agent_unavailable")
                # Outer guard pins the selected socket inode by an exact bind.
                # No ambient socket fallback, agent forwarding or /run unmask.
            self.hosts.check()
            qualified_join(self.ui)
            arguments = ssh_arguments(self.ui,options,self.hosts.options(),command)
            self.process = subprocess.Popen(arguments,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,env=environment,umask=0o077)
            # Constructor failure always enters close's bounded own-child fallback.
            print(json.dumps({"scope":"omux-native-login-owned-ssh-v1","owned_ssh_pid":self.process.pid},sort_keys=True),flush=True)
            self.pidfd = os.pidfd_open(self.process.pid)
            remote = dict(self.ui["remote"])
            remote["deadline_seconds"] = max(1,min(900,int(self.until-time.monotonic())))
            write_fd(self.process.stdin.fileno(),json.dumps(remote,separators=(",",":")).encode()+b"\n",min(self.until,time.monotonic()+30))
            ready = self.remote_result("omux-yoga-portal-ready-v1")
            require(set(ready) == {"scope","uid","portal_owner_pid","portal_owner_start_ticks","owned_dialog_pid","dialog_available","portal_available"}
                and ready["uid"] == remote["uid"] and ready["dialog_available"] is True and ready["portal_available"] is True
                and type(ready["owned_dialog_pid"]) is int and ready["owned_dialog_pid"] > 0
                and type(ready["portal_owner_pid"]) is int and ready["portal_owner_pid"] > 0
                and type(ready["portal_owner_start_ticks"]) is int and ready["portal_owner_start_ticks"] > 0, "portal_readiness_invalid")
            self.hosts.check()
            self.reader,self.writer = os.pipe2(os.O_CLOEXEC|os.O_NONBLOCK)
            self.thread = threading.Thread(target=self.relay,name="omux-native-login-private-ui",daemon=True)
            self.thread.start()
            # This fd is created after Bazel and passed directly to helper in-process.
            return self.writer
        except BaseException:
            self.close()
            raise

    def relay(self):
        private_uri = None
        try:
            private_uri = worker.read_line(self.reader,self.until,4096,stop=self.stopping)
            worker.device_frame(private_uri)
            self.hosts.check()
            write_fd(self.process.stdin.fileno(),private_uri+b"\n",self.until,stop=self.stopping)
            private_uri = None
            result = self.remote_result("omux-yoga-portal-requested-v1",stop=self.stopping)
            require(result == {"scope":"omux-yoga-portal-requested-v1","uri_requested":True}, "portal_request_not_accepted")
            self.requested.set()
            self.hosts.check()
            # Dialog cancellation terminates the worker/SSH. Keep observing
            # after portal acceptance so healthy() can cancel owned native.
            while not self.stopping.wait(.2):
                require(time.monotonic() < self.until and self.process.poll() is None,"private_ui_transport_closed")
        except BaseException:
            if not self.stopping.is_set():
                self.failure = "private_ui_transport_failed"
        finally:
            private_uri = None

    def close(self,success=False):
        if self.closed:
            return
        self.closed = True
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(timeout=1)
            # Never release/reuse a descriptor while the relay might touch it.
            # A stuck relay retains custody and makes the outer owned guard
            # terminate this failed action/cgroup; it cannot produce success.
            require(not self.thread.is_alive(),"private_ui_thread_cleanup_incomplete")
        cleanup_failed = False
        try:
            if self.writer is not None:
                os.close(self.writer)
                self.writer = None
            if self.process is not None:
                try:
                    self.process.stdin.close()
                except BrokenPipeError:
                    pass
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    for sig in (signal.SIGTERM,signal.SIGKILL):
                        try:
                            if self.pidfd is not None:
                                signal.pidfd_send_signal(self.pidfd,sig)
                            elif self.process.poll() is None:
                                self.process.send_signal(sig)
                        except ProcessLookupError:
                            pass
                        try:
                            self.process.wait(timeout=5)
                            break
                        except subprocess.TimeoutExpired:
                            if sig == signal.SIGKILL:
                                cleanup_failed = True
                self.process.stdout.close()
            if self.hosts is not None:
                self.hosts.check()
                qualified_join(self.ui)
        finally:
            for fd in (self.reader,self.pidfd):
                if fd is not None:
                    os.close(fd)
            self.reader = self.pidfd = None
            if self.hosts is not None:
                self.hosts.close()
                self.hosts = None
            if self.policy is not None:
                self.policy.__exit__(None,None,None)
                self.policy = None
        require(not cleanup_failed,"owned_ssh_cleanup_incomplete")
        if success:
            require(self.requested.is_set() and self.failure is None and self.process.returncode == 0,
                "private_ui_transport_incomplete")
