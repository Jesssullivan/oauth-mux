"""Provider-free Yoga preparation bootstrap under qualified authenticated OS.

Executes only fixed read-only Nix operations and one held newly staged dialog.
No provider request, portal OpenURI, native auth read or existing file rewrite.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

PYTHON = "/nix/store/0r6k8xa2kgqyp3r4v2w7yrb80ma2iawm-python3-3.13.12/bin/python3.13"
GIO = "/nix/store/zcmsivndca5wmam9nwnbjrm0zkgykwfz-glib-2.86.3/lib/libgio-2.0.so.0.8600.3"
PLUGIN = "/nix/store/1q8sx67miwfn3ws5k7mkmkcjbym4akkp-qtbase-6.11.0/lib/qt-6/plugins/platforms/libqwayland.so"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":")).encode("ascii")


def normalized(value):
    if type(value) is str and re.fullmatch(r"sha256:[a-f0-9]{64}",value):
        return value[7:]
    require(type(value) is str and re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=",value),"nar_hash_invalid")
    return base64.b64decode(value[7:],validate=True).hex()


def file_digest(path,maximum):
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,"metadata_invalid")
        digest,count = hashlib.sha256(),0
        while count < before.st_size:
            data = os.read(fd,min(65536,before.st_size-count))
            require(bool(data),"metadata_changed")
            digest.update(data)
            count += len(data)
        witness = lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(witness(before) == witness(os.fstat(fd)) == witness(os.stat(path,follow_symlinks=False)),"metadata_changed")
        return digest.hexdigest()
    finally:
        os.close(fd)


def os_identity_digest(path):
    require(path in ("/etc/machine-id","/proc/sys/kernel/random/boot_id"),"os_identity_selector")
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode),"os_identity_custody")
        data = bytearray()
        while len(data) <= 4096:
            piece = os.read(fd,4097-len(data))
            if not piece:
                break
            data.extend(piece)
        require(0 < len(data) <= 4096,"os_identity_bound")
        return hashlib.sha256(data).hexdigest()
    finally:
        os.close(fd)


def child_death(worker):
    # Called before any GIO initialization/thread creation.
    libc = worker.C.CDLL(None)
    libc.prctl.argtypes = [worker.C.c_int]+[worker.C.c_ulong]*4
    libc.prctl.restype = worker.C.c_int
    owner = os.getpid()
    def establish():
        if libc.prctl(1,signal.SIGKILL,0,0,0) != 0 or os.getppid() != owner:
            os._exit(1)
    return establish


def nix_operation(worker,nix,arguments,until,maximum):
    process = pidfd = None
    result = bytearray()
    absent = "/.omux-yoga-qualification-unavailable"
    require(not os.path.lexists(absent),"isolated_environment_unavailable")
    environment = {"HOME":absent,"PATH":"","LANG":"C","LC_ALL":"C",
        "NIX_CONF_DIR":absent,"NIX_USER_CONF_FILES":"","NIX_CONFIG":"","NIX_PATH":"",
        "XDG_CONFIG_HOME":absent,"XDG_DATA_HOME":absent,"XDG_STATE_HOME":absent,
        "XDG_CACHE_HOME":absent,"XDG_RUNTIME_DIR":absent}
    try:
        process = subprocess.Popen(["nix","--option","plugin-files","",
            "--extra-experimental-features","nix-command",*arguments],
            executable="/proc/self/fd/"+str(nix),pass_fds=(nix,),stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=environment,
            preexec_fn=child_death(worker),umask=0o077)
        pidfd = os.pidfd_open(process.pid)
        os.set_blocking(process.stdout.fileno(),False)
        while time.monotonic() < until:
            ready,_,_ = select.select([process.stdout.fileno()],[],[],min(.2,max(0,until-time.monotonic())))
            if not ready:
                continue
            data = os.read(process.stdout.fileno(),65536)
            if not data:
                require(process.wait(timeout=max(.01,min(5,until-time.monotonic()))) == 0,"readonly_nix_refused")
                return bytes(result)
            result.extend(data)
            require(len(result) <= maximum,"readonly_nix_output_bound")
        raise ValueError("readonly_nix_deadline")
    finally:
        if process is not None:
            if process.poll() is None:
                for sig in (signal.SIGTERM,signal.SIGKILL):
                    try:
                        if pidfd is not None:
                            signal.pidfd_send_signal(pidfd,sig)
                        elif process.poll() is None:
                            process.send_signal(sig)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=5)
                        break
                    except subprocess.TimeoutExpired:
                        require(sig != signal.SIGKILL,"owned_nix_cleanup_incomplete")
            process.stdout.close()
        if pidfd is not None:
            os.close(pidfd)


def verify_rows(worker,nix,rows,until):
    require(len(rows) == 181 and sum(row["narSize"] for row in rows) == 869166464,"ui_subset_invalid")
    names = [row["path"] for row in rows]
    require(len(set(names)) == len(names),"ui_subset_invalid")
    for row in rows:
        require(set(row) == {"path","narHash","narSize","references"}
            and set(row["references"]) <= set(names),"ui_subset_invalid")
    pins = []
    try:
        for path in names:
            require(worker.STORE.fullmatch(path+"/member") and str(Path(path).resolve(strict=True)) == path,"store_selector_invalid")
            fd = os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o222,"immutable_store_custody")
            pins.append((path,fd,(info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_mtime_ns,info.st_ctime_ns)))
        actual = json.loads(nix_operation(worker,nix,["path-info","--store","daemon","--offline","--json",*names],
            min(until,time.monotonic()+60),2*1024*1024),object_pairs_hook=worker.unique)
        require(type(actual) is dict and set(actual) == set(names),"destination_registration_set")
        for row in rows:
            item = actual[row["path"]]
            require(type(item) is dict and type(item.get("narSize")) is int and item["narSize"] == row["narSize"]
                and normalized(item.get("narHash")) == normalized(row["narHash"])
                and type(item.get("references")) is list and sorted(item["references"]) == sorted(row["references"]),"destination_registration_mismatch")
            digest = nix_operation(worker,nix,["hash","path","--type","sha256","--sri",row["path"]],
                min(until,time.monotonic()+30),4096).decode("ascii").strip()
            require(normalized(digest) == normalized(row["narHash"]),"destination_physical_nar_mismatch")
        for path,fd,pin in pins:
            witness = lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_mode,s.st_mtime_ns,s.st_ctime_ns)
            require(witness(os.fstat(fd)) == pin == witness(os.stat(path,follow_symlinks=False)),"store_custody_changed")
    finally:
        for _,fd,_ in pins:
            os.close(fd)


def seat(worker,expected):
    uid = os.getuid()
    require(uid == expected["uid"] and os_identity_digest("/etc/machine-id") == expected["machineIdSha256"]
        and os_identity_digest("/proc/sys/kernel/random/boot_id") == expected["bootIdSha256"],"host_identity_changed")
    runtime = Path("/run/user/"+str(uid))
    parent = os.open(runtime,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        require(info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700,"seat_custody_invalid")
        names = os.listdir(parent)
        require(len(names) <= 1024,"seat_metadata_bound")
        candidates = []
        for name in names:
            if re.fullmatch(r"wayland-[0-9]{1,3}",name):
                info = os.stat(name,dir_fd=parent,follow_symlinks=False)
                if stat.S_ISSOCK(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o022:
                    candidates.append((name,info))
        require(len(candidates) == 1,"current_wayland_ambiguous")
        name,info = candidates[0]
        with socket.socket(socket.AF_UNIX) as endpoint:
            endpoint.settimeout(5)
            endpoint.connect("/proc/self/fd/"+str(parent)+"/"+name)
            pid,peer_uid,_ = struct.unpack("3i",endpoint.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(peer_uid == uid and pid > 1,"wayland_peer_invalid")
        require((info.st_dev,info.st_ino) == (os.stat(name,dir_fd=parent,follow_symlinks=False).st_dev,
            os.stat(name,dir_fd=parent,follow_symlinks=False).st_ino),"seat_changed")
        process = worker.Portal.__new__(worker.Portal)
        process.pid = pid
        ticks = process.pid_start()
        return ({"uid":uid,"machine_id_sha256":expected["machineIdSha256"],"boot_id_sha256":expected["bootIdSha256"],
            "wayland_socket":str(runtime/name),"wayland_device":info.st_dev,"wayland_inode":info.st_ino},
            {"wayland_peer_pid":pid,"wayland_peer_uid":peer_uid,"wayland_peer_start_ticks":ticks})
    finally:
        os.close(parent)


def stage(worker,config,until):
    # New app-owned XDG state only; existing native profiles are never opened.
    import pwd
    root = Path(pwd.getpwuid(os.getuid()).pw_dir)/".local/state/omux-native-login-ui"
    parent = os.open(root.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    task = output = None
    created = False
    try:
        info = os.fstat(parent)
        require(info.st_uid == os.getuid() and not info.st_mode & 0o022,"state_parent_custody")
        try:
            os.mkdir(root.name,0o700,dir_fd=parent)
        except FileExistsError:
            pass
        app = os.open(root.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            info = os.fstat(app)
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,"state_parent_custody")
            name = "ui-"+config["task_id"]
            os.mkdir(name,0o700,dir_fd=app)
            task = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=app)
            output = os.open("control",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=task)
            created = True
            digest,count,prefix = hashlib.sha256(),0,bytearray()
            length = config["control_bytes"]
            require(type(length) is int and 0 < length <= 128*1024*1024,"control_bound")
            while count < length:
                require(time.monotonic() < until,"stage_deadline")
                ready,_,_ = select.select([0],[],[],min(.2,max(0,until-time.monotonic())))
                if not ready:
                    continue
                data = os.read(0,min(65536,length-count))
                require(bool(data),"control_stream_closed")
                if len(prefix) < 4:
                    prefix.extend(data[:4-len(prefix)])
                    if len(prefix) == 4:
                        require(prefix == b"\x7fELF","control_not_elf")
                offset = 0
                while offset < len(data):
                    require(time.monotonic() < until,"stage_deadline")
                    written = os.write(output,data[offset:])
                    require(written > 0,"stage_write_refused")
                    offset += written
                digest.update(data)
                count += len(data)
            require(prefix == b"\x7fELF" and digest.hexdigest() == config["control_sha256"],"control_digest_mismatch")
            os.fchmod(output,0o500)
            os.fsync(output)
            os.fsync(task)
            require(worker.read_line(0,until,1,allow_eof=True) is None,"unexpected_stage_input")
            information = os.fstat(output)
            return str(root/name/"control"),(information.st_dev,information.st_ino)
        except BaseException:
            if created:
                held = os.fstat(output)
                current = os.stat("control",dir_fd=task,follow_symlinks=False)
                require((held.st_dev,held.st_ino) == (current.st_dev,current.st_ino),"stage_cleanup_custody")
                os.unlink("control",dir_fd=task)
            if task is not None:
                os.rmdir(name,dir_fd=app)
            raise
        finally:
            os.close(app)
    finally:
        for fd in (output,task,parent):
            if fd is not None:
                os.close(fd)


def prepare(worker,config):
    require(set(config) == {"expected_os","rows","control_sha256","control_bytes","task_id","deadline_seconds"},"prepare_schema")
    require(str(uuid.UUID(config["task_id"])) == config["task_id"] and worker.SHA.fullmatch(config["control_sha256"]),"prepare_selector")
    require(type(config["deadline_seconds"]) is int and 1 <= config["deadline_seconds"] <= 900,"prepare_deadline")
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.alarm(config["deadline_seconds"]+15)
    until = time.monotonic()+config["deadline_seconds"]
    os.environ.clear()
    os.environ.update({"PATH":"","LANG":"C","LC_ALL":"C","GIO_USE_VFS":"local",
        "GIO_MODULE_DIR":"/.omux-native-login-unavailable","GIO_EXTRA_MODULES":""})
    require(hasattr(os,"pidfd_open") and hasattr(signal,"pidfd_send_signal"),"prepare_pidfd_required")
    selected,peer = seat(worker,config["expected_os"])
    nix = worker.held_immutable(config["expected_os"]["remoteNixPath"],config["expected_os"]["remoteNixSha256"],64*1024*1024)
    try:
        verify_rows(worker,nix,config["rows"],until)
    finally:
        os.close(nix)
    dialog_path,staged_identity = stage(worker,config,until)
    gio = executable = portal = dialog = None
    try:
        selected.update(python_path=PYTHON,python_sha256=file_digest(PYTHON,128*1024*1024),
            gio_path=GIO,gio_sha256=file_digest(GIO,128*1024*1024),
            qt_platform_plugin=PLUGIN,qt_platform_plugin_sha256=file_digest(PLUGIN,128*1024*1024),
            dialog_path=dialog_path,dialog_sha256=config["control_sha256"],closure_qualified=True,seat_qualified=True)
        worker.check_host_and_seat(selected)
        executable = worker.held_dialog(dialog_path,selected["dialog_sha256"])
        gio = worker.held_immutable(GIO,selected["gio_sha256"],128*1024*1024)
        # All Nix subprocesses finished before GIO threading begins.
        dialog = worker.Dialog(executable,selected,until)
        portal = worker.Portal(gio,selected["uid"])
        seat_receipt = {"schema_version":1,"scope":"omux-native-login-ui-seat-v1",**selected,**peer,
            "portal_owner_pid":portal.pid,"portal_owner_start_ticks":portal.start_ticks,
            "actual_dialog_ready":True,"provider_request_performed":False,"portal_openuri_performed":False}
        dialog.close(success=True)
        dialog = None
        seat_receipt["actual_dialog_eof_clean_exit"] = True
        worker.check_host_and_seat(selected)
        current,current_peer = seat(worker,config["expected_os"])
        require(current == {key:selected[key] for key in
            ("uid","machine_id_sha256","boot_id_sha256","wayland_socket","wayland_device","wayland_inode")}
            and current_peer == peer,"seat_changed")
        return {"remote":selected,"closure":{"schema_version":1,"scope":"omux-native-login-ui-closure-v1",
            "rows":config["rows"],"verified_paths":181,"verified_nar_bytes":869166464,
            "destination_registration_verified":True,"destination_content_rehashed":True,
            "store_import_performed":False,"dialog_sha256":config["control_sha256"]},"seat":seat_receipt}
    except BaseException:
        if dialog is not None:
            dialog.close()
            dialog = None
        # Only this invocation's new public executable/task may be removed.
        parent = os.open(str(Path(dialog_path).parent),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            current = os.stat("control",dir_fd=parent,follow_symlinks=False)
            require((current.st_dev,current.st_ino) == staged_identity and current.st_uid == os.getuid()
                and current.st_nlink == 1 and stat.S_IMODE(current.st_mode) == 0o500,"stage_cleanup_custody")
            os.unlink("control",dir_fd=parent)
            os.rmdir(Path(dialog_path).parent)
        finally:
            os.close(parent)
        raise
    finally:
        if dialog is not None:
            dialog.close()
        if portal is not None:
            portal.close()
        for fd in (executable,gio):
            if fd is not None:
                os.close(fd)
