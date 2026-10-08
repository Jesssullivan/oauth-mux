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


PREPARE_PHASES = frozenset(("entry","config","seat","nix_authority","registry_content","stage",
    "input_pins","elf_closure","dialog_ready","portal_authority","dialog_eof","seat_recheck","complete"))
PREPARE_PHASE = "entry"


def set_phase(value):
    global PREPARE_PHASE
    require(value in PREPARE_PHASES,"diagnostic_phase_invalid")
    PREPARE_PHASE = value


def refusal_record(error):
    category = ("deadline" if isinstance(error,(TimeoutError,subprocess.TimeoutExpired)) else
        "missing_input" if isinstance(error,FileNotFoundError) else
        "access_refused" if isinstance(error,PermissionError) else
        "os_operation_refused" if isinstance(error,OSError) else
        "input_refused" if isinstance(error,(json.JSONDecodeError,UnicodeError)) else
        "predicate_refused" if isinstance(error,(ValueError,KeyError,TypeError)) else "unclassified")
    return {"scope":"omux-native-ui-prepare-remote-refused-v1",
        "phase":PREPARE_PHASE if PREPARE_PHASE in PREPARE_PHASES else "entry","category":category}


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
        cleanup_failure = None
        reaped = process is None
        if process is not None:
            try:
                process.wait(timeout=5)
                reaped = True
            except subprocess.TimeoutExpired:
                pass
            except BaseException as error:
                cleanup_failure = error
            if not reaped:
                for sig in (signal.SIGTERM,signal.SIGKILL):
                    try:
                        if pidfd is not None:
                            signal.pidfd_send_signal(pidfd,sig)
                        elif process.poll() is None:
                            process.send_signal(sig)
                    except ProcessLookupError:
                        pass
                    except BaseException as error:
                        cleanup_failure = cleanup_failure or error
                    try:
                        process.wait(timeout=5)
                        reaped = True
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    except BaseException as error:
                        cleanup_failure = cleanup_failure or error
            for stream in (process.stdout,):
                try:
                    stream.close()
                except BaseException as error:
                    cleanup_failure = cleanup_failure or error
        if pidfd is not None:
            try:
                os.close(pidfd)
            except BaseException as error:
                cleanup_failure = cleanup_failure or error
        require(reaped and cleanup_failure is None,"owned_nix_cleanup_incomplete")


def release_fds(fds):
    failure = None
    for fd in fds:
        if fd is not None:
            try:
                os.close(fd)
            except BaseException as error:
                failure = failure or error
    require(failure is None,"owned_prepare_descriptor_cleanup_incomplete")


def verify_rows(worker,nix,rows,until,retained=None):
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
        if retained is not None:
            retained.extend(pins)
            pins = []
    finally:
        release_fds(fd for _,fd,_ in pins)


class ElfClosure:
    """Keep every transitive selected ELF under the already rehashed181 roots."""
    def __init__(self,worker,executable,dialog_path,rows,plugin,until,root_pins):
        self.worker,self.until = worker,until
        self.roots = frozenset(row["path"] for row in rows)
        self.root_pins = root_pins
        self.files,self.pins,self.names = {},[],{}
        self.pending = []
        self.total = 0
        try:
            require(len(self.roots) == 181 and {path for path,_,_ in root_pins} == self.roots,
                "dialog_elf_inventory")
            self.check()
            fd = os.dup(executable)
            self.pins.append((dialog_path,fd,self.witness(os.fstat(fd))))
            control = self.read(fd)
            metadata = self.metadata(control)
            require(metadata["interpreter"] is not None,"dialog_elf_interpreter_missing")
            interpreter = self.member(metadata["interpreter"])
            require(interpreter == "/nix/store/fjkx1l5cnskzrqacf08z7i8z17256w0j-glibc-2.42-61/lib/ld-linux-x86-64.so.2",
                "dialog_elf_interpreter_differs")
            self.visit(interpreter,())
            self.names[Path(interpreter).name] = interpreter
            self.walk(dialog_path,control,(),control=True)
            self.drain()
            self.visit(self.member(plugin),())
            self.drain()
            self.check()
        except BaseException:
            self.close()
            raise

    def tick(self):
        require(time.monotonic() < self.until,"dialog_elf_deadline")

    def member(self,value):
        self.tick()
        require(type(value) is str and self.worker.STORE.fullmatch(value)
            and "$" not in value and ":" not in value,"dialog_elf_nonclosure_path")
        lexical = os.path.normpath(value)
        require(lexical == value and "/".join(lexical.split("/")[:4]) in self.roots,"dialog_elf_nonclosure_path")
        physical = str(Path(lexical).resolve(strict=True))
        require(self.worker.STORE.fullmatch(physical)
            and "/".join(physical.split("/")[:4]) in self.roots,"dialog_elf_nonclosure_path")
        return physical

    def read(self,fd):
        self.tick()
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 128*1024*1024,"dialog_elf_file_bound")
        self.total += before.st_size
        require(self.total <= 512*1024*1024,"dialog_elf_total_bound")
        result = bytearray()
        while len(result) < before.st_size:
            self.tick()
            data = os.pread(fd,min(65536,before.st_size-len(result)),len(result))
            require(bool(data),"dialog_elf_changed")
            result.extend(data)
        require(self.witness(before) == self.witness(os.fstat(fd)),"dialog_elf_changed")
        return bytes(result)

    @staticmethod
    def witness(info):
        return (info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

    def metadata(self,payload):
        result = elf.elf_metadata(payload,max_bytes=128*1024*1024)
        require(result["machine"] == 62 and len(result["needed"]) <= 128
            and len(result["rpath"]) <= 256,"dialog_elf_metadata_bound")
        # Reuse the validated segment bounds to preserve RPATH inheritance rules.
        header = struct.unpack_from("<HHIQQQIHHHHHH",payload,16)
        kinds = set()
        search_tag_count = 0
        for index in range(header[9]):
            record = struct.unpack_from("<IIQQQQQQ",payload,header[4]+index*header[8])
            if record[0] == 2:
                for offset in range(record[2],record[2]+record[5],16):
                    tag = struct.unpack_from("<qQ",payload,offset)[0]
                    if tag == 0:
                        break
                    if tag in (15,29):
                        kinds.add(tag)
                        search_tag_count += 1
        require(len(kinds) <= 1,"dialog_elf_conflicting_search_tags")
        result["runpath"] = 29 in kinds
        # Whole-empty tags are ignored by glibc; nonempty empty colon components
        # select CWD. RUNPATH presence still blocks ancestor RPATH inheritance.
        if search_tag_count == 1 and result["rpath"] == [""]:
            result["rpath"] = []
        return result

    def directory(self,value,origin,control):
        self.tick()
        require(type(value) is str and bool(value),"dialog_elf_empty_search")
        if value == "$ORIGIN" or value.startswith("$ORIGIN/"):
            require(not control,"dialog_elf_control_origin_search")
            value = origin+value[len("$ORIGIN"):]
        require("$" not in value and value.startswith("/nix/store/")
            and ":" not in value,"dialog_elf_nonclosure_search")
        normalized = os.path.normpath(value)
        require("/".join(normalized.split("/")[:4]) in self.roots,"dialog_elf_nonclosure_search")
        physical = str(Path(value).resolve(strict=False))
        require("/".join(physical.split("/")[:4]) in self.roots,"dialog_elf_nonclosure_search")
        if os.path.lexists(physical):
            info = os.stat(physical,follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o222,
                "dialog_elf_search_custody")
            # Refuse unmodelled loader-selected hardware variants.
            require(not os.path.lexists(physical+"/glibc-hwcaps"),"dialog_elf_hwcaps_unqualified")
        return physical

    def resolve(self,name,directories,parent):
        self.tick()
        if "/" in name:
            require(name.startswith("/nix/store/"),"dialog_elf_nonclosure_needed")
            return self.member(name)
        require(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}",name),"dialog_elf_needed_name")
        parent_name = Path(parent).name
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}",parent_name):
            parent_name = "selected-elf"
        # glibc reuses a mapped name before trying any new search directory.
        if name in self.names:
            physical = self.names[name]
            require(physical in self.files,"dialog_elf_loaded_name_without_hold")
            return physical
        for index,descriptor in enumerate(directories):
            self.tick()
            # A descriptor keeps the originating held DSO's ORIGIN context.
            # Validate before any existence/candidate probe. A denied prefix
            # stops this lookup; it is never skipped to seek a later match.
            try:
                directory = self.directory(*descriptor)
            except ValueError as error:
                raise ValueError(str(error)+":parent="+parent_name+":search_index="+str(index)) from None
            candidate = directory+"/"+name
            if os.path.lexists(candidate):
                # Ordered paths determine the first selection. A malformed or
                # foreign first candidate refuses; never fall through it.
                physical = self.member(candidate)
                self.names[name] = physical
                return physical
        # Only public ELF basenames and validated public DT_NEEDED names appear.
        raise ValueError("dialog_elf_needed_unresolved:"+parent_name+":"+name)

    def walk(self,path,payload,inherited,control=False):
        metadata = self.metadata(payload)
        if metadata["interpreter"] is not None:
            require(self.member(metadata["interpreter"]) ==
                "/nix/store/fjkx1l5cnskzrqacf08z7i8z17256w0j-glibc-2.42-61/lib/ld-linux-x86-64.so.2",
                "dialog_elf_interpreter_differs")
        origin = str(Path(path).parent)
        directories = []
        for value in metadata["rpath"]:
            if control:
                # The externally staged executable may carry no ambient path,
                # including paths that would happen to be unused this run.
                directories.append((self.directory(value,origin,True),"",False))
            else:
                # Held immutable DSO metadata is not authority to search a path.
                # Keep its order and origin; resolve validates only if reached.
                directories.append((value,origin,False))
        directories = tuple(directories)
        fixed = tuple((self.directory(value,"",False),"",False)
            for value in self.worker.DIALOG_LIBRARY_DIRECTORIES)
        before = () if metadata["runpath"] else directories+inherited
        after = directories if metadata["runpath"] else ()
        search = tuple(dict.fromkeys(before+fixed+after))
        ancestry = inherited if metadata["runpath"] else directories+inherited
        require(len(search) <= 1024 and len(ancestry) <= 1024,"dialog_elf_search_bound")
        for needed in metadata["needed"]:
            self.visit(self.resolve(needed,search,path),ancestry)

    def drain(self):
        # Map all direct siblings before their children, matching dl-deps BFS.
        # Every queued file is already held and participates in final check().
        while self.pending:
            self.tick()
            path,payload,inherited = self.pending.pop(0)
            self.walk(path,payload,inherited)

    def visit(self,path,inherited):
        self.tick()
        if path in self.files:
            return
        require(len(self.files) < 256,"dialog_elf_graph_bound")
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o222 and stat.S_ISREG(info.st_mode),
                "dialog_elf_file_custody")
            self.pins.append((path,fd,self.witness(info)))
            fd = None
            self.files[path] = True
            self.pending.append((path,self.read(self.pins[-1][1]),inherited))
        finally:
            if fd is not None:
                os.close(fd)

    def check(self):
        self.tick()
        for path,fd,witness in self.root_pins:
            self.tick()
            measured = lambda info:(info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_mtime_ns,info.st_ctime_ns)
            require(measured(os.fstat(fd)) == witness == measured(os.stat(path,follow_symlinks=False)),
                "dialog_elf_root_changed")
        for path,fd,witness in self.pins:
            self.tick()
            require(self.witness(os.fstat(fd)) == witness ==
                self.witness(os.stat(path,follow_symlinks=False)),"dialog_elf_changed")

    def close(self):
        self.pending = []
        failed = False
        for _,fd,_ in self.pins:
            try:
                os.close(fd)
            except OSError:
                failed = True
        self.pins = []
        require(not failed,"dialog_elf_release_incomplete")


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
        release_fds((output,task,parent))


def prepare(worker,config):
    set_phase("config")
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
    set_phase("seat")
    selected,peer = seat(worker,config["expected_os"])
    set_phase("nix_authority")
    nix = worker.held_immutable(config["expected_os"]["remoteNixPath"],config["expected_os"]["remoteNixSha256"],64*1024*1024)
    root_pins = []
    try:
        try:
            set_phase("registry_content")
            verify_rows(worker,nix,config["rows"],until,root_pins)
        finally:
            os.close(nix)
    except BaseException:
        release_fds(fd for _,fd,_ in root_pins)
        raise
    try:
        set_phase("stage")
        dialog_path,staged_identity = stage(worker,config,until)
    except BaseException:
        release_fds(fd for _,fd,_ in root_pins)
        raise
    gio = executable = portal = dialog = graph = None
    try:
        set_phase("input_pins")
        selected.update(python_path=PYTHON,python_sha256=file_digest(PYTHON,128*1024*1024),
            gio_path=GIO,gio_sha256=file_digest(GIO,128*1024*1024),
            qt_platform_plugin=PLUGIN,qt_platform_plugin_sha256=file_digest(PLUGIN,128*1024*1024),
            dialog_path=dialog_path,dialog_sha256=config["control_sha256"],closure_qualified=True,seat_qualified=True)
        worker.check_host_and_seat(selected)
        executable = worker.held_dialog(dialog_path,selected["dialog_sha256"])
        gio = worker.held_immutable(GIO,selected["gio_sha256"],128*1024*1024)
        set_phase("elf_closure")
        graph = ElfClosure(worker,executable,dialog_path,config["rows"],PLUGIN,until,root_pins)
        # All Nix subprocesses finished before GIO threading begins.
        set_phase("dialog_ready")
        dialog = worker.Dialog(executable,selected,until)
        set_phase("portal_authority")
        portal = worker.Portal(gio,selected["uid"])
        seat_receipt = {"schema_version":1,"scope":"omux-native-login-ui-seat-v1",**selected,**peer,
            "portal_owner_pid":portal.pid,"portal_owner_start_ticks":portal.start_ticks,
            "actual_dialog_ready":True,"provider_request_performed":False,"portal_openuri_performed":False}
        set_phase("dialog_eof")
        dialog.close(success=True)
        dialog = None
        graph.check()
        seat_receipt["actual_dialog_eof_clean_exit"] = True
        set_phase("seat_recheck")
        worker.check_host_and_seat(selected)
        current,current_peer = seat(worker,config["expected_os"])
        require(current == {key:selected[key] for key in
            ("uid","machine_id_sha256","boot_id_sha256","wayland_socket","wayland_device","wayland_inode")}
            and current_peer == peer,"seat_changed")
        set_phase("complete")
        return {"remote":selected,"closure":{"schema_version":1,"scope":"omux-native-login-ui-closure-v1",
            "rows":config["rows"],"verified_paths":181,"verified_nar_bytes":869166464,
            "destination_registration_verified":True,"destination_content_rehashed":True,
            "store_import_performed":False,"dialog_sha256":config["control_sha256"]},"seat":seat_receipt}
    except BaseException:
        cleanup_failure = None
        if dialog is not None:
            try:
                dialog.close()
            except BaseException as error:
                cleanup_failure = error
            dialog = None
        # Retain owned public stage if child closure was unresolved. A close
        # fault must still reach all resource release in the outer finally.
        if cleanup_failure is None:
            parent = None
            try:
                parent = os.open(str(Path(dialog_path).parent),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                current = os.stat("control",dir_fd=parent,follow_symlinks=False)
                require((current.st_dev,current.st_ino) == staged_identity and current.st_uid == os.getuid()
                    and current.st_nlink == 1 and stat.S_IMODE(current.st_mode) == 0o500,"stage_cleanup_custody")
                os.unlink("control",dir_fd=parent)
                os.rmdir(Path(dialog_path).parent)
            finally:
                if parent is not None:
                    os.close(parent)
        require(cleanup_failure is None,"owned_prepare_dialog_cleanup_incomplete")
        raise
    finally:
        cleanup_failure = None
        releases = ([dialog.close] if dialog is not None else []) + (
            [portal.close] if portal is not None else []) + ([graph.close] if graph is not None else [])
        releases += [lambda fd=fd: os.close(fd) for _,fd,_ in root_pins]
        releases += [lambda fd=fd: os.close(fd) for fd in (executable,gio) if fd is not None]
        for release in releases:
            try:
                release()
            except BaseException as error:
                cleanup_failure = cleanup_failure or error
        require(cleanup_failure is None,"owned_prepare_resource_cleanup_incomplete")
