"""Declared provider-free UI preparation. Outputs exactly three public receipts."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import select
import shlex
import signal
import stat
import subprocess
import sys
import time
import types
import uuid

import yoga_portal_carrier as carrier
import yoga_portal_worker as worker
import yoga_controller_delivery as delivery
import yoga_delivery_settings as settings

INPUT = "/omux-native-login-ui-prepare/input.json"
AUTHORITY = "/omux-native-login-ui-prepare/os-qualification.json"
OUTPUT = "/omux-native-login-ui-output"
ROOTS = frozenset((
    "/nix/store/0r6k8xa2kgqyp3r4v2w7yrb80ma2iawm-python3-3.13.12",
    "/nix/store/zcmsivndca5wmam9nwnbjrm0zkgykwfz-glib-2.86.3",
    "/nix/store/1q8sx67miwfn3ws5k7mkmkcjbym4akkp-qtbase-6.11.0",
    "/nix/store/l1nqjg1yx6q6vx6zwsnd3ky0s7a0kfk8-qtwayland-6.11.0"))


LOCAL_PHASES = frozenset(("entry","arguments","guard","input_namespace","output_namespace","manifest",
    "os_authority","control_input","inventory_input","worker_input","remote_worker_input","elf_input",
    "bootstrap_encode","host_authority","backend_constructor","os_before","remote_prepare","os_after",
    "receipt_validate","receipt_publish","complete","ssh_encode","ssh_environment","ssh_spawn",
    "ssh_pidfd","ssh_send","ssh_receive","ssh_wait","remote_result"))
REMOTE_PHASES = frozenset(("entry","config","seat","nix_authority","registry_content","stage",
    "input_pins","elf_closure","dialog_ready","portal_authority","dialog_eof","seat_recheck","complete"))
REFUSAL_CATEGORIES = frozenset(("bootstrap_bound","os_changed","agent_custody","binding_refused",
    "ssh_authentication","ssh_host_key","ssh_transport","backend_authority","deadline","missing_input",
    "access_refused","os_operation_refused","input_refused","predicate_refused","unclassified"))
ACTIVE_PHASE = "entry"


def set_phase(value):
    global ACTIVE_PHASE
    require(value in LOCAL_PHASES,"diagnostic_phase_invalid")
    ACTIVE_PHASE = value


class RemoteRefusal(ValueError):
    def __init__(self,record):
        require(type(record) is dict and set(record) == {"scope","phase","category"}
            and record["scope"] == "omux-native-ui-prepare-remote-refused-v1"
            and record["phase"] in REMOTE_PHASES and record["category"] in REFUSAL_CATEGORIES,
            "remote_refusal_frame_invalid")
        self.record = {"remote_phase":record["phase"],"remote_category":record["category"]}
        super().__init__("remote_prepare_refused")


def refusal_record(error):
    name = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else None
    selected = {"declared_bootstrap_source_bound":"bootstrap_bound","remote_command_bound":"bootstrap_bound",
        "actual_os_qualification_changed":"os_changed","agent_custody":"agent_custody","agent_peer":"agent_custody",
        "fixed_host_pin_required":"binding_refused","selected_control_digest":"binding_refused",
        "fixed_inventory_required":"binding_refused","fixed-qualification-binding-required":"binding_refused"}
    category = selected.get(name)
    if category is None and isinstance(error,delivery.GateError):
        flags = error.hints.get("stderrFlags",{}) if type(error.hints) is dict else {}
        if type(flags) is not dict:
            flags = {}
        category = ("ssh_authentication" if flags.get("ssh_auth_rejected") is True else
            "ssh_host_key" if flags.get("host_key_rejected") is True else
            "ssh_transport" if any(flags.get(key) is True for key in
                ("connection_refused","connection_timed_out","connection_reset","host_unresolved")) else
            "backend_authority")
    if category is None:
        category = ("deadline" if isinstance(error,(TimeoutError,subprocess.TimeoutExpired)) else
            "missing_input" if isinstance(error,FileNotFoundError) else
            "access_refused" if isinstance(error,PermissionError) else
            "os_operation_refused" if isinstance(error,OSError) else
            "input_refused" if isinstance(error,(json.JSONDecodeError,UnicodeError)) else
            "predicate_refused" if isinstance(error,(ValueError,KeyError,TypeError)) else "unclassified")
    result = {"scope":"omux-native-login-ui-prepare-refused-v1",
        "reason":"provider_free_preparation_refused",
        "phase":ACTIVE_PHASE if ACTIVE_PHASE in LOCAL_PHASES else "entry","category":category}
    if isinstance(error,RemoteRefusal):
        result.update(error.record)
    if isinstance(error,delivery.GateError) and type(error.hints) is dict:
        observed = error.hints.get("osBootstrapFailure")
        if type(observed) is dict and set(observed) == {"step","category"} \
                and type(observed["step"]) is str and type(observed["category"]) is str \
                and observed["step"] in delivery.qualification.REMOTE_FAILURE_STEPS \
                and observed["category"] in delivery.qualification.REMOTE_FAILURE_CATEGORIES:
            result["os_bootstrap_phase"] = observed["step"]
            result["os_bootstrap_category"] = observed["category"]
    return result


def bootstrap(worker_source,remote_source,elf_source):
    code = ("import json,sys,types\n"
        "w=types.ModuleType('omux_qualified_ui_worker')\nexec(compile("+repr(worker_source)+",'<declared-ui-worker>','exec'),w.__dict__)\n"
        "r=types.ModuleType('omux_ui_prepare_worker')\nexec(compile("+repr(remote_source)+",'<declared-ui-prepare>','exec'),r.__dict__)\n"
        "e=types.ModuleType('omux_pure_elf_parser')\nexec(compile("+repr(elf_source)+",'<declared-elf-parser>','exec'),e.__dict__)\nr.elf=e\n"
        "try:\n c=json.loads(w.read_line(0,w.time.monotonic()+30,262144),object_pairs_hook=w.unique)\n"
        " result=r.prepare(w,c)\n print(r.canonical(result).decode('ascii'),flush=True)\n"
        "except BaseException as error:\n print(r.canonical(r.refusal_record(error)).decode('ascii'),flush=True)\n sys.exit(1)\n")
    require(len(code.encode()) <= 96*1024,"declared_bootstrap_source_bound")
    return code


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":")).encode("ascii")


def elf_parser_source(payload):
    """Export only existing bounded pure parser code from its declared source."""
    require(len(payload) <= 128*1024,"declared_elf_parser_bound")
    text = payload.decode("utf8")
    tree = ast.parse(text)
    expected = {"_MAX_FILE":128*1024*1024,"_MAX_BACKEND_FILE":512*1024*1024,
        "_MAX_HEADERS":4096,"_MAX_DYNAMIC":4096,"_MAX_STRING":4096,
        "_MACHINES":{"x86_64-linux":62,"aarch64-linux":183}}
    constants = set(expected)
    def bounded_constant(node,depth=0):
        require(depth <= 8,"declared_elf_constant_depth")
        if isinstance(node,ast.Constant) and type(node.value) is int:
            require(0 < node.value <= 512*1024*1024,"declared_elf_constant_bound")
            return node.value
        if isinstance(node,ast.Constant) and type(node.value) is str:
            require(len(node.value) <= 32,"declared_elf_constant_bound")
            return node.value
        if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Mult):
            left,right = bounded_constant(node.left,depth+1),bounded_constant(node.right,depth+1)
            require(type(left) is int and type(right) is int and left*right <= 512*1024*1024,
                "declared_elf_constant_bound")
            return left*right
        if isinstance(node,ast.Dict):
            require(len(node.keys) <= 4,"declared_elf_constant_bound")
            keys = [bounded_constant(key,depth+1) for key in node.keys]
            values = [bounded_constant(value,depth+1) for value in node.values]
            require(all(type(key) is str for key in keys) and len(set(keys)) == len(keys)
                and all(type(value) is int for value in values),"declared_elf_constant_shape")
            return dict(zip(keys,values))
        raise worker.Refusal("declared_elf_constant_shape")
    functions = {"_check_range","_slice","_cstring","_file_limit","elf_metadata"}
    selected,seen = [],set()
    for node in tree.body:
        names = {target.id for target in node.targets if isinstance(target,ast.Name)} if isinstance(node,ast.Assign) else set()
        key = node.name if isinstance(node,ast.FunctionDef) else next(iter(names)) if len(names) == 1 else None
        if key in constants|functions:
            require(key not in seen,"declared_elf_parser_duplicate")
            if key in constants:
                require(bounded_constant(node.value) == expected[key],"declared_elf_constant_differs")
            seen.add(key)
            selected.append(ast.get_source_segment(text,node))
    require(seen == constants|functions,"declared_elf_parser_contract")
    return "import struct\n"+"\n\n".join(selected)+"\n"


def require(value,reason):
    worker.require(value,reason)


def subset(data):
    require(hashlib.sha256(data).hexdigest() == delivery.INVENTORY_SHA,"fixed_inventory_required")
    inventory = json.loads(data,object_pairs_hook=worker.unique)
    rows = {row["path"]:row for row in inventory["paths"]}
    require(len(rows) == 472,"fixed_inventory_required")
    selected,pending = set(),list(ROOTS)
    while pending:
        path = pending.pop()
        if path in selected:
            continue
        require(path in rows,"reference_closed_subset_required")
        selected.add(path)
        pending.extend(rows[path]["references"])
    result = [rows[path] for path in sorted(selected)]
    require(len(result) == 181 and sum(row["narSize"] for row in result) == 869166464,"fixed_ui_subset_required")
    return result


def namespace(path,key):
    descriptor = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    info = os.fstat(descriptor)
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700
        and os.environ.get(key) == str(info.st_dev)+":"+str(info.st_ino),"guard_namespace_identity_required")
    return descriptor,(info.st_dev,info.st_ino,info.st_uid,info.st_mode)


def private_metadata(directory,name,maximum):
    descriptor = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) in (0o400,0o600) and 0 < before.st_size <= maximum,"private_metadata_custody")
        data = os.pread(descriptor,before.st_size+1,0)
        witness = lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(len(data) == before.st_size and witness(before) == witness(os.fstat(descriptor))
            == witness(os.stat(name,dir_fd=directory,follow_symlinks=False)),"private_metadata_changed")
        return data
    finally:
        os.close(descriptor)


def ssh_environment(ui):
    environment = {"HOME":os.environ["HOME"]} if "HOME" in os.environ else {}
    if ui["ssh_auth_socket"] is not None:
        environment["SSH_AUTH_SOCK"] = "/omux-native-login-ui-prepare/ssh-agent.sock"
        import socket,struct
        info = os.stat(environment["SSH_AUTH_SOCK"],follow_symlinks=False)
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(),"agent_custody")
        with socket.socket(socket.AF_UNIX) as channel:
            channel.settimeout(5)
            channel.connect(environment["SSH_AUTH_SOCK"])
            require(struct.unpack("3i",channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1] == os.getuid(),"agent_peer")
    return environment


def remote_prepare(ui,options,hosts,code,payload,until):
    process = pidfd = None
    try:
        set_phase("ssh_encode")
        command = carrier.remote_command("/usr/bin/python3",code)
        require(len(command.encode()) <= 120*1024,"remote_command_bound")
        arguments = carrier.ssh_arguments(ui,options,hosts.options(),command)
        set_phase("ssh_environment")
        environment = ssh_environment(ui)
        set_phase("ssh_spawn")
        process = subprocess.Popen(arguments,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,env=environment,umask=0o077)
        print(json.dumps({"scope":"omux-native-ui-prepare-owned-ssh-v1","owned_ssh_pid":process.pid}),flush=True)
        set_phase("ssh_pidfd")
        pidfd = os.pidfd_open(process.pid)
        set_phase("ssh_send")
        carrier.write_fd(process.stdin.fileno(),payload,until)
        process.stdin.close()
        set_phase("ssh_receive")
        result = worker.read_line(process.stdout.fileno(),until,256*1024)
        require(worker.read_line(process.stdout.fileno(),until,16,allow_eof=True) is None,"remote_output_extra")
        set_phase("ssh_wait")
        status = process.wait(timeout=max(.01,min(5,until-time.monotonic())))
        set_phase("remote_result")
        observed = json.loads(result,object_pairs_hook=worker.unique)
        if status != 0:
            raise RemoteRefusal(observed)
        require(not(type(observed) is dict and observed.get("scope") ==
            "omux-native-ui-prepare-remote-refused-v1"),"remote_refusal_with_zero_status")
        return observed
    finally:
        cleanup_failure = None
        reaped = process is None
        if process is not None:
            try:
                if not process.stdin.closed:
                    process.stdin.close()
            except BrokenPipeError:
                pass
            except BaseException as error:
                cleanup_failure = error
            try:
                process.wait(timeout=5)
                reaped = True
            except subprocess.TimeoutExpired:
                pass
            except BaseException as error:
                cleanup_failure = cleanup_failure or error
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
            try:
                process.stdout.close()
            except BaseException as error:
                cleanup_failure = cleanup_failure or error
        if pidfd is not None:
            try:
                os.close(pidfd)
            except BaseException as error:
                cleanup_failure = cleanup_failure or error
        require(reaped and cleanup_failure is None,"owned_prepare_ssh_cleanup_incomplete")


def publish(directory,files):
    require(os.listdir(directory) == [],"new_empty_output_required")
    created = []
    try:
        for name,data in files.items():
            descriptor = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
            try:
                initial = os.fstat(descriptor)
                created.append((name,initial.st_dev,initial.st_ino))
                offset = 0
                while offset < len(data):
                    count = os.write(descriptor,data[offset:])
                    require(count > 0,"receipt_write_refused")
                    offset += count
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(directory)
    except BaseException:
        for name,device,inode in reversed(created):
            current = os.stat(name,dir_fd=directory,follow_symlinks=False)
            require((current.st_dev,current.st_ino) == (device,inode),"receipt_cleanup_custody")
            os.unlink(name,dir_fd=directory)
        raise


def main():
    set_phase("arguments")
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control","inventory","source-receipt","known-hosts","worker","remote-worker","elf-parser"):
        parser.add_argument("--"+name,required=True)
    arguments = parser.parse_args()
    set_phase("guard")
    require(os.environ.get("OMUX_NATIVE_LOGIN_UI_PREPARE_INPUT_MANIFEST") == INPUT,"guard_manifest_required")
    require(hasattr(os,"pidfd_open") and hasattr(signal,"pidfd_send_signal"),"pidfd_required")
    set_phase("input_namespace")
    directory,input_identity = namespace(str(Path(INPUT).parent),"OMUX_NATIVE_LOGIN_UI_NAMESPACE_ID")
    set_phase("output_namespace")
    output,output_identity = namespace(OUTPUT,"OMUX_NATIVE_LOGIN_UI_OUTPUT_ID")
    try:
        set_phase("manifest")
        config = json.loads(private_metadata(directory,"input.json",16384),object_pairs_hook=worker.unique)
        require(type(config) is dict and set(config) == {"schema_version","scope","os_qualification_sha256",
            "control_sha256","known_hosts_path","ssh_auth_socket","output_parent","deadline_seconds"}
            and type(config["schema_version"]) is int and config["schema_version"] == 1
            and config["scope"] == "omux-native-login-ui-prepare-v1" and config["output_parent"] == OUTPUT
            and type(config["deadline_seconds"]) is int and 1 <= config["deadline_seconds"] <= 900,"prepare_manifest_invalid")
        original = int(os.environ["OMUX_NATIVE_LOGIN_UI_ORIGINAL_DEADLINE_NS"])/10**9
        until = min(original-30,time.monotonic()+config["deadline_seconds"])
        require(until-time.monotonic() > 30,"original_deadline_required")
        set_phase("os_authority")
        raw = private_metadata(directory,"os-qualification.json",16384)
        require(hashlib.sha256(raw).hexdigest() == config["os_qualification_sha256"],"os_qualification_digest")
        qualified = settings.qualification(json.loads(raw,object_pairs_hook=worker.unique))
        set_phase("control_input")
        control = delivery.read_public(arguments.control,128*1024*1024,until)
        require(hashlib.sha256(control).hexdigest() == config["control_sha256"] and control.startswith(b"\x7fELF"),"selected_control_digest")
        set_phase("inventory_input")
        inventory_bytes = delivery.read_public(arguments.inventory,8*1024*1024,until)
        delivery.selected(inventory_bytes,delivery.read_public(arguments.source_receipt,8*1024*1024,until))
        rows = subset(inventory_bytes)
        set_phase("worker_input")
        worker_source = delivery.read_public(arguments.worker,65536,until).decode("utf8")
        set_phase("remote_worker_input")
        remote_source = delivery.read_public(arguments.remote_worker,65536,until).decode("utf8")
        set_phase("elf_input")
        elf_source = elf_parser_source(delivery.read_public(arguments.elf_parser,128*1024,until))
        set_phase("bootstrap_encode")
        code = bootstrap(worker_source,remote_source,elf_source)
        ui = {"ssh_path":qualified["sshPath"],"ssh_auth_socket":config["ssh_auth_socket"]}
        set_phase("host_authority")
        with delivery.KnownHostAuthority(arguments.known_hosts,until) as hosts,carrier.operator_config(include_user=False) as options:
            require(str(Path(config["known_hosts_path"]).resolve(strict=True)) == delivery.KNOWN_HOSTS_SOURCE
                == str(Path(arguments.known_hosts).resolve(strict=True)),"fixed_host_pin_required")
            doctor_options = [*options,"-l","jsullivan2","-oHostName=100.104.152.110",
                "-oProxyCommand=none","-oProxyJump=none","-oPermitLocalCommand=no","-oRemoteCommand=none",
                "-oForwardX11=no"]
            set_phase("backend_constructor")
            backend = delivery.Backend(qualified["sshPath"],doctor_options,until,
                {"sshPath":qualified["sshPath"],"sshSha256":qualified["sshSha256"],"remote":qualified["remote"]},hosts)
            backend.env = ssh_environment(ui)
            # Existing bootstrap reobserves the full OS/Nix tuple before staging.
            set_phase("os_before")
            require(backend.qualify() == qualified["remote"],"actual_os_qualification_changed")
            remote_config = {"expected_os":qualified["remote"],"rows":rows,"control_sha256":config["control_sha256"],
                "control_bytes":len(control),"task_id":str(uuid.uuid4()),"deadline_seconds":max(1,min(900,int(until-time.monotonic())))}
            set_phase("remote_prepare")
            observed = remote_prepare(ui,options,hosts,code,canonical(remote_config)+b"\n"+control,until)
            set_phase("os_after")
            require(backend.qualify() == qualified["remote"],"actual_os_qualification_changed")
            hosts.check()
        set_phase("receipt_validate")
        require(type(observed) is dict and set(observed) == {"remote","closure","seat"}
            and observed["closure"]["rows"] == rows and observed["seat"]["actual_dialog_eof_clean_exit"] is True
            and observed["seat"]["provider_request_performed"] is False and observed["seat"]["portal_openuri_performed"] is False,"observed_receipt_invalid")
        remote = observed["remote"]
        closure = canonical({**observed["closure"],"source_inventory_sha256":delivery.INVENTORY_SHA,
            "os_qualification_sha256":config["os_qualification_sha256"]})
        seat = canonical(observed["seat"])
        join = canonical({"schema_version":1,"scope":"omux-native-login-ui-qualification-v1","host_alias":"yoga",
            "remote":remote,"controller_ssh":{"path":qualified["sshPath"],"sha256":qualified["sshSha256"]},
            "closure_receipt_sha256":hashlib.sha256(closure).hexdigest(),"seat_receipt_sha256":hashlib.sha256(seat).hexdigest()})
        require(private_metadata(directory,"os-qualification.json",16384) == raw,"os_input_changed")
        require(input_identity == tuple(getattr(os.fstat(directory),key) for key in ("st_dev","st_ino","st_uid","st_mode"))
            and output_identity == tuple(getattr(os.fstat(output),key) for key in ("st_dev","st_ino","st_uid","st_mode")),"namespace_changed")
        set_phase("receipt_publish")
        publish(output,{"closure.json":closure,"seat.json":seat,"ui-qualification.json":join})
        set_phase("complete")
        print(json.dumps({"scope":"omux-native-login-ui-prepared-v1","ui_qualification_sha256":hashlib.sha256(join).hexdigest(),
            "closure_receipt_sha256":hashlib.sha256(closure).hexdigest(),"seat_receipt_sha256":hashlib.sha256(seat).hexdigest(),
            "provider_request_performed":False,"portal_openuri_performed":False},sort_keys=True),flush=True)
    finally:
        os.close(output)
        os.close(directory)


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        print(json.dumps(refusal_record(error),sort_keys=True),file=sys.stderr)
        sys.exit(1)
