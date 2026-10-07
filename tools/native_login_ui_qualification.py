"""Declared provider-free UI preparation. Outputs exactly three public receipts."""
import argparse
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


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":")).encode("ascii")


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
        command = carrier.remote_command("/usr/bin/python3",code)
        require(len(command.encode()) <= 120*1024,"remote_command_bound")
        arguments = carrier.ssh_arguments(ui,options,hosts.options(),command)
        process = subprocess.Popen(arguments,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,env=ssh_environment(ui),umask=0o077)
        print(json.dumps({"scope":"omux-native-ui-prepare-owned-ssh-v1","owned_ssh_pid":process.pid}),flush=True)
        pidfd = os.pidfd_open(process.pid)
        carrier.write_fd(process.stdin.fileno(),payload,until)
        process.stdin.close()
        result = worker.read_line(process.stdout.fileno(),until,256*1024)
        require(worker.read_line(process.stdout.fileno(),until,16,allow_eof=True) is None,"remote_output_extra")
        require(process.wait(timeout=max(.01,min(5,until-time.monotonic()))) == 0,"remote_prepare_refused")
        return json.loads(result,object_pairs_hook=worker.unique)
    finally:
        if process is not None:
            if not process.stdin.closed:
                process.stdin.close()
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
                        require(sig != signal.SIGKILL,"owned_prepare_ssh_cleanup_incomplete")
            process.stdout.close()
        if pidfd is not None:
            os.close(pidfd)


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
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control","inventory","source-receipt","known-hosts","worker","remote-worker"):
        parser.add_argument("--"+name,required=True)
    arguments = parser.parse_args()
    require(os.environ.get("OMUX_NATIVE_LOGIN_UI_PREPARE_INPUT_MANIFEST") == INPUT,"guard_manifest_required")
    require(hasattr(os,"pidfd_open") and hasattr(signal,"pidfd_send_signal"),"pidfd_required")
    directory,input_identity = namespace(str(Path(INPUT).parent),"OMUX_NATIVE_LOGIN_UI_NAMESPACE_ID")
    output,output_identity = namespace(OUTPUT,"OMUX_NATIVE_LOGIN_UI_OUTPUT_ID")
    try:
        config = json.loads(private_metadata(directory,"input.json",16384),object_pairs_hook=worker.unique)
        require(type(config) is dict and set(config) == {"schema_version","scope","os_qualification_sha256",
            "control_sha256","known_hosts_path","ssh_auth_socket","output_parent","deadline_seconds"}
            and type(config["schema_version"]) is int and config["schema_version"] == 1
            and config["scope"] == "omux-native-login-ui-prepare-v1" and config["output_parent"] == OUTPUT
            and type(config["deadline_seconds"]) is int and 1 <= config["deadline_seconds"] <= 900,"prepare_manifest_invalid")
        original = int(os.environ["OMUX_NATIVE_LOGIN_UI_ORIGINAL_DEADLINE_NS"])/10**9
        until = min(original-30,time.monotonic()+config["deadline_seconds"])
        require(until-time.monotonic() > 30,"original_deadline_required")
        raw = private_metadata(directory,"os-qualification.json",16384)
        require(hashlib.sha256(raw).hexdigest() == config["os_qualification_sha256"],"os_qualification_digest")
        qualified = settings.qualification(json.loads(raw,object_pairs_hook=worker.unique))
        control = delivery.read_public(arguments.control,128*1024*1024,until)
        require(hashlib.sha256(control).hexdigest() == config["control_sha256"] and control.startswith(b"\x7fELF"),"selected_control_digest")
        inventory_bytes = delivery.read_public(arguments.inventory,8*1024*1024,until)
        delivery.selected(inventory_bytes,delivery.read_public(arguments.source_receipt,8*1024*1024,until))
        rows = subset(inventory_bytes)
        worker_source = delivery.read_public(arguments.worker,65536,until).decode("utf8")
        remote_source = delivery.read_public(arguments.remote_worker,65536,until).decode("utf8")
        code = ("import json,sys,types\n"
            "w=types.ModuleType('omux_qualified_ui_worker')\nexec(compile("+repr(worker_source)+",'<declared-ui-worker>','exec'),w.__dict__)\n"
            "r=types.ModuleType('omux_ui_prepare_worker')\nexec(compile("+repr(remote_source)+",'<declared-ui-prepare>','exec'),r.__dict__)\n"
            "try:\n c=json.loads(w.read_line(0,w.time.monotonic()+30,262144),object_pairs_hook=w.unique)\n"
            " result=r.prepare(w,c)\n print(r.canonical(result).decode('ascii'),flush=True)\n"
            "except BaseException:\n sys.stderr.write('omux-native-ui-prepare-refused\\n')\n sys.exit(1)\n")
        require(len(code.encode()) <= 96*1024,"declared_bootstrap_source_bound")
        ui = {"ssh_path":qualified["sshPath"],"ssh_auth_socket":config["ssh_auth_socket"]}
        with delivery.KnownHostAuthority(arguments.known_hosts,until) as hosts,carrier.operator_config(include_user=False) as options:
            require(str(Path(config["known_hosts_path"]).resolve(strict=True)) == delivery.KNOWN_HOSTS_SOURCE
                == str(Path(arguments.known_hosts).resolve(strict=True)),"fixed_host_pin_required")
            doctor_options = [*options,"-l","jsullivan2","-oHostName=100.104.152.110",
                "-oProxyCommand=none","-oProxyJump=none","-oPermitLocalCommand=no","-oRemoteCommand=none",
                "-oForwardX11=no"]
            backend = delivery.Backend(qualified["sshPath"],doctor_options,until,
                {"sshPath":qualified["sshPath"],"sshSha256":qualified["sshSha256"],"remote":qualified["remote"]},hosts)
            backend.env = ssh_environment(ui)
            # Existing bootstrap reobserves the full OS/Nix tuple before staging.
            require(backend.qualify() == qualified["remote"],"actual_os_qualification_changed")
            remote_config = {"expected_os":qualified["remote"],"rows":rows,"control_sha256":config["control_sha256"],
                "control_bytes":len(control),"task_id":str(uuid.uuid4()),"deadline_seconds":max(1,min(900,int(until-time.monotonic())))}
            observed = remote_prepare(ui,options,hosts,code,canonical(remote_config)+b"\n"+control,until)
            require(backend.qualify() == qualified["remote"],"actual_os_qualification_changed")
            hosts.check()
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
        publish(output,{"closure.json":closure,"seat.json":seat,"ui-qualification.json":join})
        print(json.dumps({"scope":"omux-native-login-ui-prepared-v1","ui_qualification_sha256":hashlib.sha256(join).hexdigest(),
            "closure_receipt_sha256":hashlib.sha256(closure).hexdigest(),"seat_receipt_sha256":hashlib.sha256(seat).hexdigest(),
            "provider_request_performed":False,"portal_openuri_performed":False},sort_keys=True),flush=True)
    finally:
        os.close(output)
        os.close(directory)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        print('{"scope":"omux-native-login-ui-prepare-refused-v1","reason":"provider_free_preparation_refused"}',file=sys.stderr)
        sys.exit(1)
