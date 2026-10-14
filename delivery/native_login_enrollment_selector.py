"""Private acquisition-to-existing-enrollment metadata; never reads credentials."""
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

NAME = "input.json"
INPUT_DIRECTORY = "enrollment-inputs"
FIELDS = frozenset(("ownership","instance","prefix","records","runtime_state","service_path","existing_archive"))

def require(value):
    if not value:
        raise ValueError("native-enrollment-selector-refused")

def tick(deadline):
    require(type(deadline) is int and time.monotonic_ns() < deadline)

def canonical(value):
    require(type(value) is str and value.startswith("/") and value != "/" and len(value) <= 4096
        and value == os.path.normpath(value)
        and not any(c.isspace() or ord(c) <= 0x20 or ord(c) == 0x7f or c in ":\\" for c in value))
    return Path(value)

def pin(value,width=64):
    require(type(value) is str and re.fullmatch("[0-9a-f]{"+str(width)+"}",value))

def execution_root(root,home):
    require(root == home/".local/state/omux-execution-20261005"
        or root.parent == Path("/srv/fast-local/jess/state/codex")
        and re.fullmatch("omux-[a-z0-9-]+",root.name))

def validate_template(value,home):
    home = canonical(str(home))
    require(type(value) is dict and set(value) == FIELDS
        and value["ownership"] == "omux-installation" and value["instance"] == "default")
    fixed = {"prefix":home/".local/share/omux","records":home/".local/state/omux-install",
        "runtime_state":home/".local/state/omux",
        "service_path":home/".local/share/omux/units/ai.xoxd.omux.service"}
    require(all(canonical(value[k]) == path for k,path in fixed.items()))
    archive = value["existing_archive"]
    require(type(archive) is dict and set(archive) == {
        "archive_path","archive_sha256","archive_bytes","manifest_sha256","qualification"})
    pin(archive["archive_sha256"]); pin(archive["manifest_sha256"])
    require(type(archive["archive_bytes"]) is int and 0 < archive["archive_bytes"] <= 256*1024*1024)
    q = archive["qualification"]
    require(type(q) is dict and set(q) == {"path","sha256","bytes","source_commit","graph_sha256"})
    pin(q["sha256"]); pin(q["graph_sha256"]); pin(q["source_commit"],40)
    require(type(q["bytes"]) is int and 0 < q["bytes"] <= 8*1024*1024)
    receipt = canonical(q["path"])
    require(receipt.name == "receipt.json" and str(uuid.UUID(receipt.parent.name)) == receipt.parent.name)
    execution_root(receipt.parent.parent,home)
    selected = canonical(archive["archive_path"])
    outputs = [p for p in selected.parents if p.name == "output-base"]
    require(len(outputs) == 1)
    output = outputs[0]
    require(selected == output/"execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz")
    container = output.parent
    require(re.fullmatch("cache-v2-[0-9a-f]{64}",container.name)
        or str(uuid.UUID(container.name)) == container.name)
    execution_root(container.parent,home)
    require(container.parent == receipt.parent.parent)
    return value

def generated(template,source_path,home):
    validate_template(template,home)
    source = canonical(str(source_path))
    for key in ("prefix","records","runtime_state"):
        path = canonical(template[key])
        require(path != source and path not in source.parents and source not in path.parents)
    # Metadata selection is not installed/runtime/source verification. The next
    # existing-enrollment admission independently establishes each authority.
    return {"schema_version":1,**template,"action":"enroll-existing",
        "native_context":{"application":"codex","provenance":"authorized-working-native-context",
            "codex_home":str(source)},
        "permissions":{"connect_source":True,"activate_service":False,"restart_daemon":False}}

def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()

def unique(items):
    result = {}
    for key,value in items:
        require(key not in result)
        result[key] = value
    return result

def identity(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink)

def file_identity(info):
    return identity(info)+(info.st_size,info.st_mtime_ns,info.st_ctime_ns)

def directory(path,deadline):
    path = canonical(str(path))
    tick(deadline)
    fd = os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            tick(deadline)
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            require(info.st_uid in (0,os.getuid()) and (not info.st_mode & 0o022 or sticky))
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        return fd
    except BaseException:
        os.close(fd)
        raise

def recheck(path,held,deadline):
    named = directory(path,deadline)
    try:
        require(identity(os.fstat(named)) == identity(os.fstat(held)))
    finally:
        os.close(named)
    tick(deadline)

def auth_metadata(root_fd):
    # O_PATH cannot materialize the auth payload. Even metadata qualification
    # does not establish provider identity or grant eligibility.
    fd = os.open("auth.json",os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root_fd)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) in (0o400,0o600) and info.st_nlink == 1
            and 0 < info.st_size <= 128*1024)
        return file_identity(info)
    finally:
        os.close(fd)

def membership(fd):
    with os.scandir(fd) as entries:
        names = [next(entries,None) for _ in range(2)]
    require(names[0] is not None and names[0].name == NAME and names[1] is None)

def publish(template,root,root_fd,home,deadline):
    payload = encoded(generated(template,root,home))
    require(len(payload) <= 65536 and re.fullmatch("native-login-[0-9a-f]{32}",Path(root).name))
    recheck(root,root_fd,deadline)
    auth_before = auth_metadata(root_fd)
    # The unchanged resident Admission consumes an exclusive private namespace
    # containing only input.json, never the native profile's auth/XDG files.
    os.mkdir(INPUT_DIRECTORY,0o700,dir_fd=root_fd)
    namespace = Path(root)/INPUT_DIRECTORY
    namespace_fd = fd = None
    try:
        namespace_fd = os.open(INPUT_DIRECTORY,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root_fd)
        info = os.fstat(namespace_fd)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        recheck(root,root_fd,deadline); recheck(namespace,namespace_fd,deadline)
        fd = os.open(NAME,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=namespace_fd)
        offset = 0
        while offset < len(payload):
            tick(deadline)
            count = os.write(fd,payload[offset:])
            require(count > 0); offset += count
        os.fsync(fd)
        before = os.fstat(fd)
        require(stat.S_IMODE(before.st_mode) == 0o600 and before.st_uid == os.getuid()
            and before.st_nlink == 1 and before.st_size == len(payload))
        require(os.pread(fd,65537,0) == payload and file_identity(os.fstat(fd)) == file_identity(before))
        os.fsync(namespace_fd); os.fsync(root_fd)
        recheck(root,root_fd,deadline); recheck(namespace,namespace_fd,deadline)
        membership(namespace_fd)
        require(auth_metadata(root_fd) == auth_before
            and file_identity(os.stat(NAME,dir_fd=namespace_fd,follow_symlinks=False)) == file_identity(before))
    finally:
        for held in (fd,namespace_fd):
            if held is not None:
                os.close(held)
    # On refusal keep owned partials for diagnosis; never erase native history.
    tick(deadline)

def verify_generated(parent,template,home,deadline):
    validate_template(template,home)
    parent = canonical(str(parent))
    parent_fd = directory(parent,deadline)
    root_fd = namespace_fd = fd = None
    try:
        with os.scandir(parent_fd) as entries:
            names = [next(entries,None) for _ in range(2)]
        require(names[0] is not None and names[1] is None
            and re.fullmatch("native-login-[0-9a-f]{32}",names[0].name))
        root = parent/names[0].name
        root_fd = directory(root,deadline)
        auth_before = auth_metadata(root_fd)
        namespace = root/INPUT_DIRECTORY
        namespace_fd = directory(namespace,deadline)
        membership(namespace_fd)
        fd = os.open(NAME,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=namespace_fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
            and 0 < before.st_size <= 65536)
        tick(deadline)
        payload = os.pread(fd,65537,0)
        require(len(payload) == before.st_size)
        value = json.loads(payload,object_pairs_hook=unique)
        expected = generated(template,root,home)
        require(encoded(value) == encoded(expected) and payload == encoded(expected))
        recheck(parent,parent_fd,deadline); recheck(root,root_fd,deadline)
        recheck(namespace,namespace_fd,deadline); membership(namespace_fd)
        with os.scandir(parent_fd) as entries:
            names = [next(entries,None) for _ in range(2)]
        require(names[0] is not None and names[0].name == root.name and names[1] is None)
        require(auth_metadata(root_fd) == auth_before
            and file_identity(os.fstat(fd)) == file_identity(before)
            and file_identity(os.stat(NAME,dir_fd=namespace_fd,follow_symlinks=False)) == file_identity(before))
        tick(deadline)
        return {"selector_ready":True,"identity_verified":False,"resident_enrollment_completed":False,
            "renewal_owner":"native","native_support":False}
    finally:
        for held in (fd,namespace_fd,root_fd,parent_fd):
            if held is not None:
                os.close(held)
