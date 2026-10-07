"""Metadata-only inert fresh runtime input declaration, never execution authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

KIND = "omux-fresh-native-runtime-selection-v1"
RUNTIME_KIND = "omux-fresh-native-runtime-v1"
HOME_STATE = Path("/home/jess/.local/state/omux-execution-20261005")
MAX_SELECTION = 16*1024*1024

def require(value):
    if not value:
        raise ValueError("fresh-runtime-inert-input-refused")

def unique(pairs):
    value = {}
    for name,item in pairs:
        require(name not in value)
        value[name] = item
    return value

def canonical(value):
    require(type(value) is str and value.startswith("/") and len(value) <= 4096
        and not any(part in ("",".","..") for part in value.split("/")[1:])
        and not any(c.isspace() or c in ":\\\0" for c in value))
    return Path(value)

OPERATOR_ROOTS = (HOME_STATE,Path("/srv/fast-local/jess/state/codex/omux-native-candidate-20261007"))
PACKAGE_SUFFIX = "/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_fresh_native_runtime_package/test.outputs/fresh-native-runtime"

def operator_path(value,filename):
    path = canonical(value)
    require(path.parent in OPERATOR_ROOTS and path.name == filename)
    return path

def declarations(selected):
    require(type(selected) is dict and set(selected) == {"kind","package_selection","package_run",
        "producer_graph_sha256","producer_source_sha256","archive","manifest","receipt","bundle_directory"}
        and selected["kind"] == KIND)
    for role in ("package_selection","package_run","archive","manifest","receipt"):
        row = selected[role]
        require(type(row) is dict and set(row) == {"path","sha256","bytes"}
            and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",row["sha256"])
            and type(row["bytes"]) is int and 0 < row["bytes"] <=
                (1024*1024*1024 if role == "archive" else 256*1024*1024))
        canonical(row["path"])
    operator_path(selected["package_selection"]["path"],"package-selection.json")
    run = canonical(selected["package_run"]["path"])
    require(run.parent.parent == HOME_STATE and run.name == "receipt.json"
        and str(uuid.UUID(run.parent.name)) == run.parent.name)
    def parent(value,name):
        path = canonical(value)
        text = str(path.parent)
        require(path.name == name and text.endswith(PACKAGE_SUFFIX))
        base = Path(text[:-len(PACKAGE_SUFFIX)])
        require(base.name == "output-base" and base.parent.parent == HOME_STATE)
        epoch = base.parent.name
        if epoch.startswith("cache-v2-"):
            require(re.fullmatch(r"[0-9a-f]{64}",epoch[len("cache-v2-"):]))
        else:
            require(str(uuid.UUID(epoch)) == epoch)
        return path.parent
    package = parent(selected["archive"]["path"],"fresh-native-runtime.tar.gz")
    require(parent(selected["manifest"]["path"],"runtime-manifest.json") == package
        and parent(selected["receipt"]["path"],"runtime-receipt.json") == package)
    root = canonical(selected["bundle_directory"])
    require(root.parent == package and re.fullmatch(r"[0-9a-f]{64}",root.name)
        and all(type(selected[name]) is str and re.fullmatch(r"[0-9a-f]{64}",selected[name])
            for name in ("producer_graph_sha256","producer_source_sha256")))
    pins = {role:selected[role] for role in ("archive","manifest","receipt")}
    input_pin = {"kind":RUNTIME_KIND}
    for role,row in pins.items():
        input_pin[role+"_sha256"] = row["sha256"]
        input_pin[role+"_bytes"] = row["bytes"]
    return {"files":pins,"input_pin":input_pin}

def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--selection",required=True)
    parser.add_argument("--sha256",required=True)
    parser.add_argument("--bytes",type=int,required=True)
    args = parser.parse_args()
    path = operator_path(args.selection,"fresh-runtime-selection.json")
    require(type(args.bytes) is int and 0 < args.bytes <= MAX_SELECTION
        and re.fullmatch(r"[0-9a-f]{64}",args.sha256))
    descriptor = os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            require(info.st_uid in (0,os.getuid()) and not info.st_mode & 0o022)
        held = os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=descriptor)
        try:
            info = os.fstat(held)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and not info.st_mode & 0o022 and info.st_size == args.bytes)
            raw = os.pread(held,args.bytes+1,0)
            require(len(raw) == args.bytes and hashlib.sha256(raw).hexdigest() == args.sha256)
            witness = lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
            require(witness(info) == witness(os.fstat(held)) ==
                witness(os.stat(path.name,dir_fd=descriptor,follow_symlinks=False)))
        finally:
            os.close(held)
    finally:
        os.close(descriptor)
    print(json.dumps(declarations(json.loads(raw,object_pairs_hook=unique)),sort_keys=True,separators=(",",":")))

if __name__ == "__main__":
    try:
        main()
    except (OSError,ValueError,KeyError,TypeError):
        sys.exit("fresh-runtime-inert-input-refused")
