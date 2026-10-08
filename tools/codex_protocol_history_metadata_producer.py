"""One fixed offline rules_rs hub regeneration; no native dispatch or cache reuse."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time

import codex_live_source as source
import codex_protocol_history_source as history
import codex_protocol_history_metadata as metadata
import codex_retained_sdk_export as sdk

KIND = "omux-protocol-history-metadata-input-v1"
OUTPUT_KIND = "omux-protocol-history-metadata-v1"
INPUT_NAME = "omux_protocol_history_metadata_inputs"
# Fixed observed retained source receipt custody, distinct from action writers.
SOURCE_RECEIPT_MODE = 0o555
INPUT_CONTROL = Path("/srv/fast-local/jess/state/codex/omux-native-candidate-20261007/protocol-history-metadata-input.json")
EXPORT_ROOT = Path("/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export")
EXPORT_SHA = "1aa4c87d689f464e576a5c6a51b4c6350a8f0346f6b94299856d01db5147d4f0"
BAZEL = "/nix/store/ia8gp7v2h790lwdx7a7p5clh063v0qy1-bazel-9.0.1/bin/bazel"
LOCKED_PATH = "/nix/store/4bwbk4an4bx7cb8xwffghvjjyfyl7m2i-bash-interactive-5.3p9/bin:/nix/store/jjxngswsb214vb58qx485jhmilf0kxxy-coreutils-9.10/bin:/nix/store/0r6k8xa2kgqyp3r4v2w7yrb80ma2iawm-python3-3.13.12/bin:/nix/store/c0277k5giric1mn9dklllavbzvxl6hzb-git-2.53.0/bin"
SOURCE_SCOPE = re.compile(r"(?:/home/jess/\.local/state/omux-execution-20261005|/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005)/(?:cache-v2-[0-9a-f]{64}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/output-base/execroot/_main/bazel-out/[A-Za-z0-9_-]+/testlogs/tools/codex_protocol_history_source_producer/test.outputs/protocol-history-source")
PHASE = "selection"
MAX_LOG = {"stdout":16*1024*1024,"stderr":4*1024*1024}
DEADLINE = None


def require(value):
    metadata.require(value)


def tick(count=0):
    require(DEADLINE is None or time.monotonic() < DEADLINE)


def parse_selection(raw, digest):
    require(type(raw) is bytes and len(raw) <= 8192
        and type(digest) is str and source.HASH.fullmatch(digest) is not None
        and source.sha(raw) == digest)
    document = json.loads(raw,object_pairs_hook=source.unique)
    return validate_document(document)


def validate_document(document):
    require(type(document) is dict and set(document) == {"kind","source_root",
        "source_receipt_sha256","export_root","export_receipt_sha256"}
        and document["kind"] == KIND
        and type(document["source_root"]) is str
        and SOURCE_SCOPE.fullmatch(document["source_root"]) is not None
        and type(document["source_receipt_sha256"]) is str
        and source.HASH.fullmatch(document["source_receipt_sha256"]) is not None
        and document["export_root"] == str(EXPORT_ROOT)
        and document["export_receipt_sha256"] == EXPORT_SHA)
    return document


def validate_query_tools(value):
    require(type(value) is dict and set(value) == {"schemaVersion", "kind", "tools", "path", "java_home", "roots"}
        and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
        and value["kind"] == "omux-codex-metadata-query-tools-v1"
        and type(value["tools"]) is dict and set(value["tools"]) == {"bazel", "bash", "coreutils", "python", "git"}
        and value["path"] == LOCKED_PATH.split(":") and value["java_home"] == sdk.JDK)
    expected = dict(zip(("bash", "coreutils", "python", "git"),
        (directory + "/" + binary for directory, binary in zip(value["path"], ("bash", "env", "python3", "git")))))
    expected["bazel"] = BAZEL
    require(value["tools"] == expected and type(value["roots"]) is list
        and value["roots"] == sorted(set(value["roots"])) and 0 < len(value["roots"]) <= 4096
        and all(type(root) is str and re.fullmatch(r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9._+-]+", root)
                for root in value["roots"])
        and all("/".join(path.split("/")[:4]) in value["roots"]
                for path in list(expected.values()) + [value["java_home"]]))
    return True


def declared_query_tools(runfiles, rows):
    selected = [row[2] for row in rows if len(row) == 3 and row[0] in ("", "_main") and row[1] == "omux_nix"]
    require(len(selected) == 1 and re.fullmatch(r"[A-Za-z0-9_+.-]{1,256}", selected[0]) is not None)
    parent = (runfiles/selected[0]).resolve(strict=True)
    require(parent.name == selected[0] and "external" in parent.parts)
    fd = source.directory(parent)
    try:
        raw, _ = source.read(fd, "codex-metadata-query-tools.json", 1024*1024)
    finally:
        os.close(fd)
    return validate_query_tools(json.loads(raw, object_pairs_hook=source.unique))


def declared_selection():
    # Resolve only the exact apparent data repository through Bazel's mapping.
    require(len(sys.argv) == 1 and os.environ.get("TEST_SRCDIR")
        and os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR") and os.environ.get("TEST_TIMEOUT"))
    runfiles = Path(os.environ["TEST_SRCDIR"]).resolve(strict=True)
    require(runfiles.is_absolute())
    mapping_path = runfiles/"_repo_mapping"
    raw = mapping_path.read_bytes()
    require(len(raw) <= 1024*1024)
    rows = [line.split(",") for line in raw.decode().splitlines()]
    require(declared_query_tools(runfiles, rows) is True)
    selected = [row[2] for row in rows if len(row) == 3 and row[0] in ("","_main")
        and row[1] == INPUT_NAME]
    require(len(selected) == 1 and re.fullmatch(r"[A-Za-z0-9_+.-]{1,256}",selected[0]) is not None
        and (selected[0] == INPUT_NAME or selected[0].endswith("+"+INPUT_NAME)))
    parent = (runfiles/selected[0]).resolve(strict=True)
    require(parent.name == selected[0] and "external" in parent.parts)
    fd = source.directory(parent)
    try:
        data,_ = source.read(fd,"metadata-input.json",8192)
        pin,_ = source.read(fd,"metadata-input.sha256",65)
    finally:os.close(fd)
    require(re.fullmatch(rb"[0-9a-f]{64}\n",pin) is not None)
    return parse_selection(data,pin.decode().strip()),source.sha(data)


def identity(info):
    return (info.st_dev,info.st_ino,info.st_uid,stat.S_IMODE(info.st_mode))


def hold_root(path):
    fd = source.directory(path)
    return fd,identity(os.fstat(fd))


def recheck_root(path, held):
    fd,before = held
    require(identity(os.fstat(fd)) == before)
    named = source.directory(path)
    try:require(identity(os.fstat(named)) == before)
    finally:os.close(named)


def load_candidate(document):
    root = Path(document["source_root"])
    fd = source.directory(root)
    try:
        raw,mode = source.read(fd,"source-receipt.json",source.MAX_METADATA)
    finally:os.close(fd)
    require(mode == SOURCE_RECEIPT_MODE and source.sha(raw) == document["source_receipt_sha256"])
    report = json.loads(raw,object_pairs_hook=source.unique)
    before,parent = history.load_parent()
    expected = history.transform(before,history.PATCH_BYTES)
    inventory = {name:{"mode":mode,"sha256":source.sha(value)}
        for name,(mode,value) in expected.items()}
    require(type(report["schema_version"]) is int and report["schema_version"] == 1
        and report["kind"] == history.KIND
        and report["status"] == "verified-protocol-history-source-pending-sdk-metadata"
        and report["commit"] == source.COMMIT
        and report["parent_source_root"] == str(history.PARENT)
        and report["parent_source_receipt_sha256"] == history.PARENT_RECEIPT_SHA
        and report["parent_source_inventory_sha256"] == history.PARENT_INVENTORY_SHA
        and report["patch_sha256"] == history.PARENT_PATCHES+[history.PATCH_SHA]
        and report["source_inventory"] == inventory
        and report["inventory_sha256"] == source.sha(source.canonical(inventory))
        and type(report["tracked_files"]) is int and report["tracked_files"] == len(expected)
        and type(report["source_bytes"]) is int
        and report["source_bytes"] == sum(len(value) for _,value in expected.values())
        and report["graph_files"] == {name:{"sha256":source.sha(expected[name][1])} for name in history.GRAPH}
        and report["parent_graph_files"] == {name:{"sha256":source.sha(before[name][1])} for name in history.GRAPH}
        and report["sdk_metadata_qualified"] is False
        and report["native_support"] is False and report["native_compile_passed"] is False
        and report["provider_evaluation"] is False)
    source.verify_written(root/"source",expected)
    return report,expected,parent


def read_hub(root):
    budget = sdk.Budget(time.time()+max(1,min(1200,DEADLINE-time.monotonic())),tick)
    rows = sdk.inventory(root,budget)
    require(0 < len(rows) <= 16 and all(row["kind"] == "file" and "/" not in row["path"]
        and row["size"] <= metadata.MAX_HUB_FILE for row in rows))
    fd = sdk.open_dir(root)
    values = {}
    try:
        for row in rows:
            digest,size,raw = sdk.read_file(fd,row["path"],budget,capture=True)
            require(digest == row["sha256"] and size == row["size"])
            values[row["path"]] = raw
    finally:os.close(fd)
    return values


def query_plan(work, source_root, exported):
    require(type(exported) is dict and type(exported["repositories"]) is dict
        and exported["registry_cache"] == str(EXPORT_ROOT/"registry-cache"))
    overrides = metadata.retained_overrides(exported["repositories"],str(EXPORT_ROOT))
    argv = [BAZEL,"--batch","--output_user_root="+str(work/"user-root"),
        "--output_base="+str(work/"output-base"),"--host_jvm_args=-Xmx768m",
        "--host_jvm_args=-XX:ActiveProcessorCount=1","--ignore_all_rc_files","query",
        "--lockfile_mode=error","--repository_disable_download",
        "--repository_cache="+exported["registry_cache"],"--repo_contents_cache=",
        "--loading_phase_threads=2","--repo_env=PATH="+LOCKED_PATH,
        "--repo_env=CARGO_NET_OFFLINE=true"]
    argv += ["--override_repository="+name+"="+directory for name,directory in sorted(overrides.items())]
    argv += ["--output=build","@crates//:all"]
    env = {"PATH":LOCKED_PATH,"USE_BAZEL_VERSION":"9.0.1","CARGO_NET_OFFLINE":"true",
        "HOME":str(work/"home"),"CARGO_HOME":str(work/"home/cargo"),
        "XDG_CACHE_HOME":str(work/"home/cache"),"XDG_CONFIG_HOME":str(work/"home/config"),
        "XDG_STATE_HOME":str(work/"home/state"),"LANG":"C.UTF-8","LC_ALL":"C.UTF-8"}
    return {"argv":argv,"environment":env,"cwd":str(source_root)}


def execute_query(plan, output):
    # Hash bounded public streams; retain no raw child stderr/stdout.
    child = None
    selector = None
    streams = {}
    failed = False
    try:
        child = subprocess.Popen(plan["argv"],cwd=plan["cwd"],env=plan["environment"],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
        selector = selectors.DefaultSelector()
        for name,pipe in (("stdout",child.stdout),("stderr",child.stderr)):
            os.set_blocking(pipe.fileno(),False)
            streams[name] = [hashlib.sha256(),0]
            selector.register(pipe,selectors.EVENT_READ,name)
        while selector.get_map():
            require(time.monotonic() < DEADLINE-90)
            for key,_ in selector.select(min(1,max(0,DEADLINE-90-time.monotonic()))):
                try:value = os.read(key.fileobj.fileno(),65536)
                except BlockingIOError:continue
                if not value:
                    selector.unregister(key.fileobj)
                    continue
                name = key.data
                streams[name][1] += len(value)
                require(streams[name][1] <= MAX_LOG[name])
                streams[name][0].update(value)
        result = child.wait(timeout=max(0.1,DEADLINE-90-time.monotonic()))
        require(type(result) is int and result == 0)
        return result
    finally:
        if selector is not None:
            try:selector.close()
            except (OSError,ValueError):failed = True
        if child is not None:
            try:alive = child.poll() is None
            except (OSError,subprocess.SubprocessError):alive = True;failed = True
            if alive:
                try:child.kill()
                except (OSError,subprocess.SubprocessError):failed = True
                try:child.wait(timeout=5)
                except (OSError,subprocess.SubprocessError):failed = True
            for pipe in (child.stdout,child.stderr):
                if pipe is not None:
                    try:pipe.close()
                    except (OSError,ValueError):failed = True
        require(not failed)

def write_receipt(root, report):
    fd = source.directory(root)
    try:
        out = os.open("metadata-receipt.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        with os.fdopen(out,"wb") as stream:
            stream.write(source.encoded(report));stream.flush()
            os.fchmod(stream.fileno(),0o444);os.fsync(stream.fileno())
        os.fsync(fd);os.fchmod(fd,0o555)
    finally:os.close(fd)


def produce(document, selector_sha, temporary, output, seconds, *, absolute_deadline=None):
    global DEADLINE,PHASE
    validate_document(document)
    require(type(selector_sha) is str and source.HASH.fullmatch(selector_sha) is not None)
    require(type(seconds) is int and 1 <= seconds <= 840
        and not temporary.exists() and not output.exists())
    require(absolute_deadline is None or type(absolute_deadline) is float
        and 0 < absolute_deadline-time.monotonic() <= seconds)
    DEADLINE = time.monotonic()+seconds if absolute_deadline is None else absolute_deadline
    source.DEADLINE = DEADLINE
    held = []
    try:
        PHASE = "source"
        source_hold = hold_root(Path(document["source_root"]));held.append(source_hold)
        export_hold = hold_root(EXPORT_ROOT);held.append(export_hold)
        report,files,parent = load_candidate(document)
        PHASE = "sdk"
        exported = sdk.validate_export(EXPORT_ROOT,EXPORT_SHA,source.BASE_INVENTORY,
            parent["baseline_graph_files"],on_read=tick)
        previous_hub = read_hub(EXPORT_ROOT/"repositories"/metadata.HUB)
        temporary.mkdir(mode=0o700);output.mkdir(mode=0o700)
        fd = source.write_source(temporary/"workspace",files);os.close(fd)
        for name in ("home","home/cargo","home/cache","home/config","home/state"):
            (temporary/name).mkdir(mode=0o700)
        plan = query_plan(temporary,temporary/"workspace/source",exported)
        PHASE = "query"
        result = execute_query(plan,output)
        PHASE = "hub"
        generated_root = temporary/"output-base/external"/metadata.HUB
        generated_hub = read_hub(generated_root)
        require(metadata.verify_hub_delta(previous_hub,generated_hub) is True)
        hub = output/"hub";hub.mkdir(mode=0o700)
        for name,value in sorted(generated_hub.items()):
            with (hub/name).open("xb") as stream:
                stream.write(value);stream.flush();os.fchmod(stream.fileno(),0o444);os.fsync(stream.fileno())
        os.chmod(hub,0o555)
        require(read_hub(hub) == generated_hub)
        PHASE = "readback"
        source.verify_written(temporary/"workspace/source",files)
        after,_,_ = load_candidate(document)
        require(after == report)
        after_export = sdk.validate_export(EXPORT_ROOT,EXPORT_SHA,source.BASE_INVENTORY,
            parent["baseline_graph_files"],on_read=tick)
        require(after_export == exported)
        recheck_root(Path(document["source_root"]),source_hold);recheck_root(EXPORT_ROOT,export_hold)
        envelope = {"schema_version":1,"kind":OUTPUT_KIND,"status":"verified-strict-regenerated-protocol-history-hub",
            "selector_sha256":selector_sha,"inputs":document,"source_inventory_sha256":report["inventory_sha256"],
            "source_graph":report["graph_files"],"parent_export_inventory_sha256":exported["inventory_sha256"],
            "module_lock_unchanged":True,"cargo_lock_unchanged":True,"query_exit":result,
            "query_plan":plan,"generated_hub":{name:{"sha256":source.sha(value),"bytes":len(value),"mode":0o444}
                for name,value in sorted(generated_hub.items())},
            "retained_hub":{name:{"sha256":source.sha(value),"bytes":len(value)} for name,value in sorted(previous_hub.items())},
            "source_and_export_rechecked":True,"sdk_export_qualified":False,"native_compile_passed":False,
            "native_support":False,"provider_evaluation":False}
        tick()
        write_receipt(output,envelope)
        return envelope
    finally:
        for fd,_ in held:os.close(fd)
        source.DEADLINE = None


def main():
    global PHASE
    os.umask(0o077)
    document,pin = declared_selection()
    seconds = min(840,int(os.environ["TEST_TIMEOUT"])-60)
    temporary = Path(os.environ["TEST_TMPDIR"]).resolve(strict=True)/"protocol-history-metadata-work"
    output = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)/"protocol-history-metadata"
    produce(document,pin,temporary,output,seconds)
    print("strict generated Cargo hub verified; full SDK export and native compilation unrun")


if __name__ == "__main__":
    try:main()
    except (ValueError,OSError,KeyError,TypeError,UnicodeError,SyntaxError,json.JSONDecodeError,subprocess.SubprocessError):
        print("protocol history metadata refused at "+PHASE,file=sys.stderr)
        raise SystemExit(1) from None
