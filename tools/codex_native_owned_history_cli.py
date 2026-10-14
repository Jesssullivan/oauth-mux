"""Genuine history13 full-model -> fixed CLI -> portable package action.

All code execution is declared Bazel child work inside the same current tree
SOURCE/SDK callback. No old runtime receipt projection or caller pass flag.
"""
import argparse
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).parent.parent/"delivery"))
sys.path.insert(0,str(Path(__file__).parent.parent/"integrations/codex-owner-runtime"))
import owned_history_runtime as proof
import runtime_package as runtime
import portable
import codex_native_siwc_catalog_models as models
import codex_native_profile as native
import codex_retained_sdk_tree_reader as tree

source, family, shared = models.source, models.family, models.shared
OUTPUT = "native-owned-history-cli"
TARGET = "//tools:codex_native_owned_history_cli_producer"


def fixed_binary(output_base):
    root = output_base/"execroot/_main/bazel-out"
    fd = source.directory(root)
    try:
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                source.tick(); proof.need(len(names)<64); names.append(entry.name)
        selected = [name for name in names if re.fullmatch(r"[A-Za-z0-9_.-]+-opt",name)]
        proof.need(len(selected) == 1)
        return root/selected[0]/"bin/codex-rs/cli/codex"
    finally: os.close(fd)


def prepare_work(work):
    proof.need(not work.exists())
    work.mkdir(mode=0o700)
    (work/"package-transform").mkdir(mode=0o700)


def build_plan(published,sdk,report,work,cutoff):
    # Concrete current owner is admitted before scratch effects or any IO.
    proof.need(type(sdk) is tree.HeldRetainedSdkTree and published.active
               and report["kind"] == models.history.KIND and len(report["patch_sha256"]) == 13
               and report["patch_sha256"][-1] == proof.HISTORY_PATCH
               and report["native_owned_history_controls_sha256"] == proof.HISTORY_CONTROL
               and report["transported_sdk"] == sdk.record())
    sdk.check(); published.full(); mapping = sdk.mapping()
    tools = family.query_tools.verify_repository(family.query.QUERY_REPOSITORY,cutoff)
    proof.need(tools["status"] == "declared-fixed-query-tools-byte-qualified" and tools["inputs_rechecked"] is True
               and not work.exists())
    # Keep this directory for the action lifetime: creating/removing a sibling
    # after compiler ancestry capture would invalidate its original witness.
    prepare_work(work)
    candidate = SimpleNamespace(source=published.path/"source",root=work,
                                lease=SimpleNamespace(output_base=work/"output-base"))
    args = SimpleNamespace(native_export_root=sdk.sdk_root,native_mode="owned-history-cli")
    plan = native.command_from_verified_inputs(args,work,family.query.LOCKED_PATH,
        tools["query_tools"]["tools"]["bash"],candidate,(report,mapping),
        {"owned-history-cli":("build",(proof.CLI,),None)},gates=None)
    plan = shared.project_hub(plan,mapping,published.path/"hub/source",sdk.sdk_root)
    proof.need(plan["argv"][-1] == proof.CLI and plan["argv"].count("build") == 1
               and not any(arg.startswith(("--test_filter","--test_arg","--nobuild")) for arg in plan["argv"]))
    plan["environment"]["CARGO_NET_OFFLINE"] = "true"
    plan["argv"].insert(plan["argv"].index("build")+1,"--repo_env=CARGO_NET_OFFLINE=true")
    proof.need(family.query_tools.verify_repository(family.query.QUERY_REPOSITORY,cutoff) == tools)
    return plan,tools


def held_runtime_inputs(owner,path,runfiles):
    raw=owner.add(path,proof.MAX_METADATA,modes=(0o444,0o555,0o644))
    selected=runtime.read_runtime_inputs(path,runfiles)
    proof.need(0<len(selected)<=32 and owner.raw(path)==raw)
    owner.fence()
    return selected,raw


def publish_owned(owner,output,bodies,*,prepared=None):
    """Join each readonly held leaf to its still-live exclusive creator FD."""
    proof.need(type(bodies) is dict and set(bodies) == {
        "codex-original","runtime.tar.gz","runtime-manifest.json",
        "runtime-receipt.json","cli-stdout.log","cli-stderr.log"})
    with proof.Held(owner.deadline,owner.until_ns) as creators:
        parent = creators.open(output,os.O_RDONLY|os.O_DIRECTORY)
        initial = proof.identity(os.fstat(parent))
        proof.need(initial == proof.identity(os.stat(output,follow_symlinks=False))
                   and initial[3] == os.getuid() and initial[2]&0o7777 == 0o700)
        if prepared is not None:
            fd,anchor=prepared
            proof.need(proof.identity(os.fstat(fd)) == initial and initial[:6] == anchor[:6])
        leaves = {}
        for name,body in bodies.items():
            proof.need(type(body) is bytes and len(body)<=proof.MAX_FILE)
            fd = creators.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,parent=parent)
            pending = memoryview(body)
            while pending:
                creators.tick(); count = os.write(fd,pending); proof.need(count>0); pending = pending[count:]
            os.fchmod(fd,0o444); os.fsync(fd)
            leaves[name] = (fd,proof.identity(os.fstat(fd)))
        # Only the creator's fixed root mode transition is permitted. No leaf
        # identity is recaptured after a creator or directory close.
        before = proof.identity(os.fstat(parent))
        proof.need(before == proof.identity(os.stat(output,follow_symlinks=False))
                   and before[:6] == initial[:6])
        os.fchmod(parent,0o555); os.fsync(parent)
        root = proof.identity(os.fstat(parent))
        if prepared is not None: proof.need(proof.identity(os.fstat(prepared[0])) == root)
        for name,body in bodies.items():
            owner.add(output/name,proof.MAX_FILE,expected=proof.sha(body),size=len(body))
            fd,anchor = leaves[name]
            proof.need(proof.identity(os.fstat(fd)) == anchor == owner.files[output/name]["identity"])
        proof.need(owner.parents[output][1] == root
                   and proof.identity(os.stat(output,follow_symlinks=False)) == root)
        owner.full()
    # All creator closes have completed. Held/named originals span them.
    owner.full()


class Compiler(models.AfterModelsOwner):
    """Prepared callback owner: model dispatcher enrolls close before prepare."""
    def __init__(self,args):
        self.args = args
        self.output = self.owner = self.streams = None
        self.retired_owner = None
        self.root_slot=proof.Slot(); self.root_anchor=None
        self.ready = self.prepared = False

    def prepare(self,entry,until,cutoff):
        proof.need(not self.prepared and type(entry) is int and type(until) is int
                   and until-entry == 1200*10**9 and cutoff == (entry+600*10**9)/10**9)
        self.entry,self.until,self.cutoff = entry,until,cutoff
        self.output = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)/OUTPUT
        # The sibling must exist before SOURCE/model publication captures ancestors.
        self.output.mkdir(mode=0o700)
        self.root_slot.fd=os.open(self.output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        self.root_anchor=proof.identity(os.fstat(self.root_slot.fd))
        proof.need(self.root_anchor == proof.identity(os.stat(self.output,follow_symlinks=False))
            and self.root_anchor[3] == os.getuid() and self.root_anchor[2]&0o7777 == 0o700)
        self.prepared = True

    def __call__(self,extra,published,sdk,report,retained,inputs,entry,until,cutoff,models_pin):
        proof.need(self.prepared and not self.ready and (entry,until,cutoff) == (self.entry,self.until,self.cutoff)
                   and type(sdk) is tree.HeldRetainedSdkTree)
        # Capture the actual model publication already retained by ExtraOwners;
        # no caller-constructed summary can authorize this branch.
        model_path = Path(models_pin["path"])
        raw_model = extra.evidence.raws[str(model_path)]
        proof.need(source.sha(raw_model) == models_pin["sha256"] and len(raw_model) == models_pin["bytes"])
        model_result = family.decode(raw_model)
        expected = models.history_expected_tests()
        proof.validate_models(model_result,expected)
        proof.need(model_result["source"]["receipt_sha256"] == source.sha(published.raw)
                   and model_result["source"]["inventory_sha256"] == report["inventory_sha256"]
                   and model_result["transported_sdk"] == sdk.record())
        work = Path(os.environ["TEST_TMPDIR"]).resolve(strict=True)/"owned-history-cli-work"
        plan,tools = build_plan(published,sdk,report,work,cutoff)
        self.streams = shared.ChildStreams(work/"cli-streams")
        inputs.check_all(); retained.full(); extra.full(); sdk.fence(); published.fence()
        shared.run_once(plan,self.streams,cutoff)
        binary = fixed_binary(work/"output-base")
        # Binary/transform tools are fixed owned compiler or declared Nix roles.
        # Opened fd ownership exists before enrollment, through the shared slot owner.
        self.owner = proof.Held(cutoff,entry+600*10**9)
        original = self.owner.add(binary,proof.MAX_FILE,modes=(0o555,0o755))
        for name in ("strip","patchelf","ca_bundle"):
            value = Path(getattr(self.args,name))
            self.owner.add(value,32*1024*1024,modes=(0o444,0o555),owner=0)
        runtime_files,manifest_raw = held_runtime_inputs(self.owner,self.args.runtime_files_manifest,Path(os.environ["TEST_SRCDIR"]))
        for path in runtime_files: self.owner.add(path,32*1024*1024,modes=(0o444,0o555),owner=0)
        tool_pins = {name:proof.sha(self.owner.raw(Path(getattr(self.args,name)))) for name in ("strip","patchelf","ca_bundle")}
        tool_pins["runtime_files_manifest"] = proof.sha(manifest_raw)
        private = work/"package-transform"
        copied = private/"codex"
        try:
            with copied.open("xb") as stream:
                stream.write(original); stream.flush(); os.fchmod(stream.fileno(),0o700); os.fsync(stream.fileno())
            timeout = min(180,cutoff-time.monotonic()-90)
            proof.need(timeout>0)
            subprocess.run([str(self.args.strip),"--strip-all",str(copied)],stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=timeout,
                env={"LC_ALL":"C","PATH":family.query.LOCKED_PATH})
            stripped = portable._read(copied,max_bytes=proof.MAX_FILE); source.tick()
            raw_files,witness = portable.assemble_linux(copied,copied,runtime_files,self.args.patchelf,
                "x86_64-linux",self.args.ca_bundle,backend_max_bytes=proof.MAX_FILE,action_deadline=cutoff-90)
            files = {}
            for name,body in raw_files.items():
                if name.startswith("lib/omux/lib/") or name == "lib/omux/share/ca-bundle.crt":
                    files["lib/codex/"+name.removeprefix("lib/omux/")] = body
            files[proof.BACKEND] = raw_files["lib/omux/libexec/omux.bin"]
            loader = "lib/codex/"+witness["loader"].removeprefix("lib/omux/")
            files["bin/codex"] = runtime.codex_launcher(Path(loader).name)
            runtime_info = {"loader":loader,"dependencies":sorted("lib/codex/"+name.removeprefix("lib/omux/") for name in witness["dependencies"]),
                "backendInterpreter":witness["backendInterpreter"],"caBundle":proof.CA,"backend_max_bytes":proof.MAX_FILE}
        finally:
            if copied.exists(): copied.unlink()
        source.tick(); self.owner.full(); sdk.check(); inputs.check_all(); retained.full(); extra.full()
        stdout,stderr = (self.streams.bytes(name) for name in ("stdout","stderr"))
        build = {"target":proof.CLI,"exit":0,"configuration":"opt","argv":plan["argv"],"argv_sha256":proof.sha(proof.encoded(plan["argv"])),
            "environment":plan["environment"],"source_inventory_sha256":report["inventory_sha256"],
            "binary_sha256":proof.sha(original),"binary_bytes":len(original),
            "stdout_sha256":proof.sha(stdout),"stderr_sha256":proof.sha(stderr)}
        executable = {phase+"_sha256":proof.sha(raw) for phase,raw in (("original",original),("stripped",stripped),("packaged",files[proof.BACKEND]))}
        executable.update({phase+"_bytes":len(raw) for phase,raw in (("original",original),("stripped",stripped),("packaged",files[proof.BACKEND]))})
        manifest = {"schema_version":1,"kind":proof.KIND,"status":proof.STATUS,"target":"x86_64-linux",
            "files":{name:{"sha256":proof.sha(raw),"bytes":len(raw),"mode":0o644 if name==proof.CA else 0o755} for name,raw in sorted(files.items())},
            "runtime":runtime_info,"executable":executable,"source":model_result["source"],
            "models_sha256":proof.sha(proof.encoded(model_result)),"sdk_sha256":proof.sha(proof.encoded(sdk.record()))}
        manifest_bytes = runtime.json_bytes(manifest)
        payload = runtime.archive_bytes(files,manifest)
        receipt = {"schema_version":1,"kind":proof.KIND,"status":proof.STATUS,
            "archive_sha256":proof.sha(payload),"archive_bytes":len(payload),"manifest_sha256":proof.sha(manifest_bytes),
            "build":build,"models":model_result,"source":model_result["source"],"sdk":sdk.record(),"tools":tool_pins,
            "native_support":False,"provider_qualified":False,"ordinary_qualified":False,"live_handoff_qualified":False}
        receipt_raw = proof.encoded(receipt)
        proof.verify_package(payload,receipt_raw,expected_tests=expected,portable=portable,runtime=runtime)
        bodies = {"codex-original":original,"runtime.tar.gz":payload,"runtime-manifest.json":manifest_bytes,
            "runtime-receipt.json":receipt_raw,"cli-stdout.log":stdout,"cli-stderr.log":stderr}
        publish_owned(self.owner,self.output,bodies,prepared=(self.root_slot.fd,self.root_anchor))
        self.ready = True; self.full()

    def full(self):
        proof.need(self.prepared and time.monotonic_ns()<self.entry+600*10**9 and time.monotonic_ns()<self.until)
        # During the preceding genuine model child the prepared callback owns
        # no image yet. It never turns a pending image into a success result.
        if self.owner is not None: self.owner.full()
        if self.streams is not None: self.streams.fence()
        if self.ready:
            fd = self.owner.directory(self.output)
            names = []
            with os.scandir(fd) as rows:
                for row in rows:
                    self.owner.tick(); proof.need(len(names)<7); names.append(row.name)
            proof.need(set(names) == {"codex-original","runtime.tar.gz","runtime-manifest.json","runtime-receipt.json","cli-stdout.log","cli-stderr.log"})
        self.short()

    def short(self):
        proof.need(self.prepared and time.monotonic_ns()<self.entry+600*10**9 and time.monotonic_ns()<self.until)
        if not self.ready:
            proof.need(proof.identity(os.fstat(self.root_slot.fd)) == self.root_anchor
                == proof.identity(os.stat(self.output,follow_symlinks=False)))
        if self.owner is not None: self.owner.fence()
        if self.streams is not None: self.streams.fence()
        if not self.ready: return
        # Exact final owned directory/leaf full-nine anchors detect namespace
        # drift without any new bulk bytes/listing after SDK normal close.

    def close(self):
        if self.owner is None and self.streams is None and self.root_slot.fd is None: return
        first = None
        for owner in (self.streams,self.owner,self.root_slot):
            if owner is not None:
                try: owner.close()
                except BaseException as error:
                    if first is None: first = error
        self.retired_owner = self.owner
        self.streams = self.owner = None
        if first is not None: raise first

    def terminal(self):
        proof.need(self.ready and self.retired_owner is not None)
        self.retired_owner.named_fence()
        proof.need(time.monotonic_ns()<self.entry+600*10**9 and time.monotonic_ns()<self.until)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ("strip","patchelf","ca-bundle","runtime-files-manifest"):
        parser.add_argument("--"+name,type=Path,required=True)
    args = parser.parse_args()
    sys.argv[1:] = []
    compiler = Compiler(args)
    # The tree-model successor owns this callback admission/terminal capability;
    # no fallback to the current old source/model route is permitted.
    models.main(_after_models=compiler)
    compiler.terminal()
    print("native-owned-history-cli: actual models and CLI/package completed; installed proof unrun",flush=True)
    compiler.terminal()


if __name__ == "__main__":
    try: main()
    except shared.REFUSAL_ERRORS:
        print("owned history CLI/package refused",file=sys.stderr)
        raise SystemExit(1) from None
