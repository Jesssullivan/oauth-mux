"""Current history13 package proof owner across ordinary setup, launch and resume."""
import hashlib
from decimal import Decimal
import os
from pathlib import Path
import re
import select
import stat
import time
import xml.etree.ElementTree as ET
import owned_history_runtime as proof

PROFILE = "native-owned-history-cli-reserved"
TARGETS = ["//tools:codex_native_owned_history_cli_test","//tools:codex_native_owned_history_cli_producer"]
OUTPUT_NAMES = {"codex-original","runtime.tar.gz","runtime-manifest.json","runtime-receipt.json","cli-stdout.log","cli-stderr.log"}
PUBLIC_ROOTS = ("/home/jess/.local/state/omux-execution-20261005",
                "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005")


def xml_success(raw):
    proof.need(type(raw) is bytes and 0 < len(raw) <= proof.MAX_METADATA)
    root = ET.fromstring(raw)
    suites = list(root.iter("testsuite"))
    proof.need(bool(suites) and bool(list(root.iter("testcase"))))
    for suite in suites:
        count = suite.attrib.get("tests")
        proof.need(type(count) is str and re.fullmatch(r"[1-9][0-9]{0,6}",count) is not None)
    for suite in [root,*suites]:
        for name in ("failures","errors","skipped","disabled"):
            if name in suite.attrib: proof.need(suite.attrib[name] == "0")
    proof.need(not any(node.tag in ("failure","error","skipped") for node in root.iter()))


def selected(raw):
    value = proof.decode(raw)
    proof.need(set(value) == {"schema_version","kind","status","package"}
        and value["schema_version"] == 1 and value["kind"] == proof.SELECTION_KIND
        and value["status"] == "qualified-history13-cli-package" and type(value["package"]) is dict)
    row = value["package"]
    proof.need(set(row) == {"root","files","producer"} and set(row["files"]) == OUTPUT_NAMES)
    producer = row["producer"]
    proof.need(set(producer) == {"receipt","sha256","source_commit","graph_sha256"})
    for name in ("sha256","graph_sha256"): proof.pin(producer[name])
    proof.need(re.fullmatch(r"[0-9a-f]{40}",producer["source_commit"]) is not None)
    outer = Path(producer["receipt"])
    proof.need(outer.is_absolute() and str(outer) == os.path.normpath(str(outer))
        and outer.name == "receipt.json" and str(outer.parent.parent) in PUBLIC_ROOTS
        and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",outer.parent.name) is not None)
    prefix = str(outer.parent/"output-base/execroot/_main/bazel-out")+"/"
    suffix = "/testlogs/tools/codex_native_owned_history_cli_producer/test.outputs/native-owned-history-cli"
    proof.need(type(row["root"]) is str and row["root"].startswith(prefix) and row["root"].endswith(suffix)
        and re.fullmatch(r"[A-Za-z0-9_.-]+",row["root"][len(prefix):-len(suffix)]) is not None)
    for name,pin in row["files"].items():
        proof.need(set(pin) == {"sha256","bytes"} and type(pin["bytes"]) is int
            and 0 <= pin["bytes"] <= (proof.MAX_FILE if name == "codex-original" else proof.MAX_ARCHIVE if name.endswith(".tar.gz") else proof.MAX_METADATA))
        proof.pin(pin["sha256"])
    return row


def guardian_state(outer,outer_path):
    """Historical success metadata remains exact; current bytes are owned below."""
    import guard_native_owned_history_cli_reserved as guard
    run=Path(outer_path).parent; unit="omux-execution-"+run.name+".service"
    proof.need(outer["id"] == outer["artifact_epoch"] == run.name and outer["unit"] == unit
        and outer["output_base"] == str(run/"output-base"))
    observed=outer["observed_properties"]
    proof.need(all(observed.get(key)==value for key,value in {
        "MemoryMax":str(guard.MEMORY),"MemorySwapMax":"0","TasksMax":str(guard.TASKS),
        "PrivateNetwork":"yes","KillMode":"control-group","SendSIGKILL":"yes", "OOMPolicy":"kill",
        "RemainAfterExit":"yes"}.items()))
    token=observed.get("CPUQuotaPerSecUSec")
    match=re.fullmatch(r"([0-9]{1,7}(?:[.][0-9]{1,6})?)(us|ms|s)",token) if type(token) is str else None
    proof.need(match is not None and Decimal(match[1])*{"us":1,"ms":1000,"s":1000000}[match[2]] == guard.CPU*10000)
    proof.need(type(observed.get("MainPID")) is str and re.fullmatch(r"[1-9][0-9]{0,9}",observed["MainPID"]) is not None
        and type(observed.get("ControlGroup")) is str and observed["ControlGroup"].startswith("/")
        and observed["ControlGroup"].endswith("/"+unit) and os.path.normpath(observed["ControlGroup"]) == observed["ControlGroup"])
    startup=outer["startup_history"]
    proof.need(type(startup) is list and 0<len(startup)<=128 and type(startup[-1]) is dict
        and startup[-1]["ActiveState"] == "active" and startup[-1]["SubState"] == "running"
        and startup[-1]["MainPID"] == startup[-1]["ExecMainPID"] == observed["MainPID"]
        and startup[-1]["ControlGroup"] == observed["ControlGroup"])
    original=outer["original_cgroup_identity"]
    proof.need(type(original) is dict and set(original)=={"device","inode"}
        and all(type(original[key]) is int and original[key]>0 for key in original))
    resident=outer["native_owned_history_cli_reservation"]["resident"]
    proof.need(type(resident) is dict and set(resident)=={"scope","observations","kernel_bounds",
        "initial_direct_process_count","initial_direct_processes_retained","outer_pid_namespace_matched",
        "hierarchical_caps","descendant_process_inventory","installation_qualified","health_observed",
        "custody_observed","resident_signalled","whole_host_reservation"}
        and resident["scope"] == "sampled-fixed-default-cgroup-kernel-reservation-v1"
        and type(resident["observations"]) is int and 1<=resident["observations"]<=65535
        and type(resident["initial_direct_process_count"]) is int and 1<=resident["initial_direct_process_count"]<=32
        and all(resident[key] is True for key in ("initial_direct_processes_retained","outer_pid_namespace_matched","hierarchical_caps"))
        and all(resident[key] is False for key in ("descendant_process_inventory","installation_qualified","health_observed",
            "custody_observed","resident_signalled","whole_host_reservation")))
    guard.kernel.kernel_bounds(resident["kernel_bounds"])
    proof.need(resident["initial_direct_process_count"]<=int(resident["kernel_bounds"]["pids.max"]))
    cleanup=outer["cleanup"]
    proof.need(type(cleanup) is dict and set(cleanup)=={"state","stop","ownership","readback_attempts","pre_stop","post_stop"}
        and cleanup["state"] == "empty" and cleanup["stop"] == "succeeded" and cleanup["ownership"] == "verified"
        and type(cleanup["readback_attempts"]) is int and 2<=cleanup["readback_attempts"]<=8)
    pre,post=cleanup["pre_stop"],cleanup["post_stop"]
    common={"schema_version","scope","LoadState","ActiveState","SubState","MainPID",
            "Id_matches","InvocationID_matches","ExecMainPID_matches"}
    proof.need(type(pre) is dict and set(pre)==common|{"ExecMainCode","ExecMainStatus","Result","RemainAfterExit","terminal_class"}
        and pre["schema_version"] == 1 and pre["scope"] == "reserved-owned-pre-stop-diagnostic-v1"
        and pre["LoadState"] == "loaded" and (pre["ActiveState"],pre["SubState"]) in (("active","exited"),("inactive","dead"))
        and pre["MainPID"] == "zero" and all(pre[name] is True for name in ("Id_matches","InvocationID_matches","ExecMainPID_matches"))
        and pre["ExecMainCode"] == "1" and type(pre["ExecMainStatus"]) is int and pre["ExecMainStatus"] == 0
        and pre["Result"] == "success" and pre["RemainAfterExit"] == "yes" and pre["terminal_class"] == "unqualified")
    proof.need(type(post) is dict and set(post)==common|{"original_cgroup_state","predicate"}
        and post["schema_version"] == 1 and post["scope"] == "reserved-owned-post-stop-diagnostic-v1"
        and post["LoadState"] in ("loaded","not-found") and post["ActiveState"] == "inactive" and post["SubState"] == "dead"
        and post["MainPID"] == "zero" and post["Id_matches"] is True
        and all(type(post[key]) is bool for key in ("InvocationID_matches","ExecMainPID_matches"))
        and (post["LoadState"] == "not-found" or post["InvocationID_matches"] is post["ExecMainPID_matches"] is True)
        and post["original_cgroup_state"] in ("empty","absent") and post["predicate"] == "manager-predicate-passed")


def package_context(receipt,outer,outer_path):
    """Bind current package/model/SDK facts to independently read CLI guardian."""
    import guard_native_owned_history_cli_reserved as guard
    reservation=outer["native_owned_history_cli_reservation"]
    entry,until=(reservation[name] for name in ("original_entry_monotonic_ns","original_deadline_monotonic_ns"))
    proof.need(type(entry) is int and type(until) is int and until-entry==1200*10**9)
    context={"mode":guard.INPUT_MODE,"epoch":str(Path(outer_path).parent),
        "source_commit":outer["source_commit"],"graph_sha256":outer["graph_sha256"],
        "entry_monotonic_ns":entry,"deadline_monotonic_ns":until}
    model=receipt["models"]
    proof.need(model["producer_context"] == context
        and model["original_entry_monotonic_ns"] == entry
        and model["original_outer_deadline_monotonic_ns"] == until
        and model["original_proof_deadline_monotonic_ns"] == entry+600*10**9
        and receipt["sdk"] == model["transported_sdk"]
        and receipt["sdk"]["consumer_context"] == {
            "MODE":context["mode"],"EPOCH":context["epoch"],"SOURCE_COMMIT":context["source_commit"],
            "GRAPH_SHA256":context["graph_sha256"],"ENTRY_NS":str(entry),"DEADLINE_NS":str(until)})


def collector_roles(index,outer,root):
    import guard_test_evidence as collector
    parts=Path(root).parts
    proof.need(parts.count("bazel-out")==1)
    configuration=parts[parts.index("bazel-out")+1]
    proof.need(type(index) is dict and set(index)=={"schema","bazel_exit","epoch_start_ns","targets","bytes","copied_files","results","acceptance"}
        and type(index["schema"]) is int and index["schema"]==1 and type(index["bazel_exit"]) is int and index["bazel_exit"]==0
        and type(index["epoch_start_ns"]) is int and index["epoch_start_ns"]==outer["epoch_start_ns"]
        and index["targets"]==TARGETS and type(index["results"]) is list and len(index["results"])==len(TARGETS)
        and index["acceptance"]=="evidence copies preserve invocation status; no inferred PASS")
    roles=[]; total=copied=0
    for result,target in zip(index["results"],TARGETS):
        proof.need(type(result) is dict and set(result)=={"target","configuration","state","files"}
            and result["target"]==target and result["configuration"]==configuration and result["state"]=="observed"
            and type(result["files"]) is list and len(result["files"])==len(collector.FILES)
            and [row["source"] for row in result["files"]]==list(collector.FILES))
        for row in result["files"]:
            mandatory=row["source"] in ("test.log","test.xml")
            if row["state"]=="copied":
                filename=proof.sha((target+"\0"+configuration+"\0"+row["source"]).encode())+".evidence"
                proof.need(set(row)=={"source","state","file","sha256","bytes"} and row["file"]==filename
                    and type(row["bytes"]) is int and (0<row["bytes"]<=proof.MAX_METADATA if mandatory else 0<=row["bytes"]<=collector.MAX_BYTES))
                proof.pin(row["sha256"]); total+=row["bytes"]; copied+=1
                if mandatory: roles.append((target,row["source"],row))
            else:
                proof.need(not mandatory and set(row)=={"source","state","bytes"}
                    and row["state"] in ("missing","stale")
                    and type(row["bytes"]) is int and row["bytes"]==0)
    proof.need(type(index["bytes"]) is int and index["bytes"]==total<=collector.MAX_BYTES
        and type(index["copied_files"]) is int and index["copied_files"]==copied<=collector.MAX_FILES)
    return roles


class Reader:
    def __init__(self,selection,selection_sha,aliases,deadline,until_ns):
        self.owner = proof.Held(deadline,until_ns)
        self.installed = self.retired_installed = None; self.closed = False; self.manifest = None
        self.selection_path = Path(selection); self.selection_sha = proof.pin(selection_sha)
        self.alias_path = Path(aliases)
        try:
            proof.need(self.selection_path.name == "runtime-selection.json" and self.alias_path.name == "input-aliases.json")
            raw = self.owner.add(self.selection_path,16384,expected=selection_sha,size=Path(selection).stat().st_size,
                modes=(0o444,0o555,0o644))
            self.row = selected(raw)
            document = proof.decode(self.owner.add(self.alias_path,65536,modes=(0o444,0o555,0o644)))
            proof.need(set(document) == {"kind","inputs"} and document["kind"] == "omux-owned-history-runtime-inputs-v3"
                       and type(document["inputs"]) is list and len(document["inputs"]) <= 32)
            self.aliases = {}
            for row in document["inputs"]:
                proof.need(set(row) == {"path","alias"} and row["path"] not in self.aliases)
                proof.safe_name(row["alias"]); proof.need(row["alias"].startswith("input/"))
                self.aliases[row["path"]] = self.alias_path.parent/row["alias"]
            self.required = {str(self.selection_path),str(self.alias_path)}
        except BaseException as primary:
            try: self.owner.close()
            except BaseException as cleanup: proof.preserve_primary(primary,cleanup)
            raise

    def read(self,path,sha,maximum,size=None,*,provenance=False):
        path = Path(path); proof.need(str(path) in self.aliases)
        alias = self.aliases[str(path)]
        proof.need(alias.resolve(strict=True) == path)
        if alias not in self.owner.files:
            # 0600 is admitted only after exact independent producer/index derivation.
            self.owner.add(alias,maximum,expected=sha,size=size if size is not None else path.stat().st_size,
                modes=(0o444,0o555,0o600) if provenance else (0o444,0o555))
        raw = self.owner.raw(alias); proof.need(proof.sha(raw) == sha)
        self.required.add(str(path))
        return raw

    def guardian(self):
        producer = self.row["producer"]
        outer_path = Path(producer["receipt"])
        outer = proof.decode(self.read(outer_path,producer["sha256"],proof.MAX_METADATA,provenance=True))
        guardian_state(outer,outer_path)
        import guard_native_owned_history_cli_reserved as guard
        reservation = outer["native_owned_history_cli_reservation"]
        proof.need(reservation == guard.projection(reservation["original_entry_monotonic_ns"],
            reservation["original_deadline_monotonic_ns"],True,reservation["resident"])
            and outer["profile"] == PROFILE and outer["targets"] == TARGETS
            and outer["source_commit"] == producer["source_commit"] and outer["graph_sha256"] == producer["graph_sha256"]
            and outer["exit"] == outer["workload_exit"] == 0 and outer["controller_failure"] is None
            and outer["source_dirty"] == "false" and outer["verb"] == "test" and outer["manager"] == "system"
            and outer["cache_reuse_requested"] is False and outer["cache_policy"] is None and outer["cache_key"] is None
            and outer["descendants_empty"] is True and outer["cleanup"]["state"] == "empty"
            and outer["cleanup"]["ownership"] == "verified" and outer["cleanup"]["readback_attempts"] >= 2
            and outer["test_evidence"]["state"] == "preserved")
        guard.kernel.kernel_bounds(reservation["resident"]["kernel_bounds"])
        from yoga_delivery_settings import effective_runtime
        effective_runtime(outer["observed_properties"]["RuntimeMaxUSec"],840)
        index = proof.decode(self.read(outer_path.parent/"test-evidence.json",outer["test_evidence"]["sha256"],
            proof.MAX_METADATA,provenance=True))
        for target,name,row in collector_roles(index,outer,self.row["root"]):
            raw = self.read(outer_path.parent/"test-evidence"/row["file"],row["sha256"],proof.MAX_METADATA,row["bytes"],provenance=True)
            if name == "test.xml": xml_success(raw)
            elif target == TARGETS[1]:
                marker = b"native-owned-history-cli: actual models and CLI/package completed; installed proof unrun\n"
                proof.need(raw.count(marker) == 1)
        return outer

    def load(self):
        self.owner.tick(); outer=self.guardian()
        bodies = {name:self.read(Path(self.row["root"])/name,pin["sha256"],
            proof.MAX_FILE if name=="codex-original" else proof.MAX_ARCHIVE if name.endswith(".tar.gz") else proof.MAX_METADATA,
            pin["bytes"]) for name,pin in self.row["files"].items()}
        from pathlib import Path as ActualPath
        root = ActualPath(__file__).parent.parent/"integrations/codex-upstream"
        controls = {}
        for name,sha in proof.CONTROL_PINS.items():
            alias = root/name
            if alias not in self.owner.files:
                self.owner.add(alias,65536,expected=sha,size=alias.stat().st_size,modes=(0o444,0o555,0o644))
            controls[name] = self.owner.raw(alias)
        import portable
        import runtime_package as runtime
        expected = proof.required_tests(controls)
        manifest,files = proof.verify_package(bodies["runtime.tar.gz"],bodies["runtime-receipt.json"],
            expected_tests=expected,portable=portable,runtime=runtime)
        receipt = proof.decode(bodies["runtime-receipt.json"])
        package_context(receipt,outer,self.row["producer"]["receipt"])
        proof.need(runtime.json_bytes(manifest) == bodies["runtime-manifest.json"]
            and proof.sha(bodies["codex-original"]) == receipt["build"]["binary_sha256"]
            and len(bodies["codex-original"]) == receipt["build"]["binary_bytes"]
            and proof.sha(bodies["cli-stdout.log"]) == receipt["build"]["stdout_sha256"]
            and proof.sha(bodies["cli-stderr.log"]) == receipt["build"]["stderr_sha256"]
            and set(self.aliases) == self.required-{str(self.selection_path),str(self.alias_path)})
        self.owner.full(); self.owner.fence()
        if self.manifest is not None: proof.need(self.manifest == manifest)
        self.manifest = manifest
        return manifest,files

    def __call__(self,candidate,receipt):
        manifest,files = self.load()
        for alias,name in ((Path(candidate),"runtime.tar.gz"),(Path(receipt),"runtime-receipt.json")):
            proof.need(alias.resolve(strict=True) == Path(self.row["root"])/name)
            if alias not in self.owner.files:
                row = self.row["files"][name]
                self.owner.add(alias,proof.MAX_ARCHIVE if name.endswith(".tar.gz") else proof.MAX_METADATA,
                    expected=row["sha256"],size=row["bytes"])
        self.owner.fence()
        return manifest,files

    def verify_process(self,native,binary):
        proof.need(self.manifest is not None)
        self.load()
        root = Path(binary).parent.parent
        if self.installed is None:
            self.installed = proof.Held(self.owner.deadline,self.owner.until_ns)
            for name,row in self.manifest["files"].items():
                self.installed.add(root/name,proof.MAX_FILE if name==proof.BACKEND else 32*1024*1024,
                    expected=row["sha256"],size=row["bytes"],modes=(row["mode"],))
        self.installed.full(); self.owner.fence()
        native.alive()
        pid = native.process.pid
        # A pidfd pins the running peer rather than a caller path/previous PID.
        slot = proof.Slot()
        self.installed.slots.append(slot)  # enrollment precedes kernel acquisition
        slot.fd = os.pidfd_open(pid)
        actual_pidfd = slot.fd
        try:
            proof.need(not select.select([actual_pidfd],[],[],0)[0])
            # /proc/exe is an intentional kernel magic link, unlike input aliases.
            exe_slot = proof.Slot(); self.installed.slots.append(exe_slot)
            exe_slot.fd = os.open("/proc/"+str(pid)+"/exe",os.O_RDONLY|os.O_CLOEXEC)
            executable = exe_slot.fd
            loader = self.installed.files[root/self.manifest["runtime"]["loader"]]["identity"]
            proof.need(proof.identity(os.fstat(executable)) == loader)
            with open("/proc/"+str(pid)+"/maps","rb") as stream: raw = stream.read(256*1024+1)
            proof.need(len(raw)<=256*1024 and len(raw.splitlines())<=4096)
            executable_roles = (proof.BACKEND,*self.manifest["runtime"]["dependencies"])
            allowed = {(os.major(row["identity"][0]),os.minor(row["identity"][0]),row["identity"][1])
                       for row in (self.installed.files[root/name] for name in executable_roles)}
            seen = set()
            for line in raw.splitlines():
                self.owner.tick(); parts = line.split(None,5); proof.need(len(parts)>=5)
                if b"x" not in parts[1]: continue
                if len(parts)==6 and parts[5] in (b"[vdso]",b"[vsyscall]"): continue
                proof.need(len(parts)==6 and parts[5].startswith(b"/") and not parts[5].endswith(b" (deleted)"))
                device = parts[3].split(b":"); proof.need(len(device)==2)
                key = (int(device[0],16),int(device[1],16),int(parts[4])); proof.need(key in allowed); seen.add(key)
            backend = self.installed.files[root/proof.BACKEND]["identity"]
            proof.need((os.major(backend[0]),os.minor(backend[0]),backend[1]) in seen
                and (os.major(loader[0]),os.minor(loader[0]),loader[1]) in seen
                and not select.select([actual_pidfd],[],[],0)[0])
            native.alive(); self.installed.fence(); self.owner.fence()
        finally:
            # Process inspection slots remain owned until final reader cleanup.
            # All original package/installed descriptors span subsequent native IO.
            pass

    def finish(self):
        self.load()
        if self.installed is not None: self.installed.full()
        self.owner.fence()
        if self.installed is not None: self.installed.fence()

    def close(self):
        if self.closed: return
        first = None
        for owner in (self.installed,self.owner):
            if owner is not None:
                try: owner.close()
                except BaseException as error:
                    if first is None: first = error
        self.retired_installed = self.installed
        self.installed = None; self.closed = True
        if first is not None: raise first

    def terminal(self):
        proof.need(self.closed)
        self.owner.named_fence()
        if self.retired_installed is not None: self.retired_installed.named_fence()
