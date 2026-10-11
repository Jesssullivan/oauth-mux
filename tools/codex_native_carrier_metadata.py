"""Explicit v2 metadata consumer: sealed transport, fresh custody, original proofs.

This is a separate family. A hub readback does not qualify an SDK, compiler,
installed package, native integration, credential acquisition or live handoff.
"""
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from decimal import Decimal
import copy
import json
import os
from pathlib import Path
import re
import sys
import time
import xml.etree.ElementTree as ET

import codex_native_acquisition_metadata as legacy
import codex_native_acquisition_binding as binding
import codex_native_sdk_carrier as carrier
import codex_protocol_history_native as protocol
import codex_protocol_history_query_tools as query_tools
import codex_protocol_history_metadata as metadata
import codex_retained_sdk_export as sdk
import guard_native_seed_plan_reserved as kernel

source = legacy.source
require = legacy.require
KIND = "omux-native-sdk-carrier-metadata-input-v2"
OUTPUT_KIND = "omux-native-sdk-carrier-metadata-v2"
REPOSITORY = "omux_native_sdk_carrier_inputs"
PROOF_REPOSITORY = "omux_native_sdk_carrier_proof_inputs"
PROOF_KIND = "omux-native-sdk-carrier-proof-inputs-v1"
PROOF_ALIASES = {"outer_receipt": "proof/outer-receipt.json", "test_evidence": "proof/test-evidence.json",
    "test_log": "proof/test-log.evidence", "test_xml": "proof/test-xml.evidence",
    "program_report": "proof/program-report.json"}
CONFIG = "integrations/codex-upstream/native-sdk-carrier-metadata-inputs.json"
PROFILE = "native-sdk-carrier-metadata-reserved"
SEAL_PROFILE = "native-sdk-carrier-seal-reserved"
SEAL_TARGET = "//tools:codex_native_sdk_carrier_seal_producer"
PRODUCER_KIND = "omux-native-sdk-carrier-producer-v1"
FALSE_FLAGS = ("sdk_export_qualified", "sdk_execution_qualified", "metadata_qualified",
    "compiler_qualified", "native_compile_passed", "runtime_qualified",
    "installed_package_primary_qualified", "schema_producer_qualified",
    "native_support", "provider_evaluation", "credential_acquisition_qualified",
    "live_handoff_proven", "source_witnesses_replaced", "legacy_metadata_family_qualified")
OUTPUT_FIELDS = {"schema_version", "kind", "status", "original_selection", "selector_sha256",
    "source_inventory_sha256", "source_graph", "patch_sha256", "carrier", "extraction",
    "extraction_receipt_sha256", "consumer_context", "consumer_deadline", "query_exit", "query_plan",
    "output_parent_mode", "query_tool_closure_independently_rechecked",
    "packaged_jdk_used_as_query_tool_relocation", "module_and_cargo_lock_unchanged", "retained_hub",
    "generated_hub", "source_and_extracted_carrier_rechecked", *FALSE_FLAGS}
_SCOPE = ContextVar("omux-native-carrier-metadata-scope", default=None)


def tick(deadline):
    require(type(deadline) is float and time.monotonic() < deadline)


def selection(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 16384)
    value = json.loads(raw, object_pairs_hook=source.unique)
    require(type(value) is dict and set(value) == {"schema_version", "kind", "status", "selection"}
        and type(value["schema_version"]) is int and value["schema_version"] == 2
        and value["kind"] == KIND and value["status"] == "selected-qualified-carrier-for-metadata")
    selected = value["selection"]
    require(type(selected) is dict and set(selected) == {"original_selection", "carrier", "qualification"}
        and selected["original_selection"] == binding.selected_document())
    require(type(selected["carrier"]) is dict and set(selected["carrier"]) == {"receipt_sha256"})
    protocol.pin(selected["carrier"]["receipt_sha256"])
    qualified = selected["qualification"]
    require(type(qualified) is dict and set(qualified) == {"producer", "report"})
    protocol.producer_pin(qualified["producer"])
    require(type(qualified["report"]) is dict and set(qualified["report"]) == {"path", "sha256"})
    protocol.path(qualified["report"]["path"])
    protocol.pin(qualified["report"]["sha256"])
    return copy.deepcopy(selected)


def envelope(environment):
    require(environment.get("OMUX_SDK_CARRIER_MODE") == PROFILE)
    raw = [environment.get("OMUX_SDK_CARRIER_" + name + "_NS") for name in ("ENTRY", "DEADLINE")]
    require(all(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,18}", value) for value in raw))
    entry, until = map(int, raw)
    require(until - entry == 1200 * 10**9)
    kernel.remaining(entry, until)
    epoch = protocol.path(environment.get("OMUX_SDK_CARRIER_EPOCH"))
    require(protocol.UUID.fullmatch(epoch.name) is not None
        and protocol.PRODUCER_SCOPE.fullmatch(str(epoch / "receipt.json")) is not None)
    commit, graph = (environment.get("OMUX_SDK_CARRIER_" + name) for name in ("SOURCE_COMMIT", "GRAPH_SHA256"))
    require(type(commit) is str and re.fullmatch(r"[0-9a-f]{40}", commit) is not None)
    protocol.pin(graph)
    return entry, until, {"mode": PROFILE, "epoch": str(epoch), "source_commit": commit,
        "graph_sha256": graph, "entry_monotonic_ns": entry, "deadline_monotonic_ns": until}


@contextmanager
def proof_scope(deadline):
    """Original proof APIs retain their clock; restore every touched value exactly."""
    tick(deadline)
    require(_SCOPE.get() is None)
    token = _SCOPE.set(deadline)
    saved = (source.DEADLINE, legacy.DEADLINE, legacy.INPUT_CONTROL, legacy.BINDING_SHA,
        legacy.QUERY_REPOSITORY)
    try:
        source.DEADLINE = legacy.DEADLINE = deadline
        legacy.configure_selection()
        yield
    finally:
        (source.DEADLINE, legacy.DEADLINE, legacy.INPUT_CONTROL, legacy.BINDING_SHA,
            legacy.QUERY_REPOSITORY) = saved
        _SCOPE.reset(token)


def declared_carrier(runfiles, rows, selected_input, deadline):
    tick(deadline)
    selected = [row[2] for row in rows if len(row) == 3 and row[0] in ("", "_main")
        and row[1] == REPOSITORY]
    require(len(selected) == 1 and re.fullmatch(r"[A-Za-z0-9_+.-]{1,256}", selected[0]) is not None
        and (selected[0] == REPOSITORY or selected[0].endswith("+" + REPOSITORY)))
    aliases = [runfiles / selected[0] / "carrier" / name for name in carrier.FILES]
    physical = [alias.resolve(strict=True) for alias in aliases]
    root = physical[0].parent
    expected = protocol.path(selected_input["qualification"]["report"]["path"]).parent / "sdk-carrier"
    require(root == expected and root.name == "sdk-carrier" and root.parent.name == "sdk-private"
        and all(path.parent == root and path.name == alias.name for alias, path in zip(aliases, physical)))
    alias = runfiles / selected[0] / "selection.json"
    physical_selection = alias.resolve(strict=True)
    require(physical_selection.name == "selection.json" and physical_selection.parent.name == selected[0]
        and physical_selection.parent.parent.name == "external")
    fd = source.directory(physical_selection.parent)
    try:
        raw, _ = source.read(fd, physical_selection.name, 8192)
    finally:
        os.close(fd)
    declaration = json.loads(raw, object_pairs_hook=source.unique)
    require(type(declaration) is dict and set(declaration) == {"carrier_root", "digests"}
        and declaration["carrier_root"] == str(root) and type(declaration["digests"]) is dict
        and set(declaration["digests"]) == set(carrier.FILES))
    for digest in declaration["digests"].values():
        protocol.pin(digest)
    require(declaration["digests"]["receipt.json"] == selected_input["carrier"]["receipt_sha256"])
    aliases.append(alias)
    physical.append(physical_selection)
    return root, tuple(zip(aliases, physical)), {"selection": declaration,
        "selection_path": str(physical_selection), "selection_sha256": source.sha(raw)}


def recheck_aliases(aliases, deadline):
    tick(deadline)
    require(all(alias.resolve(strict=True) == physical for alias, physical in aliases))


class ProofInputs:
    """Declare five exact proof roles before any original authentication IO."""
    def __init__(self, document, path, raw, aliases):
        self.document = copy.deepcopy(document)
        self.path = path
        self.sha256 = source.sha(raw)
        self.aliases = tuple(aliases)

    def recheck(self, deadline):
        tick(deadline)
        recheck_aliases(self.aliases, deadline)
        fd = source.directory(self.path.parent)
        try:
            raw, _ = source.read(fd, self.path.name, 65536)
        finally:
            os.close(fd)
        require(source.sha(raw) == self.sha256
            and json.loads(raw, object_pairs_hook=source.unique) == self.document)
        recheck_aliases(self.aliases, deadline)
        tick(deadline)

    def join(self, role, path, pin, deadline):
        self.recheck(deadline)
        require(role in PROOF_ALIASES and self.document["proofs"][role]["path"] == str(path)
            and self.document["proofs"][role]["sha256"] == pin)

    def record(self):
        return {"repository": PROOF_REPOSITORY, "mapping_sha256": self.sha256,
            "inputs": copy.deepcopy(self.document["proofs"])}


def declared_proofs(runfiles, rows, selected_input, deadline):
    tick(deadline)
    selected = [row[2] for row in rows if len(row) == 3 and row[0] in ("", "_main")
        and row[1] == PROOF_REPOSITORY]
    require(len(selected) == 1 and re.fullmatch(r"[A-Za-z0-9_+.-]{1,256}", selected[0]) is not None
        and (selected[0] == PROOF_REPOSITORY or selected[0].endswith("+" + PROOF_REPOSITORY)))
    alias = runfiles / selected[0] / "proof-inputs.json"
    physical = alias.resolve(strict=True)
    require(physical.name == "proof-inputs.json" and physical.parent.name == selected[0]
        and physical.parent.parent.name == "external")
    fd = source.directory(physical.parent)
    try:
        raw, _ = source.read(fd, physical.name, 65536)
    finally:
        os.close(fd)
    document = json.loads(raw, object_pairs_hook=source.unique)
    require(type(document) is dict and set(document) == {"kind", "proofs"}
        and document["kind"] == PROOF_KIND and type(document["proofs"]) is dict
        and set(document["proofs"]) == set(PROOF_ALIASES))
    aliases = [(alias, physical)]
    for role, expected_alias in PROOF_ALIASES.items():
        row = document["proofs"][role]
        require(type(row) is dict and set(row) == {"path", "sha256", "alias"} and row["alias"] == expected_alias)
        path = protocol.path(row["path"])
        protocol.pin(row["sha256"])
        data_alias = runfiles / selected[0] / expected_alias
        require(data_alias.resolve(strict=True) == path)
        aliases.append((data_alias, path))
    rows = document["proofs"]
    require(len({row["path"] for row in rows.values()}) == len(PROOF_ALIASES))
    producer, report = (selected_input["qualification"][name] for name in ("producer", "report"))
    require(rows["outer_receipt"]["path"] == producer["receipt"] and rows["outer_receipt"]["sha256"] == producer["sha256"]
        and rows["program_report"]["path"] == report["path"] and rows["program_report"]["sha256"] == report["sha256"])
    parent = protocol.path(producer["receipt"]).parent
    require(rows["test_evidence"]["path"] == str(parent / "test-evidence.json")
        and all(protocol.path(rows[role]["path"]).parent == parent / "test-evidence"
            and re.fullmatch(r"[0-9a-f]{64}\.evidence", protocol.path(rows[role]["path"]).name) is not None
            for role in ("test_log", "test_xml")))
    result = ProofInputs(document, physical, raw, aliases)
    result.recheck(deadline)
    return result


def _read_declaration(declaration, deadline):
    tick(deadline)
    path = protocol.path(declaration["selection_path"])
    fd = source.directory(path.parent)
    try:
        raw, _ = source.read(fd, path.name, 8192)
    finally:
        os.close(fd)
    require(source.sha(raw) == declaration["selection_sha256"]
        and json.loads(raw, object_pairs_hook=source.unique) == declaration["selection"])


def _recheck_initial_declaration(declaration, qualified, carrier_root, pin, candidate, deadline):
    """Join only the extractor's current held full binding inside on_bound.

    No persisted proof is accepted here. The extractor authenticates every
    byte and both NARs before this callback, then rechecks its held root and
    named leaves immediately after it. Later declaration checks stay full.
    """
    _read_declaration(declaration, deadline)
    raw = carrier.encoded(candidate)
    require(carrier.sha(raw) == pin and declaration["selection"]["carrier_root"] == str(carrier_root))
    digests = {"manifest.json": candidate["manifest_sha256"],
        "origin-receipt.json": candidate["origin"]["receipt_sha256"],
        "payload.bin": candidate["payload_sha256"], "receipt.json": pin}
    sizes = {"manifest.json": candidate["manifest_bytes"],
        "origin-receipt.json": candidate["origin"]["receipt_bytes"],
        "payload.bin": candidate["payload_bytes"], "receipt.json": len(raw)}
    files = [{"name": name, "sha256": digests[name], "size": sizes[name]} for name in carrier.FILES]
    require(qualified["report"]["carrier_receipt_sha256"] == pin
        and files == qualified["report"]["files"] and digests == declaration["selection"]["digests"])
    tick(deadline)


def recheck_declaration(declaration, qualified, carrier_root, pin, deadline, *, _held_carrier=None):
    _read_declaration(declaration, deadline)
    actual = carrier.publication_report(carrier_root, pin, deadline) if _held_carrier is None else (
        carrier.publication_report(carrier_root, pin, deadline, _held_carrier=_held_carrier))
    require(actual["carrier_receipt_sha256"] == pin
        and actual["files"] == qualified["report"]["files"]
        and {row["name"]: row["sha256"] for row in actual["files"]} == declaration["selection"]["digests"])
    tick(deadline)


def producer_policy(receipt):
    # Root owns the new reserved guard. Import only when a selected genuine
    # producer is actually authenticated; model parsing does not execute it.
    import guard_native_acquisition_inputs_reserved as admission
    value = receipt["native_acquisition_inputs_reservation"]
    require(receipt["profile"] == SEAL_PROFILE and list(admission.COHORTS[SEAL_PROFILE]) == [SEAL_TARGET])
    expected = admission.projection(SEAL_PROFILE, value["original_entry_monotonic_ns"],
        value["original_deadline_monotonic_ns"], True, value["resident"])
    require(value == expected and receipt["cache_reuse_requested"] is False
        and receipt["cache_policy"] is None and receipt["cache_key"] is None)
    observed = receipt["observed_properties"]
    protocol.native.phase2_effective_runtime(observed["RuntimeMaxUSec"], 1200)
    require(all(observed.get(name) == setting for name, setting in {
        "MemoryMax": "4026531840", "MemorySwapMax": "0", "TasksMax": "480", "PrivateNetwork": "yes",
        "KillMode": "control-group", "SendSIGKILL": "yes", "OOMPolicy": "kill", "RemainAfterExit": "yes"}.items()))
    token = observed.get("CPUQuotaPerSecUSec")
    match = re.fullmatch(r"([0-9]{1,7}(?:[.][0-9]{1,6})?)(us|ms|s)", token) if type(token) is str else None
    require(match is not None and Decimal(match[1]) * {"us": 1, "ms": 1000, "s": 1000000}[match[2]] == 1900000)
    resident = value["resident"]
    require(type(resident) is dict and set(resident) == {"scope", "kernel_bounds", "observations",
        "initial_direct_processes_retained", "initial_direct_process_count", "outer_pid_namespace_matched",
        "hierarchical_caps", "descendant_process_inventory", "installation_qualified", "health_observed",
        "custody_observed", "resident_signalled", "whole_host_reservation"}
        and resident["scope"] == "sampled-fixed-default-cgroup-kernel-reservation-v1"
        and type(resident["observations"]) is int and 0 < resident["observations"] <= 65535
        and type(resident["initial_direct_process_count"]) is int and 0 < resident["initial_direct_process_count"] <= 32
        and all(resident[name] is True for name in ("initial_direct_processes_retained", "outer_pid_namespace_matched", "hierarchical_caps"))
        and all(resident[name] is False for name in ("descendant_process_inventory", "installation_qualified", "health_observed",
            "custody_observed", "resident_signalled", "whole_host_reservation")))
    kernel.kernel_bounds(resident["kernel_bounds"])
    require(resident["initial_direct_process_count"] <= int(resident["kernel_bounds"]["pids.max"]))
    return value


def qualify_producer(selected, deadline, proof_inputs):
    """Program output alone cannot assert successful genuine guarded execution."""
    tick(deadline)
    value = selected["qualification"]["producer"]
    protocol.producer_pin(value)
    receipt_path = protocol.path(value["receipt"])
    require(type(proof_inputs) is ProofInputs)
    proof_inputs.join("outer_receipt", receipt_path, value["sha256"], deadline)
    receipt = protocol.read_json(receipt_path, value["sha256"], deadline)
    reserved = producer_policy(receipt)
    require(receipt["id"] == receipt_path.parent.name and receipt["unit"] == "omux-execution-" + receipt["id"] + ".service"
        and receipt["manager"] == "system" and type(receipt["exit"]) is int and receipt["exit"] == 0
        and type(receipt["workload_exit"]) is int and receipt["workload_exit"] == 0
        and receipt["controller_failure"] is None and receipt["descendants_empty"] is True
        and receipt["cleanup"]["state"] == "empty" and receipt["source_dirty"] == "false"
        and receipt["source_commit"] == value["source_commit"] and receipt["graph_sha256"] == value["graph_sha256"]
        and receipt["verb"] == "test" and receipt["targets"] == [SEAL_TARGET]
        and receipt["test_evidence"]["state"] == "preserved")
    evidence_path = receipt_path.parent / "test-evidence.json"
    proof_inputs.join("test_evidence", evidence_path, receipt["test_evidence"]["sha256"], deadline)
    evidence = protocol.read_json(evidence_path, receipt["test_evidence"]["sha256"], deadline)
    require(type(evidence["schema"]) is int and evidence["schema"] == 1
        and type(evidence["bazel_exit"]) is int and evidence["bazel_exit"] == 0
        and evidence["epoch_start_ns"] == receipt["epoch_start_ns"]
        and evidence["targets"] == [SEAL_TARGET] and len(evidence["results"]) == 1
        and evidence["results"][0]["target"] == SEAL_TARGET and evidence["results"][0]["state"] == "observed")
    for member in ("test.log", "test.xml"):
        entries = [entry for entry in evidence["results"][0]["files"] if entry["source"] == member]
        require(len(entries) == 1 and entries[0]["state"] == "copied")
        entry = entries[0]
        require(re.fullmatch(r"[0-9a-f]{64}\.evidence", entry["file"]) is not None)
        proof_inputs.join("test_log" if member == "test.log" else "test_xml",
            receipt_path.parent / "test-evidence" / entry["file"], entry["sha256"], deadline)
        fd = protocol.trusted_parent(receipt_path.parent / "test-evidence")
        try:
            digest, count, raw = protocol.hash_regular(fd, entry["file"], 64 * 1024 * 1024, True,
                on_read=lambda count: tick(deadline))
            require(digest == entry["sha256"] and type(entry["bytes"]) is int and count == entry["bytes"] and count > 0)
            if member == "test.xml":
                xml = ET.fromstring(raw)
                suites = [xml] if xml.tag == "testsuite" else list(xml.findall("testsuite"))
                require(xml.tag in ("testsuite", "testsuites") and suites and all(
                    int(suite.get("tests", "0")) > 0 and all(int(suite.get(name, "0")) == 0
                        for name in ("failures", "errors", "skipped")) for suite in suites))
        finally:
            os.close(fd)
    report = selected["qualification"]["report"]
    path = protocol.path(report["path"])
    prefix = str(protocol.path(receipt["output_base"])) + "/execroot/_main/bazel-out/"
    suffix = "/testlogs/tools/" + SEAL_TARGET.split(":")[1] + "/test.outputs/sdk-private/native-sdk-carrier-producer.json"
    require(str(path).startswith(prefix) and str(path).endswith(suffix)
        and re.fullmatch(r"[A-Za-z0-9_.-]+", str(path)[len(prefix):-len(suffix)]) is not None)
    proof_inputs.join("program_report", path, report["sha256"], deadline)
    proof = protocol.read_json(path, report["sha256"], deadline, 65536)
    expected = {"kind": PRODUCER_KIND, "producer": SEAL_TARGET,
        "carrier_receipt_sha256": selected["carrier"]["receipt_sha256"],
        "origin_receipt_sha256": legacy.EXPORT_SHA,
        "producer_context": {"mode": SEAL_PROFILE, "epoch": str(receipt_path.parent),
            "source_commit": value["source_commit"], "graph_sha256": value["graph_sha256"],
            "entry_monotonic_ns": reserved["original_entry_monotonic_ns"],
            "deadline_monotonic_ns": reserved["original_deadline_monotonic_ns"],
            "work_cutoff_monotonic_ns": reserved["original_deadline_monotonic_ns"] - 30 * 10**9},
        "files": proof.get("files"),
        "all_four_leaves_rechecked": True, "sdk_execution_qualified": False, "metadata_qualified": False,
        "compiler_qualified": False, "runtime_qualified": False}
    require(proof == expected and proof["all_four_leaves_rechecked"] is True
        and all(proof[name] is False for name in ("sdk_execution_qualified", "metadata_qualified",
            "compiler_qualified", "runtime_qualified"))
        and all(type(proof["producer_context"][name]) is int for name in
            ("entry_monotonic_ns", "deadline_monotonic_ns", "work_cutoff_monotonic_ns")))
    files = proof["files"]
    require(type(files) is list and len(files) == 4 and all(type(row) is dict and set(row) == {"name", "sha256", "size"}
        and row["name"] in carrier.FILES and type(row["size"]) is int and 0 <= row["size"] <= 16 * 1024**3 for row in files)
        and [row["name"] for row in files] == list(carrier.FILES))
    for row in files:
        protocol.pin(row["sha256"])
    require(next(row["sha256"] for row in files if row["name"] == "receipt.json") == selected["carrier"]["receipt_sha256"])
    proof_inputs.recheck(deadline)
    tick(deadline)
    return {"outer_receipt_sha256": value["sha256"], "report_sha256": report["sha256"],
        "proof_inputs": proof_inputs.record(), "report": proof}


def origin_join(report):
    require(report["origin"]["root"] == str(legacy.EXPORT_ROOT)
        and report["origin"]["receipt_sha256"] == legacy.EXPORT_SHA
        and report["origin"]["baseline_inventory_sha256"] == source.BASE_INVENTORY)


def query_plan(work, source_root, exported, sdk_root):
    """Same offline query, with explicit fresh SDK repository/registry roots."""
    require(type(exported["repositories"]) is dict and exported["registry_cache"] == str(sdk_root / "registry-cache"))
    overrides = metadata.retained_overrides(exported["repositories"], str(sdk_root))
    argv = [legacy.BAZEL, "--batch", "--output_user_root=" + str(work / "user-root"),
        "--output_base=" + str(work / "output-base"), "--host_jvm_args=-Xmx768m",
        "--host_jvm_args=-XX:ActiveProcessorCount=1", "--ignore_all_rc_files", "query",
        "--lockfile_mode=error", "--repository_disable_download",
        "--repository_cache=" + exported["registry_cache"], "--repo_contents_cache=",
        "--loading_phase_threads=2", "--repo_env=PATH=" + legacy.LOCKED_PATH,
        "--repo_env=CARGO_NET_OFFLINE=true"]
    argv += ["--override_repository=" + name + "=" + directory for name, directory in sorted(overrides.items())]
    argv += ["--output=build", "@crates//:all"]
    env = {"PATH": legacy.LOCKED_PATH, "USE_BAZEL_VERSION": "9.0.1", "CARGO_NET_OFFLINE": "true",
        "HOME": str(work / "home"), "CARGO_HOME": str(work / "home/cargo"),
        "XDG_CACHE_HOME": str(work / "home/cache"), "XDG_CONFIG_HOME": str(work / "home/config"),
        "XDG_STATE_HOME": str(work / "home/state"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    return {"argv": argv, "environment": env, "cwd": str(source_root)}


def write_receipt(root, report, deadline):
    """Keep the held private ancestor mode; seal only the new regular receipt."""
    tick(deadline)
    root.check()
    out = os.open("metadata-receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600, dir_fd=root.fd)
    try:
        carrier.write_all(out, source.encoded(report), root.clock)
        os.fchmod(out, 0o444)
        os.fsync(out)
    finally:
        os.close(out)
    os.fsync(root.fd)
    root.check()
    require(carrier.read(root, "metadata-receipt.json", source.MAX_METADATA) == source.encoded(report))


def produce(selected, selector_sha, carrier_root, aliases, declaration, proof_inputs, temporary, output, deadline, context):
    tick(deadline)
    require(selection(source.encoded({"schema_version": 2, "kind": KIND,
        "status": "selected-qualified-carrier-for-metadata", "selection": selected})) == selected)
    require(_SCOPE.get() == deadline and selected["original_selection"] == binding.selected_document()
        and not temporary.exists() and not output.exists())
    require(type(context) is dict and set(context) == {"mode", "epoch", "source_commit", "graph_sha256",
        "entry_monotonic_ns", "deadline_monotonic_ns"} and context["mode"] == PROFILE
        and type(context["entry_monotonic_ns"]) is int and type(context["deadline_monotonic_ns"]) is int
        and context["deadline_monotonic_ns"] - context["entry_monotonic_ns"] == 1200 * 10**9
        and deadline == float(context["entry_monotonic_ns"] / 10**9) + 600)
    protocol.pin(selector_sha)
    pin = selected["carrier"]["receipt_sha256"]
    qualified = qualify_producer(selected, deadline, proof_inputs)
    with ExitStack() as stack:
        carrier_hold = stack.enter_context(carrier.HeldCarrier(carrier_root, pin, deadline))
        origin = report = files = parent = output_hold = temporary_hold = source_hold = binding_hold = None
        def accept_initial(candidate):
            nonlocal origin, report, files, parent, output_hold, temporary_hold, source_hold, binding_hold
            started_ns = time.monotonic_ns()
            def progress(phase):
                # Static phase diagnostics only; this clock grants no allowance.
                print("sdk-carrier-initial-callback: " + phase
                    + " elapsed_ns=" + str(max(0, time.monotonic_ns() - started_ns)),
                    file=sys.stderr, flush=True)
            progress("start")
            try:
                origin_join(candidate)
                require(candidate["producer_context"] == qualified["report"]["producer_context"])
                _recheck_initial_declaration(declaration, qualified, carrier_root, pin, candidate, deadline)
                progress("declaration-ready")
                recheck_aliases(aliases, deadline)
                progress("aliases-ready")
                source_hold = legacy.hold_root(Path(selected["original_selection"]["source_root"]))
                stack.callback(os.close, source_hold[0])
                binding_hold = legacy.hold_root(legacy.INPUT_CONTROL.parent)
                stack.callback(os.close, binding_hold[0])
                report, files, parent = legacy.load_retained_candidate(selected["original_selection"])
                progress("source-ready")
                output.mkdir(mode=0o700)
                output_hold = stack.enter_context(carrier.Root(output, carrier.Clock(deadline), sealed=False, owned=True))
                temporary.mkdir(mode=0o700)
                temporary_hold = stack.enter_context(carrier.Root(temporary, carrier.Clock(deadline), sealed=False, owned=True))
                origin = candidate
                progress("output-ready")
            except BaseException:
                progress("refused")
                raise
        # SDK scratch is workload-local; only the regenerated hub/report are retained.
        extracted = temporary / "extracted"
        extraction = carrier.extract(carrier_root, pin, extracted, deadline, on_bound=accept_initial,
            _held_carrier=carrier_hold)
        extraction_pin = carrier.sha(carrier.encoded(extraction))
        require(carrier.revalidate_extraction(carrier_root, pin, extracted, deadline,
            pinned_extraction_receipt_sha256=extraction_pin, _held_carrier=carrier_hold) == extraction)
        sdk_root = extracted / "sdk"
        fresh = {role: stack.enter_context(carrier.Root(extracted / role, carrier.Clock(deadline)))
            for role in ("sdk", "jdk")}
        exported = sdk.validate_export(sdk_root, legacy.EXPORT_SHA, source.BASE_INVENTORY,
            parent["baseline_graph_files"], on_read=lambda count: tick(deadline))
        previous_hub = legacy.read_hub(sdk_root / "repositories" / metadata.HUB)
        fd = source.write_source(temporary / "workspace", files)
        os.close(fd)
        for name in ("home", "home/cargo", "home/cache", "home/config", "home/state"):
            (temporary / name).mkdir(mode=0o700)
        plan = query_plan(temporary, temporary / "workspace/source", exported, sdk_root)
        query_exit = legacy.execute_query(plan, output)
        generated = legacy.read_hub(temporary / "output-base/external" / metadata.HUB)
        binding.verify_hub_delta(previous_hub, generated)
        hub = {name: ("100644", raw) for name, raw in generated.items()}
        fd = source.write_source(output / "hub", hub)
        os.close(fd)
        source.verify_written(output / "hub/source", hub)
        require(qualify_producer(selected, deadline, proof_inputs) == qualified)
        recheck_declaration(declaration, qualified, carrier_root, pin, deadline, _held_carrier=carrier_hold)
        query = query_tools.verify_repository(legacy.QUERY_REPOSITORY, deadline)
        require(query["status"] == "declared-fixed-query-tools-byte-qualified" and query["inputs_rechecked"] is True)
        source.verify_written(temporary / "workspace/source", files)
        require(legacy.load_retained_candidate(selected["original_selection"])[0] == report)
        require(sdk.validate_export(sdk_root, legacy.EXPORT_SHA, source.BASE_INVENTORY,
            parent["baseline_graph_files"], on_read=lambda count: tick(deadline)) == exported)
        require(carrier_hold.report() == origin)
        require(carrier.revalidate_extraction(carrier_root, pin, extracted, deadline,
            pinned_extraction_receipt_sha256=extraction_pin, _held_carrier=carrier_hold) == extraction)
        legacy.recheck_root(Path(selected["original_selection"]["source_root"]), source_hold)
        legacy.recheck_root(legacy.INPUT_CONTROL.parent, binding_hold)
        for root in [output_hold, temporary_hold, carrier_hold, *fresh.values()]:
            root.check()
        recheck_aliases(aliases, deadline)
        source.verify_written(output / "hub/source", hub)
        result = {"schema_version": 2, "kind": OUTPUT_KIND,
            "status": "verified-fresh-carrier-custody-regenerated-native-acquisition-hub",
            "original_selection": selected["original_selection"], "selector_sha256": selector_sha,
            "source_inventory_sha256": report["inventory_sha256"], "source_graph": report["graph_files"],
            "patch_sha256": report["patch_sha256"], "carrier": {"declared_root": str(carrier_root),
                "receipt_sha256": pin, "origin": origin["origin"], "origin_custody": origin["origin_custody"],
                "producer_context": origin["producer_context"], "qualification": qualified,
                "declaration": declaration},
            "extraction": extraction, "extraction_receipt_sha256": extraction_pin, "consumer_context": context,
            "consumer_deadline": deadline, "query_exit": query_exit, "query_plan": plan,
            "output_parent_mode": "0700",
            "query_tool_closure_independently_rechecked": True,
            "packaged_jdk_used_as_query_tool_relocation": False,
            "module_and_cargo_lock_unchanged": True,
            "retained_hub": [{"path": name, "sha256": source.sha(raw)} for name, raw in sorted(previous_hub.items())],
            "generated_hub": [{"path": name, "sha256": source.sha(raw)} for name, raw in sorted(generated.items())],
            "source_and_extracted_carrier_rechecked": True, **{name: False for name in FALSE_FLAGS}}
        tick(deadline)
        write_receipt(output_hold, result, deadline)
        # Long final carrier content/NAR IO precedes the last fresh output proof.
        # A scoped report or completed copy can never replace this full read.
        carrier_hold.full_final()
        temporary_hold.check()
        require(carrier.revalidate_extraction(carrier_root, pin, extracted, deadline,
            pinned_extraction_receipt_sha256=extraction_pin, _held_carrier=carrier_hold) == extraction)
        source.verify_written(temporary / "workspace/source", files)
        source.verify_written(output / "hub/source", hub)
        legacy.recheck_root(Path(selected["original_selection"]["source_root"]), source_hold)
        legacy.recheck_root(legacy.INPUT_CONTROL.parent, binding_hold)
        for root in [output_hold, temporary_hold, carrier_hold, *fresh.values()]:
            root.check()
        recheck_aliases(aliases, deadline)
        proof_inputs.recheck(deadline)
        require(carrier.read(output_hold, "metadata-receipt.json", source.MAX_METADATA) == source.encoded(result))
        tick(deadline)
        return result


def main():
    os.umask(0o077)
    require(len(sys.argv) == 1 and all(os.environ.get(name) for name in
        ("TEST_SRCDIR", "TEST_UNDECLARED_OUTPUTS_DIR", "TEST_TMPDIR", "TEST_TIMEOUT")))
    entry, until, context = envelope(os.environ)
    deadline = query_tools.consumer_deadline(float(entry / 10**9), 600)
    with proof_scope(deadline):
        raw = binding.ninth.parent.declared(CONFIG, 16384)
        selected = selection(raw)
        runfiles = Path(os.environ["TEST_SRCDIR"]).resolve(strict=True)
        mapping = (runfiles / "_repo_mapping").read_bytes()
        require(len(mapping) <= 1024 * 1024)
        rows = [line.split(",") for line in mapping.decode().splitlines()]
        require(legacy.declared_query_tools(runfiles, rows) is True)
        root, aliases, declaration = declared_carrier(runfiles, rows, selected, deadline)
        proof_inputs = declared_proofs(runfiles, rows, selected, deadline)
        output_parent = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
        temporary_parent = Path(os.environ["TEST_TMPDIR"]).resolve(strict=True)
        result = produce(selected, source.sha(raw), root, aliases, declaration, proof_inputs,
            temporary_parent / "native-sdk-carrier-metadata-work",
            output_parent / "native-sdk-carrier-metadata", deadline, context)
        require(binding.ninth.parent.declared(CONFIG, 16384) == raw)
        tick(deadline)
    print("native-sdk-carrier-metadata-v2: regenerated hub; downstream qualifications false", flush=True)
    print("omux-native-carrier-metadata-output-sha256=" + source.sha(source.encoded(result)), flush=True)


if __name__ == "__main__":
    main()
