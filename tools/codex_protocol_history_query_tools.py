"""Finite read-only query tool proof; no evaluator, builder or store mutation.

The exact fixed tools must be ready outputs of the archived current graph.
A successful reserved missing-plan action is a prerequisite, not seed authority.
"""
import argparse
import json
import math
import os
from pathlib import Path
import re
import sys
import stat
import time
from decimal import Decimal
import xml.etree.ElementTree as ET

import native_flake_seed_plan_inputs as inputs
import native_flake_seed_plan as restored
import native_flake_schedule as schedule
import native_flake_sources as sources
import native_flake_missing_plan as missing
import nix_private_store_seed as seed
import nix_private_store_qualification as proof
import nix_interpreter_closure as closure
import nar_descriptor as nar
import codex_query_registration as registration
from verify_declared_nars import open_declared, metadata_alias_roots
from guard_native_seed_plan_reserved import kernel_bounds

KIND = "omux-protocol-history-query-tool-inputs-v1"
SELECTION_KIND = "omux-protocol-history-query-tool-selection-v1"
REPOSITORY = "omux_protocol_history_query_tools"
TARGET = "//tools:native_flake_seed_plan_qualification"
MAX_ROOTS, MAX_BYTES = 4096, seed.MAX_BYTES
FILES = schedule.PROJECT_FILES
IMPLEMENTATIONS = ("native_flake_schedule.py", "native_flake_sources.py",
    "nix_private_store_seed.py", "nix_private_store_qualification.py",
    "nar_descriptor.py", "verify_declared_nars.py", "verify_cached_nars.py",
    "nix_source_probe.py", "nix_interpreter_closure.py")
# Constants copied exactly from the maintained metadata query, not caller input.
TOOLS = {
    "bazel": "/nix/store/ia8gp7v2h790lwdx7a7p5clh063v0qy1-bazel-9.0.1/bin/bazel",
    "bash": "/nix/store/4bwbk4an4bx7cb8xwffghvjjyfyl7m2i-bash-interactive-5.3p9/bin/bash",
    "coreutils": "/nix/store/jjxngswsb214vb58qx485jhmilf0kxxy-coreutils-9.10/bin/env",
    "python": "/nix/store/0r6k8xa2kgqyp3r4v2w7yrb80ma2iawm-python3-3.13.12/bin/python3",
    "git": "/nix/store/c0277k5giric1mn9dklllavbzvxl6hzb-git-2.53.0/bin/git",
}
JAVA = "/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7"
PATH = [TOOLS[name].rsplit("/", 1)[0] for name in ("bash", "coreutils", "python", "git")]
require = seed.require


def consumer_deadline(entry, seconds):
    """Capture once at consumer entry; reuse for the whole action and rechecks.

    Consumer actions retain their outer Bazel/guardian cutoff, but their work
    budget cannot exceed the protected source-admission budget. Never renew it
    at a verifier call or after metadata generation.
    """
    now = time.monotonic()
    require(type(entry) is float and math.isfinite(entry) and 0 <= entry <= now
        and type(seconds) is int and 1 <= seconds <= 840)
    deadline = entry + min(seconds, sources.MAX_SECONDS)
    require(math.isfinite(deadline) and 0 < deadline - now <= sources.MAX_SECONDS)
    return deadline


def decode(raw, maximum=inputs.MAX_METADATA):
    return inputs.decode(raw, maximum)


def selection(value):
    require(type(value) is dict and set(value) == {
        "schema_version", "kind", "inputs", "plan", "candidates"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["kind"] == SELECTION_KIND)
    inputs.pin(value["inputs"], inputs.MAX_SELECTION)
    require(inputs.coordinator_leaf(value["inputs"]["path"], "native-flake-seed-plan-selection.json"))
    run = value["plan"]
    require(type(run) is dict and set(run) == {
        "receipt", "evidence", "log", "xml", "result", "source_commit", "graph_sha256"})
    for name in ("receipt", "evidence", "log", "xml", "result"):
        inputs.pin(run[name], schedule.MAX_GRAPH_BYTES)
    require(inputs.coordinator_leaf(run["receipt"]["path"], "receipt.json"))
    parent = str(Path(run["receipt"]["path"]).parent)
    require(run["evidence"]["path"] == parent + "/test-evidence.json"
        and type(run["source_commit"]) is str
        and re.fullmatch(r"[a-f0-9]{40}", run["source_commit"]) is not None
        and type(run["graph_sha256"]) is str and inputs.HEX.fullmatch(run["graph_sha256"]) is not None)
    for name in ("log", "xml"):
        require(re.fullmatch(re.escape(parent) + r"/test-evidence/[a-f0-9]{64}[.]evidence",
            run[name]["path"]) is not None)
    suffix = "/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/native_flake_seed_plan_qualification/test.outputs/native-flake-seed-plan.json"
    require(run["result"]["path"] == parent+"/output-base"+suffix)
    candidate = value["candidates"]
    require(type(candidate) is dict)
    if set(candidate)=={"registration","paths"}:
        # Historical immutable linkFarm metadata route remains unchanged.
        for name, leaf in (("registration", "registration"), ("paths", "store-paths")):
            inputs.pin(candidate[name], seed.MAX_METADATA)
            require(re.fullmatch(seed.STORE + "/" + leaf, candidate[name]["path"]) is not None)
        require(str(Path(candidate["registration"]["path"]).parent)
            == str(Path(candidate["paths"]["path"]).parent))
    else:
        require(set(candidate)=={"kind","registration","paths","report","producer"}
            and candidate["kind"] in registration.CANDIDATE_KINDS)
        producer=candidate["producer"]
        require(type(producer) is dict and set(producer)=={
            "receipt","evidence","log","xml","source_commit","graph_sha256"})
        for name in ("receipt","evidence","log","xml"):
            inputs.pin(producer[name],registration.MAX_OUTPUT)
        require(inputs.coordinator_leaf(producer["receipt"]["path"],"receipt.json")
            and type(producer["source_commit"]) is str
            and re.fullmatch(r"[a-f0-9]{40}",producer["source_commit"]) is not None
            and type(producer["graph_sha256"]) is str and inputs.HEX.fullmatch(producer["graph_sha256"]) is not None
            and producer["source_commit"]==run["source_commit"] and producer["graph_sha256"]==run["graph_sha256"])
        parent=str(Path(producer["receipt"]["path"]).parent)
        require(producer["evidence"]["path"]==parent+"/test-evidence.json")
        for name in ("log","xml"):
            require(re.fullmatch(re.escape(parent)+r"/test-evidence/[a-f0-9]{64}[.]evidence",
                producer[name]["path"]) is not None)
        target = registration.RESERVED_TARGET if candidate["kind"] == registration.RESERVED_CANDIDATE_KIND else registration.TARGET
        output=parent+"/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"+target.split(":")[1]+"/test.outputs/"
        for name,leaf in (("registration","registration"),("paths","store-paths"),("report","query-registration.json")):
            inputs.pin(candidate[name],registration.MAX_OUTPUT)
            require(candidate[name]["path"]==output+leaf)
    return value


def roles(top, selected):
    result = {"seed_selection": top["inputs"]}
    result.update({"producer_" + name: pin for name, pin in inputs.metadata_roles(selected).items()})
    result.update({"plan_" + name: top["plan"][name]
        for name in ("receipt", "evidence", "log", "xml", "result")})
    result.update({"candidate_" + name: top["candidates"][name] for name in ("registration", "paths")})
    if top["candidates"].get("kind") in registration.CANDIDATE_KINDS:
        result["candidate_report"]=top["candidates"]["report"]
        result.update({"candidate_"+name:top["candidates"]["producer"][name]
            for name in ("receipt","evidence","log","xml")})
    return result


def plan_success(top, selected, raw, body, runtime_records):
    """Supplied bounded public bytes only; never locate a receipt implicitly."""
    pin = top["plan"]
    receipt = decode(raw["plan_receipt"])
    epoch = Path(pin["receipt"]["path"]).parent.name
    require(receipt["id"] == receipt["artifact_epoch"] == epoch
        and receipt["unit"] == "omux-execution-" + epoch + ".service"
        and receipt["profile"] == "native-seed-plan-reserved" and receipt["manager"] == "system"
        and receipt["verb"] == "test" and receipt["targets"] == [TARGET]
        and type(receipt["exit"]) is int and receipt["exit"] == 0
        and type(receipt["workload_exit"]) is int and receipt["workload_exit"] == 0
        and receipt["controller_failure"] is None and receipt["descendants_empty"] is True
        and receipt["cleanup"]["state"] == "empty" and receipt["source_dirty"] == "false"
        and receipt["cache_reuse_requested"] is False
        and receipt["output_base"] == str(Path(pin["receipt"]["path"]).parent/"output-base")
        and receipt["source_commit"] == pin["source_commit"] and receipt["graph_sha256"] == pin["graph_sha256"]
        and receipt["test_evidence"]["state"] == "preserved"
        and receipt["test_evidence"]["sha256"] == pin["evidence"]["sha256"])
    observed = receipt["observed_properties"]
    expected = {**inputs.RESOURCE_PROPERTIES, "MemoryMax": "4026531840", "TasksMax": "480"}
    del expected["CPUQuotaPerSecUSec"]
    require(type(observed) is dict and all(observed.get(name) == value for name, value in expected.items()))
    matched = re.fullmatch(r"([0-9]{1,7}(?:[.][0-9]{1,6})?)(us|ms|s)",
        observed.get("CPUQuotaPerSecUSec", "")) if type(observed.get("CPUQuotaPerSecUSec")) is str else None
    require(matched is not None and Decimal(matched[1])*{"us": 1, "ms": 1000, "s": 1000000}[matched[2]] == 1900000)
    inputs.duration(observed["RuntimeMaxUSec"])
    require(pin["result"]["path"] == inputs.output_base(receipt["output_base"])
        + "/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/native_flake_seed_plan_qualification/test.outputs/native-flake-seed-plan.json")
    reservation = receipt["native_seed_plan_reservation"]
    require(reservation["scope"] == "native-seed-plan-reserved-v1" and reservation["mode"] == "qualification"
        and reservation["verified_after_cleanup"] is True
        and reservation["seed_qualification"] is False
        and reservation["seed_qualification_requires_matching_outer_success"] is True
        and reservation["native_runtime_qualified"] is False and reservation["complete_build_seed_qualified"] is False)
    resident = reservation["resident"]
    require(type(resident) is dict and set(resident) == {
        "scope", "kernel_bounds", "observations", "initial_direct_processes_retained",
        "initial_direct_process_count", "outer_pid_namespace_matched", "hierarchical_caps",
        "descendant_process_inventory", "installation_qualified", "health_observed",
        "custody_observed", "resident_signalled", "whole_host_reservation"}
        and resident["scope"] == "sampled-fixed-default-cgroup-kernel-reservation-v1")
    bounds = kernel_bounds(resident["kernel_bounds"])
    require(type(resident["observations"]) is int and 1 <= resident["observations"] <= 65535
        and type(resident["initial_direct_process_count"]) is int
        and 1 <= resident["initial_direct_process_count"] <= int(bounds["pids.max"]))
    for name in ("initial_direct_processes_retained", "outer_pid_namespace_matched", "hierarchical_caps"):
        require(resident[name] is True)
    for name in ("descendant_process_inventory", "installation_qualified", "health_observed",
                 "custody_observed", "resident_signalled", "whole_host_reservation"):
        require(resident[name] is False)
    entry, deadline = (reservation[name] for name in
        ("original_entry_monotonic_ns", "original_deadline_monotonic_ns"))
    require(type(entry) is int and type(deadline) is int and entry > 0 and deadline-entry == 1200*10**9)
    evidence = decode(raw["plan_evidence"])
    require(type(receipt["epoch_start_ns"]) is int and receipt["epoch_start_ns"] > 0
        and type(evidence["schema"]) is int and evidence["schema"] == 1
        and type(evidence["bazel_exit"]) is int and evidence["bazel_exit"] == 0
        and type(evidence["epoch_start_ns"]) is int and evidence["epoch_start_ns"] == receipt["epoch_start_ns"]
        and evidence["targets"] == [TARGET] and len(evidence["results"]) == 1)
    row = evidence["results"][0]
    require(row["target"] == TARGET and row["state"] == "observed")
    for name, member in (("log", "test.log"), ("xml", "test.xml")):
        files = [item for item in row["files"] if item["source"] == member]
        require(len(files) == 1 and files[0]["state"] == "copied"
            and files[0]["file"] == Path(pin[name]["path"]).name
            and files[0]["sha256"] == pin[name]["sha256"]
            and type(files[0]["bytes"]) is int and files[0]["bytes"] == pin[name]["bytes"])
    xml = ET.fromstring(raw["plan_xml"])
    suites = [xml] if xml.tag == "testsuite" else list(xml.findall("testsuite"))
    require(xml.tag in ("testsuite", "testsuites") and bool(suites)
        and all(int(item.get("tests", "0")) > 0 and all(int(item.get(name, "0")) == 0
            for name in ("failures", "errors", "skipped")) for item in suites))
    report = decode(raw["plan_result"], proof.MAX_OUTPUT)
    require(type(report) is dict and set(report) == {
        "schema_version", "kind", "plan", "restored_registration_sha256", "verified_roots",
        "verified_nar_bytes", "graph_rechecked", "original_and_copied_bytes_rechecked",
        "realized", "complete_build_seed_verified", "native_runtime_qualified", "sdk_qualified",
        "execution_authority", "private_root_removed", "status", "selection_sha256", "mapping_sha256",
        "producer_epoch", "producer_receipt_sha256", "producer_source_commit", "producer_graph_sha256",
        "obligations_sha256", "input_metadata_rechecked", "locked_sources_rechecked",
        "qualification_provider_requests", "outer_success_and_owned_empty_required", "platform",
        "guard_epoch", "original_entry_monotonic_ns", "original_work_deadline_monotonic_ns",
        "declared_files_rechecked", "producer_implementation_rechecked", "reserved_execution_envelope"}
        and type(report["mapping_sha256"]) is str and inputs.HEX.fullmatch(report["mapping_sha256"]) is not None
        and report["platform"] == {"nonroot": True, "no_new_privileges": True,
            "effective_capabilities_empty": True}
        and all(value is True for value in report["platform"].values()))
    require(report["kind"] == restored.KIND and report["status"] == "selected-fresh-private-missing-plan-qualified"
        and type(report["schema_version"]) is int and report["schema_version"] == 1
        and report["guard_epoch"] == epoch and report["selection_sha256"] == top["inputs"]["sha256"]
        and report["producer_epoch"] == Path(selected["producer"]["receipt"]["path"]).parent.name
        and report["producer_receipt_sha256"] == selected["producer"]["receipt"]["sha256"]
        and report["producer_source_commit"] == selected["producer"]["source_commit"]
        and report["producer_graph_sha256"] == selected["producer"]["graph_sha256"]
        and report["obligations_sha256"] == selected["obligations"]["sha256"])
    for name in ("graph_rechecked", "original_and_copied_bytes_rechecked", "private_root_removed",
            "input_metadata_rechecked", "locked_sources_rechecked", "declared_files_rechecked",
            "producer_implementation_rechecked", "outer_success_and_owned_empty_required"):
        require(report[name] is True)
    for name in ("realized", "complete_build_seed_verified", "native_runtime_qualified", "sdk_qualified", "execution_authority"):
        require(report[name] is False)
    require(type(report["qualification_provider_requests"]) is int and report["qualification_provider_requests"] == 0)
    envelope = report["reserved_execution_envelope"]
    require(envelope["profile"] == "native-seed-plan-reserved"
        and type(envelope["original_entry_monotonic_ns"]) is int and envelope["original_entry_monotonic_ns"] == entry
        and type(envelope["original_deadline_monotonic_ns"]) is int and envelope["original_deadline_monotonic_ns"] == deadline)
    require(type(report["original_entry_monotonic_ns"]) is int
        and type(report["original_work_deadline_monotonic_ns"]) is int
        and entry <= report["original_entry_monotonic_ns"] < report["original_work_deadline_monotonic_ns"] <= deadline-60*10**9)
    require(type(envelope["outer_work_deadline_monotonic_ns"]) is int
        and envelope["outer_work_deadline_monotonic_ns"] == deadline-30*10**9
        and type(envelope["private_cleanup_deadline_monotonic_ns"]) is int
        and envelope["private_cleanup_deadline_monotonic_ns"] == report["original_work_deadline_monotonic_ns"]+30*10**9)
    old_candidates = inputs.candidate_records(selected, {
        name: raw["producer_" + name] for name in inputs.metadata_roles(selected)})
    _, selected_old = restored.candidates(body, old_candidates)
    merged = {**runtime_records, **selected_old}
    registration = "".join("\n".join(merged[root]["record"])+"\n" for root in sorted(merged))
    require(report["restored_registration_sha256"] == seed.sha(registration.encode("ascii")))
    current = report["plan"]
    require(type(current) is dict and set(current) == {
        "willBuild", "willSubstitute", "unknown", "missing_input_sources", "missing_ready_input_outputs",
        "unresolved_input_outputs", "requested_target_ready", "required_input_paths_present", "complete_build_seed_verified"})
    for name in ("willBuild", "willSubstitute", "unknown"):
        require(type(current[name]) is list and current[name] == sorted(set(current[name])))
    actual = missing.MissingPlan(frozenset(current["willBuild"]), frozenset(current["willSubstitute"]),
        frozenset(current["unknown"]), ())
    require(seed.encoded(restored.readiness(body, actual, merged)) == seed.encoded(current))
    require(type(report["verified_roots"]) is int and report["verified_roots"] == len(merged)
        and type(report["verified_nar_bytes"]) is int and 0 < report["verified_nar_bytes"] <= seed.MAX_BYTES
        and report["verified_nar_bytes"] == sum(int(row["record"][2]) for row in merged.values()))
    return report


def lineage(top, raw, runtime_raw, source_raw, project, wrapper, implementations, deadline):
    selected = inputs.selection(decode(raw["seed_selection"], inputs.MAX_SELECTION))
    require(seed.sha(raw["seed_selection"]) == top["inputs"]["sha256"])
    original = {name: raw["producer_" + name] for name in inputs.metadata_roles(selected)}
    inputs.producer_success(selected, original)
    body = decode(original["obligations"], schedule.MAX_GRAPH_BYTES)
    locked = sources.locked_sources(project["flake.lock"])
    sources.admit(project["flake.lock"], source_raw, deadline=deadline)
    source_report = body["source_proof"]
    require(source_report["passed"] is True and source_report["sourceNarVerified"] is True
        and source_report["contentRehashed"] is True and source_report["buildSeedVerified"] is False
        and source_report["nativeRuntimeQualified"] is False and source_report["executionAuthority"] is False
        and source_report["lockSha256"] == seed.sha(project["flake.lock"])
        and source_report["descriptorSha256"] == seed.sha(source_raw)
        and len(source_report["sources"]) == 3)
    require({row["role"]: {key: row[key] for key in ("node", "revision", "narHash")}
        for row in source_report["sources"]} == locked)
    require(body["implementation_sha256"] == implementations and set(implementations) == set(IMPLEMENTATIONS))
    body, runtime, records = restored.join_obligations(original["obligations"],
        selected["obligations"]["sha256"], runtime_raw, source_report, project, seed.sha(wrapper))
    plan_success(top, selected, raw, body, records)
    return body


def choose(body, records):
    roots = sorted({"/".join(path.split("/")[:4]) for path in TOOLS.values()} | {JAVA})
    require(len(roots) == 6)
    outputs = {item["path"] for row in body["derivations"].values()
        for item in row["outputs"].values() if item["path"] is not None}
    require(set(roots) <= outputs and set(roots) <= set(records))
    selected = closure.reachable(records, roots)
    require(0 < len(selected) <= MAX_ROOTS)
    descriptor = {"schemaVersion": 1, "kind": "omux-codex-metadata-query-tools-v1",
        "tools": dict(TOOLS), "path": list(PATH), "java_home": JAVA, "roots": selected}
    return descriptor, {root: records[root] for root in selected}


def verify_objects(descriptor, records, objects, opener, deadline):
    """Complete NAR/reference proof; never execute or follow descriptor links."""
    require(type(objects) is dict and set(objects) == set(records) == set(descriptor["roots"]))
    fixed_roots = sorted({"/".join(path.split("/")[:4]) for path in TOOLS.values()} | {JAVA})
    require(descriptor == {"schemaVersion": 1, "kind": "omux-codex-metadata-query-tools-v1",
        "tools": dict(TOOLS), "path": list(PATH), "java_home": JAVA,
        "roots": closure.reachable(records, fixed_roots)})
    total, nodes = 0, 0
    executable = {}
    for root in sorted(records):
        item = objects[root]
        require(set(item) == {"descriptor", "regularInputs"} and item["descriptor"]["root"] == root)
        by_path, _ = nar.validate_descriptor(item["descriptor"])
        nodes += len(by_path)
        require(nodes <= nar.MAX_ENTRIES and set(item["regularInputs"]) == {
            name for name, node in by_path.items() if node["type"] == "regular"})
        total += restored.object_hash(item["descriptor"], records[root], opener, deadline)
        require(total <= MAX_BYTES)
        executable[root] = item["descriptor"]
    # Symlinks, wrappers, loader and JVM references remain in the closed NAR graph.
    for path in TOOLS.values():
        seed.resolve_member({"descriptors": executable}, path)
    seed.resolve_member({"descriptors": executable}, JAVA+"/bin/java")
    return {"roots": len(records), "nar_bytes": total, "regular_inputs": sum(
        len(row["regularInputs"]) for row in objects.values())}


def raw_inputs(top, deadline):
    raw = {"seed_selection": inputs.selected_bytes(top["inputs"], deadline)}
    selected = inputs.selection(decode(raw["seed_selection"], inputs.MAX_SELECTION))
    for name, pin in roles(top, selected).items():
        raw[name] = inputs.selected_bytes(pin, deadline)
    return selected, raw


def candidate_records(top, raw, project=None):
    if top["candidates"].get("kind") in registration.CANDIDATE_KINDS:
        return registration.validate_success(top["candidates"],raw,project,top["plan"])
    # This new purpose admits canonical current-flake names without changing
    # the declared runtime-seed grammar or its4096 root/reference ceiling.
    paths = raw["candidate_paths"].decode("ascii").splitlines()
    require(paths == sorted(set(paths)) and 0 < len(paths) <= MAX_ROOTS
        and all(closure.current_flake_path_refusal(path) is None for path in paths))
    return closure.registrations(raw["candidate_registration"].decode("ascii"), paths,
        current_flake_paths=True)


def generate(raw, digest, runtime_raw, source_raw, project, wrapper, implementations, directory, deadline):
    require(type(digest) is str and inputs.HEX.fullmatch(digest) is not None and seed.sha(raw) == digest)
    top = selection(decode(raw, inputs.MAX_SELECTION))
    selected, metadata = raw_inputs(top, deadline)
    body = lineage(top, metadata, runtime_raw, source_raw, project, wrapper, implementations, deadline)
    descriptor, records = choose(body, candidate_records(top, metadata, project))
    objects, regular, entries, total = {}, [], 0, 0
    for root in sorted(records):
        proof.tick(deadline)
        require(Path(root).resolve(strict=True) == Path(root))
        current = nar.describe(root)
        proof.tick(deadline)
        nodes, _ = nar.validate_descriptor(current)
        entries += len(nodes)
        require(entries <= nar.MAX_ENTRIES)
        mapping = {}
        for relative, node in sorted(nodes.items()):
            proof.tick(deadline)
            if node["type"] != "regular":
                continue
            path = root + ("/" + relative if relative else "")
            require(str(Path(path).resolve(strict=True)) == path)
            alias = "regular/" + str(len(regular)).zfill(8)
            regular.append({"source": path, "alias": alias})
            mapping[relative] = {"source": path, "alias": alias}
            total += node["size"]
            require(len(regular) <= seed.MAX_FILES and total <= MAX_BYTES)
        objects[root] = {"descriptor": current, "regularInputs": mapping}
    directory = Path(directory)
    (directory/"metadata").mkdir(mode=0o700)
    role_pins = roles(top, selected)
    declared = {}
    for index, name in enumerate(sorted(role_pins)):
        alias = "metadata/" + str(index).zfill(8)
        (directory/alias).write_bytes(metadata[name])
        os.chmod(directory/alias, 0o444)
        declared[name] = {"alias": alias, "pin": role_pins[name]}
    bundle = {"schema_version": 1, "kind": KIND, "selection_sha256": digest,
        "query_tools": descriptor, "metadata": declared, "objects": objects}
    content = inputs.encode(bundle)
    require(len(content) <= inputs.MAX_MAPPING)
    (directory/"query-inputs.json").write_bytes(content)
    (directory/"codex-metadata-query-tools.json").write_bytes(inputs.encode(descriptor))
    return {"regularInputs": regular, "metadata": [row["alias"] for row in declared.values()],
        "metadataInputs": [row["path"] for row in role_pins.values()], "mapping_sha256": seed.sha(content)}


def qualify(top_raw, digest, bundle_raw, mapping_sha256, bundle_path,
        runtime_raw, source_raw, project, wrapper, implementations, deadline):
    require(seed.sha(top_raw) == digest and seed.sha(bundle_raw) == mapping_sha256)
    top = selection(decode(top_raw, inputs.MAX_SELECTION))
    bundle = decode(bundle_raw, inputs.MAX_MAPPING)
    require(type(bundle) is dict and set(bundle) == {
        "schema_version", "kind", "selection_sha256", "query_tools", "metadata", "objects"}
        and type(bundle["schema_version"]) is int and bundle["schema_version"] == 1
        and bundle["kind"] == KIND and bundle["selection_sha256"] == digest)
    aliases = metadata_alias_roots(bundle_path)
    def read_metadata(expected):
        result = {}
        for name in expected:
            item = bundle["metadata"][name]
            require(set(item) == {"alias", "pin"} and item["pin"] == expected[name]
                and re.fullmatch(r"metadata/[0-9]{8}", item["alias"]) is not None)
            node = {"size": item["pin"]["bytes"], "executable": False}
            with open_declared(Path(bundle_path).parent/item["alias"],
                [Path(root)/item["alias"] for root in aliases], item["pin"]["path"], node) as stream:
                content = bytearray()
                while len(content) <= node["size"]:
                    proof.tick(deadline)
                    part = stream.read(min(65536, node["size"]+1-len(content)))
                    if not part:
                        break
                    content.extend(part)
            require(len(content) == node["size"] and seed.sha(content) == item["pin"]["sha256"])
            result[name] = bytes(content)
        return result
    # Validate this independently scoped role before any referenced role IO.
    raw = read_metadata({"seed_selection": top["inputs"]})
    selected = inputs.selection(decode(raw["seed_selection"], inputs.MAX_SELECTION))
    expected = roles(top, selected)
    require(set(bundle["metadata"]) == set(expected) and all(
        bundle["metadata"][name] == {"pin": expected[name],
            "alias": "metadata/"+str(index).zfill(8)}
        for index, name in enumerate(sorted(expected))))
    raw = read_metadata(expected)
    body = lineage(top, raw, runtime_raw, source_raw, project, wrapper, implementations, deadline)
    descriptor, records = choose(body, candidate_records(top, raw, project))
    require(bundle["query_tools"] == descriptor)
    labels = set()
    for root, row in bundle["objects"].items():
        for relative, item in row["regularInputs"].items():
            require(set(item) == {"source", "alias"} and item["source"] == root+("/"+relative if relative else "")
                and re.fullmatch(r"regular/[0-9]{8}", item["alias"]) is not None and item["alias"] not in labels)
            labels.add(item["alias"])
    require(len(labels) <= seed.MAX_FILES and labels == {
        "regular/"+str(index).zfill(8) for index in range(len(labels))})
    def opener(root, relative):
        row = bundle["objects"][root]
        node = {item["path"]: item for item in row["descriptor"]["nodes"]}[relative]
        item = row["regularInputs"][relative]
        stream = open_declared(Path(bundle_path).parent/item["alias"],
            [Path(path)/item["alias"] for path in aliases], item["source"], node)
        try:
            actual = os.fstat(stream.fileno())
            require(actual.st_uid in (0,os.getuid()) and stat.S_IMODE(actual.st_mode) in (0o444,0o555))
            return stream
        except BaseException:
            stream.close()
            raise
    counts = verify_objects(descriptor, records, bundle["objects"], opener, deadline)
    require(read_metadata(expected) == raw)
    proof.tick(deadline)
    return {"schema_version": 1, "kind": KIND, "status": "declared-fixed-query-tools-byte-qualified",
        "selection_sha256": digest, "mapping_sha256": mapping_sha256,
        "query_tools": descriptor, "counts": counts, "inputs_rechecked": True,
        "realized": False, "complete_build_seed_verified": False,
        "sdk_qualified": False, "native_runtime_qualified": False, "execution_authority": False}


def repository_read(parent, name, maximum, deadline):
    """Finite generated data, physical regular files and stable held/named inode."""
    proof.tick(deadline)
    require(type(name) is str and not name.startswith("/")
        and all(part not in ("", ".", "..") for part in name.split("/")))
    selected = Path(parent)/name
    require(selected.resolve(strict=True) == selected)
    with nar.open_regular(str(selected), "") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid in (0,os.getuid())
            and not before.st_mode & 0o022 and before.st_nlink == 1
            and 0 < before.st_size <= maximum)
        content = bytearray()
        while len(content) <= maximum:
            proof.tick(deadline)
            part = stream.read(min(65536,maximum+1-len(content)))
            if not part:
                break
            content.extend(part)
        with nar.open_regular(str(selected), "") as named:
            require(len(content) == before.st_size and inputs.witness(before)
                == inputs.witness(os.fstat(stream.fileno())) == inputs.witness(os.fstat(named.fileno())))
    return bytes(content)


def verify_repository(parent, deadline):
    """Consumer gate under the caller's ONE original absolute deadline."""
    require(type(deadline) is float and math.isfinite(deadline))
    proof.tick(deadline)
    parent = Path(parent)
    require(parent.is_absolute() and parent.resolve(strict=True) == parent)
    names = {"selection.json": inputs.MAX_SELECTION, "selection.sha256": 65,
        "query-inputs.json": inputs.MAX_MAPPING, "inputs.sha256": 65,
        "codex-metadata-query-tools.json": 1024**2, "seed.json": seed.MAX_METADATA,
        "source-descriptors.json": nar.MAX_METADATA_BYTES, "wrapper.nix": 65536}
    names.update({"project/"+name: 2*1024**2 for name in FILES})
    names.update({name: 1024**2 for name in IMPLEMENTATIONS})
    raw = {name: repository_read(parent,name,bound,deadline) for name,bound in names.items()}
    require(all(re.fullmatch(rb"[a-f0-9]{64}\n",raw[name]) is not None
        for name in ("selection.sha256", "inputs.sha256")))
    result = qualify(raw["selection.json"],raw["selection.sha256"][:-1].decode("ascii"),
        raw["query-inputs.json"],raw["inputs.sha256"][:-1].decode("ascii"),parent/"query-inputs.json",
        raw["seed.json"],raw["source-descriptors.json"],{name:raw["project/"+name] for name in FILES},
        raw["wrapper.nix"],{name:seed.sha(raw[name]) for name in IMPLEMENTATIONS},deadline)
    require(decode(raw["codex-metadata-query-tools.json"]) == result["query_tools"])
    require({name:repository_read(parent,name,bound,deadline) for name,bound in names.items()} == raw)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("selection", "sha256", "seed", "descriptors", "project", "wrapper", "directory"):
        parser.add_argument("--"+name, required=True)
    args = parser.parse_args()
    deadline = float(time.monotonic()+schedule.MAX_SECONDS)
    project_paths = decode(seed.metadata(args.project, inputs.MAX_SELECTION), inputs.MAX_SELECTION)
    require(set(project_paths) == set(FILES))
    project = {name: seed.metadata(path, 2*1024**2) for name, path in project_paths.items()}
    implementations = {name: seed.sha(seed.metadata(Path(__file__).parent/name, 1024**2)) for name in IMPLEMENTATIONS}
    result = generate(seed.metadata(args.selection, inputs.MAX_SELECTION), args.sha256,
        seed.metadata(args.seed, seed.MAX_METADATA), seed.metadata(args.descriptors, nar.MAX_METADATA_BYTES),
        project, seed.metadata(args.wrapper, 65536), implementations, args.directory, deadline)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
