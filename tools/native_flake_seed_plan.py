"""Finite restored missing-plan consumer, not an executable/admission owner.

The declared owner must supply pinned producer success and exact regular-label
openers. This primitive never discovers host roots or queries a shared DB.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import stat

import nar_descriptor as nar
import native_flake_missing_plan as missing
import native_flake_schedule as schedule
import nix_private_store_seed as seed
import nix_private_store_qualification as proof
from nix_interpreter_closure import reachable

KIND = "omux-native-flake-restored-plan-v1"
MAX_ROOTS = schedule.MAX_GENERATED_OBJECTS
MAX_CANDIDATE_ROOTS = 4096
MAX_NAR_BYTES = seed.MAX_BYTES


def require(value):
    seed.require(value)


def object_hash(descriptor, row, opener, deadline, *, retained_transport=False):
    require(type(retained_transport) is bool)
    nodes, _ = nar.validate_descriptor(descriptor)
    require(descriptor["root"] == row["record"][0])
    def checked(root, relative):
        require(root == descriptor["root"] and relative in nodes and nodes[relative]["type"] == "regular")
        stream = opener(root, relative)
        try:
            actual = os.fstat(stream.fileno())
            node = nodes[relative]
            require(stat.S_ISREG(actual.st_mode) and actual.st_size == node["size"])
            if retained_transport:
                require(stat.S_IMODE(actual.st_mode) == 0o555 and actual.st_uid == os.getuid()
                    and actual.st_gid == os.getgid() and actual.st_nlink == 1)
            else:
                require(bool(actual.st_mode & stat.S_IXUSR) == node["executable"])
            return stream
        except BaseException:
            stream.close()
            raise
    result = nar.hash_descriptor(descriptor, opener=checked, deadline=deadline)
    require(result["narHash"] == "sha256:"+seed.expected_hash(row["record"][1])
            and result["narSize"] == int(row["record"][2]))
    return result["narSize"]


def producer_objects(obligations, runtime):
    """Pin generated/imported objects to the actual producer registration."""
    runtime_rows = seed.validate(runtime)
    generated = obligations["generated"]
    require(type(generated) is dict and 0 < len(generated) <= MAX_ROOTS)
    roots = sorted(set(runtime_rows) | set(generated))
    require(len(roots) <= MAX_ROOTS and not set(runtime_rows) & set(generated))
    records = proof.readback_records(obligations["registration"].encode("ascii"), roots,
                                    current_flake_paths=True)
    schedule.same_records(runtime_rows, {root: records[root] for root in runtime_rows})
    require(seed.sha(obligations["registration"].encode("ascii")) == obligations["registration_sha256"])
    imported = obligations["target"]["sourcePaths"]
    require(set(imported) == {"project", *schedule.sources.ROLES})
    artifacts, roles = set(), set()
    for logical, item in generated.items():
        require(type(item) is dict and set(item) in (
            {"descriptor", "narHash", "narSize", "artifact_root"},
            {"descriptor", "narHash", "narSize", "source_role"}))
        descriptor = item["descriptor"]
        nar.validate_descriptor(descriptor)
        require(descriptor["root"] == logical and logical in records)
        require(item["narHash"] == "sha256:"+seed.expected_hash(records[logical]["record"][1])
                and type(item["narSize"]) is int and item["narSize"] == int(records[logical]["record"][2]))
        if "source_role" in item:
            role = item["source_role"]
            require(role in imported and imported[role] == logical and role not in roles)
            roles.add(role)
        else:
            artifact = item["artifact_root"]
            require(type(artifact) is str and re.fullmatch("generated/[0-9]{8}", artifact) is not None
                    and artifact not in artifacts)
            artifacts.add(artifact)
    require(roles == set(imported) and set(obligations["derivations"]) <= set(generated))
    require(obligations["target"]["outPath"] not in records)
    return records


def join_obligations(raw, digest, runtime_raw, source_report, project, wrapper_sha256):
    """Only an independently pinned successful obligations body is admitted.

    Outer guard success/evidence and producer/controller identity are the
    declared owner's separate positive prerequisites, not inferred here.
    """
    require(type(raw) is bytes and len(raw) <= schedule.MAX_GRAPH_BYTES
            and type(digest) is str and re.fullmatch("[a-f0-9]{64}", digest) is not None
            and seed.sha(raw) == digest)
    value = schedule.parse(raw)
    fields = {"schema_version", "kind", "status", "target", "derivations", "generated",
        "seed_sha256", "source_proof", "project_sha256", "wrapper_sha256", "expression_sha256",
        "derivation_json_sha256", "registration_sha256", "registration",
        "runtime_seed_rechecked", "source_rechecked", "realized", "complete_build_seed_verified",
        "native_runtime_qualified", "sdk_qualified", "execution_authority", "scheduler_pruned_plan",
        "outer_guard_success_and_owned_empty_required", "private_root_removed", "platform", "guard_epoch",
        "seed_file_inventory_sha256", "source_descriptors_sha256", "implementation_sha256"}
    require(type(value) is dict and set(value) == fields
            and type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["kind"] == schedule.KIND and value["status"] == "current-target-obligations-discovered")
    for name in ("runtime_seed_rechecked", "source_rechecked", "private_root_removed",
                 "outer_guard_success_and_owned_empty_required"):
        require(value[name] is True)
    for name in ("realized", "complete_build_seed_verified", "native_runtime_qualified",
                 "sdk_qualified", "execution_authority", "scheduler_pruned_plan"):
        require(value[name] is False)
    require(seed.encoded(value["platform"]) == seed.encoded({
        "nonroot": True, "no_new_privileges": True, "effective_capabilities_empty": True}))
    require(type(value["guard_epoch"]) is str
        and re.fullmatch("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", value["guard_epoch"]) is not None)
    implementations = {"native_flake_schedule.py", "native_flake_sources.py", "nix_private_store_seed.py",
        "nix_private_store_qualification.py", "nar_descriptor.py", "verify_declared_nars.py",
        "verify_cached_nars.py", "nix_source_probe.py", "nix_interpreter_closure.py"}
    require(type(value["implementation_sha256"]) is dict and set(value["implementation_sha256"]) == implementations
        and all(type(pin) is str and re.fullmatch("[a-f0-9]{64}", pin) is not None
            for pin in value["implementation_sha256"].values()))
    require(all(type(value[name]) is str and re.fullmatch("[a-f0-9]{64}", value[name]) is not None
        for name in ("seed_sha256", "wrapper_sha256", "expression_sha256", "derivation_json_sha256",
                     "registration_sha256", "seed_file_inventory_sha256", "source_descriptors_sha256")))
    require(value["source_descriptors_sha256"] == source_report["descriptorSha256"])
    require(type(value["target"]) is dict
        and set(value["target"]) == {"drvPath", "outPath", "system", "sourcePaths"})
    target = schedule.target_document(seed.encoded({
        "drvPath": value["target"]["drvPath"], "outputPath": value["target"]["outPath"],
        "system": value["target"]["system"], "sourcePaths": value["target"]["sourcePaths"]}))
    require(seed.encoded(target) == seed.encoded(value["target"]))
    require(seed.encoded(value["source_proof"]) == seed.encoded(source_report))
    require(type(runtime_raw) is bytes and value["seed_sha256"] == seed.sha(runtime_raw))
    require(set(project) == set(schedule.PROJECT_FILES)
            and value["project_sha256"] == {name: seed.sha(raw) for name, raw in project.items()}
            and value["wrapper_sha256"] == wrapper_sha256)
    require(len(runtime_raw) <= seed.MAX_METADATA)
    runtime = json.loads(runtime_raw, object_pairs_hook=seed.unique)
    records = producer_objects(value, runtime)
    require(target["drvPath"] in value["derivations"])
    missing.allowed_paths(frozenset(value["derivations"]))
    return value, runtime, records


def candidates(obligations, candidate_records):
    """Select exact output-path matches plus their closed registered references.

    Metadata is only a candidate selector. Every selected root must later have
    independently declared descriptor/regular-byte proof before DB import.
    """
    graph = obligations["derivations"]
    outputs = {item["path"] for row in graph.values() for item in row["outputs"].values()
               if item["path"] is not None}
    require(type(candidate_records) is dict and len(candidate_records) <= MAX_CANDIDATE_ROOTS)
    if candidate_records:
        text = "".join("\n".join(candidate_records[root]["record"])+"\n" for root in sorted(candidate_records))
        parsed = seed.registrations(text, sorted(candidate_records))
        schedule.same_records(parsed, candidate_records)
    ready = sorted(outputs & set(candidate_records))
    selected = reachable(candidate_records, ready) if ready else []
    require(len(selected) <= MAX_CANDIDATE_ROOTS)
    return ready, {logical: candidate_records[logical] for logical in selected}


def readiness(obligations, plan, records):
    """Missing inputSrcs remain visible even if QueryMissing exits zero.

    Required ready child outputs are tested only for actual willBuild rows;
    derivations pruned by Nix impose no additional input-source requirement.
    """
    require(type(plan) is missing.MissingPlan and type(plan.willSubstitute) is frozenset
            and type(plan.unknown) is frozenset and not plan.willSubstitute and not plan.unknown)
    graph = obligations["derivations"]
    require(type(plan.willBuild) is frozenset and plan.willBuild <= set(graph)
            and all(type(path) is str and re.fullmatch(missing.DRV, path) is not None for path in plan.willBuild))
    absent_srcs, absent_outputs, unresolved = set(), set(), set()
    for drv in sorted(plan.willBuild):
        row = graph[drv]
        absent_srcs.update(path for path in row["inputSrcs"] if path not in records)
        for child, names in row["inputDrvs"].items():
            require(child in graph)
            if child in plan.willBuild:
                continue
            for name in names:
                require(name in graph[child]["outputs"])
                output = graph[child]["outputs"][name]["path"]
                if output is None:
                    unresolved.add(child+"!"+name)
                elif output not in records:
                    absent_outputs.add(output)
    requested = obligations["target"]["outPath"]
    ready = not plan.willBuild and requested in records
    require(bool(plan.willBuild) or ready)
    return {"willBuild": sorted(plan.willBuild), "willSubstitute": [], "unknown": [],
        "missing_input_sources": sorted(absent_srcs), "missing_ready_input_outputs": sorted(absent_outputs),
        "unresolved_input_outputs": sorted(unresolved), "requested_target_ready": ready,
        "required_input_paths_present": not (absent_srcs or absent_outputs or unresolved),
        "complete_build_seed_verified": False}


def restore_plan(obligations, runtime, producer_records, selected_candidates,
                 descriptors, opener, parent, deadline, *, runner=proof.run,
                 retained_roots=frozenset()):
    """Fresh copied store, exact registration/graph readback and genuine dry run.

    descriptors/opener must be built solely from finite declared labels by the
    future action owner. No ambient default opener, target discovery or receipt
    admission exists in this primitive.
    """
    proof.tick(deadline)
    require(type(retained_roots) is frozenset
        and retained_roots <= {logical for logical, item in obligations["generated"].items()
            if "artifact_root" in item})
    actual_producer = producer_objects(obligations, runtime)
    schedule.same_records(actual_producer, producer_records)
    _, actual_selected = candidates(obligations, selected_candidates)
    require(set(actual_selected) == set(selected_candidates))
    merged = dict(producer_records)
    for logical, row in selected_candidates.items():
        if logical in merged:
            schedule.same_records({logical: merged[logical]}, {logical: row})
        else:
            merged[logical] = row
    require(set(descriptors) == set(merged) and 0 < len(merged) <= MAX_ROOTS)
    registration = "".join("\n".join(merged[root]["record"])+"\n" for root in sorted(merged))
    require(type(registration) is str and len(registration.encode("ascii")) <= proof.MAX_OUTPUT)
    parsed = seed.registrations(registration, sorted(merged), current_flake_paths=True)
    schedule.same_records(parsed, merged)
    split = lambda path: ("/".join(path.split("/")[:4]), "/".join(path.split("/")[4:]))
    def witness(stream):
        row = os.fstat(stream.fileno())
        return (row.st_dev, row.st_ino, row.st_uid, row.st_gid, row.st_mode,
                row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    with ExitStack() as held:
        canonical = {name: seed.resolve_member(runtime, runtime["tools"][name]) for name in ("nix", "nix_store")}
        tools = {name: held.enter_context(opener(*split(path))) for name, path in canonical.items()}
        before = {name: witness(stream) for name, stream in tools.items()}
        held_paths = {canonical[name]: stream for name, stream in tools.items()}
        def pinned(root, relative):
            path = root+("/"+relative if relative else "")
            if path not in held_paths:
                return opener(root, relative)
            os.lseek(held_paths[path].fileno(), 0, os.SEEK_SET)
            return os.fdopen(os.dup(held_paths[path].fileno()), "rb")
        total = 0
        for logical in sorted(merged):
            proof.tick(deadline)
            total += object_hash(descriptors[logical], merged[logical], pinned, deadline,
                                 retained_transport=logical in retained_roots)
            require(total <= MAX_NAR_BYTES)
        root = proof.OwnedRoot(parent)
        result = None
        try:
            root.recheck()
            require(os.statvfs(root.path).f_bavail*os.statvfs(root.path).f_frsize >= 2*total+proof.FREE_FLOOR)
            for name in ("private-store", "home", "config", "tmp"):
                (root.path/name).mkdir(mode=0o700)
            private = root.path/"private-store"
            store = private/"nix/store"
            store.mkdir(parents=True, mode=0o755)
            for logical in sorted(merged):
                copied = schedule.copy_tree(descriptors[logical], store/logical.rsplit("/",1)[1], pinned, deadline)
                row = merged[logical]["record"]
                require(copied["narHash"] == "sha256:"+seed.expected_hash(row[1])
                    and copied["narSize"] == int(row[2]))
            for name, path in canonical.items():
                with opener(*split(path)) as current:
                    require(witness(tools[name]) == before[name] == witness(current))
            reg = root.path/"registration"
            reg.write_bytes(registration.encode("ascii"))
            os.chmod(reg, 0o400)
            common = proof.common(runtime["tools"]["nix_store"], private)
            with nar.open_regular(str(reg), "") as stream:
                require(runner(common+["--load-db"], proof.environment(root.path), root.path,
                    deadline, input_file=stream, tool_fd=tools["nix_store"].fileno()) == b"")
            dumped = runner(common+["--dump-db"], proof.environment(root.path), root.path,
                deadline, tool_fd=tools["nix_store"].fileno())
            schedule.same_records(merged, proof.readback_records(dumped, sorted(merged),
                                                               current_flake_paths=True))
            raw_graph = runner(schedule.plan(runtime["tools"], private, "", obligations["target"]["drvPath"]),
                proof.environment(root.path), root.path, deadline, tool_fd=tools["nix"].fileno(),
                output_limit=schedule.MAX_GRAPH_BYTES)
            graph = schedule.derivations(raw_graph, obligations["target"])
            require(seed.sha(raw_graph) == obligations["derivation_json_sha256"]
                    and seed.encoded(graph) == seed.encoded(obligations["derivations"]))
            # query() itself has fixed capture/4MiB/held-FD/offline grammar.
            plan = missing.query(runtime["tools"], private, root.path, obligations["target"]["drvPath"],
                frozenset(graph), deadline, tool_fd=tools["nix_store"].fileno())
            checks = readiness(obligations, plan, merged)
            for logical in sorted(merged):
                original = object_hash(descriptors[logical], merged[logical], pinned, deadline,
                                       retained_transport=logical in retained_roots)
                physical = store/logical.rsplit("/",1)[1]
                actual = proof.describe_root(logical, physical)
                require(seed.encoded(actual) == seed.encoded(descriptors[logical]))
                copied = object_hash(actual, merged[logical],
                    lambda root, relative: nar.open_regular(str(store/root.rsplit("/",1)[1]), relative), deadline)
                require(original == copied)
            for name, path in canonical.items():
                with opener(*split(path)) as current:
                    require(witness(tools[name]) == before[name] == witness(current))
            root.recheck()
            result = {"schema_version": 1, "kind": KIND, "plan": checks,
                "restored_registration_sha256": seed.sha(registration.encode("ascii")),
                "verified_roots": len(merged), "verified_nar_bytes": total,
                "graph_rechecked": True, "original_and_copied_bytes_rechecked": True,
                "realized": False, "complete_build_seed_verified": False, "native_runtime_qualified": False,
                "sdk_qualified": False, "execution_authority": False}
        finally:
            root.close(deadline+proof.CLEANUP_SECONDS)
        require(not os.path.lexists(root.path))
        proof.tick(deadline)
        result["private_root_removed"] = True
        return result
