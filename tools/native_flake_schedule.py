"""Fixed offline current-flake obligations in an owned private store; no builds."""
import argparse
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

import nar_descriptor as nar
import native_flake_sources as sources
import nix_interpreter_closure as closure
import nix_private_store_seed as seed
import nix_private_store_qualification as proof
from verify_declared_nars import metadata_alias_roots, open_declared

KIND = "omux-native-flake-obligations-v1"
MAX_SECONDS = 600
MAX_GRAPH_BYTES = 32 * 1024**2
MAX_ARTIFACT_BYTES = 64 * 1024**2
MAX_OBJECTS = 4096
# Total generated inventory includes imported sources/scripts beyond graph derivations.
MAX_GENERATED_OBJECTS = closure.GENERATED_MAX_RECORDS
PROJECT_FILES = ("flake.nix", "flake.lock", "tools/zig-index.json", "tools/codex_upstream_archives.json")
PHASE = "admission"
PHASE_ELAPSED = []
DIAGNOSTICS = None
DIAGNOSTIC_ENTRY = None
GRAPH_DOCUMENT_REASON = None
GRAPH_PATH_SITE = None
GRAPH_PATH_REFUSAL = None
REGISTRATION_JOIN_REASON = None
REGISTRATION_READBACK_PHASES = frozenset(("registration-readback-ascii", "registration-readback-wire",
    "registration-readback-wire-hash", "registration-readback-parse"))
GRAPH_PATH_SITES = frozenset(("derivation-key", "input-source", "input-derivation",
                              "output-path", "fixed-output-env"))
MAX_WITNESS_MS = (MAX_SECONDS + 120) * 1000


def elapsed_witness(entry):
    require(type(entry) is float)
    elapsed = max(0, int((time.monotonic()-entry)*1000))
    return {"elapsed_ms": min(elapsed, MAX_WITNESS_MS), "clamped": elapsed > MAX_WITNESS_MS}


def diagnostic_summary():
    """Only fixed phases/numeric timing and already-redacted child metadata."""
    return {"phase": PHASE, "phase_elapsed": PHASE_ELAPSED,
            "elapsed": elapsed_witness(DIAGNOSTIC_ENTRY) if DIAGNOSTIC_ENTRY is not None else None,
            "child": DIAGNOSTICS, "graph_document_reason": GRAPH_DOCUMENT_REASON,
            "graph_path_site": GRAPH_PATH_SITE, "graph_path_refusal": GRAPH_PATH_REFUSAL,
            "registration_readback_phase": proof.PHASE if PHASE == "generated-registration-records"
                and proof.PHASE in REGISTRATION_READBACK_PHASES else None,
            "registration_join_reason": REGISTRATION_JOIN_REASON,
            "registration_parse": closure.REGISTRATION_PARSE_DIAGNOSTIC
                if PHASE == "generated-registration-records" else None}


def require(value):
    seed.require(value)


def path_refused(site, reason):
    global GRAPH_PATH_SITE, GRAPH_PATH_REFUSAL
    if site is not None:
        require(isinstance(site, str) and site in GRAPH_PATH_SITES)
        GRAPH_PATH_SITE, GRAPH_PATH_REFUSAL = site, reason
    raise ValueError("current-flake store path refused")


def store_path(value, *, drv=False, site=None):
    # One pinned grammar shared with purpose-bound generated registration parsing.
    reason = closure.current_flake_path_refusal(value, drv=drv)
    if reason is not None:
        path_refused(site, reason)
    return value

def base_path(value, *, drv=False, site=None):
    if not isinstance(value, str):
        path_refused(site, "type")
    if "/" in value:
        path_refused(site, "basename")
    return store_path("/nix/store/" + value, drv=drv, site=site)


def parse(raw):
    require(isinstance(raw, bytes) and len(raw) <= MAX_GRAPH_BYTES)
    return json.loads(raw, object_pairs_hook=seed.unique)


def target_document(raw):
    value = parse(raw)
    # Nix 2.34 JSON collapses any attrset carrying the reserved outPath key.
    # Use one exact nonreserved wire key, then retain the existing internal ABI.
    require(isinstance(value, dict) and set(value) == {"drvPath", "outputPath", "system", "sourcePaths"}
        and value["system"] == "x86_64-linux"
        and isinstance(value["sourcePaths"], dict))
    store_path(value["drvPath"], drv=True)
    store_path(value["outputPath"])
    require(value["outputPath"].endswith("-omux-bazel-closure")
        and set(value["sourcePaths"]) == {"project", *sources.ROLES})
    for path in value["sourcePaths"].values():
        store_path(path)
    require(len(set(value["sourcePaths"].values())) == 4)
    return {"drvPath": value["drvPath"], "outPath": value["outputPath"],
            "system": value["system"], "sourcePaths": value["sourcePaths"]}


def derivations(raw, target):
    """Pinned Nix 2.34 JSON version4, with fixed redacted refusal families."""
    global GRAPH_DOCUMENT_REASON, GRAPH_PATH_SITE, GRAPH_PATH_REFUSAL
    GRAPH_DOCUMENT_REASON, GRAPH_PATH_SITE, GRAPH_PATH_REFUSAL = None, None, None
    reason = "envelope"
    try:
        value = parse(raw)
        require(isinstance(value, dict) and set(value) == {"version", "derivations"}
            and type(value["version"]) is int and value["version"] == 4)
        rows = value["derivations"]
        require(isinstance(rows, dict) and 0 < len(rows) <= MAX_OBJECTS)
        result = {}
        required = {"name", "version", "outputs", "inputs", "system", "builder", "args", "env"}
        for basename, row in rows.items():
            reason = "path"
            path = base_path(basename, drv=True, site="derivation-key")
            reason = "node"
            require(isinstance(row, dict) and required <= set(row) <= required | {"structuredAttrs"}
                and type(row["version"]) is int and row["version"] == 4
                and isinstance(row["name"], str) and len(row["name"]) <= 256
                and isinstance(row["system"], str) and len(row["system"]) <= 128
                and isinstance(row["builder"], str) and len(row["builder"]) <= 4096
                and isinstance(row["args"], list) and all(isinstance(arg, str) for arg in row["args"])
                and isinstance(row["env"], dict) and all(isinstance(key, str) and isinstance(item, str)
                    for key, item in row["env"].items()))
            reason = "inputs"
            inputs = row["inputs"]
            require(isinstance(inputs, dict) and set(inputs) == {"srcs", "drvs"}
                and isinstance(inputs["srcs"], list) and len(inputs["srcs"]) <= MAX_OBJECTS
                and len(set(inputs["srcs"])) == len(inputs["srcs"])
                and isinstance(inputs["drvs"], dict) and len(inputs["drvs"]) <= MAX_OBJECTS)
            reason = "path"
            input_srcs = sorted(base_path(item, site="input-source") for item in inputs["srcs"])
            input_drvs = {}
            for name, node in inputs["drvs"].items():
                reason = "path"
                child = base_path(name, drv=True, site="input-derivation")
                reason = "inputs"
                require(isinstance(node, dict) and set(node) == {"outputs", "dynamicOutputs"}
                    and isinstance(node["outputs"], list) and 0 < len(node["outputs"]) <= 32
                    and len(set(node["outputs"])) == len(node["outputs"])
                    and all(isinstance(output, str) and re.fullmatch("[A-Za-z0-9_+-]{1,64}", output)
                        for output in node["outputs"])
                    and isinstance(node["dynamicOutputs"], dict) and not node["dynamicOutputs"])
                input_drvs[child] = sorted(node["outputs"])
            reason = "output"
            outputs = row["outputs"]
            require(isinstance(outputs, dict) and 0 < len(outputs) <= 32)
            selected = {}
            for name, item in outputs.items():
                reason = "output"
                require(isinstance(name, str) and re.fullmatch("[A-Za-z0-9_+-]{1,64}", name)
                    and isinstance(item, dict))
                if set(item) == {"path"}:
                    reason = "path"
                    expected = base_path(item["path"], site="output-path")
                    reason = "env"
                    require(row["env"].get(name) == expected)
                    selected[name] = {"kind": "input-addressed", "path": expected}
                elif set(item) == {"method", "hash"}:
                    require(isinstance(item["method"], str) and len(item["method"]) <= 64
                        and isinstance(item["hash"], str) and len(item["hash"]) <= 256)
                    reason = "path"
                    selected[name] = {"kind": "fixed-content", "method": item["method"], "hash": item["hash"],
                                      "path": store_path(row["env"].get(name), site="fixed-output-env")}
                elif not item:
                    # Preserve an unresolved obligation; never claim complete seed.
                    selected[name] = {"kind": "deferred", "path": None}
                else:
                    raise ValueError("unsupported floating/dynamic/impure derivation")
            result[path] = {"name": row["name"], "system": row["system"], "builder": row["builder"],
                "outputs": selected, "inputDrvs": input_drvs, "inputSrcs": input_srcs,
                "json_sha256": seed.sha(seed.encoded(row))}
        reason = "target-join"
        require(target["drvPath"] in result
            and result[target["drvPath"]]["outputs"].get("out", {}).get("path") == target["outPath"])
        reason = "reachability"
        pending, seen = [target["drvPath"]], set()
        while pending:
            path = pending.pop()
            if path in seen:
                continue
            require(path in result)
            seen.add(path)
            row = result[path]
            for child, outputs in row["inputDrvs"].items():
                require(child in result and all(output in result[child]["outputs"] for output in outputs))
                pending.append(child)
            pending.extend(item for item in row["inputSrcs"] if item.endswith(".drv"))
        require(seen == set(result))
        return result
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError):
        # Literals above only: never retain input values, paths or exception text.
        GRAPH_DOCUMENT_REASON = reason
        raise


def same_records(left, right):
    global REGISTRATION_JOIN_REASON
    REGISTRATION_JOIN_REASON = "roots"
    require(set(left) == set(right))
    for logical in left:
        a, b = left[logical], right[logical]
        REGISTRATION_JOIN_REASON = "nar-hash"
        require(seed.expected_hash(a["record"][1]) == seed.expected_hash(b["record"][1]))
        REGISTRATION_JOIN_REASON = "nar-size"
        require(int(a["record"][2]) == int(b["record"][2]))
        REGISTRATION_JOIN_REASON = "deriver"
        require(a["record"][3] == b["record"][3])
        REGISTRATION_JOIN_REASON = "references"
        require(set(a["references"]) == set(b["references"]))
    REGISTRATION_JOIN_REASON = None


def copy_tree(descriptor, destination, opener, deadline, *, durable=True):
    """Reuse the seed copier; source descriptors gain no host-link execution."""
    require(type(durable) is bool)
    for node in sorted(descriptor["nodes"], key=lambda row: (len(row["path"].split("/")) if row["path"] else 0, row["path"])):
        proof.tick(deadline)
        path = destination / node["path"] if node["path"] else destination
        if node["type"] == "directory":
            path.mkdir(mode=0o700)
        elif node["type"] == "symlink":
            path.symlink_to(node["target"])
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output, opener(descriptor["root"], node["path"]) as original:
                remaining = node["size"]
                while remaining:
                    proof.tick(deadline)
                    data = original.read(min(65536, remaining))
                    require(bool(data))
                    output.write(data)
                    remaining -= len(data)
                require(original.read(1) == b"")
                output.flush()
                if durable:
                    os.fsync(output.fileno())
                os.fchmod(output.fileno(), 0o555 if node["executable"] else 0o444)
    actual = proof.describe_root(descriptor["root"], destination)
    require(seed.encoded(actual) == seed.encoded(descriptor))
    copied = nar.hash_descriptor(actual,
        opener=lambda _, name: nar.open_regular(str(destination), name), deadline=deadline)
    original = nar.hash_descriptor(descriptor, opener=opener, deadline=deadline)
    require(copied == original)
    return copied


def copied_sources(bundle, label_root, physical_roots, directory, deadline):
    paths, hashes = {}, {}
    for item in bundle["sources"]:
        role, descriptor = item["role"], item["descriptor"]
        nodes = {node["path"]: node for node in descriptor["nodes"]}
        def opener(root, relative):
            require(root == descriptor["root"] and relative in item["regularInputs"])
            alias = item["regularInputs"][relative]
            return open_declared(Path(label_root) / alias,
                [Path(base) / alias for base in physical_roots],
                str(Path(root) / relative), nodes[relative])
        (directory / role).mkdir(mode=0o700)
        path = directory / role / "source"
        # Disposable inputs are rehashed before import, with no crash promise.
        copied = copy_tree(descriptor, path, opener, deadline, durable=False)
        require(copied["narHash"] == item["narHash"])
        paths[role], hashes[role] = path, copied["narHash"][7:]
    return paths, hashes


def project_copy(payloads, directory, deadline):
    require(set(payloads) == set(PROJECT_FILES))
    directory.mkdir(mode=0o700)
    (directory / "tools").mkdir(mode=0o700)
    for name in PROJECT_FILES:
        proof.tick(deadline)
        require(isinstance(payloads[name], bytes) and len(payloads[name]) <= 2 * 1024**2)
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "wb") as output:
            output.write(payloads[name])
            output.flush()
            os.fsync(output.fileno())
    descriptor = nar.describe(directory)
    hashed = nar.hash_descriptor(descriptor, deadline=deadline)
    return hashed["narHash"][7:]


def expression(wrapper, paths, hashes):
    require(set(paths) == set(hashes) == {"project", *sources.ROLES})
    bindings = {}
    for role in paths:
        require(Path(paths[role]).is_absolute() and re.fullmatch("[a-f0-9]{64}", hashes[role]) is not None)
        bindings[role] = ('builtins.path { name = "source"; recursive = true; path = ' +
            json.dumps(str(paths[role])) + '; sha256 = ' + json.dumps(hashes[role]) + '; }')
    return ("let projectSource = "+bindings["project"]+"; nixpkgsSource = "+bindings["nixpkgs"]+
        "; utilsSource = "+bindings["flake-utils"]+"; systemsSource = "+bindings["systems"]+
        "; in ("+wrapper+") { inherit projectSource nixpkgsSource utilsSource systemsSource; }")


def plan(tools, private, expr, drv=None):
    base = proof.common(tools["nix"], private) + ["--extra-experimental-features", "nix-command",
        "--offline", "--option", "pure-eval", "true"]
    # MixEvalArgs belongs to the selected leaf command, not root NixArgs.
    evaluation_store = ["--eval-store", "local?root="+str(private)]
    return base + (["eval"] + evaluation_store + ["--json", "--expr", expr] if drv is None else
                   ["derivation", "show"] + evaluation_store +
                   ["--recursive", store_path(drv, drv=True)])


def generated_objects(private, records, runtime_roots, target, graph, deadline):
    """Retain new evaluated objects; imported full sources stay mapped by NAR."""
    imported = set(target["sourcePaths"].values())
    require(imported <= set(records) and target["outPath"] not in records)
    srcs = {path for row in graph.values() for path in row["inputSrcs"]}
    require(srcs | set(graph) <= set(records))
    selected = sorted(set(records) - set(runtime_roots))
    # Count all retained registrations; never prune foreign roots to fit the envelope.
    require(len(records) <= MAX_GENERATED_OBJECTS and len(selected) <= MAX_GENERATED_OBJECTS)
    objects, payloads, total = {}, {}, 0
    for index, logical in enumerate(selected):
        proof.tick(deadline)
        physical = private / "nix/store" / logical.rsplit("/", 1)[1]
        descriptor = proof.describe_root(logical, physical)
        hashed = nar.hash_descriptor(descriptor,
            opener=lambda _, name: nar.open_regular(str(physical), name), deadline=deadline)
        row = records[logical]["record"]
        require(hashed["narHash"] == "sha256:"+seed.expected_hash(row[1]) and hashed["narSize"] == int(row[2]))
        item = {"descriptor": descriptor, "narHash": hashed["narHash"], "narSize": hashed["narSize"]}
        if logical in imported:
            item["source_role"] = next(name for name, path in target["sourcePaths"].items() if path == logical)
        else:
            item["artifact_root"] = "generated/"+str(index).zfill(8)
            for node in descriptor["nodes"]:
                if node["type"] == "regular":
                    require(type(node["size"]) is int and 0 <= node["size"] <= MAX_ARTIFACT_BYTES-total)
                    total += node["size"]
                    raw = bytearray()
                    with nar.open_regular(str(physical), node["path"]) as stream:
                        remaining = node["size"]
                        while remaining:
                            proof.tick(deadline)
                            data = stream.read(min(65536, remaining))
                            require(bool(data))
                            raw.extend(data)
                            remaining -= len(data)
                        require(stream.read(1) == b"")
                    payloads[(item["artifact_root"], node["path"])] = bytes(raw)
        objects[logical] = item
    require(len(objects) <= MAX_GENERATED_OBJECTS and set(graph) <= set(objects))
    return objects, payloads


def operate(value, seed_raw, descriptor_raw, descriptor_path, project, wrapper, parent, deadline, *, runner=proof.run, entry=None):
    global PHASE, PHASE_ELAPSED, DIAGNOSTICS, DIAGNOSTIC_ENTRY, GRAPH_DOCUMENT_REASON, GRAPH_PATH_SITE, GRAPH_PATH_REFUSAL, REGISTRATION_JOIN_REASON
    DIAGNOSTIC_ENTRY = float(time.monotonic()) if entry is None else entry
    require(type(DIAGNOSTIC_ENTRY) is float and DIAGNOSTIC_ENTRY <= time.monotonic())
    PHASE_ELAPSED, DIAGNOSTICS, GRAPH_DOCUMENT_REASON = [], None, None
    GRAPH_PATH_SITE, GRAPH_PATH_REFUSAL, REGISTRATION_JOIN_REASON = None, None, None
    closure.REGISTRATION_PARSE_DIAGNOSTIC = None
    def phase(name):
        global PHASE
        PHASE = name
        require(len(PHASE_ELAPSED) < 24)
        PHASE_ELAPSED.append({"phase": name, **elapsed_witness(DIAGNOSTIC_ENTRY)})
    phase("source-verify")
    bundle = json.loads(descriptor_raw, object_pairs_hook=seed.unique)
    physical_roots = metadata_alias_roots(descriptor_path)
    label_root = Path(descriptor_path).absolute().parent
    # Admit every locked role/label and the exact wire-size bound before any copy.
    _, _, _, _, source_bytes = sources.admit(project["flake.lock"], descriptor_raw, deadline=deadline)
    seed.validate(value)
    opener = proof.source_opener(value, {row["source"] for row in value["files"]})
    canonical = {name: seed.resolve_member(value, value["tools"][name]) for name in ("nix", "nix_store")}
    split = lambda path: ("/".join(path.split("/")[:4]), "/".join(path.split("/")[4:]))
    def witness(stream):
        row = os.fstat(stream.fileno())
        return (row.st_dev, row.st_ino, row.st_uid, row.st_gid, row.st_mode,
                row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    with ExitStack() as held:
        streams = {path: held.enter_context(opener(*split(path))) for path in set(canonical.values())}
        original_stat = {path: witness(stream) for path, stream in streams.items()}
        def pinned(root, relative):
            path = root+("/"+relative if relative else "")
            if path not in streams:
                return opener(root, relative)
            os.lseek(streams[path].fileno(), 0, os.SEEK_SET)
            return os.fdopen(os.dup(streams[path].fileno()), "rb")
        executable = streams[canonical["nix"]]
        legacy_executable = streams[canonical["nix_store"]]
        phase("runtime-seed-byte-proof")
        seed_bytes = proof.verify_nars(value, pinned, deadline)
        root = proof.OwnedRoot(parent)
        result = None
        try:
            root.recheck()
            require(os.statvfs(root.path).f_bavail * os.statvfs(root.path).f_frsize >=
                2*(seed_bytes+source_bytes)+proof.FREE_FLOOR)
            for name in ("private-store", "home", "config", "tmp", "sources"):
                (root.path/name).mkdir(mode=0o700)
            private = root.path/"private-store"
            phase("seed-copy")
            proof.copy_seed(value, private, pinned, deadline)
            phase("source-copy")
            before_sources = sources.verify(project["flake.lock"], descriptor_raw, label_root,
                physical_roots, deadline=deadline, copy_directory=root.path/"sources")
            require(before_sources["verifiedNarBytes"] == source_bytes)
            paths = {role: root.path/"sources"/role/"source" for role in sources.ROLES}
            hashes = {row["role"]: row["narHash"][7:] for row in before_sources["sources"]}
            (root.path/"project").mkdir(mode=0o700)
            paths["project"] = root.path/"project/source"
            hashes["project"] = project_copy(project, paths["project"], deadline)
            reg = root.path/"registration"
            reg.write_bytes(value["registration"].encode())
            os.chmod(reg, 0o400)
            # The explicit companion resolves within the same held seed.
            legacy = proof.common(value["tools"]["nix_store"], private)
            phase("registration-import")
            with nar.open_regular(str(reg), "") as stream:
                require(runner(legacy+["--load-db"], proof.environment(root.path), root.path, deadline,
                    input_file=stream, tool_fd=legacy_executable.fileno()) == b"")
            phase("registration-readback")
            initial_dump = runner(legacy+["--dump-db"], proof.environment(root.path), root.path, deadline,
                tool_fd=legacy_executable.fileno())
            initial = proof.readback_records(initial_dump, value["roots"])
            expected = seed.registrations(value["registration"], value["roots"])
            same_records(initial, expected)
            phase("source-store-import")
            imported = {}
            for role in sorted(paths):
                raw_path = runner(legacy+["--add-fixed", "--recursive", "sha256", str(paths[role])],
                    proof.environment(root.path), root.path, deadline, tool_fd=legacy_executable.fileno())
                logical = raw_path.decode("ascii").strip()
                require(raw_path == (logical+"\n").encode() and logical.endswith("-source"))
                imported[role] = Path(store_path(logical))
            expr = expression(wrapper, imported, hashes)
            phase("current-flake-evaluation")
            DIAGNOSTICS = {}
            raw_target = runner(plan(value["tools"], private, expr), proof.environment(root.path), root.path,
                deadline, tool_fd=executable.fileno(), output_limit=MAX_GRAPH_BYTES, diagnostics=DIAGNOSTICS)
            phase("target-document")
            target = target_document(raw_target)
            phase("imported-source-join")
            require(target["sourcePaths"] == {role: str(path) for role, path in imported.items()})
            phase("recursive-obligations")
            DIAGNOSTICS = {}
            raw_graph = runner(plan(value["tools"], private, expr, target["drvPath"]), proof.environment(root.path),
                root.path, deadline, tool_fd=executable.fileno(), output_limit=MAX_GRAPH_BYTES,
                diagnostics=DIAGNOSTICS)
            phase("recursive-document")
            graph = derivations(raw_graph, target)
            phase("generated-registration-dump")
            DIAGNOSTICS = {}
            dumped = runner(legacy+["--dump-db"], proof.environment(root.path), root.path, deadline,
                tool_fd=legacy_executable.fileno(), diagnostics=DIAGNOSTICS)
            phase("generated-registration-ascii")
            lines = dumped.decode("ascii").splitlines()
            phase("generated-registration-roots")
            roots, offset = [], 0
            while offset < len(lines):
                require(offset+5 <= len(lines) and re.fullmatch("[0-9]{1,4}", lines[offset+4]) is not None)
                roots.append(lines[offset])
                offset += 5+int(lines[offset+4])
            phase("generated-registration-records")
            records = proof.readback_records(dumped, roots, current_flake_paths=True)
            phase("runtime-registration-roots")
            require(set(value["roots"]) <= set(records))
            phase("runtime-registration-join")
            same_records({logical: records[logical] for logical in value["roots"]}, initial)
            phase("generated-byte-proof")
            objects, payloads = generated_objects(private, records, value["roots"], target, graph, deadline)
            for role, path in target["sourcePaths"].items():
                require(objects[path]["narHash"] == "sha256:"+hashes[role])
            require(proof.verify_nars(value, pinned, deadline) == seed_bytes)
            require(proof.verify_nars(value,
                lambda logical, relative: nar.open_regular(str(private/"nix/store"/logical.rsplit("/", 1)[1]), relative),
                deadline, root_directory=private/"nix/store") == seed_bytes)
            require(sources.verify(project["flake.lock"], descriptor_raw, label_root, physical_roots,
                deadline=deadline) == before_sources)
            root.recheck()
            for path, stream in streams.items():
                with opener(*split(path)) as current:
                    require(witness(stream) == original_stat[path] and witness(current) == original_stat[path])
            result = {"schema_version": 1, "kind": KIND, "status": "current-target-obligations-discovered",
                "target": target, "derivations": graph, "generated": objects,
                "seed_sha256": seed.sha(seed_raw), "source_proof": before_sources,
                "project_sha256": {name: seed.sha(raw) for name, raw in project.items()},
                "wrapper_sha256": seed.sha(wrapper.encode()), "expression_sha256": seed.sha(expr.encode()),
                "derivation_json_sha256": seed.sha(raw_graph),
                "registration_sha256": seed.sha(dumped), "registration": dumped.decode("ascii"),
                "runtime_seed_rechecked": True, "source_rechecked": True,
                "realized": False, "complete_build_seed_verified": False, "native_runtime_qualified": False,
                "sdk_qualified": False, "execution_authority": False,
                "scheduler_pruned_plan": False, "outer_guard_success_and_owned_empty_required": True}
        finally:
            failed_phase = PHASE
            phase("private-cleanup")
            root.close(deadline+proof.CLEANUP_SECONDS)
            PHASE = failed_phase
        require(not os.path.lexists(root.path))
        proof.tick(deadline)
        result["private_root_removed"] = True
        return result, payloads


def persist(result, payloads, directory, deadline):
    proof.tick(deadline)
    directory = Path(directory).resolve(strict=True)
    require(directory.is_dir() and os.stat(directory).st_uid == os.getuid())
    (directory/"generated").mkdir(mode=0o700)
    for logical, item in result["generated"].items():
        if "artifact_root" not in item:
            continue
        destination = directory/item["artifact_root"]
        payload_lookup = lambda _, name: io.BytesIO(payloads[(item["artifact_root"], name)])
        copied = copy_tree(item["descriptor"], destination, payload_lookup, deadline)
        require(copied["narHash"] == item["narHash"] and copied["narSize"] == item["narSize"])
    proof.tick(deadline)
    raw = seed.encoded(result)
    require(len(raw) <= MAX_GRAPH_BYTES)
    fd = os.open(directory/"native-flake-obligations.json",
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    global PHASE
    entry = time.monotonic()
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("seed", "descriptors", "flake", "lock", "zig-index", "archives", "wrapper"):
        parser.add_argument("--"+name, required=True)
    args = parser.parse_args()
    marker = os.environ.get("OMUX_EXECUTION_GUARD", "")
    require(bool(re.fullmatch(r"/[A-Za-z0-9_./-]{1,900}/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", marker))
        and ".." not in Path(marker).parts)
    timeout = os.environ.get("TEST_TIMEOUT", "")
    require(re.fullmatch("[0-9]{1,5}", timeout) is not None and int(timeout) > proof.CLEANUP_SECONDS)
    deadline = float(entry+min(MAX_SECONDS, int(timeout)-proof.CLEANUP_SECONDS))
    with open("/proc/self/status", encoding="ascii") as stream:
        platform = proof.platform(stream.read(65537), os.getuid())
    seed_path = Path(args.seed).resolve(strict=True)
    seed_raw = seed.metadata(seed_path, seed.MAX_METADATA)
    value = json.loads(seed_raw, object_pairs_hook=seed.unique)
    seed.validate(value)
    for row in value["files"]:
        alias = seed_path.parent/row["alias"]
        require(alias.exists() and alias.resolve(strict=True) == Path(row["source"]))
    for name, filename in (("native", "native.json"), ("paths", "store-paths"), ("registration", "registration")):
        require(seed.sha(seed.metadata(seed_path.parent/filename, seed.MAX_METADATA)) == value["metadata_sha256"][name])
    inventory_sha256 = seed.sha(seed.metadata(seed_path.parent/"file-inventory.json", seed.MAX_METADATA))
    names = ("flake", "lock", "zig_index", "archives")
    project = {filename: seed.metadata(Path(getattr(args, name)).resolve(strict=True), 2*1024**2)
               for filename, name in zip(PROJECT_FILES, names)}
    descriptor_path = Path(args.descriptors).absolute()
    descriptors = seed.metadata(descriptor_path.resolve(strict=True), nar.MAX_METADATA_BYTES)
    wrapper = seed.metadata(Path(args.wrapper).resolve(strict=True), 65536).decode("ascii")
    result, payloads = operate(value, seed_raw, descriptors, descriptor_path, project, wrapper,
        os.environ["TEST_TMPDIR"], deadline, entry=entry)
    result["platform"], result["guard_epoch"] = platform, Path(marker).name
    result["seed_file_inventory_sha256"] = inventory_sha256
    result["source_descriptors_sha256"] = seed.sha(descriptors)
    result["implementation_sha256"] = {name: seed.sha(seed.metadata(Path(__file__).resolve().parent/name, 1024**2))
        for name in ("native_flake_schedule.py", "native_flake_sources.py", "nix_private_store_seed.py",
                     "nix_private_store_qualification.py", "nar_descriptor.py", "verify_declared_nars.py",
                     "verify_cached_nars.py", "nix_source_probe.py", "nix_interpreter_closure.py")}
    persist(result, payloads, os.environ["TEST_UNDECLARED_OUTPUTS_DIR"], deadline)
    print("current native flake obligations retained; complete build seed and realization remain unqualified")


if __name__ == "__main__":
    try:
        def interrupted(signum, frame):
            raise KeyboardInterrupt
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, interrupted)
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError, KeyboardInterrupt):
        print("native flake obligations refused at "+PHASE, file=sys.stderr)
        print("native flake public diagnostic "+json.dumps(diagnostic_summary(), sort_keys=True), file=sys.stderr)
        raise SystemExit(1) from None
