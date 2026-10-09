"""Selected successful obligations and finite declared leaves for a dry run.

Repository generation declares inert bytes. Qualification alone hashes/restores
them; neither operation realizes a closure or grants native dispatch authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import xml.etree.ElementTree as ET

import nar_descriptor as nar
import native_flake_schedule as schedule
import native_flake_seed_plan as plan
import native_flake_sources as sources
import nix_private_store_seed as seed
import nix_private_store_qualification as proof
from verify_declared_nars import metadata_alias_roots, open_declared

KIND = "omux-native-flake-seed-plan-inputs-v1"
SELECTION_KIND = "omux-native-flake-seed-plan-selection-v1"
TARGET = "//tools:native_flake_schedule_qualification"
COORDINATORS = ("/home/jess/.local/state/omux-execution-20261005",
    "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005")
UUID = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
HEX = re.compile(r"[a-f0-9]{64}\Z")
MAX_SELECTION = 64 * 1024
MAX_METADATA = 64 * 1024 * 1024
MAX_MAPPING = nar.MAX_METADATA_BYTES
RETAINED_TRANSPORT = "bazel-test-output-0555-v1"
RESOURCE_PROPERTIES = {"MemoryMax": "4294967296", "MemorySwapMax": "0",
    "TasksMax": "512", "CPUQuotaPerSecUSec": "2s", "PrivateNetwork": "yes",
    "KillMode": "control-group", "SendSIGKILL": "yes", "OOMPolicy": "kill"}


def require(value):
    seed.require(value)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()+b"\n"


def decode(raw, maximum=MAX_METADATA):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    return json.loads(raw, object_pairs_hook=seed.unique)


def canonical(value):
    require(type(value) is str and value.startswith("/") and len(value) <= 4096
        and str(Path(value)) == value and not any(part in ("", ".", "..")
            for part in value.split("/")[1:])
        and not any(c.isspace() or c in "\\\x00" for c in value))
    return value


def pin(value, maximum=MAX_METADATA):
    require(type(value) is dict and set(value) == {"path", "sha256", "bytes"})
    canonical(value["path"])
    require(type(value["sha256"]) is str and HEX.fullmatch(value["sha256"])
        and type(value["bytes"]) is int and 0 < value["bytes"] <= maximum)
    return value


def coordinator_leaf(path, leaf):
    return any(re.fullmatch(re.escape(root)+"/"+UUID+"/"+re.escape(leaf), path)
               for root in COORDINATORS)


def output_base(path):
    canonical(path)
    require(any(re.fullmatch(re.escape(root)+r"/(?:"+UUID+
        r"|cache-v2-[a-f0-9]{64})/output-base", path) for root in COORDINATORS))
    return path


def selection(value):
    require(type(value) is dict and set(value) == {"schema_version", "kind", "producer",
        "obligations", "candidates"} and type(value["schema_version"]) is int
        and value["schema_version"] == 1 and value["kind"] == SELECTION_KIND)
    producer = value["producer"]
    require(type(producer) is dict and set(producer) == {"receipt", "evidence", "log", "xml",
        "source_commit", "graph_sha256"})
    for name in ("receipt", "evidence", "log", "xml"):
        pin(producer[name], MAX_METADATA)
    require(coordinator_leaf(producer["receipt"]["path"], "receipt.json"))
    parent = str(Path(producer["receipt"]["path"]).parent)
    require(producer["evidence"]["path"] == parent+"/test-evidence.json")
    require(all(re.fullmatch(re.escape(parent)+r"/test-evidence/[a-f0-9]{64}[.]evidence",
        producer[name]["path"]) for name in ("log", "xml")))
    require(type(producer["source_commit"]) is str
        and re.fullmatch(r"[a-f0-9]{40}", producer["source_commit"]) is not None
        and type(producer["graph_sha256"]) is str and HEX.fullmatch(producer["graph_sha256"]) is not None)
    pin(value["obligations"], schedule.MAX_GRAPH_BYTES)
    # Reject unrelated cache leaves before any referenced role is read.
    suffix = "/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/native_flake_schedule_qualification/test.outputs/native-flake-obligations.json"
    require(any(re.fullmatch(re.escape(root)+r"/(?:"+UUID+
        r"|cache-v2-[a-f0-9]{64})/output-base"+re.escape(suffix),
        value["obligations"]["path"]) for root in COORDINATORS))
    candidate = value["candidates"]
    if candidate is not None:
        require(type(candidate) is dict and set(candidate) == {"registration", "paths"})
        for name, leaf in (("registration", "registration"), ("paths", "store-paths")):
            pin(candidate[name], seed.MAX_METADATA)
            require(re.fullmatch(seed.STORE+"/"+leaf, candidate[name]["path"]) is not None)
        require(str(Path(candidate["registration"]["path"]).parent)
            == str(Path(candidate["paths"]["path"]).parent))
    return value


def witness(row):
    return (row.st_dev, row.st_ino, row.st_uid, row.st_gid, row.st_mode,
        row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)


def selected_bytes(value, deadline):
    """Canonical no-follow metadata leaf, hash, size and stable named witness."""
    pin(value)
    proof.tick(deadline)
    with nar.open_regular(value["path"], "") as stream:
        before = os.fstat(stream.fileno())
        require(before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022
            and before.st_nlink == 1 and before.st_size == value["bytes"])
        content = bytearray()
        while len(content) <= value["bytes"]:
            proof.tick(deadline)
            part = stream.read(min(65536, value["bytes"]+1-len(content)))
            if not part:
                break
            content.extend(part)
        require(len(content) == value["bytes"] and seed.sha(content) == value["sha256"])
        with nar.open_regular(value["path"], "") as named:
            require(witness(before) == witness(os.fstat(stream.fileno()))
                == witness(os.fstat(named.fileno())))
        return bytes(content)


def duration(value):
    require(type(value) is str)
    match = re.fullmatch(r"([1-9][0-9]*)(us|ms|s|min)", value)
    require(match is not None)
    result = int(match[1])*{"us": 1e-6, "ms": .001, "s": 1, "min": 60}[match[2]]
    require(0 < result <= 1200)
    return result


def producer_success(selected, raw):
    """Only supplied pinned bytes; no ambient receipt/evidence lookup."""
    selected = selection(selected)
    receipt = decode(raw["receipt"])
    epoch = Path(selected["producer"]["receipt"]["path"]).parent.name
    require(receipt["id"] == epoch and receipt["artifact_epoch"] == epoch
        and receipt["unit"] == "omux-execution-"+epoch+".service"
        and receipt["profile"] == "standard" and receipt["manager"] == "system"
        and type(receipt["exit"]) is int and receipt["exit"] == 0
        and type(receipt["workload_exit"]) is int and receipt["workload_exit"] == 0
        and receipt["controller_failure"] is None and receipt["descendants_empty"] is True
        and receipt["cleanup"]["state"] == "empty" and receipt["source_dirty"] == "false"
        and receipt["source_commit"] == selected["producer"]["source_commit"]
        and receipt["graph_sha256"] == selected["producer"]["graph_sha256"]
        and receipt["verb"] == "test" and receipt["targets"] == [TARGET]
        and receipt["test_evidence"]["state"] == "preserved")
    observed = receipt["observed_properties"]
    require(type(observed) is dict and all(observed.get(name) == value
        for name, value in RESOURCE_PROPERTIES.items()))
    duration(observed["RuntimeMaxUSec"])
    base = output_base(receipt["output_base"])
    expected = base+"/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/native_flake_schedule_qualification/test.outputs/native-flake-obligations.json"
    require(selected["obligations"]["path"] == expected)
    require(type(receipt["epoch_start_ns"]) is int and receipt["epoch_start_ns"] > 0
        and receipt["test_evidence"]["sha256"] == selected["producer"]["evidence"]["sha256"])
    evidence = decode(raw["evidence"])
    require(type(evidence["schema"]) is int and evidence["schema"] == 1
        and type(evidence["bazel_exit"]) is int and evidence["bazel_exit"] == 0
        and type(evidence["epoch_start_ns"]) is int
        and evidence["epoch_start_ns"] == receipt["epoch_start_ns"]
        and evidence["targets"] == [TARGET] and type(evidence["results"]) is list
        and len(evidence["results"]) == 1)
    row = evidence["results"][0]
    require(row["target"] == TARGET and row["state"] == "observed")
    for role, member in (("log", "test.log"), ("xml", "test.xml")):
        entries = [item for item in row["files"] if item["source"] == member]
        require(len(entries) == 1 and entries[0]["state"] == "copied")
        item = entries[0]
        expected_pin = selected["producer"][role]
        require(item["file"] == Path(expected_pin["path"]).name
            and item["sha256"] == expected_pin["sha256"]
            and type(item["bytes"]) is int and item["bytes"] == expected_pin["bytes"])
    xml = ET.fromstring(raw["xml"])
    suites = [xml] if xml.tag == "testsuite" else list(xml.findall("testsuite"))
    require(xml.tag in ("testsuite", "testsuites") and bool(suites))
    require(all(int(row.get("tests", "0")) > 0 and all(int(row.get(name, "0")) == 0
        for name in ("failures", "errors", "skipped")) for row in suites))
    if "obligations" in raw:
        body = decode(raw["obligations"], schedule.MAX_GRAPH_BYTES)
        require(body["guard_epoch"] == epoch)
    return receipt


def candidate_records(selected, raw):
    if selected["candidates"] is None:
        return {}
    lines = raw["candidate_paths"].decode("ascii").splitlines()
    require(lines == sorted(set(lines)) and 0 < len(lines) <= plan.MAX_CANDIDATE_ROOTS
        and all(re.fullmatch(seed.STORE, path) for path in lines))
    return seed.registrations(raw["candidate_registration"].decode("ascii"), lines)


def metadata_roles(selected):
    roles = {name: value for name, value in selected["producer"].items()
        if name in ("receipt", "evidence", "log", "xml")}
    roles["obligations"] = selected["obligations"]
    if selected["candidates"] is not None:
        roles.update(candidate_registration=selected["candidates"]["registration"],
            candidate_paths=selected["candidates"]["paths"])
    return roles


def mapping(selected, raw, runtime_raw, source_raw, project_sources, deadline):
    """All role namespaces are admitted before sidecar or candidate tree IO."""
    producer_success(selected, raw)
    body = decode(raw["obligations"], schedule.MAX_GRAPH_BYTES)
    require(body["seed_sha256"] == seed.sha(runtime_raw)
        and body["source_descriptors_sha256"] == seed.sha(source_raw))
    runtime = decode(runtime_raw, seed.MAX_METADATA)
    records = plan.producer_objects(body, runtime)
    candidates = candidate_records(selected, raw)
    _, chosen = plan.candidates(body, candidates)
    source_bundle = decode(source_raw, nar.MAX_METADATA_BYTES)
    require(type(source_bundle["sources"]) is list and len(source_bundle["sources"]) == 3)
    source_items = {item["role"]: item for item in source_bundle["sources"]}
    require(set(source_items) == set(sources.ROLES))
    sources.validate_selection({role: item["descriptor"]["root"]
        for role, item in source_items.items()})
    require(set(project_sources) == set(schedule.PROJECT_FILES))
    roots, regular, count, nodes = {}, [], 0, 0
    def add(logical, descriptor, physical, *, retained=False):
        nonlocal count, nodes
        require(logical not in roots)
        by_path, _ = nar.validate_descriptor(descriptor)
        require(descriptor["root"] == logical)
        nodes += len(by_path)
        require(nodes <= nar.MAX_ENTRIES)
        mapped = {}
        for relative, node in sorted(by_path.items()):
            if node["type"] != "regular":
                continue
            actual = canonical(physical(relative))
            proof.tick(deadline)
            with nar.open_regular(actual, "") as stream:
                info = os.fstat(stream.fileno())
                require(info.st_size == node["size"])
                if retained:
                    require(stat.S_IMODE(info.st_mode) == 0o555 and info.st_uid == os.getuid()
                        and info.st_gid == os.getgid() and info.st_nlink == 1)
                else:
                    require(bool(info.st_mode & stat.S_IXUSR) == node["executable"])
            alias = "regular/"+str(count).zfill(8)
            count += 1
            require(count <= seed.MAX_FILES)
            mapped[relative] = {"alias": alias, "source": actual}
            regular.append({"alias": alias, "source": actual})
        roots[logical] = {"descriptor": descriptor, "regularInputs": mapped}
        if retained:
            roots[logical]["retained_transport"] = RETAINED_TRANSPORT
    for logical in runtime["roots"]:
        add(logical, runtime["descriptors"][logical],
            lambda relative, logical=logical: logical+("/"+relative if relative else ""))
    output = Path(selected["obligations"]["path"]).parent
    for logical, item in sorted(body["generated"].items()):
        if "artifact_root" in item:
            physical = output/item["artifact_root"]
            actual = nar.describe(physical)
            expected_nodes, _ = nar.validate_descriptor(item["descriptor"])
            actual_nodes, _ = nar.validate_descriptor(actual)
            require(set(actual_nodes) == set(expected_nodes))
            for relative, node in actual_nodes.items():
                if node["type"] == "regular":
                    require(expected_nodes[relative]["type"] == "regular" and node["executable"] is True)
                    node["executable"] = expected_nodes[relative]["executable"]
            require(seed.encoded({**actual, "root": logical}) == seed.encoded(item["descriptor"]))
            add(logical, item["descriptor"], lambda relative, physical=physical:
                str(physical/relative) if relative else str(physical), retained=True)
        elif item["source_role"] == "project":
            require({node["path"] for node in item["descriptor"]["nodes"]
                if node["type"] == "regular"} == set(project_sources))
            add(logical, item["descriptor"], lambda relative: project_sources[relative])
        else:
            descriptor = source_items[item["source_role"]]["descriptor"]
            require(seed.encoded({**descriptor, "root": logical}) == seed.encoded(item["descriptor"]))
            origin = descriptor["root"]
            add(logical, item["descriptor"], lambda relative, origin=origin: str(Path(origin)/relative))
    for logical in sorted(chosen):
        if logical in roots:
            schedule.same_records({logical: records[logical]}, {logical: chosen[logical]})
            continue
        require(Path(logical).resolve(strict=True) == Path(logical))
        descriptor = nar.describe(logical)
        add(logical, descriptor, lambda relative, logical=logical:
            logical+("/"+relative if relative else ""))
    require(set(roots) == set(records) | set(chosen))
    return {"schema_version": 1, "kind": KIND, "roots": roots}, regular


def bundle_opener(bundle, bundle_path):
    require(type(bundle) is dict and set(bundle) == {"schema_version", "kind", "selection_sha256",
        "metadata", "roots"} and type(bundle["schema_version"]) is int
        and bundle["schema_version"] == 1 and bundle["kind"] == KIND)
    roots = bundle["roots"]
    require(type(roots) is dict and 0 < len(roots) <= plan.MAX_ROOTS)
    labels, by_root, retained, identities = set(), {}, set(), {}
    for logical, row in roots.items():
        require(type(row) is dict and set(row) in ({"descriptor", "regularInputs"},
            {"descriptor", "regularInputs", "retained_transport"})
            and row["descriptor"]["root"] == logical)
        if "retained_transport" in row:
            require(row["retained_transport"] == RETAINED_TRANSPORT)
            retained.add(logical)
        nodes, _ = nar.validate_descriptor(row["descriptor"])
        by_root[logical] = nodes
        require(set(row["regularInputs"]) == {name for name, node in nodes.items()
            if node["type"] == "regular"})
        for item in row["regularInputs"].values():
            require(type(item) is dict and set(item) == {"alias", "source"})
            canonical(item["source"])
            require(type(item["alias"]) is str and re.fullmatch(r"regular/[0-9]{8}", item["alias"])
                and item["alias"] not in labels)
            labels.add(item["alias"])
    require(len(labels) <= seed.MAX_FILES and labels == {
        "regular/"+str(index).zfill(8) for index in range(len(labels))})
    physical = metadata_alias_roots(bundle_path)
    def opener(logical, relative):
        require(logical in roots and relative in roots[logical]["regularInputs"])
        row = roots[logical]
        item = row["regularInputs"][relative]
        node = by_root[logical][relative]
        def opened():
            stream = open_declared(Path(bundle_path).parent/item["alias"],
                [Path(root)/item["alias"] for root in physical], item["source"],
                {**node, "executable": True} if logical in retained else node)
            try:
                if logical in retained:
                    info = os.fstat(stream.fileno())
                    require(stat.S_IMODE(info.st_mode) == 0o555 and info.st_uid == os.getuid()
                        and info.st_gid == os.getgid() and info.st_nlink == 1)
                    key = (logical, relative)
                    identity = witness(info)
                    require(key not in identities or identities[key] == identity)
                    identities.setdefault(key, identity)
                    with nar.open_regular(item["source"], "") as named:
                        require(witness(os.fstat(named.fileno())) == identity)
                return stream
            except BaseException:
                stream.close()
                raise
        stream = opened()
        if logical not in retained:
            return stream
        class RetainedLease:
            def fileno(self):
                return stream.fileno()
            def read(self, count=-1):
                return stream.read(count)
            def __enter__(self):
                return self
            def close(self):
                if stream.closed:
                    return
                try:
                    require(witness(os.fstat(stream.fileno())) == identities[(logical, relative)])
                    with opened() as named:
                        require(witness(os.fstat(named.fileno())) == identities[(logical, relative)])
                finally:
                    stream.close()
            def __exit__(self, *args):
                self.close()
        return RetainedLease()
    return opener


def declared_metadata(bundle, bundle_path, selected, deadline):
    expected = metadata_roles(selected)
    require(type(bundle["metadata"]) is dict and set(bundle["metadata"]) == set(expected))
    roots = metadata_alias_roots(bundle_path)
    result = {}
    for index, name in enumerate(sorted(expected)):
        item = bundle["metadata"][name]
        require(type(item) is dict and set(item) == {"alias", "pin"}
            and item["pin"] == expected[name] and item["alias"] == "metadata/"+str(index).zfill(8))
        proof.tick(deadline)
        path = Path(bundle_path).parent/item["alias"]
        node = {"size": item["pin"]["bytes"], "executable": False}
        with open_declared(path, [Path(root)/item["alias"] for root in roots], item["pin"]["path"], node) as stream:
            raw = stream.read(item["pin"]["bytes"]+1)
        require(len(raw) == item["pin"]["bytes"] and seed.sha(raw) == item["pin"]["sha256"])
        result[name] = raw
    return result


def materialize_regular(directory, regular, deadline):
    """Batch only the closed declared aliases; byte qualification stays in TEST."""
    require(type(regular) is list and 0 < len(regular) <= seed.MAX_FILES)
    for index, item in enumerate(regular):
        proof.tick(deadline)
        require(type(item) is dict and set(item) == {"alias", "source"}
            and item["alias"] == "regular/"+str(index).zfill(8))
        canonical(item["source"])
    directory = Path(directory)
    require(directory.is_absolute() and directory.resolve(strict=True) == directory)
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    child = None
    child_identity = None
    created = []
    try:
        held = os.fstat(parent)
        require(held.st_uid == os.getuid() and not held.st_mode & 0o022)
        os.mkdir("regular", mode=0o755, dir_fd=parent)
        info = os.stat("regular", dir_fd=parent, follow_symlinks=False)
        child_identity = (info.st_dev, info.st_ino)
        child = os.open("regular", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        require((os.fstat(child).st_dev, os.fstat(child).st_ino) == child_identity)
        for item in regular:
            proof.tick(deadline)
            source = item["source"]
            require(str(Path(source).resolve(strict=True)) == source)
            with nar.open_regular(source, "") as stream:
                before = witness(os.fstat(stream.fileno()))
                leaf = item["alias"].split("/")[1]
                os.symlink(source, leaf, dir_fd=child)
                info = os.stat(leaf, dir_fd=child, follow_symlinks=False)
                created.append((leaf, (info.st_dev, info.st_ino)))
                with nar.open_regular(source, "") as named:
                    require(before == witness(os.fstat(stream.fileno())) == witness(os.fstat(named.fileno())))
        proof.tick(deadline)
        require(sorted(os.listdir(child)) == [str(index).zfill(8) for index in range(len(regular))])
    except BaseException as primary:
        if child_identity is not None:
            try:
                for leaf, identity in reversed(created):
                    info = os.stat(leaf, dir_fd=child, follow_symlinks=False)
                    require(stat.S_ISLNK(info.st_mode) and (info.st_dev, info.st_ino) == identity)
                    os.unlink(leaf, dir_fd=child)
                info = os.stat("regular", dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == child_identity)
                os.rmdir("regular", dir_fd=parent)
            except BaseException:
                primary.add_note("selected owned alias cleanup refused")
        raise
    finally:
        if child is not None:
            os.close(child)
        os.close(parent)


def generate(selected_raw, digest, runtime_raw, source_raw, project_sources, directory, deadline,
             *, materialize=False):
    require(type(digest) is str and HEX.fullmatch(digest) and seed.sha(selected_raw) == digest)
    selected = selection(decode(selected_raw, MAX_SELECTION))
    roles = metadata_roles(selected)
    raw = {name: selected_bytes(roles[name], deadline)
        for name in ("receipt", "evidence", "log", "xml")}
    producer_success(selected, raw)
    for name in sorted(set(roles)-set(raw)):
        raw[name] = selected_bytes(roles[name], deadline)
    result, regular = mapping(selected, raw, runtime_raw, source_raw, project_sources, deadline)
    result["selection_sha256"] = digest
    result["metadata"] = {}
    directory = Path(directory)
    (directory/"metadata").mkdir(mode=0o700)
    for index, name in enumerate(sorted(roles)):
        alias = "metadata/"+str(index).zfill(8)
        (directory/alias).write_bytes(raw[name])
        os.chmod(directory/alias, 0o444)
        result["metadata"][name] = {"alias": alias, "pin": roles[name]}
    content = encode(result)
    require(len(content) <= MAX_MAPPING)
    (directory/"inputs.json").write_bytes(content)
    if materialize:
        materialize_regular(directory, regular, deadline)
    return {"regularInputs": regular, "mapping_sha256": seed.sha(content),
        "regularMaterialized": materialize,
        "metadata": [item["alias"] for item in result["metadata"].values()],
        "metadataInputs": [roles[name]["path"] for name in sorted(roles)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("selection", "sha256", "seed", "descriptors", "project", "directory"):
        parser.add_argument("--"+name, required=True)
    parser.add_argument("--materialize", action="store_true")
    args = parser.parse_args()
    original_deadline = float(time.monotonic()+schedule.MAX_SECONDS)
    read = lambda file, limit: seed.metadata(Path(file), limit)
    project_sources = decode(read(args.project, MAX_SELECTION), MAX_SELECTION)
    report = generate(read(args.selection, MAX_SELECTION), args.sha256,
        read(args.seed, seed.MAX_METADATA), read(args.descriptors, nar.MAX_METADATA_BYTES),
        project_sources, args.directory, original_deadline, materialize=args.materialize)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
