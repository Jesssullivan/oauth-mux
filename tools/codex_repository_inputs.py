"""Export verified repository bytes and narrowly proved Bazel 9 HTTP markers.

No fetch, Git operation, SDK invocation or compiler admission occurs here. The
caller selects raw receipt digests and shard meanings independently. Ambient
canonical-ID files are never read. The cache is a new retained output, not a
mutation of any parent. Its inherited custody directory name is disclosed.
"""

import argparse
import ast
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import tomllib
from urllib.parse import urlsplit

from codex_dependency_bundle import (
    Budget, COMMON, DESCRIPTOR_SHA, HASH, MAX_BYTES, MAX_FILE, MAX_METADATA,
    MAX_OBJECTS, MAX_ROWS, SOURCE_RECEIPT, SOURCE_RECEIPT_SHA, authority, encoded,
    inventory, load_bundle, payload_fd, require, retained_location, row_checked,
    stream_object, verify_plan_authority,
)
from codex_dependency_union import (
    ACTIVE_PLAN_ROOT, ACTIVE_PLAN_SHA, MAX_SHARDS, OutputCustody, PLAN_ROOT,
    PLAN_SHA, TOOLS_ROOT, TOOLS_SHA, historical_membership, read_tools, verify_shard,
)
from codex_sdk_dependencies import CRATE_FACT, public_url, sha
from codex_sdk_profile import (
    ARCHIVE_MANIFEST_SHA, GRAPH, dependency_location, hash_regular, trusted_parent,
    validate_source,
)
from restore_pristine_inputs import unique_object

HTTP_RULES = {"@@bazel_tools//tools/build_defs/repo:http.bzl%" + name
              for name in ("http_archive", "http_file", "http_jar")}
CANONICAL_POLICY = "bazel-9.0.1-http-default-urls-enabled"
BAZEL_EVIDENCE = [
    "https://github.com/bazelbuild/bazel/blob/9.0.1/tools/build_defs/repo/http.bzl",
    "https://github.com/bazelbuild/bazel/blob/9.0.1/tools/build_defs/repo/cache.bzl",
    "https://github.com/bazelbuild/bazel/blob/9.0.1/src/main/java/com/google/devtools/build/lib/bazel/repository/cache/DownloadCache.java",
    "https://github.com/bazelbuild/bazel/blob/9.0.1/src/main/java/com/google/devtools/build/lib/bazel/repository/downloader/DownloadManager.java",
]
PHASES = frozenset(("entry-arguments", "entry-context", "selected-authority", "source-authority",
                   "active-plan", "union-receipt", "union-parents", "union-contract", "union-bytes",
                   "caller-mappings", "git-requirements", "output-custody", "output-bytes",
                   "final-verification", "output-publication"))
CATEGORIES = frozenset(("argument-shape", "permission", "missing-input", "path-type",
                       "occupied-output", "io", "contract", "schema", "source-syntax"))


class InvalidArguments(ValueError):
    """Argument diagnostics contain no caller-provided strings."""


class InvalidParentJson(ValueError):
    """Malformed or non-object parent JSON never reaches export selection."""


def parse_parent_json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, TypeError, RecursionError):
        raise InvalidParentJson() from None
    if not isinstance(value, dict):
        raise InvalidParentJson()
    return value


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes raw argv/value text. Only a fixed category
        # crosses this boundary; message is intentionally not inspected.
        raise InvalidArguments()


class ExportRefusal(ValueError):
    def __init__(self, phase, category):
        self.phase, self.category = phase, category
        super().__init__(refusal_message(phase, category))


def refusal_message(phase, category):
    require(phase in PHASES and category in CATEGORIES, "invalid diagnostic category")
    return "Native repository input export refused: phase=" + phase + " category=" + category


def failure_category(error):
    """Inspect types only; never errno text, paths, values or exception bodies."""
    if isinstance(error, InvalidArguments):
        return "argument-shape"
    if isinstance(error, PermissionError):
        return "permission"
    if isinstance(error, FileNotFoundError):
        return "missing-input"
    if isinstance(error, (NotADirectoryError, IsADirectoryError)):
        return "path-type"
    if isinstance(error, FileExistsError):
        return "occupied-output"
    if isinstance(error, OSError):
        return "io"
    if isinstance(error, (InvalidParentJson, KeyError, TypeError, json.JSONDecodeError, RecursionError)):
        return "schema"
    if isinstance(error, SyntaxError):
        return "source-syntax"
    return "contract"


def read_receipt(root_fd, expected, budget=None):
    require(isinstance(expected, str) and HASH.fullmatch(expected), "receipt pin differs")
    actual, _, raw = hash_regular(root_fd, "bundle-receipt.json", MAX_METADATA, True,
                                 on_read=budget.tick if budget is not None else None)
    if budget is not None:
        budget.tick()
    require(actual == expected, "raw receipt digest differs")
    return json.loads(raw, object_pairs_hook=unique_object)


def bounded_bundle(root, receipt, kind, budget):
    budget.tick()
    result = load_bundle(root, receipt, kind, budget, on_read=budget.tick)
    budget.tick()
    return result


def bounded_source_validation(budget):
    budget.tick()
    result = validate_source(SOURCE_RECEIPT.parent, SOURCE_RECEIPT_SHA, on_read=budget.tick)
    budget.tick()
    return result


def generated_http_mappings(module_lock, descriptors):
    """Recover actual caller class and URL order, not a descriptor's lost fields.

    Only the exact Bazel http_* rules are supported. BCR archive mirror ordering,
    custom rules and Cargo/rules_rs downloads remain unmapped. Registry reads
    use checksum-only getBytes; patches/overlays need no default URL markers.
    """
    selected = {(row_checked(row)["type"], row["identity"]): row for row in descriptors}
    require(len(selected) == len(descriptors), "descriptor identities duplicate")
    mappings, unsupported, seen = [], [], set()
    nodes = 0

    def walk(value, identity="moduleExtensions", depth=0):
        nonlocal nodes
        nodes += 1
        require(depth <= 32 and nodes <= MAX_ROWS * 16, "repository walk bound differs")
        if isinstance(value, dict):
            key = ("generated-repository-download", identity)
            row = selected.get(key)
            if row is not None:
                seen.add(key)
                attributes = value.get("attributes")
                if value.get("repoRuleId") not in HTTP_RULES or not isinstance(attributes, dict):
                    unsupported.append({"identity": identity, "reason": "unproved-repository-rule-caller"})
                else:
                    urls = attributes.get("urls", [])
                    require(isinstance(urls, list), "HTTP URL list differs")
                    urls = ([attributes["url"]] if attributes.get("url") else []) + urls
                    digest = sha(attributes.get("sha256"), attributes.get("integrity"))
                    require(digest == row["sha256"], "HTTP caller digest differs")
                    if urls != row["urls"]:
                        unsupported.append({"identity": identity, "reason": "descriptor-lost-actual-URL-order"})
                    else:
                        require(0 < len(urls) <= 16 and all(isinstance(url, str)
                                and len(url) <= 8192 and public_url(url, digest) for url in urls),
                                "HTTP caller URLs differ")
                        canonical = attributes.get("canonical_id", "")
                        require(isinstance(canonical, str) and len(canonical.encode()) <= 131072
                                and not any(c in canonical for c in "\0\r\n"), "canonical ID differs")
                        canonical = canonical or " ".join(urls)
                        mappings.append({"identity": identity, "sha256": digest, "urls": urls,
                                         "repository_rule_id": value["repoRuleId"],
                                         "canonical_id": canonical,
                                         "marker": "id-" + hashlib.sha256(canonical.encode()).hexdigest()})
            for name, child in value.items():
                walk(child, identity + "/" + name, depth + 1)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, identity + "/" + str(index), depth + 1)

    walk(module_lock.get("moduleExtensions", {}))
    for key, row in selected.items():
        if key in seen or row["type"] in ("bazel-registry-file", "bazel-module-patches", "bazel-module-overlay"):
            continue
        unsupported.append({"identity": row["identity"], "reason": "unproved-canonical-ID-caller",
                            "type": row["type"]})
    return sorted(mappings, key=lambda row: row["identity"]), sorted(unsupported, key=lambda row: row["identity"])


def git_requirements(module_lock, cargo_lock, module_text):
    """Typed public remote/full-commit requirements, never downloadable archives.

    Literal MODULE git_repository calls are parsed as syntax, not executed.
    Cargo and rules_rs snapshots retain independent evidence in each dedup row.
    Unsupported source text is hashed rather than placed in diagnostics.
    """
    requirements, unsupported = {}, []

    def add(remote, commit, evidence):
        parsed = urlsplit(remote)
        require(parsed.scheme == "https" and parsed.hostname in ("github.com", "chromium.googlesource.com")
                and parsed.netloc == parsed.hostname and parsed.username is None
                and parsed.password is None and not parsed.query and not parsed.fragment
                and re.fullmatch(r"/[A-Za-z0-9._/-]+", parsed.path)
                and ".." not in parsed.path.split("/") and re.fullmatch(r"[0-9a-f]{40}", commit),
                "Git requirement is not a public pinned remote")
        row = requirements.setdefault((remote, commit), {"type": "git-repository-input",
            "remote": remote, "commit": commit, "evidence": [], "materialized": False,
            "archive_sha256": None})
        if evidence not in row["evidence"]:
            row["evidence"].append(evidence)
        require(len(requirements) <= MAX_ROWS, "Git requirements exceed bound")

    pattern = re.compile(r"git\+(https://[^?#]+)\?rev=([0-9a-f]{40})#([0-9a-f]{40})(?:_([A-Za-z0-9_-]+))?")
    def source(value, evidence, snapshot=False):
        matched = pattern.fullmatch(value)
        if matched and matched[2] == matched[3] and (snapshot or matched[4] is None):
            add(matched[1], matched[2], evidence)
        else:
            unsupported.append({"type": "unparsed-Git-requirement", "source_sha256": hashlib.sha256(value.encode()).hexdigest()})

    packages = cargo_lock.get("package", [])
    require(isinstance(packages, list) and len(packages) <= 15000, "Cargo package bound differs")
    for package in packages:
        value = package.get("source")
        if isinstance(value, str) and value.startswith("git+"):
            source(value, {"kind": "cargo-lock", "source_sha256": hashlib.sha256(value.encode()).hexdigest()})
    facts = module_lock.get("facts", {}).get(CRATE_FACT, {})
    require(isinstance(facts, dict) and len(facts) <= 15000, "rules_rs snapshot bound differs")
    for key, value in facts.items():
        if key.startswith("git+"):
            require(isinstance(value, str) and len(value) <= 1024 * 1024, "Git snapshot size differs")
            source(key, {"kind": "rules-rs-snapshot", "source_sha256": hashlib.sha256(key.encode()).hexdigest(),
                         "snapshot_sha256": hashlib.sha256(value.encode()).hexdigest()}, True)
    tree = ast.parse(module_text)
    aliases = [node for node in tree.body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == "git_repository" for target in node.targets)]
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "git_repository"]
    if calls:
        require(len(aliases) == 1 and isinstance(aliases[0].value, ast.Call)
                and isinstance(aliases[0].value.func, ast.Name) and aliases[0].value.func.id == "use_repo_rule"
                and [ast.literal_eval(arg) for arg in aliases[0].value.args]
                    == ["@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository"],
                "MODULE Git rule alias differs")
    for call in calls:
        require(not call.args and all(keyword.arg for keyword in call.keywords), "MODULE Git call differs")
        values = {keyword.arg: ast.literal_eval(keyword.value) for keyword in call.keywords}
        require(len(values) == len(call.keywords) and isinstance(values.get("remote"), str)
                and isinstance(values.get("commit"), str), "MODULE Git literal pin differs")
        add(values["remote"], values["commit"], {"kind": "module-git-repository",
                                              "call_sha256": hashlib.sha256(ast.dump(call).encode()).hexdigest()})
    return [requirements[key] for key in sorted(requirements)], unsupported


def union_contract(report, plan, expected_parents, source_inventory, sources):
    """Reconstruct every object, byte length, origin and partition from parents."""
    require(all(report.get(key) == value for key, value in COMMON.items() if key != "schema_version")
            and type(report.get("schema_version")) is int and report["schema_version"] == 2
            and report.get("status") == "verified-finite-dependency-union"
            and report.get("parent_receipts") == expected_parents
            and report.get("source_inventory_sha256") == source_inventory
            and report.get("descriptors") == plan["descriptors"]
            and report.get("derivations") == plan.get("derivations", [])
            and report.get("unresolved") == plan["unresolved"]
            and report.get("canonical_id_metadata_exported") is False
            and report.get("ambient_cache_read") is False
            and all(report.get(key) is False for key in ("closure_proved", "offline_analysis_proved", "native_support", "provider_evaluation")),
            "union authority differs")
    admitted = {row_checked(row)["sha256"] for row in plan["descriptors"]}
    objects, origins, inputs = {}, {}, 0
    require(3 <= len(sources) <= MAX_SHARDS + 3 and len({source[0] for source in sources}) == len(sources),
            "union parent source count differs")
    for receipt, selected in sources:
        require(HASH.fullmatch(receipt) and isinstance(selected, dict) and len(selected) <= MAX_OBJECTS,
                "union parent object shape differs")
        for digest, record in selected.items():
            require(digest in admitted and type(record.get("bytes")) is int
                    and 0 <= record["bytes"] <= MAX_FILE, "union contains unadmitted parent object")
            length = {"bytes": record["bytes"]}
            require(digest not in objects or objects[digest] == length, "parent object length differs")
            objects[digest] = length
            origins.setdefault(digest, []).append(receipt)
            inputs += 1
    require(len(objects) <= MAX_OBJECTS and sum(row["bytes"] for row in objects.values()) <= MAX_BYTES,
            "union export bound differs")
    missing = [row for row in plan["missing"] if row["sha256"] not in objects]
    require({row["sha256"] for row in missing} == admitted - set(objects), "union missing partition differs")
    def count_types(rows):
        result = {}
        for row in rows:
            result[row["type"]] = result.get(row["type"], 0) + 1
        return result
    counts = {"input_objects": inputs, "unique_objects": len(objects), "duplicate_objects": inputs - len(objects),
              "missing_objects": len(missing), "missing_by_type": count_types(missing),
              "unresolved_rows": len(plan["unresolved"]), "unresolved_by_type": count_types(plan["unresolved"])}
    reported_objects, reported_counts = report.get("objects"), report.get("counts")
    require(isinstance(reported_objects, dict) and all(isinstance(row, dict) and set(row) == {"bytes"}
            and type(row["bytes"]) is int for row in reported_objects.values())
            and isinstance(reported_counts, dict) and set(reported_counts) == set(counts)
            and all(type(reported_counts[key]) is int for key in counts if not key.endswith("_by_type"))
            and all(isinstance(reported_counts[key], dict)
                    and all(type(value) is int for value in reported_counts[key].values())
                    for key in counts if key.endswith("_by_type")), "union numeric record shape differs")
    require(report.get("objects") == objects and report.get("object_origins") == origins
            and report.get("missing") == missing and report.get("counts") == counts, "union parent reconstruction differs")
    return objects


def verify_parents(plan, expected, budget):
    require(isinstance(expected, dict) and set(expected) == {"plan", "active_plan", "tools", "tools_manifest", "shards"}
            and expected["plan"] == PLAN_SHA and expected["tools"] == TOOLS_SHA
            and expected["tools_manifest"] == ARCHIVE_MANIFEST_SHA
            and expected["active_plan"] == {"root": str(ACTIVE_PLAN_ROOT), "receipt_sha256": ACTIVE_PLAN_SHA},
            "independent union parent selection differs")
    historical = bounded_bundle(PLAN_ROOT, PLAN_SHA, "plan", budget)
    historical_membership(historical, plan)
    sources = [(PLAN_SHA, historical["objects"]), (ACTIVE_PLAN_SHA, plan["objects"])]
    rows = expected["shards"]
    require(isinstance(rows, list) and 1 <= len(rows) <= MAX_SHARDS, "independent shard count differs")
    roots, receipts, selections = set(), {PLAN_SHA, ACTIVE_PLAN_SHA, TOOLS_SHA}, set()
    active_started = False
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"root", "receipt_sha256", "parent_plan_sha256", "shard_index", "shard_size"},
                "independent shard binding differs")
        root, receipt, parent, index, size = (row[key] for key in ("root", "receipt_sha256", "parent_plan_sha256", "shard_index", "shard_size"))
        require(isinstance(root, str) and isinstance(receipt, str) and HASH.fullmatch(receipt)
                and parent in (PLAN_SHA, ACTIVE_PLAN_SHA) and type(index) is int and type(size) is int
                and 0 <= index < MAX_ROWS and 1 <= size <= 64
                and root not in roots and receipt not in receipts and (parent, index, size) not in selections,
                "duplicate or invalid independent shard selection")
        require(not active_started or parent == ACTIVE_PLAN_SHA, "shard parent order differs")
        active_started |= parent == ACTIVE_PLAN_SHA
        roots.add(root); receipts.add(receipt); selections.add((parent, index, size))
        shard = bounded_bundle(Path(root), receipt, "producer", budget)
        verify_shard(historical if parent == PLAN_SHA else plan, shard, parent, index, size)
        historical_membership(shard, plan)
        sources.append((receipt, shard["objects"]))
    # Existing producer always retains its immutable first16 separately.
    from codex_dependency_union import SHARD_ROOT, SHARD_SHA
    require(rows[0] == {"root": str(SHARD_ROOT), "receipt_sha256": SHARD_SHA,
                       "parent_plan_sha256": PLAN_SHA, "shard_index": 0, "shard_size": 16},
            "historical first16 selection differs")
    fd = trusted_parent(TOOLS_ROOT)
    try:
        budget.tick()
        sources.append((TOOLS_SHA, read_tools(fd, TOOLS_SHA, budget, on_read=budget.tick)))
        budget.tick()
    finally:
        os.close(fd)
    return sources


class RepositoryOutput(OutputCustody):
    """Use the established anchored writer; add only independently derived IDs."""
    def publish_inputs(self, report):
        markers = {}
        for row in report["http_mappings"]:
            require(row.get("repository_rule_id") in HTTP_RULES
                    and isinstance(row.get("canonical_id"), str)
                    and row["marker"] == "id-" + hashlib.sha256(row["canonical_id"].encode()).hexdigest(),
                    "forged canonical ID marker")
            if row["sha256"] in report["objects"]:
                markers.setdefault(row["sha256"], set()).add(row["marker"])
        for digest, names in sorted(markers.items()):
            self.check()
            directory = self.digest_directory(digest)
            for name in sorted(names):
                require(re.fullmatch(r"id-[0-9a-f]{64}", name), "derived marker differs")
                fd = self._create_file(directory, name)
                try:
                    self._seal(directory, name, fd)
                finally:
                    os.close(fd)
        require(set(os.listdir(self.root_fd)) == {"content_addressable"},
                "repository output root inventory differs")
        content = next(child for parent, name, child, _, _ in self.directories
                       if parent == self.root_fd and name == "content_addressable")
        require(os.listdir(content) == ["sha256"], "repository output algorithm inventory differs")
        require(set(os.listdir(self.cas_fd)) == set(report["objects"]), "repository output digest inventory differs")
        for digest in report["objects"]:
            directory = self.digest_directory(digest)
            require(set(os.listdir(directory)) == {"file"} | markers.get(digest, set()),
                    "repository output marker inventory differs")
        value = encoded(report)
        fd = self._create_file(self.root_fd, "repository-inputs-receipt.json")
        try:
            self._write(self.root_fd, "repository-inputs-receipt.json", fd, value)
            self._seal(self.root_fd, "repository-inputs-receipt.json", fd)
        finally:
            os.close(fd)
        require(set(os.listdir(self.root_fd)) == {"repository-inputs-receipt.json", "content_addressable"},
                "repository publication inventory differs")
        for directory in reversed(self.fds):
            self.check(); os.fsync(directory)
        self.disk_check()
        return hashlib.sha256(value).hexdigest()

    def digest_directory(self, digest):
        self.check()
        return next(child for parent, name, child, _, _ in self.directories
                    if parent == self.cas_fd and name == digest)


def named_root_check(path, held):
    """A retained path must still denote the held root before publication."""
    named = trusted_parent(Path(path))
    try:
        require(OutputCustody._identity(os.fstat(named)) == OutputCustody._identity(os.fstat(held)),
                "retained root substituted")
    finally:
        os.close(named)


def checked_payload(root_fd, digest):
    fd = payload_fd(root_fd, digest)
    try:
        require(os.fstat(fd).st_nlink == 1, "retained payload has multiple links")
        return fd
    except BaseException:
        os.close(fd)
        raise


def source_graph(budget):
    validated = bounded_source_validation(budget)
    root = Path(validated["source"])
    values = {}
    for path in ("MODULE.bazel", "MODULE.bazel.lock", "codex-rs/Cargo.lock"):
        selected = Path(path)
        fd = trusted_parent(root / selected.parent)
        try:
            budget.tick()
            digest, _, value = hash_regular(fd, selected.name, 32 * 1024 * 1024, True, on_read=budget.tick)
            budget.tick()
            require(digest == GRAPH[path], "source graph digest differs")
            values[path] = value
        finally:
            os.close(fd)
    return (json.loads(values["MODULE.bazel.lock"], object_pairs_hook=unique_object),
            tomllib.loads(values["codex-rs/Cargo.lock"].decode()), values["MODULE.bazel"].decode())


def materialize(*, plan_root, plan_sha256, union_root, union_sha256, parent_receipts,
                source_receipt_sha256, descriptor_sha256, output_parent, _on_phase=None):
    """Only trusted caller-selected pins may enter; receipt fields select nothing."""
    def enter(phase):
        if _on_phase is not None:
            _on_phase(phase)

    enter("selected-authority")
    require((Path(plan_root), plan_sha256, source_receipt_sha256, descriptor_sha256)
            == (ACTIVE_PLAN_ROOT, ACTIVE_PLAN_SHA, SOURCE_RECEIPT_SHA, DESCRIPTOR_SHA),
            "active source/plan selection differs")
    union_root = dependency_location(Path(union_root))
    budget = Budget()
    budget.tick()
    enter("source-authority")
    manifest, source_inventory = authority(on_read=budget.tick)
    budget.tick()
    enter("active-plan")
    plan = bounded_bundle(Path(plan_root), plan_sha256, "plan", budget)
    require(plan.get("source_inventory_sha256") == source_inventory, "active plan source inventory differs")
    with ExitStack() as stack:
        plan_fd = trusted_parent(plan_root)
        stack.callback(os.close, plan_fd)
        require(read_receipt(plan_fd, plan_sha256, budget) == plan, "held active plan differs")
        verify_plan_authority(plan, manifest, plan_fd, budget)
        enter("union-receipt")
        union_fd = trusted_parent(union_root)
        stack.callback(os.close, union_fd)
        report = read_receipt(union_fd, union_sha256, budget)
        enter("union-parents")
        sources = verify_parents(plan, parent_receipts, budget)
        enter("union-contract")
        objects = union_contract(report, plan, parent_receipts, source_inventory, sources)
        enter("union-bytes")
        inventory(union_fd, objects)
        # Rehash every union payload before any output is created.
        for digest, record in objects.items():
            fd = checked_payload(union_fd, digest)
            try:
                length, _ = stream_object(fd, digest, budget)
                require(length == record["bytes"], "union payload length differs")
            finally:
                os.close(fd)
        enter("caller-mappings")
        module, cargo, module_text = source_graph(budget)
        mappings, unmapped = generated_http_mappings(module, plan["descriptors"])
        enter("git-requirements")
        git, git_unparsed = git_requirements(module, cargo, module_text)
        enter("output-custody")
        destination = RepositoryOutput(output_parent, budget)
        stack.callback(destination.close)
        enter("output-bytes")
        for digest, record in sorted(objects.items()):
            fd = checked_payload(union_fd, digest)
            try:
                destination.disk_check()
                require(destination.copy(fd, digest, budget) == record["bytes"], "exported payload length differs")
            finally:
                os.close(fd)
        result = {"schema_version": 1, "status": "verified-finite-repository-input-export", "ruling_id": "R-N13",
            "source_receipt_sha256": source_receipt_sha256, "descriptor_sha256": descriptor_sha256,
            "source_inventory_sha256": source_inventory, "graph_sha256": GRAPH,
            "active_plan": {"root": str(plan_root), "receipt_sha256": plan_sha256},
            "union": {"root": str(union_root), "receipt_sha256": union_sha256}, "parent_receipts": parent_receipts,
            "cache_root": str(destination.root_path), "objects": objects,
            "http_mappings": mappings, "unmapped_callers": unmapped, "canonical_id_policy": CANONICAL_POLICY,
            "canonical_id_required_repo_env": {"BAZEL_HTTP_RULES_URLS_AS_DEFAULT_CANONICAL_ID": "1"},
            "bazel_evidence": BAZEL_EVIDENCE, "git_requirements": git, "unparsed_git_requirements": git_unparsed,
            "missing": report["missing"], "unresolved": report["unresolved"],
            "closure_proved": False, "offline_analysis_proved": False, "sdk_compilation_admitted": False,
            "git_materialization_proved": False, "all_canonical_ids_proved": False,
            "native_support": False, "provider_evaluation": False, "ambient_cache_read": False,
            "budgets": {"shared_read_bytes": MAX_BYTES, "retained_bytes": MAX_BYTES,
                        "per_file_bytes": MAX_FILE, "metadata_per_read_bytes": MAX_METADATA,
                        "source_passes": 3, "deadline_seconds": 1200,
                        "accounting": "actual chunks from every source/metadata/CAS pass including repeated verification; deadline per read and node"},
            "scope": "rehash all selected CAS bytes; exact Bazel9 generated http_* markers only; no repository analysis or compiler admission"}
        enter("final-verification")
        bounded_source_validation(budget)
        named_root_check(plan_root, plan_fd)
        named_root_check(union_root, union_fd)
        require(read_receipt(plan_fd, plan_sha256, budget) == plan and read_receipt(union_fd, union_sha256, budget) == report,
                "input receipt changed before publication")
        inventory(union_fd, objects)
        # All input reads are finished. Publishing only writes output bytes and
        # performs zero-byte deadline/custody ticks on the same Budget.
        result["read_bytes_accounted"] = budget.read_bytes
        enter("output-publication")
        digest = destination.publish_inputs(result)
        return result, digest


def main(arguments=None):
    phase = "entry-arguments"
    def enter(value):
        nonlocal phase
        require(value in PHASES, "invalid diagnostic phase")
        phase = value
    try:
        parser = SafeParser(prog="codex_repository_inputs", allow_abbrev=False)
        for name in ("plan", "union"):
            parser.add_argument("--" + name + "-root", type=Path, required=True)
            parser.add_argument("--" + name + "-sha256", required=True)
        parser.add_argument("--source-receipt-sha256", required=True)
        parser.add_argument("--descriptor-sha256", required=True)
        parser.add_argument("--parent-receipts-json", required=True)
        args = parser.parse_args(arguments)
        enter("entry-context")
        require(os.environ.get("OMUX_EXECUTION_GUARD") and os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR"),
                "declared contained repository-input output required")
        require(len(args.parent_receipts_json.encode()) <= MAX_METADATA, "parent selection exceeds bound")
        expected = parse_parent_json(args.parent_receipts_json)
        _, digest = materialize(plan_root=args.plan_root, plan_sha256=args.plan_sha256,
            union_root=args.union_root, union_sha256=args.union_sha256, parent_receipts=expected,
            source_receipt_sha256=args.source_receipt_sha256, descriptor_sha256=args.descriptor_sha256,
            output_parent=Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]), _on_phase=enter)
        print(json.dumps({"receipt_sha256": digest, "sdk_compilation_admitted": False}))
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, RecursionError) as error:
        raise ExportRefusal(phase, failure_category(error)) from None


if __name__ == "__main__":
    try:
        main()
    except ExportRefusal as error:
        raise SystemExit(refusal_message(error.phase, error.category))
