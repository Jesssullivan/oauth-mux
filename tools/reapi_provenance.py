"""Bounded, metadata-only Bazel 9 Darwin graph/SpawnExec reconciliation.

Inputs are private operator files. Nothing here writes or emits raw commands,
environment, target labels, endpoints, inputs or receipt contents. Aquery does
not contain platform exec_properties. SpawnExec properties come from the submitted
spawn, not the selected worker; matching them never proves worker routing.
Repository bootstrap is outside the analyzed action graph. External spawn tools
are execution dependencies and must reconcile alongside product spawns.

Schemas: bazelbuild/bazel tag 9.0.1, src/main/protobuf/{analysis_v2,spawn}.proto.
The expanded JSON log is concatenated objects, not a JSON array. Persistent
action-cache hits have no SpawnExec and therefore fail complete reconciliation.
Use a clean output root and --config=reapi-proof for a fresh execution receipt.
"""
import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys

LIMIT = 256 * 1024 * 1024
MAX_ITEMS = 1_000_000
MAX_ACTIONS = 100_000
MAX_DEPTH = 128
ROOT = re.compile(r"/nix/store/[a-z0-9]{32}-[^/\s\"']+")
ABSOLUTE_INPUT = re.compile(r"/nix/store/[a-z0-9]{32}-[^/\s\"':;,(){}\[\]]+(?:/[^\s\"':;,(){}\[\]]*)?")
CLOSURE = re.compile(r"[a-z0-9]{32}-omux-bazel-closure")
PLATFORM = re.compile(r"@@?(?:omux_nix|\+omux_nix_repository\+omux_nix)//:execution_platform")
NIX_REPOSITORIES = {"omux_nix", "+omux_nix_repository+omux_nix"}
REPOSITORY = re.compile(r"external/([a-zA-Z0-9_.+-]+)/")
REQUIRED = {"OmuxSwiftUI", "OmuxMacOSBundle", "OmuxMacOSArchive", "ZigBuildExe"}
REQUIRED_TARGETS = {
    ("//clients/macos:control", "OmuxSwiftUI"),
    ("//clients/macos:Omux", "OmuxMacOSBundle"),
    ("//clients/macos:archive", "OmuxMacOSArchive"),
    ("//:omux", "ZigBuildExe"),
    ("//:omuxd", "ZigBuildExe"),
}
NON_SPAWN = {"FileWrite", "FileWriteAction", "ParameterFileWrite", "ExecutableSymlink", "RepoMappingManifest", "SourceSymlinkManifest", "SymlinkTree", "RunfilesTree", "Symlink", "UnresolvedSymlink", "SolibSymlink", "TemplateExpand", "Middleman"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Rejected(ValueError):
    """Only fixed, source-owned messages may become public failure metadata."""


def fail(message):
    raise Rejected(message)


def object_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail("duplicate JSON field")
        value[key] = item
    return value


DECODER = json.JSONDecoder(object_pairs_hook=object_pairs, parse_constant=lambda _: fail("nonfinite JSON"))


def read(path):
    # Limit the read itself, including a file that grows after its stat.
    with path.open("rb") as stream:
        value = stream.read(LIMIT + 1)
    if len(value) > LIMIT:
        fail("input exceeds bound")
    return value.decode("utf-8")


def load(path):
    return DECODER.decode(read(path))


def load_receipts(path):
    text = read(path)
    cursor, records = 0, []
    while cursor < len(text):
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor == len(text):
            break
        record, cursor = DECODER.raw_decode(text, cursor)
        if not isinstance(record, dict) or len(records) >= MAX_ACTIONS:
            fail("expanded execution receipt shape rejected")
        records.append(record)
    return records


def array(value, bound=MAX_ITEMS):
    if not isinstance(value, list) or len(value) > bound:
        fail("array shape or bound rejected")
    return value


def pairs(value, key, proto_defaults=False):
    result = {}
    for item in array(value):
        name = item[key]
        content = item.get("value", "") if proto_defaults else item["value"]
        if not isinstance(name, str) or not isinstance(content, str) or name in result:
            fail("metadata pairs rejected")
        result[name] = content
    return result


def table(items):
    result = {}
    for item in array(items):
        identifier = str(item["id"])
        if not re.fullmatch(r"[1-9][0-9]*", identifier) or identifier in result:
            fail("duplicate or invalid graph identifier")
        result[identifier] = item
    return result


def safe_path(value):
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value or any(part in {"", ".", ".."} for part in value.split("/")):
        fail("execution path rejected")
    return value


def identity(label, mnemonic, arguments, environment, outputs):
    if not isinstance(label, str) or not re.fullmatch(r"(?:@@?[a-zA-Z0-9_.+-]+)?//[^\s]+", label):
        fail("target label rejected")
    if not isinstance(mnemonic, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", mnemonic):
        fail("action mnemonic rejected")
    if not array(arguments) or not all(isinstance(arg, str) for arg in arguments):
        fail("command identity missing")
    output_set = {safe_path(output) for output in array(outputs)}
    if not output_set or len(output_set) != len(outputs):
        fail("action outputs missing or duplicated")
    return digest([label, mnemonic, arguments, sorted(environment.items()), sorted(output_set)])


def package_aliases(manifest, roots):
    aliases = {}
    packages = manifest.get("packages", {})
    if not isinstance(packages, dict) or len(packages) > MAX_ITEMS:
        fail("package alias manifest rejected")
    for name, package in packages.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.+-]+", name) or name in {".", ".."} or not isinstance(package, dict):
            fail("package alias manifest rejected")
        for output in {"out", "dev", "lib", "bin"} & package.keys():
            root = package[output]
            if not isinstance(root, str) or not ROOT.fullmatch(root) or root not in roots:
                fail("package alias root outside authorized closure")
            aliases["packages/" + name + "/" + output] = root
    return aliases


def input_roots(paths, roots, aliases, absolute_files):
    mapped = set()
    for path in paths:
        safe_path(path)
        repository = REPOSITORY.match(path)
        if repository and "omux_host" in repository.group(1):
            fail("coordinator tools in Darwin execution")
        if repository and repository.group(1) in NIX_REPOSITORIES:
            relative = path[repository.end():]
            if relative.startswith("closure/"):
                root = "/nix/store/" + relative.split("/")[1]
                if root not in roots:
                    fail("undeclared Nix input")
                mapped.add(root)
                absolute_files.add("/nix/store/" + relative[len("closure/"):])
            elif relative.startswith("packages/"):
                prefix = "/".join(relative.split("/")[:3])
                if prefix not in aliases or relative == prefix:
                    fail("declared package alias missing from authorized manifest")
                root = aliases[prefix]
                mapped.add(root)
                absolute_files.add(root + relative[len(prefix):])
    return mapped


def absolute_inputs(arguments, environment, mapped, declared, authorized, absolute_files):
    executable = arguments[0]
    if executable.startswith("/"):
        root_match = ROOT.match(executable)
        if not root_match:
            fail("ambient absolute executable rejected")
        if executable not in absolute_files:
            fail("absolute executable is not a declared file")
    elif safe_path(executable) not in declared:
        fail("executable is not a declared input")
    for entry in environment.get("PATH", "").split(":"):
        if entry and not ROOT.match(entry):
            fail("ambient executable search path rejected")
    for value in arguments + list(environment.values()):
        for match in ABSOLUTE_INPUT.finditer(value):
            reference = match.group().rstrip("/")
            root = ROOT.match(reference).group()
            if root not in mapped:
                if root in authorized:
                    fail("authorized store root absent from declared action inputs")
                fail("absolute reference outside authorized closure")
            # Store roots may not be escaped by a traversal suffix.
            if ".." in reference.split("/"):
                fail("absolute tool traversal rejected")
            if reference not in absolute_files and not any(path.startswith(reference + "/") for path in absolute_files):
                fail("absolute file or directory has no declared input path")


@dataclass
class Plan:
    counts: Counter
    roots: frozenset
    outputs: frozenset
    action_outputs: dict
    tree_outputs: frozenset
    action_inputs: dict
    action_input_trees: dict
    symlink_targets: dict
    aliases: dict


def action_plan(graph, manifest, store_paths):
    if not isinstance(graph, dict) or not isinstance(manifest, dict) or manifest.get("system") != "aarch64-darwin" or not isinstance(manifest.get("apple"), dict) or manifest["apple"].get("sdk_version") != "14.4":
        fail("expected Darwin manifest missing")
    lines = store_paths.splitlines()
    roots = frozenset(lines)
    if not lines or len(lines) > MAX_ITEMS or len(lines) != len(roots) or any(not ROOT.fullmatch(root) for root in roots):
        fail("closure root list rejected")
    aliases = package_aliases(manifest, roots)
    fragments = table(graph.get("pathFragments", []))
    artifacts = table(graph.get("artifacts", []))
    sets = table(graph.get("depSetOfFiles", []))
    targets = table(graph.get("targets", []))
    path_cache, set_cache = {}, {}
    expanded = 0

    def path(identifier, pending=frozenset()):
        if identifier in pending or len(pending) >= MAX_DEPTH:
            fail("artifact path cycle or depth")
        if identifier not in path_cache:
            fragment = fragments[identifier]
            label = fragment["label"]
            if not isinstance(label, str) or "/" in label:
                fail("path fragment rejected")
            parent = str(fragment.get("parentId", "0"))
            path_cache[identifier] = safe_path((path(parent, pending | {identifier}) + "/" if parent != "0" else "") + label)
        return path_cache[identifier]

    def artifact(identifier):
        return path(str(artifacts[str(identifier)]["pathFragmentId"]))

    def inputs(identifier, pending=frozenset()):
        nonlocal expanded
        if identifier in pending or len(pending) >= MAX_DEPTH:
            fail("input depset cycle or depth")
        if identifier not in set_cache:
            item = sets[identifier]
            value = {artifact(art) for art in array(item.get("directArtifactIds", []))}
            for child in array(item.get("transitiveDepSetIds", [])):
                value.update(inputs(str(child), pending | {identifier}))
            expanded += len(value)
            if expanded > 8 * MAX_ITEMS:
                fail("depset expansion bound")
            set_cache[identifier] = value
        return set_cache[identifier]

    registered = array(graph.get("actions", []), MAX_ACTIONS)
    actions, registrations, unique = [], Counter(), {}
    for action in registered:
        fingerprint = digest(action)
        if fingerprint in unique:
            index = unique[fingerprint]
            if actions[index] != action:
                fail("action registration identity collision")
        else:
            index = len(actions)
            unique[fingerprint] = index
            actions.append(action)
        registrations[index] += 1
    artifact_trees = {artifact(identifier) for identifier, item in artifacts.items() if item.get("isTreeArtifact") is True}
    for action in actions:
        if action.get("mnemonic") == "RunfilesTree":
            artifact_trees.update(artifact(identifier) for identifier in array(action.get("outputIds", [])))
    producers = {}
    for index, action in enumerate(actions):
        for identifier in array(action.get("outputIds", [])):
            output = artifact(identifier)
            producers.setdefault(output, []).append(index)
    root_actions = [index for index, action in enumerate(actions) if targets.get(str(action.get("targetId")), {}).get("label") == "//clients/macos:archive" and action.get("mnemonic") == "OmuxMacOSArchive"]
    if len(root_actions) != 1:
        fail("one explicit application archive target root required")
    reachable, queue = set(), list(root_actions)
    while queue:
        index = queue.pop()
        if index in reachable:
            continue
        reachable.add(index)
        action = actions[index]
        declared = set()
        for identifier in array(action.get("inputDepSetIds", [])):
            declared.update(inputs(str(identifier)))
        for parameter in array(action.get("paramFiles", [])):
            declared.add(safe_path(parameter["execPath"]))
        for input_path in declared:
            if input_path in producers:
                queue.extend(producers[input_path])
            else:
                # A generated child may reference an enclosing tree artifact.
                pieces = input_path.split("/")
                for size in range(len(pieces) - 1, 0, -1):
                    parent = "/".join(pieces[:size])
                    if parent in artifact_trees and parent in producers:
                        queue.extend(producers[parent])
                        break

    for owners in producers.values():
        selected = [index for index in owners if index in reachable]
        if len(selected) > 1:
            if all(not actions[index].get("arguments") for index in selected):
                fail("multiple reachable non-spawn actions own the same output")
            fail("multiple reachable actions own the same output")

    plan, mnemonics, product_targets = Counter(), Counter(), set()
    output_paths, tree_outputs, action_outputs = set(), set(), {}
    action_inputs, action_input_trees, symlink_targets = {}, {}, {}
    external, non_spawn = 0, 0
    for index in sorted(reachable):
        action = actions[index]
        arguments = action.get("arguments", [])
        if not arguments:
            if action.get("mnemonic") not in NON_SPAWN:
                fail("spawn command missing from analysis")
            non_spawn += 1
            if action.get("mnemonic") == "UnresolvedSymlink":
                target = action.get("unresolvedSymlinkTarget")
                if not isinstance(target, str) or not target:
                    fail("unresolved symlink target missing")
                if target.startswith("/"):
                    match = ROOT.match(target)
                    if not match or match.group() not in roots or ".." in target.split("/"):
                        fail("unresolved symlink escapes immutable closure")
                else:
                    safe_path(target)
                for identifier in array(action.get("outputIds", [])):
                    symlink_targets[artifact(identifier)] = target
            continue
        label = targets[str(action["targetId"])]["label"]
        mnemonic = action["mnemonic"]
        if not PLATFORM.fullmatch(action.get("executionPlatform", "")):
            fail("execution platform is not the declared closure")
        # analysis_v2.proto string scalars have no presence; aquery omits an
        # explicitly empty value. Expanded SpawnExec JSON prints defaults.
        environment = pairs(action.get("environmentVariables", []), "key", proto_defaults=True)
        declared = set()
        for identifier in array(action.get("inputDepSetIds", [])):
            declared.update(inputs(str(identifier)))
        # Bazel may represent response files as virtual spawn inputs rather
        # than Artifact IDs. --include_param_files keeps their paths explicit.
        for parameter in array(action.get("paramFiles", [])):
            declared.add(safe_path(parameter["execPath"]))
        absolute_files = set()
        mapped = input_roots(declared, roots, aliases, absolute_files)
        try:
            absolute_inputs(arguments, environment, mapped, declared, roots, absolute_files)
        except Rejected as error:
            # Only source-owned mnemonic names can refine public failure text.
            known = {name: "declared absolute input check failed in " + name for name in REQUIRED | {"ZigVersionValidation", "TranslateC", "TranslateCBuild"}}
            if str(error) in {"authorized store root absent from declared action inputs", "absolute reference outside authorized closure"} and mnemonic in known:
                scope = "product action" if label.startswith("//") else "external tool action"
                fail(known[mnemonic] + " (" + scope + "): " + str(error))
            raise
        outputs = [artifact(identifier) for identifier in array(action.get("outputIds", []))]
        if output_paths.intersection(outputs):
            fail("multiple analyzed spawns own the same output")
        key = identity(label, mnemonic, arguments, environment, outputs)
        plan[key] += 1
        output_paths.update(outputs)
        action_outputs[key] = frozenset(outputs)
        action_inputs[key] = frozenset(declared)
        action_input_trees[key] = frozenset(declared & artifact_trees)
        tree_outputs.update(artifact(identifier) for identifier in action.get("outputIds", []) if artifacts[str(identifier)].get("isTreeArtifact") is True)
        external += not label.startswith("//")
        if label.startswith("//"):
            mnemonics[mnemonic] += 1
            product_targets.add((label, mnemonic))
    if not REQUIRED_TARGETS <= product_targets:
        fail("complete application/archive action plan missing")
    summary = {
        "spawn_actions": sum(plan.values()), "product_actions": sum(mnemonics.values()),
        "scope": "archive_artifact_producer_dependencies",
        "registered_actions": len(registered), "reachable_actions": len(reachable),
        "reachable_registered_actions": sum(registrations[index] for index in reachable),
        "duplicate_registered_actions": len(registered) - len(actions),
        "unrequested_registered_actions": len(registered) - sum(registrations[index] for index in reachable),
        "external_tool_actions": external, "non_spawn_actions": non_spawn,
        "required_product_mnemonics": {name: mnemonics[name] for name in sorted(REQUIRED)},
        "other_product_actions": sum(value for name, value in mnemonics.items() if name not in REQUIRED),
        "manifest_content_sha256": digest(manifest),
        "store_paths_sha256": hashlib.sha256(store_paths.encode()).hexdigest(),
        "plan_sha256": digest(sorted(plan.items())),
        "declared_inputs_sha256": digest(sorted((key, sorted(value)) for key, value in action_inputs.items())),
        "analysis_routing_verified": False,
        "receipt_platform_properties_match": False,
        "worker_routing_verified": False,
        "repository_bootstrap_verified": False,
    }
    return Plan(plan, roots, frozenset(output_paths), action_outputs, frozenset(tree_outputs), action_inputs, action_input_trees, symlink_targets, aliases), summary


def file_digest(value):
    if not isinstance(value, dict) or not re.fullmatch(r"[0-9a-f]{64}", value.get("hash", "")) or value.get("hashFunctionName", "").lower().replace("-", "") != "sha256":
        fail("SHA256 receipt digest missing")
    size = value.get("sizeBytes")
    if isinstance(size, str) and re.fullmatch(r"0|[1-9][0-9]*", size):
        size = int(size)
    if type(size) is not int or not 0 <= size <= 2**63 - 1:
        fail("receipt digest size rejected")
    return value["hash"], size


def reconcile(plan, records, closure, fresh=False):
    if not CLOSURE.fullmatch(closure):
        fail("closure identity rejected")
    seen, counts, action_digests, output_digests = Counter(), Counter(), [], {}
    input_digests = []
    generated_input_values = []
    tree_receipts, actual_output_paths = [], set()
    for record in array(records, MAX_ACTIONS):
        arguments = record.get("commandArgs")
        environment = pairs(record.get("environmentVariables", []), "name")
        key = identity(record.get("targetLabel"), record.get("mnemonic"), arguments, environment, record.get("listedOutputs"))
        if key not in plan.counts:
            fail("receipt has no matching analyzed action")
        routing = pairs(record.get("platform", {}).get("properties", []), "name")
        if routing.get("nix_closure") != closure:
            fail("receipt closure routing does not match")
        if record.get("status") != "" or type(record.get("exitCode")) is not int or record["exitCode"] != 0:
            fail("unsuccessful execution receipt")
        if record.get("remotable") is not True:
            fail("receipt is not remotable")
        receipt_inputs = array(record.get("inputs", []))
        paths = [safe_path(item["path"]) for item in receipt_inputs]
        path_set = set(paths)
        if len(paths) != len(path_set):
            fail("duplicate receipt input path")
        declared = plan.action_inputs[key]
        input_trees = plan.action_input_trees[key]
        if not declared.difference(input_trees) <= path_set:
            fail("declared regular action inputs missing from receipt")
        for item in receipt_inputs:
            path = item["path"]
            if path not in declared and not any(path.startswith(tree + "/") for tree in input_trees):
                fail("foreign input in execution receipt")
            if "symlinkTargetPath" in item:
                if "digest" in item or plan.symlink_targets.get(path) != item["symlinkTargetPath"]:
                    fail("unresolved symlink input does not match analysis")
                input_digests.append((key, path, digest(["unresolved_symlink", item["symlinkTargetPath"]])))
            else:
                # An omitted digest can describe a virtual/empty file in Bazel.
                # That shape cannot attest content, so reject rather than infer.
                input_value = file_digest(item.get("digest"))
                input_digests.append((key, path, input_value))
                generated_input_values.append((path, input_value))
        for tree in input_trees:
            tree_receipts.append((tree, frozenset(path for path in path_set if path.startswith(tree + "/"))))
        absolute_files = set()
        mapped = input_roots(paths, plan.roots, plan.aliases, absolute_files)
        absolute_inputs(arguments, environment, mapped, path_set, plan.roots, absolute_files)
        cache, runner = record.get("cacheHit"), record.get("runner")
        if type(cache) is not bool:
            fail("cache provenance missing")
        if cache and runner == "remote cache hit":
            if fresh:
                fail("fresh proof contains a cache hit")
            counts["remote_cache_hits"] += 1
        elif not cache and runner == "remote":
            counts["remote_executions"] += 1
        else:
            fail("receipt did not execute remotely or accept a remote cache result")
        action_digests.append(file_digest(record.get("digest")))
        actual_paths = set()
        owned_outputs = plan.action_outputs[key]
        for output in array(record.get("actualOutputs", [])):
            path = safe_path(output["path"])
            if path in actual_paths:
                fail("duplicate actual output")
            actual_paths.add(path)
            if path not in owned_outputs:
                # Tree artifact children have separate paths in expanded logs.
                if not any(path.startswith(parent + "/") for parent in owned_outputs & plan.tree_outputs):
                    fail("receipt output was not declared")
            if "digest" in output:
                value = file_digest(output["digest"])
                if path in output_digests and output_digests[path] != value:
                    fail("receipt output digest disagreement")
                output_digests[path] = value
            elif plan.symlink_targets.get(path) != output.get("symlinkTargetPath") or "symlinkTargetPath" not in output:
                fail("actual output content metadata missing")
        if not owned_outputs.difference(plan.tree_outputs) <= actual_paths:
            fail("regular output materialization receipt missing")
        for path in owned_outputs.difference(plan.tree_outputs):
            if path not in output_digests:
                fail("regular output content digest missing")
        actual_output_paths.update(actual_paths)
        seen[key] += 1
    if seen != plan.counts:
        fail("analyzed spawns and execution receipts do not reconcile")
    for tree, input_paths in tree_receipts:
        if tree in plan.tree_outputs:
            produced = {path for path in actual_output_paths if path.startswith(tree + "/")}
            if input_paths != produced:
                fail("generated tree inputs do not match producer output enumeration")
    for path, value in generated_input_values:
        if path in actual_output_paths and output_digests.get(path) != value:
            fail("generated input content does not match producer receipt")
    return {"remote_executions": counts["remote_executions"], "remote_cache_hits": counts["remote_cache_hits"], "receipt_platform_properties_match": True, "worker_routing_verified": False, "fresh_execution_verified": bool(fresh), "declared_regular_inputs_accounted_for": True, "regular_output_digest_metadata_complete": True, "tree_output_materialization_verified": False, "action_digests_sha256": digest(sorted(action_digests)), "input_digests_sha256": digest(sorted(input_digests))}, output_digests


def artifact_summary(path, exec_path, plan, output_digests):
    safe_path(exec_path)
    if exec_path not in plan.outputs or exec_path not in output_digests:
        fail("artifact receipt digest missing")
    value, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            if size > 8 * 1024**3:
                fail("artifact size bound")
            value.update(block)
    result = value.hexdigest(), size
    if output_digests[exec_path] != result:
        fail("artifact bytes do not match remote output digest")
    return {"artifact_verified": True, "artifact_sha256": result[0], "artifact_bytes": size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("aquery", "manifest", "store-paths"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--closure", required=True)
    parser.add_argument("--target-root", choices=["//clients/macos:archive"], required=True)
    parser.add_argument("--execution-log", type=Path)
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--artifact-exec-path")
    parser.add_argument("--input-hashes-only", action="store_true")
    args = parser.parse_args()
    if not CLOSURE.fullmatch(args.closure) or (args.fresh and not args.execution_log) or bool(args.artifact) != bool(args.artifact_exec_path) or (args.artifact and not args.execution_log):
        fail("incomplete provenance request")
    graph_text, manifest_text = read(args.aquery), read(args.manifest)
    if args.input_hashes_only:
        if args.execution_log or args.artifact:
            fail("input fingerprint request cannot reconcile execution")
        print(json.dumps({"phase": "input_fingerprints_only", "aquery_sha256": hashlib.sha256(graph_text.encode()).hexdigest(), "manifest_sha256": hashlib.sha256(manifest_text.encode()).hexdigest(), "store_paths_sha256": hashlib.sha256(read(args.store_paths).encode()).hexdigest(), "worker_routing_verified": False, "installed_proof": False}, sort_keys=True))
        return
    plan, summary = action_plan(DECODER.decode(graph_text), DECODER.decode(manifest_text), read(args.store_paths))
    summary.update({"phase": "analysis_only", "installed_proof": False, "artifact_verified": False, "manifest_sha256": hashlib.sha256(manifest_text.encode()).hexdigest(), "aquery_sha256": hashlib.sha256(graph_text.encode()).hexdigest(), "closure_basename": args.closure})
    if args.execution_log:
        metadata, outputs = reconcile(plan, load_receipts(args.execution_log), args.closure, args.fresh)
        summary.update(metadata)
        summary["phase"] = "execution_reconciled"
        if args.artifact:
            summary.update(artifact_summary(args.artifact, args.artifact_exec_path, plan, outputs))
    print(json.dumps(summary, sort_keys=True))


def run_cli():
    """Emit only fixed reasons and a line in this source, never exception data."""
    try:
        main()
    except Rejected as error:
        sys.exit("Darwin provenance reconciliation rejected: " + str(error))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, UnicodeError) as error:
        reasons = {KeyError: "schema-key", TypeError: "schema-type", AttributeError: "schema-attribute", RecursionError: "depth", UnicodeError: "encoding", ValueError: "value"}
        reason = "io" if isinstance(error, OSError) else reasons.get(type(error), "schema")
        source_line = 0
        traceback = error.__traceback__
        while traceback is not None:
            if traceback.tb_frame.f_code.co_filename == __file__:
                source_line = traceback.tb_lineno
            traceback = traceback.tb_next
        sys.exit("Darwin provenance reconciliation rejected (" + reason + "; source line " + str(source_line) + ")")


if __name__ == "__main__":
    run_cli()
