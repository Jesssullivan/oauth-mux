"""Real isolated HM derivation origin and finite builder-input acquisition request.

The pinned Nix 2.34.6 JSON ABI is version 4 with basename StorePaths. This action
does not build, activate, update or remove a Home Manager generation.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

import home_manager_realization_inputs as inputs
import home_manager_generation_module_owner as module_owner

require, private, seed = inputs.require, inputs.private, inputs.seed
PROFILE = "home-manager-generation-catalogue-reserved"
KIND = "omux-linux-hm-generation-build-input-request-v1"
MAX_GRAPH_BYTES = 16 * 1024**2
MAX_REQUEST_BYTES = 32 * 1024**2
MAX_GENERATED_BYTES = 16 * 1024**2
MODULE = "home-manager-generation.nix"


def basename(value):
    require(type(value) is str and re.fullmatch(r"[0123456789abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9._+-]+", value) is not None)
    return "/nix/store/" + value


def output_name(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_+-]{0,63}", value) is not None)
    return value


def registration(raw):
    """Actual owned-store dump ABI; discover no host store or undeclared root."""
    require(type(raw) is bytes and 0 < len(raw) <= private.MAX_OUTPUT)
    lines = raw.decode("ascii").splitlines()
    roots, offset = [], 0
    while offset < len(lines):
        require(offset + 5 <= len(lines) and re.fullmatch(r"[0-9]{1,4}", lines[offset+4]) is not None)
        count = int(lines[offset+4]); require(count <= inputs.MAX_ROOTS and offset + 5 + count <= len(lines))
        roots.append(inputs.store(lines[offset])); require(len(roots) <= inputs.MAX_ROOTS)
        offset += 5 + count
    require(len(roots) == len(set(roots)))
    return private.readback_records(raw, sorted(roots))


def generated_inputs(value, private_root, records, deadline, *, required_metadata=()):
    """Retain generated public metadata bytes, not a hash of a deleted .drv.

    Newly named locked sources/artifact are represented only by verified equality
    recipes to their independently qualified complete declared input roots. Other new roots
    retain their complete regular bytes/links/descriptors in this request.
    """
    original = inputs.shape(value)
    private.compare_readback(original, {root: records[root] for root in original})
    captured, result, total = {}, {}, 0
    equal_roots = {name: value["roles"][name] for name in ("home-manager", "nixpkgs", "artifact")}
    require(type(required_metadata) is tuple and set(required_metadata) <= set(records))
    for root in sorted((set(records) - set(original)) | set(required_metadata)):
        private.tick(deadline)
        path = private_root / "nix/store" / root.rsplit("/", 1)[1]
        description = inputs.nar.describe(path); description["root"] = root
        require(len(description["nodes"]) <= seed.MAX_FILES)
        before = {}
        for node in description["nodes"]:
            private.tick(deadline)
            require(node["type"] != "symlink" or str(private_root.parent) not in node["target"])
            actual = path / node["path"] if node["path"] else path
            info = actual.lstat()
            require(info.st_uid == os.getuid() and (node["type"] == "symlink" and info.st_nlink == 1
                or node["type"] != "symlink" and not info.st_mode & 0o022))
            require(node["type"] != "regular" or info.st_nlink == 1 and not info.st_mode & 0o222)
            before[str(actual)] = inputs.facts(info)
        proof = inputs.nar.hash_descriptor(description,
            opener=lambda unused, relative: inputs.regular(path / relative if relative else path, deadline), deadline=deadline)
        record = records[root]["record"]
        require(proof["narHash"] == "sha256:" + seed.expected_hash(record[1]) and proof["narSize"] == int(record[2]))
        entry = {"descriptor": description, "narHash": proof["narHash"], "narSize": proof["narSize"], "record": record}
        equal = [original_root for original_root in equal_roots.values()
            if description["nodes"] == value["descriptors"][original_root]["nodes"]
            and proof["narHash"] == "sha256:" + seed.expected_hash(original[original_root]["record"][1])]
        if equal:
            entry["content"] = {"kind": "same-complete-declared-input-nar", "root": sorted(equal)[0]}
        else:
            files = {}
            for node in description["nodes"]:
                if node["type"] != "regular": continue
                require(node["size"] <= MAX_GENERATED_BYTES - total)
                target = path / node["path"] if node["path"] else path
                raw = inputs.raw_metadata(target, MAX_GENERATED_BYTES - total, deadline)
                require(len(raw) == node["size"] and str(private_root.parent).encode() not in raw)
                total += len(raw); require(total <= MAX_GENERATED_BYTES)
                files[node["path"]] = {"bytes": len(raw), "sha256": seed.sha(raw), "base64": base64.b64encode(raw).decode("ascii")}
            # Links remain inert literals already bound by the full descriptor.
            entry["content"] = {"kind": "complete-public-generated-members", "files": files}
        require(inputs.nar.describe(path)["nodes"] == description["nodes"])
        require({name: inputs.facts(Path(name).lstat()) for name in before} == before)
        captured.update(before); result[root] = entry
    private.tick(deadline)
    return result, captured


def graph(raw, proposal, records, bindings):
    """Close selected output edges, not merely .drv reference reachability."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_GRAPH_BYTES)
    value = json.loads(raw, object_pairs_hook=seed.unique)
    require(type(value) is dict and set(value) == {"version", "derivations"}
        and type(value["version"]) is int and value["version"] == 4)
    drvs = value["derivations"]
    require(type(drvs) is dict and 0 < len(drvs) <= inputs.MAX_ROOTS)
    require(proposal in records and proposal.endswith(".drv") and proposal.rsplit("/", 1)[1] in drvs)
    normalized = {}
    for key, row in drvs.items():
        root = basename(key)
        require(root.endswith(".drv") and root in records and type(row) is dict
            and set(row) in ({"name", "version", "outputs", "inputs", "system", "builder", "args", "env"},
                {"name", "version", "outputs", "inputs", "system", "builder", "args", "env", "structuredAttrs"})
            and type(row["version"]) is int and row["version"] == 4
            and type(row["name"]) is str and 0 < len(row["name"]) <= 211
            and (row["system"] == "x86_64-linux" or
                row["system"] == "builtin" and row["builder"] == "builtin:fetchurl"))
        require(type(row["builder"]) is str and (row["builder"] == "builtin:fetchurl" or
            re.fullmatch(seed.STORE + r"/[A-Za-z0-9._+/-]+", row["builder"]) is not None
            and not any(part in (".", "..") for part in row["builder"].split("/"))))
        require(type(row["args"]) is list and len(row["args"]) <= 4096
            and all(type(item) is str and len(item) <= 65536 and "\0" not in item for item in row["args"]))
        require(type(row["env"]) is dict and len(row["env"]) <= 4096
            and all(type(k) is str and type(v) is str and len(k) <= 256 and len(v) <= 1024**2
                and "\0" not in k + v for k, v in row["env"].items()))
        needed = row["inputs"]
        require(type(needed) is dict and set(needed) == {"srcs", "drvs"}
            and type(needed["srcs"]) is list and len(needed["srcs"]) <= inputs.MAX_ROOTS
            and len(needed["srcs"]) == len(set(needed["srcs"])) and type(needed["drvs"]) is dict
            and len(needed["drvs"]) <= inputs.MAX_ROOTS)
        sources = {basename(item) for item in needed["srcs"]}
        require(sources <= set(records))
        dependencies = {}
        for dependency, edge in needed["drvs"].items():
            dependency = basename(dependency)
            require(dependency.endswith(".drv") and type(edge) is dict
                and set(edge) == {"outputs", "dynamicOutputs"} and edge["dynamicOutputs"] == {}
                and type(edge["outputs"]) is list and 0 < len(edge["outputs"]) <= 64
                and len(edge["outputs"]) == len(set(edge["outputs"])))
            dependencies[dependency] = tuple(output_name(name) for name in edge["outputs"])
        require(type(row["outputs"]) is dict and 0 < len(row["outputs"]) <= 64)
        outputs = {}
        for name, specification in row["outputs"].items():
            output_name(name)
            require(type(specification) is dict)
            if set(specification) == {"path"}:
                outputs[name] = basename(specification["path"])
            else:
                # Fixed-content outputs have no path in version-4 JSON. Ask
                # the same isolated Nix DB for their exact output binding.
                require(set(specification) == {"method", "hash"}
                    and specification["method"] in ("flat", "nar", "text")
                    and type(specification["hash"]) is str
                    and re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", specification["hash"]) is not None)
                require((root, name) in bindings)
                outputs[name] = inputs.store(bindings[(root, name)])
            if name in row["env"]: require(row["env"][name] == outputs[name])
        normalized[root] = (row, sources, dependencies, outputs)
    visited, pending, selected, edges = set(), [proposal], set(), []
    while pending:
        root = pending.pop()
        if root in visited: continue
        require(root in normalized)
        visited.add(root)
        row, sources, dependencies, outputs = normalized[root]
        selected.update(sources)
        direct_outputs = set()
        for dependency, names in dependencies.items():
            require(dependency in normalized)
            for name in names:
                require(name in normalized[dependency][3])
                path = normalized[dependency][3][name]
                selected.add(path); direct_outputs.add(path)
                edges.append({"consumer": root, "derivation": dependency, "output": name, "path": path})
            pending.append(dependency)
        if row["builder"] != "builtin:fetchurl":
            require("/".join(row["builder"].split("/")[:4]) in sources | direct_outputs)
    require(visited == set(normalized))
    require(set(bindings) == {(root, name) for root, (row, unused, unused2, unused3) in normalized.items()
        for name, spec in row["outputs"].items() if set(spec) == {"method", "hash"}})
    # These are roots to ACQUIRE next. Their references and bytes are not known
    # merely because a derivation names them; no content authority is granted.
    known = sorted((visited | selected) & set(records))
    requested = sorted(set(inputs.reachable(records, known)) | selected)
    require(len(requested) <= inputs.MAX_ROOTS)
    return {"derivations": sorted(visited), "requiredRoots": requested,
        "requiredOutputEdges": sorted(edges, key=lambda e: (e["consumer"], e["derivation"], e["output"])),
        "missingDeclaredRoots": sorted(set(requested) - set(records)),
        "outputPath": normalized[proposal][3].get("out"), "graphSha256": seed.sha(raw),
        "builderClosureQualified": False, "generationRealized": False}


def literal(value):
    require(type(value) is str and "\0" not in value)
    return json.dumps(value).replace("${", "\\${")


def expression(value, modules, nar_hash, private_root):
    roles, artifact = value["roles"], value["artifact"]
    # builtins.storePath is unavailable in pure evaluation in pinned Nix.
    # Fixed-hash path imports read only the just-verified owned store copies.
    def fixed(role, name, pin):
        physical = private_root / "nix/store" / roles[role].rsplit("/", 1)[1]
        return ('builtins.path { name = ' + literal(name) + '; path = ' + literal(str(physical))
            + '; sha256 = ' + literal(pin) + '; }')
    return ('let modules = builtins.path { name = "omux-hm-generation-modules"; path = '
        + literal(str(modules)) + '; sha256 = ' + literal(nar_hash) + '; }; in '
        + 'import (modules + "/' + MODULE + '") { inherit modules; '
        + 'nixpkgsSource = ' + fixed("nixpkgs", "omux-locked-nixpkgs", value["pair"]["nixpkgs"]["narHash"]) + '; '
        + 'homeManagerSource = ' + fixed("home-manager", "omux-locked-home-manager", value["pair"]["home-manager"]["narHash"]) + '; '
        + 'artifactDirectory = ' + fixed("artifact", "omux-bazel-artifact", artifact["narHash"]) + '; '
        + 'artifactNarHash = ' + literal(artifact["narHash"]) + '; artifactSourceRevision = '
        + literal(artifact["sourceRevision"]) + '; channel = ' + literal(artifact["channel"]) + '; }')


class Generation:
    def __init__(self, modules):
        require(set(modules) == set(inputs.MODULES) | {MODULE})
        self.modules = modules
        self.module_root = self.description = None
        self.owner = None
        self.generated_facts = {}
        self.registered = self.generated = None

    def fence(self):
        require(self.owner is not None)
        self.owner.fence()
        require({path: inputs.facts(Path(path).lstat()) for path in self.generated_facts} == self.generated_facts)

    def close(self, deadline, *, check=True):
        if self.owner is not None: self.owner.close(deadline, check=check)

    def check(self, deadline):
        if self.registered is not None:
            value, owned, private_root, declared, runner, dumped, records, metadata = self.registered
            canonical = seed.resolve_member(value, value["roles"]["nix_store"])
            root, relative = canonical.split("/", 4)[0:4], canonical.split("/", 4)[4]
            with declared.open("/".join(root), relative) as tool:
                require(runner(private.common(value["roles"]["nix_store"], private_root) + ["--dump-db"],
                    private.environment(owned.path), owned.path, deadline, tool_fd=tool.fileno()) == dumped)
            retained, facts = generated_inputs(value, private_root, records, deadline, required_metadata=metadata)
            require(retained == self.generated and facts == self.generated_facts)
        require(inputs.nar.describe(self.module_root) == self.description)
        self.owner.admit(deadline)
        self.fence(); private.tick(deadline)

    def __call__(self, value, owned, private_root, declared, deadline, runner):
        try:
            self.owner = module_owner.Modules(owned, self.modules)
            self.owner.create(deadline)
            return self.produce(value, owned, private_root, declared, deadline, runner)
        except BaseException as failure:
            try: self.close(deadline, check=False)
            except BaseException as cleanup: raise failure from cleanup
            raise

    def produce(self, value, owned, private_root, declared, deadline, runner):
        module_root = self.owner.path
        self.owner.admit(deadline)
        description = inputs.nar.describe(module_root)
        self.module_root, self.description = module_root, description
        module_pin = inputs.nar.hash_descriptor(description,
            opener=lambda root, relative: self.owner.open(root, relative, deadline), deadline=deadline)
        nar_hash = "sha256-" + base64.b64encode(bytes.fromhex(module_pin["narHash"][7:])).decode()
        self.owner.admit(deadline)
        code = expression(value, module_root, nar_hash, private_root)
        tools = value["roles"]
        env = private.environment(owned.path)
        commands = private.common(tools["nix"], private_root) + ["--extra-experimental-features", "nix-command",
            "--offline", "--option", "pure-eval", "true", "--eval-store", "local?root=" + str(private_root)]
        canonical = seed.resolve_member(value, tools["nix"])
        root, relative = canonical.split("/", 4)[0:4], canonical.split("/", 4)[4]
        root = "/".join(root)
        with declared.open(root, relative) as tool:
            self.owner.admit(deadline)
            raw = runner(commands + ["eval", "--json", "--expr", code], env, owned.path, deadline, tool_fd=tool.fileno())
            evaluated = json.loads(raw, object_pairs_hook=seed.unique)
            require(type(evaluated) is dict and set(evaluated) == {"drvPath", "outputPath", "channel", "identity", "scope"}
                and type(evaluated["drvPath"]) is str and evaluated["drvPath"].endswith(".drv")
                and evaluated["channel"] == value["artifact"]["channel"]
                and evaluated["identity"] == ("ai.xoxd.omux.dev" if evaluated["channel"] == "development" else "ai.xoxd.omux")
                and evaluated["scope"] == "isolated-home-manager-generation-derivation-only")
            inputs.store(evaluated["drvPath"]); inputs.store(evaluated["outputPath"])
            raw_graph = runner(commands + ["derivation", "show", "--recursive", "--json", evaluated["drvPath"]],
                env, owned.path, deadline, tool_fd=tool.fileno(), output_limit=MAX_GRAPH_BYTES)
        parsed = json.loads(raw_graph, object_pairs_hook=seed.unique)
        require(type(parsed) is dict and type(parsed.get("derivations")) is dict and len(parsed["derivations"]) <= inputs.MAX_ROOTS)
        bindings = {}
        canonical = seed.resolve_member(value, tools["nix_store"])
        root, relative = canonical.split("/", 4)[0:4], canonical.split("/", 4)[4]
        root = "/".join(root)
        with declared.open(root, relative) as tool:
            dump = runner(private.common(tools["nix_store"], private_root) + ["--dump-db"],
                env, owned.path, deadline, tool_fd=tool.fileno())
            actual_records = registration(dump)
            for key, row in parsed["derivations"].items():
                path = basename(key)
                require(type(row) is dict and type(row.get("outputs")) is dict and len(row["outputs"]) <= 64)
                for name, spec in row["outputs"].items():
                    if type(spec) is dict and set(spec) == {"method", "hash"}:
                        output_name(name)
                        raw_binding = runner(private.common(tools["nix_store"], private_root) + ["--query", "--binding", name, path],
                            env, owned.path, deadline, tool_fd=tool.fileno(), output_limit=4096)
                        require(raw_binding.endswith(b"\n") and raw_binding.count(b"\n") == 1)
                        bindings[(path, name)] = inputs.store(raw_binding[:-1].decode("ascii"))
        metadata = tuple(sorted(basename(key) for key in parsed["derivations"]))
        retained, self.generated_facts = generated_inputs(value, private_root, actual_records, deadline, required_metadata=metadata)
        self.generated = retained
        self.registered = (value, owned, private_root, declared, runner, dump, actual_records, metadata)
        require(evaluated["drvPath"] in retained or evaluated["drvPath"] in value["roots"])
        result = graph(raw_graph, evaluated["drvPath"], actual_records, bindings)
        require(result["outputPath"] == evaluated["outputPath"])
        result.update(schemaVersion=1, kind=KIND, scope="actual-hm-derivation-and-build-input-acquisition-request-only",
            proposedDerivation=evaluated["drvPath"], historicalInputDerivation=tools["derivation"],
            historicalInputDerivationAuthority=False, moduleNarHash=nar_hash, homeManagerDerivationQualified=True,
            generatedInputs=retained, generatedRegistrationSha256=seed.sha(dump),
            generatedRegistration="".join("\n".join(actual_records[root]["record"])+"\n" for root in sorted(actual_records)),
            expressionSha256=seed.sha(code.encode()), artifactManifestSha256=value["artifact"]["manifestSha256"],
            activated=False, updated=False, removed=False, serviceReady=False, browserInstalled=False)
        require(len(seed.encoded(result)) <= MAX_REQUEST_BYTES)
        self.check(deadline)
        declared.check(); owned.recheck(); self.fence(); private.tick(deadline)
        return result


def provenance(value, artifact_raw, pair_raw, deadline):
    # These imports are in the target's existing complete current-HM source
    # union. Repository declarations stage every selected authority member.
    import home_manager_current_artifact as artifact
    import home_manager_current_pair_bundle as pair
    selected = artifact.selected_document(artifact_raw)
    artifact_proof = artifact.verify_retained_selected(selected, deadline)
    require(artifact_proof["manifestSha256"] == value["artifact"]["manifestSha256"]
        and artifact_proof["narHash"] == value["artifact"]["narHash"]
        and artifact_proof["sourceRevision"] == value["artifact"]["sourceRevision"])
    selection = pair.selected_document(pair_raw)
    receipt, captures, declared = pair.selected_inputs(selection, deadline)
    total, hashed = 0, hashlib.sha256()
    with declared.open("bundle") as (stream, info, check):
        while True:
            private.tick(deadline); check(); block = stream.read(65536)
            if not block: break
            total += len(block); require(total <= receipt["bundleBytes"]); hashed.update(block)
        require(total == info[6] == receipt["bundleBytes"] and hashed.hexdigest() == receipt["bundleSha256"])
        check()
    pair.recheck_captures(captures, deadline); declared.recheck()
    transport_captures = {path: inputs.control_capture(path) for path in
        (selection["root"], str(Path(selection["root"])/"bundle"), selected["root"],
         str(Path(selected["root"])/"artifact"))}
    private.tick(deadline)
    return {"artifactSelectionSha256": seed.sha(artifact_raw), "pairSelectionSha256": seed.sha(pair_raw),
        "pairProducerReceiptSha256": selection["producer"]["sha256"], "pairBundleSha256": receipt["bundleSha256"],
        "artifactProducerReceiptSha256": selected["producer"]["sha256"],
        "artifactTransportCommitment": artifact_proof["retainedTransportCommitment"],
        "transportControlCommitment": seed.sha(seed.encoded(transport_captures)),
        "pairTransportCommitment": seed.sha(seed.encoded({"bundle": list(info),
            "authority": {path: list(row[0]) for path, row in captures.items()}}))}


def main():
    parser = argparse.ArgumentParser()
    for name in ("selection", "layout", "locked-seed", "artifact-selection", "pair-selection"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--module", action="append", required=True)
    args = parser.parse_args()
    from guard_native_seed_plan_reserved import envelope, remaining
    entry = int(os.environ["OMUX_HM_ROOT_ENTRY_NS"])
    outer = int(os.environ["OMUX_HM_ROOT_DEADLINE_NS"])
    require(os.environ["OMUX_HM_RESERVED_PROFILE"] == PROFILE)
    remaining(entry, outer)
    deadline = float(min(envelope(entry, outer) / 1e9, time.monotonic() + private.MAX_SECONDS))
    paths = {"selection": args.selection, "layout": args.layout, "locked": args.locked_seed,
        "artifact": args.artifact_selection, "pair": args.pair_selection}
    bounds = {name: (seed.MAX_METADATA if name in ("layout", "locked") else 65536) for name in paths}
    captures = {name: inputs.control_capture(path) for name, path in paths.items()}
    raw = {name: inputs.control_read(path, bounds[name], captures[name], deadline) for name, path in paths.items()}
    selected = json.loads(raw["selection"], object_pairs_hook=seed.unique)
    require(type(selected) is dict and set(selected) == {"schemaVersion", "kind", "selection"}
        and type(selected["schemaVersion"]) is int and selected["schemaVersion"] == 1
        and selected["kind"] == "omux-linux-hm-realization-input-selection-v1")
    # Cold original selection still refuses before any Nix action or root read.
    row = selected["selection"]
    require(type(row) is dict and set(row) == {"path", "bytes", "sha256"}
        and type(row["path"]) is str and Path(row["path"]).is_absolute()
        and type(row["bytes"]) is int and 0 < row["bytes"] == len(raw["layout"]) <= seed.MAX_METADATA
        and inputs.digest(row["sha256"]) == seed.sha(raw["layout"]))
    value = json.loads(raw["layout"], object_pairs_hook=seed.unique)
    inputs.shape(value); require(seed.encoded(value) == raw["layout"])
    locked = json.loads(raw["locked"], object_pairs_hook=seed.unique)
    locked_pin = inputs.locked_tools(value, locked)
    private.platform(inputs.raw_metadata("/proc/" + str(os.getpid()) + "/status", 65536, deadline, proc_status=True).decode("ascii"), os.getuid())
    context = inputs.consumer_context(os.environ)
    modules, module_paths, module_captures = {}, {}, {}
    for argument in args.module:
        name, path = argument.split("=", 1)
        require(name in set(inputs.MODULES) | {MODULE} and name not in modules)
        module_paths[name] = path; module_captures[name] = inputs.control_capture(path)
        modules[name] = inputs.control_read(path, 1024**2, module_captures[name], deadline)
    require(set(modules) == set(inputs.MODULES) | {MODULE}
        and {name: seed.sha(modules[name]) for name in inputs.MODULES} == value["moduleSha256"])
    original_provenance = provenance(value, raw["artifact"], raw["pair"], deadline)
    result, declared = inputs.qualify(value, Path(args.layout).parent, os.environ["TEST_TMPDIR"], deadline,
        _registered=Generation(modules))
    result["consumerContext"] = context; result["lockedNixSeedSha256"] = locked_pin
    result["nextStage"]["provenance"] = original_provenance
    result["nextStage"]["expressionModuleSha256"] = seed.sha(modules[MODULE])

    def final():
        require(provenance(value, raw["artifact"], raw["pair"], deadline) == original_provenance)
        for name, path in paths.items():
            require(inputs.control_read(path, bounds[name], captures[name], deadline) == raw[name])
        for name, path in module_paths.items():
            require(inputs.control_read(path, 1024**2, module_captures[name], deadline) == modules[name])
        declared.check()
        for name, path in paths.items(): inputs.control_check(path, captures[name])
        for name, path in module_paths.items(): inputs.control_check(path, module_captures[name])
        inputs.consumer_context(os.environ, context); private.tick(deadline)
    final()
    encoded = seed.encoded(result); require(len(encoded) <= MAX_REQUEST_BYTES)
    sys.stdout.buffer.write(encoded); sys.stdout.flush()
    # This is an acquisition request, not retained generation output. A marker
    # remains provisional until final producer exit and original-cutoff proof.
    final()
    require(time.monotonic_ns() < envelope(entry, outer))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        print("HM generation catalogue refused", file=sys.stderr)
        raise SystemExit(125) from None
