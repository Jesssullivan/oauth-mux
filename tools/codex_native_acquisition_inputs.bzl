"""Finite ninth source/binding inputs; runtime readers independently prove bytes."""
_ROOTS = ["/home/jess/.local/state/omux-execution-20261005/", "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/"]
_FIELDS = ["schema_version", "kind", "status", "source", "binding", "metadata", "sdk", "compile"]

def _need(value):
    if not value:
        fail("native acquisition declaration refused")

def _hash(value):
    return type(value) == "string" and len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def _name(value):
    _need(type(value) == "string" and not value.startswith("/") and all([part not in ["", ".", ".."] for part in value.split("/")]) and all([c not in value for c in ["\\", "\n", "\r", "\t", "\000"]]))

def _physical(ctx, value, directory = False):
    _need(type(value) == "string" and value.startswith("/") and all([part not in ["", ".", ".."] for part in value[1:].split("/")]))
    path = ctx.path(value)
    _need(path.exists and path.is_dir == directory and str(path.realpath) == value)
    return path

def _uuid(value):
    _need(type(value) == "string" and len(value) == 36 and [value[i] for i in [8,13,18,23]] == ["-","-","-","-"] and all([c in "0123456789abcdef" for c in value.replace("-", "").elems()]))

def _epoch_path(value, leaf):
    prefixes = [root for root in _ROOTS if value.startswith(root)]
    _need(len(prefixes) == 1)
    parts = value[len(prefixes[0]):].split("/")
    _need(len(parts) == 2 and parts[1] == leaf)
    _uuid(parts[0])
    return prefixes[0] + parts[0]

def _output_path(value, target, leaf):
    _need(type(value) == "string")
    roots = [root for root in _ROOTS if value.startswith(root)]
    _need(len(roots) == 1)
    parts = value[len(roots[0]):].split("/")
    _need(len(parts) == 10 + len(leaf.split("/")) and parts[1:5] == ["output-base","execroot","_main","bazel-out"] and parts[6:10] == ["testlogs","tools",target,"test.outputs"] and parts[10:] == leaf.split("/") and parts[5] and all([c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in parts[5].elems()]))
    _uuid(parts[0])

def _producer(ctx, row, target, names):
    _need(type(row) == "dict" and sorted(row.keys()) == ["graph_sha256","receipt","sha256","source_commit"] and _hash(row["sha256"]) and _hash(row["graph_sha256"]) and type(row["source_commit"]) == "string" and len(row["source_commit"]) == 40)
    epoch = _epoch_path(row["receipt"], "receipt.json")
    receipt = _physical(ctx, row["receipt"])
    raw = ctx.read(receipt)
    _need(len(raw) <= 16 * 1024 * 1024)
    value = json.decode(raw)
    _need(value.get("verb") == "test" and target in value.get("targets", []) and value.get("exit") == 0 and value.get("workload_exit") == 0 and value.get("source_commit") == row["source_commit"] and value.get("graph_sha256") == row["graph_sha256"])
    evidence = _physical(ctx, epoch + "/test-evidence.json")
    evidence_raw = ctx.read(evidence)
    _need(len(evidence_raw) <= 16 * 1024 * 1024)
    document = json.decode(evidence_raw)
    _need(document.get("targets") == value["targets"] and len(document.get("results", [])) == len(value["targets"]))
    paths = [receipt, evidence]
    for result in document["results"]:
        _need(result.get("target") in value["targets"] and result.get("state") == "observed")
        for member in ["test.log", "test.xml"]:
            entries = [entry for entry in result.get("files", []) if entry.get("source") == member]
            _need(len(entries) == 1 and entries[0].get("state") == "copied")
            entry = entries[0]
            _need(type(entry.get("file")) == "string" and len(entry["file"]) == 73 and entry["file"].endswith(".evidence") and _hash(entry["file"][:-9]) and _hash(entry.get("sha256")))
            paths.append(_physical(ctx, epoch + "/test-evidence/" + entry["file"]))
    for path in paths:
        alias = "declared/" + str(len(names))
        ctx.watch(path)
        ctx.symlink(path, alias)
        names.append(alias)

def _implementation(ctx):
    manifest = ctx.path(ctx.attr.manifest)
    raw = ctx.read(manifest)
    _need(len(raw) <= 16384)
    value = json.decode(raw)
    _need(type(value) == "dict" and sorted(value.keys()) == sorted(_FIELDS) and value["schema_version"] == 1 and value["kind"] == "omux-native-source-acquisition-input-configuration-v1")
    ctx.watch(manifest)
    names = []
    if value["status"] == "awaiting-actual-ninth-source-and-binding":
        _need(all([value[role] == None for role in ["source","binding","metadata","sdk","compile"]]))
        ctx.file("metadata-input.json", raw, executable = False)
        ctx.file("metadata-input.sha256", "unconfigured\n", executable = False)
    else:
        _need(value["status"] == "actual-ninth-source-pinned")
        row = value["source"]
        _need(type(row) == "dict" and sorted(row.keys()) == ["inventory_sha256","producer","receipt_sha256","root"] and _hash(row["inventory_sha256"]) and _hash(row["receipt_sha256"]))
        _output_path(row["root"], "codex_native_source_acquisition_source_producer", "native-source-acquisition-source")
        _physical(ctx, row["root"], True)
        _physical(ctx, row["root"] + "/source", True)
        receipt = _physical(ctx, row["root"] + "/source-receipt.json")
        source_raw = ctx.read(receipt)
        _need(len(source_raw) <= 8 * 1024 * 1024)
        report = json.decode(source_raw)
        files = report.get("source_inventory", {})
        _need(report.get("kind") == "omux-native-source-acquisition-source-v1" and report.get("status") == "verified-ninth-acquisition-source-uncompiled" and report.get("inventory_sha256") == row["inventory_sha256"] and len(files) == 8552 and len(report.get("patch_sha256", [])) == 9)
        _producer(ctx, row["producer"], "//tools:codex_native_source_acquisition_source_producer", names)
        ctx.watch(receipt)
        ctx.symlink(receipt, "source-receipt.json")
        names.append("source-receipt.json")
        for name, pin in sorted(files.items()):
            _name(name)
            _need(type(pin) == "dict" and sorted(pin.keys()) == ["mode","sha256"] and pin["mode"] in ["100644","100755","120000"] and _hash(pin["sha256"]))
            path = ctx.path(row["root"] + "/source/" + name)
            _need(path.exists and not path.is_dir)
            if pin["mode"] == "120000":
                resolved = str(path.realpath)
                prefix = row["root"] + "/source/"
                _need(resolved.startswith(prefix) and resolved[len(prefix):] in files and files[resolved[len(prefix):]]["mode"] in ["100644","100755"])
            else:
                _physical(ctx, str(path))
            alias = "declared/" + str(len(names))
            ctx.watch(path)
            ctx.symlink(path, alias)
            names.append(alias)
        if value["binding"] == None:
            ctx.file("metadata-input.json", raw, executable = False)
            ctx.file("metadata-input.sha256", "unconfigured\n", executable = False)
        else:
            binding = value["binding"]
            _need(type(binding) == "dict" and sorted(binding.keys()) == ["path","producer","sha256"] and _hash(binding["sha256"]))
            _output_path(binding["path"], "codex_native_acquisition_binding_producer", "native-acquisition-binding/receipt.json")
            path = _physical(ctx, binding["path"])
            binding_raw = ctx.read(path)
            _need(len(binding_raw) <= 16384)
            _producer(ctx, binding["producer"], "//tools:codex_native_acquisition_binding_producer", names)
            ctx.watch(path)
            ctx.symlink(path, "binding-receipt.json")
            names.append("binding-receipt.json")
            ctx.file("metadata-input.json", binding_raw, executable = False)
            ctx.file("metadata-input.sha256", binding["sha256"] + "\n", executable = False)
    if value["sdk"] != None:
        _declare_sdk(ctx, value["sdk"], names)
    if value["compile"] != None:
        _declare_compiler(ctx, value["compile"], names)
    names += ["metadata-input.json", "metadata-input.sha256"]
    ctx.file("BUILD.bazel", "\n".join(['package(default_visibility = ["//visibility:public"])', 'exports_files({})'.format(repr(names)), 'filegroup(name = "inputs", srcs = {})'.format(repr(names)), ""]), executable = False)

codex_native_acquisition_inputs = repository_rule(implementation = _implementation, local = True, attrs = {"manifest": attr.label(mandatory = True, allow_single_file = True)})

def _declare(ctx, path, names):
    ctx.watch(path)
    alias = "declared/" + str(len(names))
    ctx.symlink(path, alias)
    names.append(alias)

def _normalize(path):
    parts = []
    for part in path.split("/"):
        if part in ["", "."]:
            continue
        if part == "..":
            _need(parts)
            parts.pop()
        else:
            parts.append(part)
    return ("/" if path.startswith("/") else "") + "/".join(parts)

def _declare_sdk(ctx, row, names):
    _need(type(row) == "dict" and sorted(row.keys()) == ["inventory_sha256","producer","receipt_sha256","root"] and _hash(row["inventory_sha256"]) and _hash(row["receipt_sha256"]))
    _output_path(row["root"], "codex_native_acquisition_sdk_export_producer", "native-acquisition-sdk-export")
    _physical(ctx, row["root"], True)
    receipt = _physical(ctx, row["root"] + "/receipt.json")
    raw = ctx.read(receipt)
    _need(len(raw) <= 256 * 1024 * 1024)
    report = json.decode(raw)
    _need(report.get("kind") == "omux-native-source-acquisition-sdk-export-v1" and report.get("status") == "verified-selected-native-source-acquisition-sdk" and report.get("inventory_sha256") == row["inventory_sha256"] and report.get("native_compile_passed") == False)
    _producer(ctx, row["producer"], "//tools:codex_native_acquisition_sdk_export_producer", names)
    _declare(ctx, receipt, names)
    metadata = _physical(ctx, "/".join(row["root"].split("/")[:-1]) + "/native-acquisition-metadata/metadata-receipt.json")
    _declare(ctx, metadata, names)
    repositories = report.get("repositories", [])
    _need(0 < len(repositories) and len(repositories) <= 1600)
    objects = {}
    for repo in repositories:
        name = repo.get("canonical_name")
        _need(type(name) == "string" and name and all([c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+.~-" for c in name.elems()]) and name not in objects)
        objects[name] = True
        _physical(ctx, row["root"] + "/repositories/" + name, True)
        for item in repo.get("files", []):
            leaf = item.get("path")
            _name(leaf)
            key = name + "/" + leaf
            _need(key not in objects and item.get("kind") in ["file","directory","symlink"])
            objects[key] = True
            path = ctx.path(row["root"] + "/repositories/" + key)
            if item["kind"] == "file":
                _need(_hash(item.get("sha256")) and type(item.get("size")) == "int" and 0 <= item["size"] and item["size"] <= 1024 * 1024 * 1024)
                _declare(ctx, _physical(ctx, str(path)), names)
            elif item["kind"] == "directory":
                _physical(ctx, str(path), True)
            else:
                # Runtime proof independently resolves every link/absence against
                # the full retained closed inventory; declarations do not promote it.
                _need(type(item.get("target")) == "string" and item["target"])
                target = item["target"]
                _need(all([c not in target for c in ["\n","\r","\t","\000"]]))
                destination = _normalize(target if target.startswith("/") else "/".join(key.split("/")[:-1]) + "/" + target)
                _need(not destination.startswith("/") or destination.startswith("/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7/"))
                ctx.watch(path)
    _need(len(objects) <= 500000)
    roots = report.get("nix_store_roots", [])
    _need(roots == ["/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7"])
    for item in report.get("nix_inventory", []):
        _name(item.get("path"))
        path = roots[0] + "/" + item["path"]
        if item.get("kind") == "file":
            _need(_hash(item.get("sha256")))
            _declare(ctx, _physical(ctx, path), names)
        elif item.get("kind") == "directory":
            _physical(ctx, path, True)
        else:
            _need(item.get("kind") == "symlink")
            _need(type(item.get("target")) == "string" and item["target"])
            ctx.watch(ctx.path(path))
    for name, pin in report.get("graph_files", {}).items():
        _name(name)
        _need(type(pin) == "dict" and sorted(pin.keys()) == ["sha256"] and _hash(pin["sha256"]))
        _declare(ctx, _physical(ctx, row["root"] + "/graph/" + name), names)
    registry = report.get("registry_metadata", {}).get("files", [])
    _need(0 < len(registry) and len(registry) <= 512)
    for item in registry:
        digest = item.get("sha256")
        _need(_hash(digest) and item.get("path") == "content_addressable/sha256/" + digest + "/file")
        _declare(ctx, _physical(ctx, row["root"] + "/registry-cache/" + item["path"]), names)

def _declare_compiler(ctx, row, names):
    _need(type(row) == "dict" and sorted(row.keys()) == ["path","sha256"] and _hash(row["sha256"]))
    _need(row["path"].startswith("/srv/fast-local/jess/git/oauth-mux/docs/agent-notes/") and row["path"].endswith(".json"))
    path = _physical(ctx, row["path"])
    raw = ctx.read(path)
    _need(len(raw) <= 1024 * 1024)
    document = json.decode(raw)
    _need(document.get("kind") == "omux-native-acquisition-compilation-v1-selection")
    _declare(ctx, path, names)
    ledger = document.get("ledger")
    _need(type(ledger) == "dict" and sorted(ledger.keys()) == ["path","sha256"] and _hash(ledger["sha256"]))
    _need(ledger["path"].startswith("/srv/fast-local/jess/git/oauth-mux/docs/agent-notes/") and ledger["path"].endswith(".json"))
    ledger_path = _physical(ctx, ledger["path"])
    ledger_raw = ctx.read(ledger_path)
    _need(len(ledger_raw) <= 1024 * 1024)
    snapshot = json.decode(ledger_raw).get("goal_snapshot")
    _need(type(snapshot) == "dict" and sorted(snapshot.keys()) == ["bytes","path","sha256"] and _hash(snapshot["sha256"]) and snapshot["path"] == "docs/agent-notes/2026-10-10-native-acquisition-input-lift.UNAPPLIED/ledger-snapshots/" + snapshot["sha256"] + ".json")
    _declare(ctx, ledger_path, names)
    _declare(ctx, _physical(ctx, "/srv/fast-local/jess/git/oauth-mux/" + snapshot["path"]), names)
    for role in ["plan","query"]:
        member = document.get(role)
        _need(type(member) == "dict" and sorted(member.keys()) == ["path","producer","sha256"] and _hash(member["sha256"]))
        _output_path(member["path"], "codex_native_acquisition_" + role + "_producer", "native-acquisition-" + role + "/receipt.json")
        _producer(ctx, member["producer"], "//tools:codex_native_acquisition_" + role + "_producer", names)
        _declare(ctx, _physical(ctx, member["path"]), names)
