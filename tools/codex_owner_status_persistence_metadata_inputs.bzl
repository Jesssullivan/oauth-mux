"""Finite actual source+sealed SDK metadata inputs; never executes a tool."""
_CONTROL = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/32da88ee-f894-4453-8371-3cc4719c8ade/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_owner_status_persistence_metadata_binding_producer/test.outputs/owner-status-persistence-metadata-binding.json"
_CONTROL_SHA = "19903dbf0c939fe88522f3ee45dfb9049739abc12ad68bdb890b04867d2b08fe"
_SOURCE = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/95f10057-c0be-4a94-98f8-291dedec0d48/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_owner_status_persistence_source_producer/test.outputs/owner-status-persistence-source"
_EXPORT = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export"
_EXPORT_SHA = "1aa4c87d689f464e576a5c6a51b4c6350a8f0346f6b94299856d01db5147d4f0"
_JDK = "/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7"

def _need(value, stage):
    if not value:
        fail("protocol-history metadata input refused: " + stage)

def _sha(value):
    return type(value) == "string" and len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def _name(value):
    _need(type(value) == "string" and not value.startswith("/") and all([part not in ["", ".", ".."] for part in value.split("/")]) and all([c not in value for c in ["\\", "\n", "\r", "\t", "\000"]]), "relative-path")

def _physical(ctx, path, directory = False):
    selected = ctx.path(path)
    _need(selected.exists and selected.is_dir == directory and str(selected.realpath) == str(selected), "physical-selected-path")
    return selected

def _normalize(path):
    result = []
    for part in path.split("/"):
        if part in ["", "."]:
            continue
        if part == "..":
            _need(result, "link-parent-escape")
            result.pop()
        else:
            result.append(part)
    return ("/" if path.startswith("/") else "") + "/".join(result)

def _resolve(key, objects, links):
    seen = {}
    for _ in range(64):
        _need(key not in seen, "link-cycle")
        seen[key] = True
        parts = key.split("/")
        candidates = ["/".join(parts[:index]) for index in range(1, len(parts) + 1) if "/".join(parts[:index]) in links]
        if not candidates:
            return key
        prefix = candidates[0]
        suffix = key[len(prefix):]
        key = _normalize(links[prefix] + suffix)
    fail("protocol-history metadata input refused: excessive-link-depth")

def _implementation(ctx):
    _need(ctx.attr.selection == _CONTROL and ctx.attr.sha256 == _CONTROL_SHA, "actual-n4-selection")
    control = _physical(ctx, _CONTROL)
    raw = ctx.read(control)
    _need(len(raw) == 2896, "actual-n4-size")
    binding = json.decode(raw)
    selection = binding.get("metadata_input", {})
    _need(binding.get("kind") == "omux-owner-status-persistence-metadata-binding-v1" and binding.get("source_reconstructed_and_fully_read") == True and selection == {"kind": "omux-owner-status-persistence-metadata-input-v1", "source_root": _SOURCE, "source_receipt_sha256": "a17c9b7294fd7b8018f60bd2210f14140598d4b04e10da05aa1733a9482f3eab", "source_inventory_sha256": "252599e5faafa05e2ff688e57e58d1890aea57ead0f35ce0633588754cae5030"}, "actual-n4-role")
    source_root = _SOURCE
    _physical(ctx, source_root, True)
    _physical(ctx, source_root + "/source", True)
    source_receipt = _physical(ctx, source_root + "/source-receipt.json")
    source_raw = ctx.read(source_receipt)
    _need(len(source_raw) <= 8 * 1024 * 1024, "source-receipt-size")
    source = json.decode(source_raw)
    files = source.get("source_inventory", {})
    _need(source.get("kind") == "omux-owner-status-persistence-source-v1" and source.get("status") == "verified-owner-status-persistence-source-pending-sdk-and-schema" and source.get("inventory_sha256") == selection["source_inventory_sha256"] and source.get("sdk_metadata_qualified") == False and source.get("native_compile_passed") == False and source.get("provider_evaluation") == False and len(files) == 8549, "source-receipt-role")
    inputs = [control, source_receipt]
    for name, row in sorted(files.items()):
        _name(name)
        _need(type(row) == "dict" and sorted(row.keys()) == ["mode", "sha256"] and row.get("mode") in ["100644", "100755", "120000"] and _sha(row.get("sha256")), "source-inventory-row")
        path = ctx.path(source_root + "/source/" + name)
        _need(path.exists and not path.is_dir, "source-inventory-file")
        if row["mode"] == "120000":
            resolved = str(path.realpath)
            prefix = source_root + "/source/"
            _need(resolved.startswith(prefix) and resolved[len(prefix):] in files and files[resolved[len(prefix):]].get("mode") in ["100644", "100755"], "source-link-target")
            ctx.watch(path)
        else:
            inputs.append(_physical(ctx, str(path)))
    _physical(ctx, _EXPORT, True)
    export_receipt = _physical(ctx, _EXPORT + "/receipt.json")
    export_raw = ctx.read(export_receipt)
    _need(len(export_raw) <= 256 * 1024 * 1024, "export-receipt-size")
    exported = json.decode(export_raw)
    repositories = exported.get("repositories", [])
    _need(exported.get("schema") == "omux-retained-native-sdk-export-v1" and exported.get("qualification_only") == False and 0 < len(repositories) and len(repositories) <= 1600 and exported.get("nix_store_roots") == [_JDK], "export-receipt-role")
    inputs.append(export_receipt)
    objects, links, absolute, absences = {}, {}, {}, {}
    for repo in repositories:
        name = repo.get("canonical_name")
        _need(type(name) == "string" and name and all([c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+.~-" for c in name.elems()]) and name not in objects, "repository-name")
        _physical(ctx, _EXPORT + "/repositories/" + name, True)
        objects[name] = {"kind": "directory"}
        absolute[name] = _EXPORT + "/repositories/" + name
        for row in repo.get("files", []):
            path = row.get("path")
            _name(path)
            key = name + "/" + path
            _need(key not in objects and row.get("kind") in ["file", "directory", "symlink"], "repository-inventory")
            objects[key], absolute[key] = row, _EXPORT + "/repositories/" + key
            if row["kind"] == "symlink":
                target = row.get("target")
                _need(type(target) == "string" and target and all([c not in target for c in ["\n", "\r", "\t", "\000"]]), "repository-link")
                destination = _normalize(target if target.startswith("/") else "/".join(key.split("/")[:-1]) + "/" + target)
                _need(destination.startswith(_JDK + "/") or not destination.startswith("/"), "repository-link-root")
                links[key] = destination
        for absence in repo.get("absent_links", []):
            _need(type(absence) == "dict" and sorted(absence.keys()) == ["origin", "target"] and type(absence["origin"]) == "string" and type(absence["target"]) == "string", "absent-link-role")
            absences[absence["origin"]] = absence["target"]
    _need(0 < len(objects) and len(objects) <= 500000 and "rules_rs++crate+crates" in objects, "repository-object-bound")
    _physical(ctx, _JDK, True)
    objects[_JDK] = {"kind": "directory"}
    absolute[_JDK] = _JDK
    for row in exported.get("nix_inventory", []):
        path = row.get("path")
        _name(path)
        key = _JDK + "/" + path
        _need(key not in objects and row.get("kind") in ["file", "directory", "symlink"], "immutable-jdk-inventory")
        objects[key], absolute[key] = row, key
        # No symbolic JDK leaf is declared as a file; its regular closure is
        # declared separately and all locked Nix tools remain target data.
        if row["kind"] == "symlink":
            target = row.get("target")
            _need(type(target) == "string" and target, "immutable-jdk-link")
            destination = _normalize(target if target.startswith("/") else "/".join(key.split("/")[:-1]) + "/" + target)
            if destination.startswith(_JDK + "/"):
                links[key] = destination
    for key, row in sorted(objects.items()):
        if row["kind"] == "file":
            _need(type(row.get("size")) == "int" and 0 <= row["size"] and row["size"] <= 1024 * 1024 * 1024 and _sha(row.get("sha256")) and type(row.get("mode")) == "int" and row["mode"] in [292, 365], "selected-file-pin")
            inputs.append(_physical(ctx, absolute[key]))
        elif row["kind"] == "directory":
            _physical(ctx, absolute[key], True)
    for key in sorted(links.keys()):
        if key.startswith(_JDK + "/"):
            continue
        resolved = _resolve(key, objects, links)
        path = ctx.path(absolute[key])
        if resolved in objects:
            _need(resolved in absolute and objects[resolved]["kind"] in ["file", "directory"] and path.exists and str(path.realpath) == absolute[resolved], "physical-selected-link")
            ctx.watch(path)
        else:
            _need(key in absences and absences[key] == resolved and not path.exists and not resolved.startswith("/") and resolved.split("/")[0] in objects, "qualified-absent-link")
    for name, pin in exported.get("graph_files", {}).items():
        _name(name)
        _need(type(pin) == "dict" and sorted(pin.keys()) == ["sha256"] and _sha(pin.get("sha256")), "graph-file-pin")
        inputs.append(_physical(ctx, _EXPORT + "/graph/" + name))
    registry = exported.get("registry_metadata", {}).get("files", [])
    _need(0 < len(registry) and len(registry) <= 512, "registry-file-bound")
    for row in registry:
        digest = row.get("sha256")
        _need(_sha(digest) and row.get("path") == "content_addressable/sha256/" + digest + "/file" and type(row.get("size")) == "int" and 0 <= row["size"] and row["size"] <= 1024 * 1024, "registry-file-pin")
        inputs.append(_physical(ctx, _EXPORT + "/registry-cache/" + row["path"]))
    _need(len(inputs) <= 500000, "declared-file-bound")
    aliases = []
    for index, path in enumerate(inputs):
        ctx.watch(path)
        alias = "input-files/" + str(index)
        ctx.symlink(path, alias)
        aliases.append(alias)
    ctx.file("metadata-input.json", raw, executable = False)
    ctx.file("metadata-input.sha256", ctx.attr.sha256 + "\n", executable = False)
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(aliases + ["metadata-input.json", "metadata-input.sha256"])),
        'filegroup(name = "inputs", srcs = {})'.format(repr(aliases + ["metadata-input.json", "metadata-input.sha256"])),
        "",
    ]), executable = False)

codex_owner_status_persistence_metadata_inputs = repository_rule(
    implementation = _implementation,
    attrs = {"selection": attr.string(mandatory = True), "sha256": attr.string(mandatory = True)},
    local = True,
)
