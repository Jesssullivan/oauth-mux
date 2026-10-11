"""Explicit pending/selected compact input; no acquisition or producer edge."""
_ROOTS = ["/home/jess/.local/state/omux-execution-20261005/", "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/"]

def bundle_configuration_valid(value):
    if type(value) != "dict" or sorted(value.keys()) != ["kind", "schema_version", "selection", "status"] or type(value["schema_version"]) != "int" or value["schema_version"] != 1 or value["kind"] != "omux-home-manager-compact-input-configuration-v1":
        return False
    if value["status"] == "awaiting-qualified-bundle":
        return value["selection"] == None
    row = value["selection"]
    if value["status"] != "selected-bundle" or type(row) != "dict" or sorted(row.keys()) != ["bundle_sha256", "receipt_sha256", "root"]:
        return False
    root = row["root"]
    if type(root) != "string" or len(root) > 4096 or not any([root.startswith(prefix) for prefix in _ROOTS]) or any([part in ["", ".", ".."] for part in root.split("/")[1:]]) or any([char in root for char in ["\\", "\n", "\r", "\t", " ", ":", "\000"]]):
        return False
    return all([type(row[key]) == "string" and len(row[key]) == 64 and all([char in "0123456789abcdef" for char in row[key].elems()]) for key in ["bundle_sha256", "receipt_sha256"]])

def _implementation(ctx):
    raw = ctx.read(ctx.attr.manifest)
    if len(raw) > 16384:
        fail("compact configuration exceeds bound")
    configuration = json.decode(raw)
    if not bundle_configuration_valid(configuration):
        fail("compact configuration must be closed pending or explicitly selected")
    ctx.watch(ctx.path(ctx.attr.manifest))
    ctx.file("selection.json", raw, executable = False)
    row = configuration["selection"]
    if row == None:
        # Valid analysis, explicit runtime refusal before selected input IO.
        for name in ["bundle", "receipt.json"]:
            ctx.file(name, "unconfigured\n", executable = False)
    else:
        root = ctx.path(row["root"])
        if not root.exists or not root.is_dir or str(root.realpath) != row["root"]:
            fail("compact root must have physical ancestry")
        for name in ["bundle", "receipt.json"]:
            candidate = ctx.path(row["root"] + "/" + name)
            if not candidate.exists or candidate.is_dir or str(candidate.realpath) != str(candidate):
                fail("compact input absent or linked")
            ctx.watch(candidate)
            ctx.symlink(candidate, name)
    ctx.file("BUILD.bazel", 'package(default_visibility = ["//visibility:public"])\nexports_files(["bundle", "receipt.json", "selection.json"])\n', executable = False)

home_manager_bundle_repository = repository_rule(implementation = _implementation, attrs = {"manifest": attr.label(mandatory = True, allow_single_file = True)}, local = True)
