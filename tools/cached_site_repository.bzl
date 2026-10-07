"""Declare cached candidate files without executing or qualifying their tools."""

def _absolute(value):
    if type(value) != "string" or not value.startswith("/") or any([part in ["", ".", ".."] for part in value.split("/")[1:]]) or any([char in value for char in ["\\", "\n", "\r"]]):
        fail("explicit absolute nontraversal input required")
    return value

def _store(value):
    value = _absolute(value)
    if not value.startswith("/nix/store/") or len(value.split("/")) != 4:
        fail("explicit immutable store root required")
    return value

def _group(files, paths):
    prefixes = ["closure/" + path.split("/")[3] for path in paths]
    return [name for name in files if any([name == prefix or name.startswith(prefix + "/") for prefix in prefixes])]

def _public_enumeration_failure(stderr, paths):
    # Never forward arbitrary traceback text, operator paths or link targets.
    # Categories are fixed; paths are drawn only from validated public metadata.
    tail = stderr[-8192:]
    category = "enumeration-unavailable"
    for marker, name in [
        ("undeclared intermediate target", "alias-outside-closure"),
        ("symlink escapes the declared immutable closure", "alias-outside-closure"),
        ("undeclared directory", "directory-outside-closure"),
        ("unsupported declared Nix input type", "unsupported-file-type"),
        ("PermissionError", "permission"),
        ("FileNotFoundError", "missing-input"),
        ("cyclic input alias", "cyclic-alias"),
    ]:
        if marker in tail:
            category = name
            break
    implicated = [path for path in paths if path in tail or path.split("/")[3] in tail][:8]
    aliases = []
    for word in tail.replace("\n", " ").split(" "):
        if word.startswith("public_source_alias=closure/"):
            alias = word[len("public_source_alias="):]
            if len(alias) <= 1400 and all([char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./+@=-" for char in alias.elems()]) and any([alias == "closure/" + path.split("/")[3] or alias.startswith("closure/" + path.split("/")[3] + "/") for path in paths]):
                aliases.append(alias)
    return json.encode({"category": category, "public_store_roots": implicated, "public_source_aliases": aliases[:8], "stderr_bytes": min(len(stderr), 8192)})

def _implementation(ctx):
    selected = _absolute(ctx.attr.inventory_path or ctx.os.environ.get("OMUX_SITE_INVENTORY", ""))
    digest = ctx.attr.inventory_sha256 or ctx.os.environ.get("OMUX_SITE_INVENTORY_SHA256", "")
    if len(digest) != 64 or any([char not in "0123456789abcdef" for char in digest.elems()]):
        fail("explicit inventory SHA256 required")
    bootstrap = _store(ctx.attr.bootstrap_closure or ctx.os.environ.get("OMUX_BAZEL_BOOTSTRAP_CLOSURE", ""))
    manifest_path = ctx.path(bootstrap + "/native.json")
    paths_path = ctx.path(bootstrap + "/store-paths")
    ctx.watch(manifest_path)
    ctx.watch(paths_path)
    host = json.decode(ctx.read(manifest_path))
    python_root = _store(host["packages"]["python"]["out"])
    if python_root not in ctx.read(paths_path).split("\n") or not ctx.path(python_root + "/bin/python3").exists:
        fail("bootstrap Python missing from declared host closure")
    python = python_root + "/bin/python3"
    input_path = ctx.path(selected)
    ctx.watch(input_path)
    content = ctx.read(input_path, watch = "no")
    if len(content) > 8 * 1024 * 1024:
        fail("candidate inventory exceeds 8 MiB")
    ctx.file("inventory.json", content, executable = False)
    # Copy validator dependencies: -I deliberately excludes ambient PYTHONPATH.
    for dependency in ctx.attr.validator_sources:
        source = ctx.path(dependency)
        ctx.watch(source)
        ctx.file(source.basename, ctx.read(source), executable = False)
    ctx.watch(ctx.path(ctx.attr.validator))
    ctx.file("cached_site_input_validator.py", ctx.read(ctx.attr.validator), executable = False)
    # -I excludes this generated script directory too; the explicit wrapper
    # inserts only our copied, declared helper directory before runpy.
    wrapper = "import runpy,sys; directory=sys.argv.pop(1); script=sys.argv.pop(1); sys.path.insert(0,directory); sys.argv[0]=script; runpy.run_path(script,run_name='__main__')"
    command = [python, "-I", "-S", "-c", wrapper, str(ctx.path(".")), str(ctx.path("cached_site_input_validator.py")), str(ctx.path("inventory.json")), digest]
    validated = ctx.execute(command, timeout = 30, environment = {"PYTHONPATH": "", "PYTHONHOME": ""})
    if validated.return_code:
        fail("public candidate inventory validation failed")
    metadata = json.decode(validated.stdout)
    for path in metadata["allPaths"]:
        _store(path)
        if not ctx.path(path).exists:
            fail("candidate descendant is unavailable")
        ctx.symlink(path, "closure/" + path.split("/")[3])
    for name, package in metadata["packages"].items():
        ctx.symlink(_store(package["out"]), "packages/" + name)
    ctx.file("store-paths", "\n".join(metadata["allPaths"]) + "\n", executable = False)
    ctx.watch(ctx.path(ctx.attr.file_inventory))
    enumerated = ctx.execute([python, "-I", "-S", ctx.path(ctx.attr.file_inventory), str(ctx.path(".")), "closure", "packages", "--inert-policy=cached-site-bluez-5.86"], timeout = 600)
    if enumerated.return_code:
        fail("guarded candidate file enumeration failed: " + _public_enumeration_failure(enumerated.stderr, metadata["allPaths"]))
    enumeration = json.decode(enumerated.stdout)
    files = enumeration["files"]
    ctx.file("execution-exclusions.json", json.encode_indent({"schemaVersion": 1, "policy": "cached-site-bluez-5.86", "exclusions": enumeration["excluded_non_inputs"], "executionAuthority": False}, indent = "  ") + "\n", executable = False)
    ctx.file("candidate.json", json.encode_indent(metadata, indent = "  ") + "\n", executable = False)
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files(["inventory.json", "candidate.json", "store-paths", "execution-exclusions.json", "packages/chromium/bin/chromium", "packages/node/bin/node"])',
        'filegroup(name = "full_closure", srcs = {})'.format(repr(files)),
        'filegroup(name = "node_closure", srcs = {})'.format(repr(_group(files, metadata["nodePaths"]))),
        'filegroup(name = "browser_closure", srcs = {})'.format(repr(_group(files, metadata["browserPaths"]))),
    ]) + "\n", executable = False)

cached_site_repository = repository_rule(
    implementation = _implementation,
    attrs = {
        "inventory_path": attr.string(),
        "inventory_sha256": attr.string(),
        "bootstrap_closure": attr.string(),
        "validator": attr.label(default = Label("//tools:cached_site_input_validator.py"), allow_single_file = True),
        "validator_sources": attr.label_list(default = [Label("//tools:cached_nix_inventory.py"), Label("//tools:verify_cached_nars.py")], allow_files = True),
        "file_inventory": attr.label(default = Label("//tools:nix_file_inventory.py"), allow_single_file = True),
    },
    environ = ["OMUX_SITE_INVENTORY", "OMUX_SITE_INVENTORY_SHA256", "OMUX_BAZEL_BOOTSTRAP_CLOSURE"],
    local = True,
)
