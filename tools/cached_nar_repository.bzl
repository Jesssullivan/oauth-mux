"""Byte-proof inputs only: inert links are data, never executable authority."""

def _absolute(value):
    if type(value) != "string" or not value.startswith("/") or any([part in ["", ".", ".."] for part in value.split("/")[1:]]) or any([character in value for character in ["\\", "\n", "\r"]]):
        fail("explicit absolute nontraversal operator input required")
    return value

def _implementation(ctx):
    selected = _absolute(ctx.attr.inventory_path or ctx.os.environ.get("OMUX_SITE_INVENTORY", ""))
    digest = ctx.attr.inventory_sha256 or ctx.os.environ.get("OMUX_SITE_INVENTORY_SHA256", "")
    if len(digest) != 64 or any([char not in "0123456789abcdef" for char in digest.elems()]):
        fail("explicit inventory SHA256 required")
    bootstrap = _absolute(ctx.attr.bootstrap_closure or ctx.os.environ.get("OMUX_BAZEL_BOOTSTRAP_CLOSURE", ""))
    if not bootstrap.startswith("/nix/store/") or len(bootstrap.split("/")) != 4:
        fail("immutable bootstrap closure required")
    manifest = ctx.path(bootstrap + "/native.json")
    paths = ctx.path(bootstrap + "/store-paths")
    ctx.watch(manifest)
    ctx.watch(paths)
    native = json.decode(ctx.read(manifest))
    python_root = native["packages"]["python"]["out"]
    if python_root not in ctx.read(paths).split("\n") or not python_root.startswith("/nix/store/") or not ctx.path(python_root + "/bin/python3").exists:
        fail("declared bootstrap Python unavailable")
    source = ctx.path(selected)
    ctx.watch(source)
    content = ctx.read(source, watch = "no")
    if len(content) > 8 * 1024 * 1024:
        fail("inventory bound exceeded")
    ctx.file("inventory.json", content, executable = False)
    for helper in [ctx.attr.generator] + ctx.attr.generator_sources:
        path = ctx.path(helper)
        ctx.watch(path)
        ctx.file(path.basename, ctx.read(path), executable = False)
    wrapper = "import runpy,sys; directory=sys.argv.pop(1); script=sys.argv.pop(1); sys.path.insert(0,directory); sys.argv[0]=script; runpy.run_path(script,run_name='__main__')"
    generated = ctx.execute([python_root + "/bin/python3", "-I", "-S", "-c", wrapper,
                             str(ctx.path(".")), str(ctx.path("nar_descriptor_repository_inventory.py")),
                             str(ctx.path("inventory.json")), digest, str(ctx.path("."))], timeout = 600)
    if generated.return_code:
        fail("declared inert NAR descriptor generation failed")
    metadata = json.decode(generated.stdout)
    if metadata["descriptorBytes"] > 256 * 1024 * 1024:
        fail("descriptor byte bound exceeded")
    labels = []
    for item in metadata["regularInputs"]:
        # Generator emits only lstat-regular paths, never link aliases.
        ctx.symlink(item["source"], item["label"])
        labels.append(item["label"])
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files(["inventory.json", "nar-descriptors.json"])',
        'filegroup(name = "regular_inputs", srcs = {})'.format(repr(labels)),
        'filegroup(name = "byteproof_inputs", srcs = [":regular_inputs", "inventory.json", "nar-descriptors.json"])',
    ]) + "\n", executable = False)

cached_nar_repository = repository_rule(
    implementation = _implementation,
    attrs = {
        "inventory_path": attr.string(),
        "inventory_sha256": attr.string(),
        "bootstrap_closure": attr.string(),
        "generator": attr.label(default = Label("//tools:nar_descriptor_repository_inventory.py"), allow_single_file = True),
        "generator_sources": attr.label_list(default = [Label("//tools:nar_descriptor.py"), Label("//tools:verify_cached_nars.py")], allow_files = True),
    },
    environ = ["OMUX_SITE_INVENTORY", "OMUX_SITE_INVENTORY_SHA256", "OMUX_BAZEL_BOOTSTRAP_CLOSURE"],
    local = True,
)
