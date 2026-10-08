"""Declare all locked native-flake source bytes without fetch or evaluation."""

def _immutable(value):
    if type(value) != "string" or not value.startswith("/nix/store/") or len(value.split("/")) != 4 or any([c in value for c in ["\n", "\r", "\000", "..", "\\"]]):
        fail("explicit immutable native source or bootstrap root required")
    return value

def _impl(ctx):
    if sorted(ctx.attr.sources.keys()) != ["flake-utils", "nixpkgs", "systems"]:
        fail("exact nixpkgs/flake-utils/systems source selection required")
    sources = {role: _immutable(value) for role, value in ctx.attr.sources.items()}
    for root in sources.values():
        selected = ctx.path(root)
        if not selected.exists or not selected.is_dir or str(selected.realpath) != root:
            fail("selected native source must be an available canonical directory")
    bootstrap = _immutable(ctx.attr.bootstrap_closure or ctx.os.environ.get("OMUX_BAZEL_BOOTSTRAP_CLOSURE", ""))
    manifest = ctx.path(bootstrap + "/native.json")
    paths = ctx.path(bootstrap + "/store-paths")
    ctx.watch(manifest)
    ctx.watch(paths)
    native = json.decode(ctx.read(manifest))
    python = _immutable(native["packages"]["python"]["out"])
    if python not in ctx.read(paths).split("\n") or not ctx.path(python + "/bin/python3").exists:
        fail("declared bootstrap Python unavailable")
    ctx.file("selection.json", json.encode(sources), executable = False)
    ctx.file("flake.lock", ctx.read(ctx.attr.lock), executable = False)
    for helper in [ctx.attr.generator] + ctx.attr.generator_sources:
        selected = ctx.path(helper)
        ctx.watch(selected)
        ctx.file(selected.basename, ctx.read(selected), executable = False)
    wrapper = "import runpy,sys; directory=sys.argv.pop(1); script=sys.argv.pop(1); sys.path.insert(0,directory); sys.argv[0]=script; runpy.run_path(script,run_name='__main__')"
    generated = ctx.execute([
        python + "/bin/python3", "-I", "-S", "-c", wrapper,
        str(ctx.path(".")), str(ctx.path("native_flake_sources.py")), "describe",
        "--selection", str(ctx.path("selection.json")),
        "--lock", str(ctx.path("flake.lock")), "--repository", str(ctx.path(".")),
    ], timeout = 600)
    if generated.return_code:
        fail("declared native source descriptor generation failed; no fetch or fallback")
    metadata = json.decode(generated.stdout)
    if metadata["descriptorBytes"] > 256 * 1024 * 1024:
        fail("native source descriptor bound exceeded")
    labels = []
    for item in metadata["regularInputs"]:
        source = item["source"]
        if not any([source.startswith(root + "/") for root in sources.values()]):
            fail("regular native source input escaped its selected root")
        selected = ctx.path(source)
        if not selected.exists or selected.is_dir or str(selected.realpath) != source:
            fail("regular native source input is unavailable or redirected")
        ctx.symlink(item["source"], item["label"])
        labels.append(item["label"])
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files(["source-descriptors.json"])',
        'filegroup(name = "regular_inputs", srcs = {})'.format(repr(labels)),
        'filegroup(name = "byteproof_inputs", srcs = [":regular_inputs", "source-descriptors.json"])',
    ]) + "\n", executable = False)

native_flake_sources_repository = repository_rule(
    implementation = _impl,
    attrs = {
        "sources": attr.string_dict(mandatory = True, doc = "Exactly three explicitly selected cached immutable roots."),
        "bootstrap_closure": attr.string(doc = "Existing locked bootstrap closure; never freshly realized."),
        "lock": attr.label(default = Label("//:flake.lock"), allow_single_file = True),
        "generator": attr.label(default = Label("//tools:native_flake_sources.py"), allow_single_file = True),
        "generator_sources": attr.label_list(default = [
            Label("//tools:nar_descriptor.py"), Label("//tools:nix_source_probe.py"),
            Label("//tools:verify_declared_nars.py"), Label("//tools:verify_cached_nars.py"),
        ], allow_files = True),
    },
    environ = ["OMUX_BAZEL_BOOTSTRAP_CLOSURE"],
    local = True,
)
