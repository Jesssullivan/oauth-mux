"""Only independently admitted public fresh-runtime pins become inert aliases."""
VARIABLE = "OMUX_CODEX_FRESH_RUNTIME_SELECTION"

def _implementation(ctx):
    path = ctx.os.environ.get(VARIABLE,"")
    sha = ctx.os.environ.get(VARIABLE+"_SHA256","")
    size = ctx.os.environ.get(VARIABLE+"_BYTES","")
    if not path or len(sha) != 64 or any([c not in "0123456789abcdef" for c in sha.elems()]) or not size or any([c not in "0123456789" for c in size.elems()]):
        fail("complete independent fresh-runtime input selection required")
    bootstrap = ctx.os.environ.get("OMUX_BAZEL_BOOTSTRAP_CLOSURE","")
    if not bootstrap.startswith("/nix/store/") or len(bootstrap.split("/")) != 4:
        fail("declared bootstrap closure required")
    manifest = ctx.path(bootstrap+"/native.json")
    membership = ctx.path(bootstrap+"/store-paths")
    ctx.watch(manifest)
    ctx.watch(membership)
    python_root = json.decode(ctx.read(manifest))["packages"]["python"]["out"]
    if python_root not in ctx.read(membership).split("\n"):
        fail("declared metadata interpreter outside bootstrap closure")
    helper = ctx.path(ctx.attr.generator)
    selected = ctx.path(path)
    ctx.watch(helper)
    ctx.watch(selected)
    ctx.file("export.py",ctx.read(helper),executable=False)
    result = ctx.execute([python_root+"/bin/python3","-I","-S",str(ctx.path("export.py")),
        "--selection",path,"--sha256",sha,"--bytes",size],timeout=60)
    if result.return_code:
        fail("independently pinned fresh runtime inert declaration refused")
    value = json.decode(result.stdout)
    names = {"archive":"runtime.tar.gz","manifest":"runtime-manifest.json","receipt":"runtime-receipt.json"}
    for role,name in names.items():
        source = ctx.path(value["files"][role]["path"])
        if not source.exists or source.is_dir or str(source.realpath) != str(source):
            fail("physical independently admitted public runtime input absent")
        ctx.watch(source)
        ctx.symlink(source,name)
    ctx.file("input-pin.json",json.encode(value["input_pin"])+"\n",executable=False)
    ctx.file("BUILD.bazel",'package(default_visibility=["//visibility:public"])\nexports_files(["runtime.tar.gz","runtime-manifest.json","runtime-receipt.json","input-pin.json"])\n',executable=False)

codex_live_fresh_runtime_repository = repository_rule(
    implementation=_implementation,
    attrs={"generator":attr.label(default=Label("//tools:codex_live_fresh_runtime_repository_input.py"),allow_single_file=True)},
    environ=[VARIABLE,VARIABLE+"_SHA256",VARIABLE+"_BYTES","OMUX_BAZEL_BOOTSTRAP_CLOSURE"],
    local=True,
)
