"""Cold exact history13 package declarations; action requalifies every byte."""
def _need(value):
    if not value:
        fail("owned history runtime declaration refused")

def _sha(value):
    return type(value) == "string" and len(value) == 64 and all([c in "0123456789abcdef" for c in value.elems()])

def _path(ctx,value):
    _need(type(value) == "string" and value.startswith("/") and all([part not in ["",".",".."] for part in value[1:].split("/")]))
    path = ctx.path(value)
    _need(path.exists and not path.is_dir and str(path.realpath) == value)
    return path

def _implementation(ctx):
    raw = ctx.read(ctx.path(ctx.attr.selection))
    _need(len(raw) <= 16384)
    config = json.decode(raw)
    _need(type(config) == "dict" and sorted(config.keys()) == ["kind","package","schema_version","status"]
        and config["schema_version"] == 1 and config["kind"] == "omux-owned-history-tree-runtime-selection-v3")
    ctx.watch(ctx.path(ctx.attr.selection))
    ctx.symlink(ctx.path(ctx.attr.selection),"runtime-selection.json")
    inputs = []
    if config["status"] == "PENDING-GENUINE-CLI-PACKAGE":
        _need(config["package"] == None)
    else:
        _need(config["status"] == "qualified-history13-cli-package" and type(config["package"]) == "dict")
        row = config["package"]
        _need(sorted(row.keys()) == ["files","producer","root"] and sorted(row["files"].keys()) ==
            ["cli-stderr.log","cli-stdout.log","codex-original","runtime-manifest.json","runtime-receipt.json","runtime.tar.gz"])
        producer = row["producer"]
        _need(sorted(producer.keys()) == ["graph_sha256","receipt","sha256","source_commit"]
            and _sha(producer["sha256"]) and _sha(producer["graph_sha256"]) and len(producer["source_commit"]) == 40)
        outer_path = _path(ctx,producer["receipt"])
        epoch = str(outer_path.dirname)
        _need(outer_path.basename == "receipt.json" and str(outer_path.dirname.dirname) in
            ["/home/jess/.local/state/omux-execution-20261005","/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005"])
        prefix = epoch+"/output-base/execroot/_main/bazel-out/"
        suffix = "/testlogs/tools/codex_native_owned_history_cli_producer/test.outputs/native-owned-history-cli"
        _need(row["root"].startswith(prefix) and row["root"].endswith(suffix))
        middle = row["root"][len(prefix):-len(suffix)]
        _need(len(middle)>0 and all([c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for c in middle.elems()]))
        outer_raw = ctx.read(outer_path); _need(len(outer_raw)<=8*1024*1024)
        outer = json.decode(outer_raw)
        targets = ["//tools:codex_native_owned_history_cli_test","//tools:codex_native_owned_history_cli_producer"]
        _need(outer.get("profile") == "native-owned-history-cli-reserved" and outer.get("targets") == targets
            and outer.get("exit") == 0 and outer.get("workload_exit") == 0)
        index_path = _path(ctx,epoch+"/test-evidence.json")
        index_raw = ctx.read(index_path); _need(len(index_raw)<=8*1024*1024)
        index = json.decode(index_raw)
        _need(index.get("targets") == targets and type(index.get("results")) == "list"
            and [result.get("target") for result in index["results"]] == targets)
        paths = [str(outer_path),str(index_path)]
        for name,pin in sorted(row["files"].items()):
            _need(sorted(pin.keys()) == ["bytes","sha256"] and _sha(pin["sha256"])
                and type(pin["bytes"]) == "int" and 0<=pin["bytes"] and pin["bytes"]<=512*1024*1024)
            paths.append(str(_path(ctx,row["root"]+"/"+name)))
        for result in index["results"]:
            _need(result.get("state") == "observed")
            for name in ["test.log","test.xml"]:
                matches = [member for member in result.get("files",[]) if member.get("source") == name]
                _need(len(matches)==1 and matches[0].get("state") == "copied")
                member = matches[0]
                _need(type(member.get("file")) == "string" and len(member["file"]) == 73
                    and member["file"].endswith(".evidence") and _sha(member["file"][:-9]) and _sha(member.get("sha256")))
                paths.append(str(_path(ctx,epoch+"/test-evidence/"+member["file"])))
        _need(len(paths)==12 and len({path: True for path in paths})==12)
        for i,path in enumerate(paths):
            alias = "input/"+str(i)
            ctx.watch(ctx.path(path)); ctx.symlink(ctx.path(path),alias)
            inputs.append({"path":path,"alias":alias})
        for name,alias in [("runtime.tar.gz","runtime.tar.gz"),("runtime-receipt.json","runtime-receipt.json")]:
            ctx.symlink(ctx.path(row["root"]+"/"+name),alias)
    ctx.file("input-aliases.json",json.encode({"kind":"omux-owned-history-runtime-inputs-v3","inputs":inputs})+"\n",executable=False)
    # The raw independently selected document is staged byte-for-byte. SHA is
    # supplied as an external selection attr; repository evaluation cannot
    # mint an authenticated producer or qualification from these checks.
    _need(_sha(ctx.attr.selection_sha256))
    ctx.file("runtime-selection.sha256",ctx.attr.selection_sha256+"\n",executable=False)
    aliases = [row["alias"] for row in inputs]+["runtime-selection.json","runtime-selection.sha256","input-aliases.json"]
    if inputs: aliases += ["runtime.tar.gz","runtime-receipt.json"]
    archive = ["runtime.tar.gz"] if inputs else []
    receipt = ["runtime-receipt.json"] if inputs else []
    ctx.file("BUILD.bazel","package(default_visibility = [\"//visibility:public\"])\nexports_files({})\nfilegroup(name=\"inputs\",srcs={})\nfilegroup(name=\"runtime_archive\",srcs={})\nfilegroup(name=\"runtime_receipt\",srcs={})\n".format(repr(aliases),repr(aliases),repr(archive),repr(receipt)),executable=False)

owned_history_runtime_inputs = repository_rule(
    implementation = _implementation,
    attrs = {"selection":attr.label(mandatory=True,allow_single_file=True),"selection_sha256":attr.string(mandatory=True)},
    local = True,
)
