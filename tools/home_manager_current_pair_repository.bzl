"""Finite declared acquired-source pack and genuine producer evidence; no leaf walk."""
_STATE = "/home/jess/.local/state/omux-home-manager-prefetch-20261006"
_KIND = "omux-acquired-home-manager-source-pack-selection-v1"
_NUL = json.decode('"\\u0000"')

def _fields(value, names):
    if type(value) != "dict" or sorted(value.keys()) != sorted(names):
        fail("packed source fields refused")

def _physical(value):
    if type(value) != "string" or not value.startswith("/") or len(value)>4096 or any([p in ["", ".", ".."] for p in value.split("/")[1:]]) or any([c in value for c in ["\\", "\n", "\r", _NUL]]):
        fail("packed source physical path refused")
    return value

def _sha(value):
    if type(value) != "string" or len(value)!=64 or any([c not in "0123456789abcdef" for c in value.elems()]):
        fail("packed source digest refused")

def _regular(ctx, source, destination):
    source = _physical(source)
    path = ctx.path(source)
    if not path.exists or path.is_dir or str(path.realpath)!=source:
        fail("packed regular input absent or linked")
    ctx.watch(path)
    ctx.symlink(path,destination)
    return destination

def _implementation(ctx):
    raw = ctx.read(ctx.attr.selection)
    if not raw or len(raw)>65536:
        fail("packed selection byte bound")
    value = json.decode(raw)
    _fields(value,["schemaVersion","kind","selection"])
    if type(value["schemaVersion"])!="int" or value["schemaVersion"]!=1 or value["kind"]!=_KIND:
        fail("packed selection scope")
    files = ["layout.json"]
    row = value["selection"]
    if row != None:
        _fields(row,["root","packSha256","packBytes","metadataSha256","producer"])
        for key in ["packSha256","metadataSha256"]:
            _sha(row[key])
        if type(row["packBytes"])!="int" or not 0<row["packBytes"]<=512*1024*1024:
            fail("packed source byte bound")
        root = _physical(row["root"])
        if not root.startswith(_STATE+"/"):
            fail("packed source state")
        parts = root[len(_STATE)+1:].split("/")
        if len(parts)!=11 or parts[1:5]!=["output-base","execroot","_main","bazel-out"] or parts[6:]!=["testlogs","tools","home_manager_acquisition_producer","test.outputs","home-manager-pair"] or not parts[5] or any([c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-" for c in parts[5].elems()]):
            fail("packed source output namespace")
        epoch = parts[0]
        if [len(p) for p in epoch.split("-")]!=[8,4,4,4,12] or any([c not in "0123456789abcdef-" for c in epoch.elems()]):
            fail("packed source epoch")
        producer = row["producer"]
        _fields(producer,["receipt","sha256","source_commit","source_dirty","graph_sha256"])
        for key in ["sha256","graph_sha256"]:
            _sha(producer[key])
        if type(producer["source_commit"])!="string" or len(producer["source_commit"])!=40 or any([c not in "0123456789abcdef" for c in producer["source_commit"].elems()]) or producer["source_dirty"]!="false" or producer["receipt"]!=_STATE+"/"+epoch+"/receipt.json":
            fail("packed source original producer")
        parent = _STATE+"/"+epoch
        for name in ["source.pack","source-pack.json"]:
            files.append(_regular(ctx,root+"/"+name,name))
        files.append(_regular(ctx,producer["receipt"],"authority/receipt.json"))
        files.append(_regular(ctx,parent+"/test-evidence.json","authority/test-evidence.json"))
        evidence_raw = ctx.read(ctx.path(parent+"/test-evidence.json"),watch="no")
        if not evidence_raw or len(evidence_raw)>16*1024*1024:
            fail("packed evidence bound")
        evidence = json.decode(evidence_raw)
        if type(evidence["results"])!="list" or len(evidence["results"])!=1 or evidence["results"][0]["target"]!="//tools:home_manager_acquisition_producer":
            fail("packed evidence cohort")
        members = evidence["results"][0]["files"]
        if type(members)!="list" or len(members)>16:
            fail("packed evidence file bound")
        for member in ["test.xml","test.log"]:
            rows = [r for r in members if r["source"]==member]
            if len(rows)!=1 or rows[0]["state"]!="copied":
                fail("packed evidence exact member")
            name = rows[0]["file"]
            if type(name)!="string" or len(name)!=73 or not name.endswith(".evidence"):
                fail("packed evidence leaf")
            _sha(name[:64])
            files.append(_regular(ctx,parent+"/test-evidence/"+name,"authority/"+name))
    ctx.file("layout.json",json.encode({"schemaVersion":1,"kind":"omux-current-home-manager-packed-layout-v1","sourceSelection":value})+"\n",executable=False)
    ctx.file("BUILD.bazel",'package(default_visibility=["//visibility:public"])\nexports_files(["layout.json"])\nfilegroup(name="pair_inputs",srcs='+repr(files)+')\n',executable=False)

current_home_manager_pair_repository = repository_rule(implementation=_implementation,local=True,
    attrs={"selection":attr.label(default="//tools:home_manager_current_pair_source_inputs.json",allow_single_file=True)})
