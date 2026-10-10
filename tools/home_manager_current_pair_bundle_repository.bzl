"""Exact selected current pair compact bytes; no artifact input or fetch."""

def _fields(value, keys):
    if type(value) != "dict" or sorted(value.keys()) != sorted(keys):
        fail("current HM selection fields refused")

def _physical(value):
    if type(value) != "string" or not value.startswith("/") or len(value)>4096 or any([part in ["", ".", ".."] for part in value.split("/")[1:]]) or any([char in value for char in ["\\", "\n", "\r"]]):
        fail("current HM physical declaration refused")
    return value

def _regular(ctx, source, destination):
    source=_physical(source)
    file=ctx.path(source)
    if not file.exists or file.is_dir or str(file.realpath)!=source:
        fail("current HM declared input absent or linked")
    ctx.watch(file)
    ctx.symlink(file,destination)
    return destination

def _implementation(ctx):
    raw=ctx.read(ctx.attr.selection)
    if len(raw)>65536:
        fail("current HM selected document bound")
    value=json.decode(raw)
    _fields(value,["schemaVersion","kind","selection"])
    if type(value["schemaVersion"])!="int" or value["schemaVersion"]!=1 or value["kind"]!="omux-current-home-manager-pair-selection-v1":
        fail("current HM selected document kind")
    ctx.file("selection.json",raw,executable=False)
    files=[]
    selection=value["selection"]
    if selection!=None:
        _fields(selection,["root","bundleSha256","receiptSha256","producer"])
        root=_physical(selection["root"])
        public=None
        for base in ["/home/jess/.local/state/omux-execution-20261005","/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005"]:
            if root.startswith(base+"/"):
                public=base
        if public==None:
            fail("current HM public epoch root required")
        parts=root[len(public)+1:].split("/")
        if len(parts)!=10 or parts[1:5]!=["output-base","execroot","_main","bazel-out"] or parts[6:]!=["testlogs","tools","home_manager_current_pair_reconstruction_producer","test.outputs"] or not parts[5] or any([char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-" for char in parts[5].elems()]):
            fail("current HM exact output namespace required")
        epoch=parts[0]
        if [len(part) for part in epoch.split("-")]!=[8,4,4,4,12] or any([char not in "0123456789abcdef-" for char in epoch.elems()]):
            fail("current HM public epoch spelling required")
        producer=selection["producer"]
        _fields(producer,["receipt","sha256","source_commit","source_dirty","graph_sha256"])
        if producer["receipt"]!=public+"/"+epoch+"/receipt.json":
            fail("current HM original producer epoch required")
        for name in ["receipt.json","bundle"]:
            files.append(_regular(ctx,root+"/"+name,name))
        receipt=_physical(producer["receipt"])
        parent=receipt.rsplit("/",1)[0]
        files.append(_regular(ctx,receipt,"authority/receipt.json"))
        files.append(_regular(ctx,parent+"/test-evidence.json","authority/test-evidence.json"))
        evidence_raw=ctx.read(ctx.path(parent+"/test-evidence.json"),watch="no")
        if len(evidence_raw)>16*1024*1024:
            fail("current HM evidence byte bound")
        evidence=json.decode(evidence_raw)
        if len(evidence["results"])!=1:
            fail("current HM evidence cohort")
        for member in evidence["results"][0]["files"]:
            if member["source"] in ["test.log","test.xml"] and member["state"]=="copied":
                name=member["file"]
                if len(name)!=73 or not name.endswith(".evidence") or any([char not in "0123456789abcdef" for char in name[:64].elems()]):
                    fail("current HM evidence leaf")
                files.append(_regular(ctx,parent+"/test-evidence/"+name,"authority/"+name))
    if selection==None:
        ctx.file("bundle","awaiting-qualified-current-pair\n",executable=False)
        ctx.file("receipt.json","awaiting-qualified-current-pair\n",executable=False)
    ctx.file("BUILD.bazel",'package(default_visibility=["//visibility:public"])\nexports_files(["selection.json","bundle","receipt.json"])\nfilegroup(name="selected_inputs",srcs='+repr(files)+')\n',executable=False)

current_home_manager_pair_bundle_repository=repository_rule(implementation=_implementation,local=True,
    attrs={"selection":attr.label(default="//tools:home_manager_current_pair_inputs.json",allow_single_file=True)})
