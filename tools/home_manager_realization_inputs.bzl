"""Explicit complete regular aliases; no Nix invocation or store discovery."""

def _implementation(ctx):
    control = ctx.path(ctx.attr.configuration)
    ctx.watch(control)
    raw = ctx.read(control)
    if len(raw) > 65536:
        fail("HM realization selection exceeds control bound")
    selected = json.decode(raw)
    if sorted(selected.keys()) != ["kind", "schemaVersion", "selection"] or selected["schemaVersion"] != 1 or selected["kind"] != "omux-linux-hm-realization-input-selection-v1":
        fail("HM realization selection kind/shape")
    ctx.file("selection.json", raw, executable = False)
    files = []
    if selected["selection"] == None:
        ctx.file("layout.json", "{}\n", executable = False)
    else:
        row = selected["selection"]
        if sorted(row.keys()) != ["bytes", "path", "sha256"] or type(row["path"]) != "string" or not row["path"].startswith("/") or row["bytes"] <= 0 or row["bytes"] > 67108864 or len(row["sha256"]) != 64:
            fail("HM realization explicit public layout selector")
        path = ctx.path(row["path"])
        if not path.exists or path.is_dir or str(path.realpath) != row["path"]:
            fail("HM realization layout unavailable/linked")
        ctx.watch(path)
        layout = ctx.read(path)
        if len(layout) != row["bytes"]:
            fail("HM realization layout size changed")
        document = json.decode(layout)
        if document.get("kind") != "omux-linux-hm-realization-input-closure-v1" or document.get("system") != "x86_64-linux":
            fail("HM realization Linux family")
        members = document["files"]
        if len(members) == 0 or len(members) > 200000:
            fail("HM realization member count")
        for index, member in enumerate(members):
            if sorted(member.keys()) != ["alias", "path", "root", "source"] or member["alias"] != "members/" + str(index):
                fail("HM realization complete alias order")
            source = ctx.path(member["source"])
            if not source.exists or source.is_dir:
                fail("HM realization declared regular unavailable")
            ctx.watch(source)
            ctx.symlink(source, member["alias"])
            files.append(member["alias"])
        # Independent SHA and all logical/reference/NAR predicates are action
        # obligations. Repository setup does not qualify this declaration.
        ctx.file("layout.json", layout, executable = False)
    ctx.file("BUILD.bazel", """package(default_visibility=["//visibility:public"])
exports_files(["selection.json", "layout.json"])
filegroup(name="members", srcs=%s)
""" % repr(files), executable = False)

home_manager_realization_inputs_repository = repository_rule(
    implementation = _implementation,
    attrs = {"configuration": attr.label(default = Label("//tools:home_manager_realization_input_selection.json"), allow_single_file = True)},
    local = True,
)
