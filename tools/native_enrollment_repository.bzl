"""Inert explicit native enrollment executable declaration; no execution or scan."""
VARIABLE = "OMUX_NATIVE_ENROLLMENT_DIRECTORY"

def _implementation(ctx):
    root = ctx.os.environ.get(VARIABLE, "")
    parts = root.split("/")
    if not root.startswith("/") or any([part in ["", ".", ".."] for part in parts[1:]]) or len(parts[-1]) != 64 or any([char not in "0123456789abcdef" for char in parts[-1]]) or any([char in root for char in ["\\", "\n", "\r", json.decode('"\\u0000"')]]):
        fail("explicit digest-named native enrollment input directory required")
    selected = ctx.path(root)
    if not selected.exists or not selected.is_dir or str(selected.realpath) != root:
        fail("native enrollment physical input directory required")
    for name in ["codex", "native-source-receipt.json"]:
        member = ctx.path(root + "/" + name)
        if not member.exists or member.is_dir or str(member.realpath) != str(member):
            fail("native enrollment regular input absent or linked")
        ctx.watch(member)
        ctx.symlink(member, name)

    runtime_names = ["runtime/bin/codex","runtime/lib/codex/lib/ld-linux-x86-64.so.2","runtime/lib/codex/lib/libc.so.6","runtime/lib/codex/lib/libdl.so.2","runtime/lib/codex/lib/libm.so.6","runtime/lib/codex/lib/libpthread.so.0","runtime/lib/codex/lib/librt.so.1","runtime/lib/codex/lib/libutil.so.1","runtime/lib/codex/libexec/codex.bin","runtime/lib/codex/share/ca-bundle.crt"]
    for name in runtime_names:
        member = ctx.path(root + "/" + name)
        if not member.exists or member.is_dir or str(member.realpath) != str(member):
            fail("full retained device runtime input absent or linked")
        ctx.watch(member)
        ctx.symlink(member, name)
    ctx.file("BUILD.bazel", 'package(default_visibility = ["//visibility:public"])\nexports_files(["codex", "native-source-receipt.json"] + ' + repr(runtime_names) + ')\nfilegroup(name = "retained_runtime", srcs = ' + repr(runtime_names) + ')\n', executable = False)

native_enrollment_repository = repository_rule(
    implementation = _implementation,
    environ = [VARIABLE],
    local = True,
)
