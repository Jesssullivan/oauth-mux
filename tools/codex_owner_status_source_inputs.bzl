"""Declare the single reviewed fifth patch; no SDK or compiler admission."""
_PATCH = "/srv/fast-local/jess/git/oauth-mux/docs/agent-notes/2026-10-09-fresh-native-interface-v2.UNAPPLIED.native.patch"

def _implementation(ctx):
    patch = ctx.path(_PATCH)
    if not patch.exists or patch.is_dir or str(patch.realpath) != str(patch):
        fail("owner-status reviewed patch absent or redirected")
    ctx.watch(patch)
    ctx.symlink(patch, "owner-status.patch")
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files(["owner-status.patch"])',
        'filegroup(name = "inputs", srcs = ["owner-status.patch"])',
        "",
    ]), executable = False)

codex_owner_status_source_inputs = repository_rule(implementation = _implementation, local = True)
