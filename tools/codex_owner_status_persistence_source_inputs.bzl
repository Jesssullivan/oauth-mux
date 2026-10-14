"""Declare only exact reviewed persistence v3 patch; parent is actual N1."""
_PATCHES = [
    "/srv/fast-local/jess/git/oauth-mux/docs/agent-notes/2026-10-09-native-export-bounded-persist-v3.UNAPPLIED.patch",
    "/srv/fast-local/jess/git/oauth-mux/docs/agent-notes/2026-10-09-native-export-bounded-persist-v3-normalized.UNAPPLIED.patch",
    "/srv/fast-local/jess/git/oauth-mux/docs/agent-notes/2026-10-09-native-export-bounded-persist-v3-strict.UNAPPLIED.patch",
]

def _implementation(ctx):
    names = []
    for index, name in enumerate(_PATCHES):
        patch = ctx.path(name)
        if not patch.exists or patch.is_dir or str(patch.realpath) != str(patch):
            fail("persistence v3 patch absent or redirected")
        ctx.watch(patch)
        alias = "persistence-v3-" + str(index) + ".patch"
        ctx.symlink(patch, alias)
        names.append(alias)
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(names)),
        'filegroup(name = "inputs", srcs = {})'.format(repr(names)),
        "",
    ]), executable = False)

codex_owner_status_persistence_source_inputs = repository_rule(implementation = _implementation, local = True)
