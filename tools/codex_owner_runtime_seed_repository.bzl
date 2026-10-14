"""Fixed original PUBLIC seed source; no retained-consumer declaration."""
_SOURCE = "/srv/fast-local/jess/git/oauth-mux/integrations/codex-owner-runtime/codex-owner-runtime.tar.gz"

def _implementation(ctx):
    original = ctx.path(_SOURCE)
    if not original.exists or original.is_dir or str(original.realpath) != _SOURCE:
        fail("original public runtime009 seed file absent or linked")
    ctx.watch(original)
    ctx.symlink(original, "archive")
    ctx.file("source-role.json", json.encode({
        "schema_version": 1,
        "kind": "codex-owner-runtime-public-seed-v1",
        "purpose": "public-byte-copy-only",
        "source_path": _SOURCE,
        "archive_name": "codex-owner-runtime.tar.gz",
        "archive_sha256": "0094334d7fd27b81f613ebe734305412bd13f95f1f3396ba2f0396168e5223ad",
        "archive_bytes": 119923125,
        "manifest_sha256": "5626b375f0f3c1818340345c952394ef44b59acbc177ab83f7b910c6fb105678",
        "receipt_sha256": "b6e4a997a15c1a82f5095325e66f23e8c012c94baf43805ace67e8786cc60094",
        "native_support": False,
    }) + "\n", executable = False)
    ctx.file("BUILD.bazel", 'package(default_visibility = ["//visibility:public"])\nexports_files(["archive", "source-role.json"])\n', executable = False)

codex_owner_runtime_seed_repository = repository_rule(implementation = _implementation, local = True)
