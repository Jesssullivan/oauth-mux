"""Independently selected compact public HM input; no producer build edge."""
BUNDLE_ROOT = "FROZEN_COMPACT_BUNDLE_ROOT_REQUIRED"
BUNDLE_SHA256 = "FROZEN_COMPACT_BUNDLE_SHA256_REQUIRED"
BUNDLE_RECEIPT_SHA256 = "FROZEN_COMPACT_RECEIPT_SHA256_REQUIRED"

def _implementation(ctx):
    if not BUNDLE_ROOT.startswith("/") or any([p in ["", ".", ".."] for p in BUNDLE_ROOT.split("/")[1:]]):
        fail("independently selected compact root required")
    for digest in [BUNDLE_SHA256, BUNDLE_RECEIPT_SHA256]:
        if len(digest) != 64 or any([c not in "0123456789abcdef" for c in digest.elems()]):
            fail("independently selected compact SHA256 required")
    for name in ["bundle", "receipt.json"]:
        candidate = ctx.path(BUNDLE_ROOT + "/" + name)
        if not candidate.exists or candidate.is_dir or str(candidate.realpath) != str(candidate):
            fail("compact declared input absent or linked")
        ctx.watch(candidate)
        ctx.symlink(candidate, name)
    ctx.file("BUILD.bazel", '\n'.join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files(["bundle", "receipt.json"])',
    ]) + '\n', executable = False)

home_manager_bundle_repository = repository_rule(implementation = _implementation, local = True)
