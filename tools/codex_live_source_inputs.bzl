"""Finite declared public baseline and reviewed native patch inputs.

The action checks pinned receipt bytes, source identity and patch digests.
This rule only declares input paths; no tool execution or cache discovery.
"""
_BASE = "/srv/fast-local/jess/state/codex/omux-codex-owner-development-20261004"
_RECEIPT = "verify-prepared-receipt-a8f6d68c30bb4099bb524ed55817d804.json"
_NOTES = "/srv/fast-local/jess/git/oauth-mux/docs/agent-notes"
_PATCHES = [
    "2026-10-07-native-text-portability.UNAPPLIED.native.patch",
    "2026-10-07-live-handoff-boundary.UNAPPLIED.native.patch",
    "2026-10-07-native-enrollment-action.UNAPPLIED.native.patch",
]

def _implementation(ctx):
    raw = ctx.read(_BASE + "/" + _RECEIPT)
    report = json.decode(raw)
    if len(raw) != 1584899 or report.get("commit") != "00c972ed5d6ff6499317fd41b7f23605b8e6850d" or report.get("complete_inventory_sha256") != "3400115fae8ef204f2ce085880b40887bcb14e2080236ba87a34be9b14fe7d3b":
        fail("fixed native source receipt authority differs")
    files = report.get("files", {})
    if len(files) != 8546 or report.get("tracked_files") != 8546:
        fail("fixed native source input count differs")
    names = []
    for index, name in enumerate(sorted(files)):
        if name.startswith("/") or any([part in ["", ".", ".."] for part in name.split("/")]) or any([character in name for character in ["\\", "\n", "\r", "\t"]]):
            fail("native source input path is noncanonical")
        if files[name].get("mode") not in ["100644", "100755", "120000"]:
            fail("native source Git mode differs")
        source = ctx.path(_BASE + "/source/" + name)
        if not source.exists:
            fail("declared native source input is absent")
        ctx.watch(source)
        # Native BUILD files must be inert data, not nested Bazel packages.
        alias = "source-inputs/" + str(index)
        ctx.symlink(source, alias)
        names.append(alias)
    ctx.symlink(_BASE + "/" + _RECEIPT, "baseline-receipt.json")
    names.append("baseline-receipt.json")
    for name in _PATCHES:
        source = ctx.path(_NOTES + "/" + name)
        if not source.exists or source.is_dir or str(source.realpath) != str(source):
            fail("reviewed native patch input absent or redirected")
        ctx.watch(source)
        ctx.symlink(source, "patches/" + name)
        names.append("patches/" + name)
    ctx.file("input-anchor.txt", "Exact pinned prepared public native source and reviewed native patch inputs only.\n", executable = False)
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files({})'.format(repr(names)),
        'filegroup(name = "inputs", srcs = {})'.format(repr(names)),
        'exports_files(["input-anchor.txt"])',
        "",
    ]), executable = False)

codex_live_source_inputs = repository_rule(implementation = _implementation, local = True)
