"""Declare an existing locked source independently of normal tool closures.

No Nix evaluation, fetch, hash or builder runs during repository setup. The
declared Bazel evaluation action verifies the source NAR against flake.lock.
"""

def _immutable(value, description):
    if type(value) != "string" or not value.startswith("/nix/store/") or len(value.split("/")) != 4 or any([c in value for c in ["\n", "\r", ".."]]):
        fail(description + " must be one explicitly selected immutable store root")
    return value

def _impl(ctx):
    source_env = ctx.attr.source_env
    if source_env not in ["OMUX_NIXPKGS_EVALUATION_SOURCE", "OMUX_SITE_NIXPKGS_EVALUATION_SOURCE"]:
        fail("source_env must select an explicitly declared runtime or site source variable")
    source = _immutable(ctx.attr.source or ctx.os.environ.get(source_env), "nixpkgs evaluation source")
    if not ctx.path(source + "/default.nix").exists:
        fail("selected source is unavailable; no fetch or alternate source is attempted")
    lock = json.decode(ctx.read(ctx.attr.lock))
    root = lock["nodes"][lock["root"]]
    node = root["inputs"]["nixpkgs"]
    if type(node) != "string":
        fail("nixpkgs lock follows indirection not supported by this bounded source declaration")
    locked = lock["nodes"][node]["locked"]
    expected = locked.get("narHash", "")
    revision = locked.get("rev", "")
    if not expected.startswith("sha256-") or not revision:
        fail("source declaration requires locked NAR SHA256 and revision")
    bootstrap = _immutable(ctx.attr.bootstrap_closure or ctx.os.environ.get("OMUX_BAZEL_BOOTSTRAP_CLOSURE"), "existing bootstrap closure")
    native = json.decode(ctx.read(bootstrap + "/native.json"))
    python = native.get("packages", {}).get("python", {}).get("out")
    python = _immutable(python, "declared bootstrap Python")
    if python not in ctx.read(bootstrap + "/store-paths").split("\n"):
        fail("bootstrap Python must belong to the declared existing host closure")
    python += "/bin/python3"
    if not ctx.path(python).exists:
        fail("declared bootstrap Python is unavailable")
    ctx.symlink(source, "closure/" + source.split("/")[3])
    ctx.file("store-paths", source + "\n")
    ctx.watch(ctx.path(ctx.attr.inventory))
    inventory = ctx.execute([python, "-I", "-S", ctx.path(ctx.attr.inventory), str(ctx.path(".")), "closure"], timeout = 600)
    if inventory.return_code:
        fail("declared source inventory failed: " + inventory.stderr)
    report = json.decode(inventory.stdout)
    ctx.file("source-input.json", json.encode_indent({
        "schemaVersion": 1,
        "source": source,
        "narHash": expected,
        "revision": revision,
        "system": native["system"],
        "verification": "pending-declared-action",
    }, indent = "  ") + "\n")
    ctx.file("BUILD.bazel", '\n'.join([
        'package(default_visibility = ["//visibility:public"])',
        'exports_files(["source-input.json", "store-paths"])',
        'filegroup(name = "source_files", srcs = {})'.format(repr(report["files"])),
    ]) + "\n")

nix_evaluation_source = repository_rule(
    implementation = _impl,
    attrs = {
        "source": attr.string(doc = "Existing source root; otherwise OMUX_NIXPKGS_EVALUATION_SOURCE."),
        "source_env": attr.string(default = "OMUX_NIXPKGS_EVALUATION_SOURCE", doc = "Select the declared runtime or site source environment variable."),
        "bootstrap_closure": attr.string(doc = "Already realized host bootstrap; no fresh closure realization."),
        "lock": attr.label(default = Label("//:flake.lock"), allow_single_file = True),
        "inventory": attr.label(default = Label("//tools:nix_file_inventory.py"), allow_single_file = True),
    },
    environ = ["OMUX_NIXPKGS_EVALUATION_SOURCE", "OMUX_SITE_NIXPKGS_EVALUATION_SOURCE", "OMUX_BAZEL_BOOTSTRAP_CLOSURE"],
    local = True,
)
