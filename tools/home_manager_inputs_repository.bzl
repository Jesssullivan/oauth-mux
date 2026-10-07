"""Declare one fixed Lab lock copy as public paired-source metadata only.

Reading this lock does not verify cached NAR bytes, source availability, Home
Manager evaluation, activation or fleet deployment. No executable, fetch,
evaluation, directory scan, credential or alternative lock path is used.
The pair mirrors nix/home_manager_inputs.py and remains separate from Omux's
own flake pins.
"""

_LOCK = "/srv/fast-local/jess/git/lab/flake.lock"
_MAX_BYTES = 65536
_PINS = {
    "home-manager": ["65258d5c65a250189fde2e35f490d15e064c4c62", "sha256-Sxu1NLTD/Ern6hFGLlZmtKCSct3YQXZI/lls8RE1XeM="],
    "nixpkgs": ["a9e6d84f9c2f9012f5fe7d964a7851352300e61a", "sha256-WncT27+3BOkgTaJZLnCsf3LcYf9RXMuR9ONSN4rzQ7s="],
}

def _implementation(ctx):
    source = ctx.path(_LOCK)
    if not source.exists or source.is_dir or str(source.realpath) != _LOCK:
        fail("The fixed physical Lab flake.lock is absent or linked")
    ctx.watch(source)
    content = ctx.read(source, watch = "no")
    if len(content) > _MAX_BYTES:
        fail("The public Lab lock exceeds its 64 KiB metadata bound")
    lock = json.decode(content)
    if lock.get("root") != "root":
        fail("Lab root lock node changed")
    nodes = lock["nodes"]
    root = nodes["root"]["inputs"]
    if root.get("home-manager") != "home-manager_2" or root.get("nixpkgs") != "nixpkgs_7":
        fail("The inspected Lab root Home Manager/nixpkgs pair changed")
    if nodes["home-manager_2"]["inputs"].get("nixpkgs") != ["nixpkgs"]:
        fail("Root Home Manager must follow the root nixpkgs input")
    for name, pin in _PINS.items():
        locked = nodes[root[name]]["locked"]
        if locked.get("rev") != pin[0] or locked.get("narHash") != pin[1]:
            fail("Paired Lab lock metadata disagrees with nix/home_manager_inputs.py: " + name)
    ctx.file("lab-lock.json", content, executable = False)
    ctx.file("BUILD.bazel", """package(default_visibility = ["//visibility:public"])
# Public metadata only; source existence/NAR hashes are separate probe gates.
exports_files(["lab-lock.json"])
filegroup(name = "inputs", srcs = ["lab-lock.json"], tags = ["metadata-only"])
""", executable = False)

home_manager_inputs_repository = repository_rule(
    implementation = _implementation,
    local = True,
)
