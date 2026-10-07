"""Explicit Apple SDK/Swift custody from the locked flake's native manifest.

This repository never discovers Xcode, runs xcrun, or accepts mutable SDK paths.
On non-Darwin hosts it supplies an unavailable configuration so normal //...
builds can skip the macOS-constrained targets without importing an Apple SDK.
"""

_SDK_SUFFIX = "/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"

def _store_path(value, description):
    if type(value) != "string" or not value.startswith("/nix/store/") or "/../" in value or "\n" in value or "\r" in value:
        fail(description + " must be an immutable /nix/store path from the locked flake")
    return value

def _quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"

def _apple_repository_impl(ctx):
    root = ctx.attr.closure or ctx.os.environ.get("OMUX_BAZEL_CLOSURE", "")
    if not root:
        fail("OMUX_BAZEL_CLOSURE is absent; invoke Bazel inside `nix develop`.")
    _store_path(root, "native closure")
    manifest_path = ctx.path(root + "/native.json")
    if not manifest_path.exists:
        fail("The flake's native closure lacks native.json.")
    native = json.decode(ctx.read(manifest_path))
    system = native.get("system", "")
    if system not in ["x86_64-linux", "aarch64-linux", "x86_64-darwin", "aarch64-darwin"]:
        fail("Unsupported Apple tool configuration host: " + system)
    available = system.endswith("-darwin")
    apple = native.get("apple", {}) if available else {}
    sdk = ""
    developer_dir = ""
    swiftc = ""
    clang = ""
    path = ""
    custody = {"system": system, "available": available, "apple": apple}
    if available:
        for key in ["sdk", "sdk_version", "swiftc", "swift_version"]:
            if not apple.get(key):
                fail("Darwin native.json must declare apple." + key + "; ambient Xcode is never used.")
        sdk = _store_path(apple["sdk"], "apple.sdk")
        if not sdk.endswith(_SDK_SUFFIX):
            fail("apple.sdk must name the flake Apple SDK's Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk.")
        developer_dir = sdk[:-len(_SDK_SUFFIX)]
        swiftc = _store_path(apple["swiftc"], "apple.swiftc")
        clang = _store_path(native.get("cc", ""), "declared clang driver")
        packages = native.get("packages", {})
        for name in ["bash", "coreutils"]:
            _store_path(packages.get(name, {}).get("out", ""), "packages." + name + ".out")
        shell = packages["bash"]["out"] + "/bin/bash"
        path = ":".join([packages["coreutils"]["out"] + "/bin", packages["bash"]["out"] + "/bin"])
        for required in [swiftc, clang, shell, sdk + "/SDKSettings.json", sdk + "/System/Library/Frameworks/SwiftUI.framework", sdk + "/System/Library/Frameworks/ServiceManagement.framework"]:
            if not ctx.path(required).exists:
                fail("Declared Apple tool/SDK input is unavailable: " + required)
        sdk_settings = json.decode(ctx.read(ctx.path(sdk + "/SDKSettings.json")))
        if sdk_settings.get("Version") != apple["sdk_version"]:
            fail("apple.sdk_version disagrees with the declared SDKSettings.json.")
        closure_manifest = ctx.path(root + "/store-paths")
        if not closure_manifest.exists:
            fail("Apple inputs require the flake's transitive store-paths manifest.")
        closure_paths = [entry for entry in ctx.read(closure_manifest).split("\n") if entry]
        tool_paths = {}
        for name in ["otool", "install_name_tool", "rcodesign"]:
            tool_path = _store_path(native.get("tools", {}).get(name, ""), "declared " + name)
            if not ctx.path(tool_path).exists:
                fail("Declared Darwin packaging tool is unavailable: " + tool_path)
            tool_root = "/".join(tool_path.split("/")[:4])
            if tool_root not in closure_paths:
                fail(name + " is absent from the flake's declared transitive closure.")
            tool_paths[name] = tool_path
        for name, required in [("SDK", developer_dir), ("Swift compiler", "/".join(swiftc.split("/")[:4])), ("clang driver", "/".join(clang.split("/")[:4]))]:
            if required not in closure_paths:
                fail(name + " is absent from the flake's declared transitive closure.")
        custody["store_paths"] = closure_paths
        custody["developer_dir"] = developer_dir
        custody["tools"] = tool_paths
        custody["tool_path"] = path
        ctx.file("swiftc", "#!{}\nset -eu\nexec {} \"$@\"\n".format(shell, _quote(swiftc)), executable = True)
    else:
        # This file is never executed: the rule reports unavailable custody at
        # analysis time if a macOS target is forced onto a non-Darwin executor.
        ctx.file("swiftc", "Apple SDK unavailable on this execution platform.\n", executable = True)
    ctx.file("custody.json", json.encode_indent(custody, indent = "  ") + "\n")
    rules_label = str(ctx.attr.rules)
    if rules_label.startswith("//"):
        rules_label = "@" + rules_label
    ctx.file("BUILD.bazel", "\n".join([
        'load({}, "omux_apple_config")'.format(repr(rules_label)),
        'package(default_visibility = ["//visibility:public"])',
        'exports_files(["custody.json"])',
        'omux_apple_config(name = "config", available = {available}, system = {system}, sdk = {sdk}, developer_dir = {developer_dir}, swiftc = "swiftc", clang = {clang}, path = {path}, custody = "custody.json", closure = "@omux_nix//:all_tools")'.format(
            available = available,
            system = repr(system),
            sdk = repr(sdk),
            developer_dir = repr(developer_dir),
            clang = repr(clang),
            path = repr(path),
        ),
        "",
    ]))

omux_apple_repository = repository_rule(
    implementation = _apple_repository_impl,
    attrs = {
        "closure": attr.string(doc = "Explicit immutable flake closure; otherwise OMUX_BAZEL_CLOSURE."),
        "rules": attr.label(default = Label("//tools:swift_rules.bzl"), allow_single_file = True),
    },
    environ = ["OMUX_BAZEL_CLOSURE"],
    local = True,
)
