"""Root-module configuration for the declared native runtime.

Zig 0.17 applies --dynamic-linker to the following module. It must precede -M,
so it belongs in zigopts; passing it as a trailing linkopt silently selects the
host loader and combines incompatible libc/loader versions.

Explicit root options contain Linux's --dynamic-linker or Darwin's -F and -L
for the locked SDK framework directory and library stubs. They precede root -M;
no host SDK discovery is performed. The repository BUILD uses separate trailing
link options. Darwin's -fno-lld follows dependency flags,
so native Mach-O linking overrides the ELF LLD selection used by dynamic deps.
"""
load("@rules_zig//zig:defs.bzl", _zig_binary = "zig_binary", _zig_test = "zig_test")
load("@omux_nix//:tool_paths.bzl", "NIX_ZIG_ROOTOPTS", "NIX_ZIG_SDK_INPUTS")

def zig_binary(**kwargs):
    kwargs["zigopts"] = kwargs.get("zigopts", []) + NIX_ZIG_ROOTOPTS
    kwargs["extra_srcs"] = kwargs.get("extra_srcs", []) + NIX_ZIG_SDK_INPUTS
    _zig_binary(**kwargs)

def zig_test(**kwargs):
    kwargs["zigopts"] = kwargs.get("zigopts", []) + NIX_ZIG_ROOTOPTS
    kwargs["extra_srcs"] = kwargs.get("extra_srcs", []) + NIX_ZIG_SDK_INPUTS
    _zig_test(**kwargs)
