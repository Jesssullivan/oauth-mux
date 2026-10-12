"""Additive test declarations for bounded Omux OSS OIDC verification.

Root BUILD composes one load/call with other OAuth owners; this macro does not
replace their declarations. The signer target is test-only and has no keys in
declared inputs or retained test evidence.
"""
load("//tools:runtime_zig.bzl", "zig_test")

def oauth_oidc_targets(zig_sources, native_linkopts, runtime_data, native_deps):
    zig_test(
        name = "oauth_oidc_crypto_test",
        main = "src/oauth_oidc_crypto.zig",
    )
    zig_test(
        name = "oauth_oidc_profile_test",
        main = "src/oauth_oidc.zig",
        srcs = zig_sources,
        deps = native_deps,
        linkopts = native_linkopts,
        data = runtime_data,
    )
    zig_test(
        name = "oauth_oidc_signed_fixture_test",
        main = "src/oauth_oidc_fixture.zig",
        srcs = ["src/oauth_oidc_crypto.zig"],
        deps = native_deps,
        linkopts = native_linkopts,
        data = runtime_data + [
            "@omux_nix//:openssl_tool",
            "@omux_nix//:openssl_tool_tools",
        ],
        env = {"OMUX_OIDC_OPENSSL": "$(rootpath @omux_nix//:openssl_tool)"},
    )
