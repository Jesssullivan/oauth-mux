"""Disjoint eighth-source targets; compose invocation after seventh BUILD delta."""
load(":rules.bzl", "python_test")

def native_context_refresh_targets(parent_sources, parent_data):
    sources = parent_sources + ["codex_native_source_context_source.py", "codex_native_source_context_refresh_source.py"]
    patch = "//integrations/codex-upstream:native_source_context_readonly_refresh_patch"
    config = "//integrations/codex-upstream:native_source_context_seventh_input"
    python_test(
        name = "codex_native_source_context_refresh_source_test",
        main = "codex_native_source_context_refresh_source_test.py",
        srcs = sources,
        data = [patch, config, "//integrations/codex-upstream:native_source_context_refresh_preimages"],
    )
    python_test(
        name = "codex_native_source_context_refresh_source_producer",
        main = "codex_native_source_context_refresh_source.py",
        srcs = sources,
        data = parent_data + [patch, config, "//integrations/codex-upstream:native_source_context_patch",
            "@omux_codex_native_source_context_refresh_inputs//:inputs"],
        tags = ["manual", "no-remote", "no-cache"],
        timeout = "long",
    )
