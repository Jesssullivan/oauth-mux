"""Separate N10 source family; no existing N9 consumer or native execution route."""
load(":rules.bzl", "python_test")
load(":codex_native_acquisition_targets.bzl", "native_acquisition_source_closure")

def native_file_writer_source_targets(source_sources, sdk_sources, parent_data):
    sources = depset([
        src for src in native_acquisition_source_closure(source_sources, sdk_sources)
        if str(src) not in ("//delivery:portable.py", "codex_native_acquisition_bridge_material.py")
    ] + ["codex_native_source_file_writer.py"]).to_list()
    controls = [
        "//integrations/codex-upstream:native_file_writer_source_configuration",
        "//integrations/codex-upstream:native_file_writer_storage_patch",
        "//integrations/codex-upstream:native_file_writer_storage_manifest",
    ]
    # SourceProofSession checks actual N9 guardian plus all original ancestors.
    # These are source/proof data only: no SDK archive, compiler or native image.
    data = depset(parent_data + controls + [
        "//integrations/codex-upstream:native_source_context_patch",
        "//integrations/codex-upstream:native_acquisition_input_configuration",
        "//integrations/codex-upstream:native_acquisition_n9_binding",
        "@omux_native_carrier_source_inputs//:inputs",
    ]).to_list()
    for name, args in [
        ("codex_native_source_file_writer_producer", []),
        ("codex_native_source_file_writer_metadata_producer", ["--metadata-only"]),
    ]:
        python_test(
            name = name,
            main = "codex_native_source_file_writer.py",
            srcs = sources,
            data = data,
            args = args,
            env_inherit = ["OMUX_NATIVE_FILE_WRITER_SOURCE_MODE", "OMUX_NATIVE_FILE_WRITER_SOURCE_ENTRY_NS", "OMUX_NATIVE_FILE_WRITER_SOURCE_DEADLINE_NS"],
            tags = ["manual", "no-remote", "no-cache"],
            timeout = "long",
        )
    python_test(
        name = "codex_native_source_file_writer_test",
        main = "codex_native_source_file_writer_test.py",
        srcs = sources,
        data = controls + ["//integrations/codex-upstream:native_file_writer_preimages", "//integrations/codex-upstream:native_file_writer_source_declaration", "BUILD.bazel", "codex_native_source_file_writer_targets.bzl"],
        target_compatible_with = ["@platforms//os:linux"],
    )
