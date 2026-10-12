"""Source/HUB precursor and fault models; real Rust driver has a distinct owner target."""
load(":rules.bzl", "python_test")
load(":codex_native_acquisition_targets.bzl", "native_acquisition_source_closure")

def native_file_writer_model_source_targets(source_sources, sdk_sources, parent_data, original_sdk_sources):
    sources = depset([
        src for src in native_acquisition_source_closure(source_sources, sdk_sources)
        if str(src) not in ("//delivery:portable.py", "codex_native_acquisition_bridge_material.py")
    ] + ["codex_native_source_file_writer.py", "guard_native_file_writer_source_reserved.py", "codex_native_file_writer_model_source.py"]).to_list()
    controls = [
        "//integrations/codex-upstream/file-writer-models:inputs",
        "//integrations/codex-upstream/file-writer-models:qualified-parent.json",
        "//integrations/codex-upstream:native_file_writer_source_configuration",
        "//integrations/codex-upstream:native_file_writer_storage_patch",
        "//integrations/codex-upstream:native_file_writer_storage_manifest",
    ]
    # Every original SOURCE ancestor, actual N10 member and guardian proof is
    # declared. SDK/JDK is complete separate authority, never legacy giant DATA.
    data = depset(parent_data + controls + [
        "//integrations/codex-upstream:native_source_context_patch",
        "//integrations/codex-upstream:native_acquisition_input_configuration",
        "//integrations/codex-upstream:native_acquisition_n9_binding",
        "@omux_native_carrier_source_inputs//:inputs",
        "@omux_native_file_writer_model_source_inputs//:inputs",
        "@omux_original_native_sdk_inputs//:inputs",
        "@omux_native_sdk_carrier_inputs//:inputs",
        "@omux_native_sdk_carrier_proof_inputs//:inputs",
        "//integrations/codex-upstream:native-sdk-carrier-metadata-inputs.json",
        "@omux_protocol_history_query_tools//:inputs",
    ]).to_list()
    python_test(
        name = "codex_native_file_writer_model_source_producer",
        main = "codex_native_file_writer_model_source.py",
        srcs = depset(sources + original_sdk_sources).to_list(),
        data = data,
        env_inherit = ["OMUX_NATIVE_FILE_WRITER_MODELS_MODE", "OMUX_NATIVE_FILE_WRITER_MODELS_ENTRY_NS", "OMUX_NATIVE_FILE_WRITER_MODELS_DEADLINE_NS", "OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH", "OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT", "OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256"],
        tags = ["manual", "no-remote", "no-cache"],
        timeout = "long",
        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    )
    python_test(
        name = "codex_native_file_writer_model_source_test",
        main = "codex_native_file_writer_model_source_test.py",
        srcs = sources + ["codex_native_source_file_writer_test.py", "codex_native_file_writer_models.py", "codex_native_file_writer_models_test.py"],
        data = controls + ["//integrations/codex-upstream/file-writer-models:BUILD.bazel", "//integrations/codex-upstream/file-writer-models:model_preimages", "BUILD.bazel", "codex_native_file_writer_model_source_targets.bzl", "codex_native_file_writer_model_source_inputs.bzl"],
        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    )



    python_test(
        name = "codex_native_file_writer_models_producer",
        main = "codex_native_file_writer_models.py",
        srcs = depset(sources + original_sdk_sources + ["codex_native_file_writer_models.py"]).to_list(),
        data = data,
        env_inherit = ["OMUX_NATIVE_FILE_WRITER_MODELS_MODE", "OMUX_NATIVE_FILE_WRITER_MODELS_ENTRY_NS", "OMUX_NATIVE_FILE_WRITER_MODELS_DEADLINE_NS", "OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH", "OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT", "OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256"],
        tags = ["manual", "no-remote", "no-cache"],
        timeout = "long",
        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    )
