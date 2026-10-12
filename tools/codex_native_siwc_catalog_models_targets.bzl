"""Additive SIWC source/HUB family; existing N10/login19 cohorts stay unchanged."""
load(":rules.bzl", "python_test")
load(":codex_native_acquisition_targets.bzl", "native_acquisition_source_closure")
load(":codex_native_siwc_catalog_content_source_targets.bzl", "catalog_content_source_data", "catalog_content_controls")

def codex_native_siwc_catalog_models_targets(source_sources, sdk_sources, parent_data, original_sdk_sources):
    sources = depset([
        src for src in native_acquisition_source_closure(source_sources, sdk_sources)
        if str(src) not in ("//delivery:portable.py", "codex_native_acquisition_bridge_material.py")
    ] + ["codex_native_source_file_writer.py", "guard_native_file_writer_source_reserved.py",
        "codex_native_file_writer_model_source.py", "codex_native_siwc_source.py", "codex_native_siwc_catalog_source.py", "codex_native_file_writer_models.py", "codex_native_siwc_catalog_models.py", "guard_native_siwc_catalog_source_reserved.py", "guard_native_siwc_catalog_content_source_reserved.py", "codex_native_n10_source_intake.py", "codex_native_siwc_catalog_content_source.py", "codex_transported_sdk_inputs.py"]).to_list()
    controls = [
        "//integrations/codex-upstream/siwc-native:inputs",
        "//integrations/codex-upstream/siwc-native-catalog:inputs",
        "//integrations/codex-upstream/siwc-native-catalog-models:inputs",
        "//integrations/codex-upstream/file-writer-models:qualified-parent.json",
        "//integrations/codex-upstream:native_file_writer_source_configuration",
        "//integrations/codex-upstream:native_file_writer_storage_patch",
        "//integrations/codex-upstream:native_file_writer_storage_manifest",
    ]
    # Current cold typed driver requests the complete explicit content closure.
    # Old source statuses refuse if their historical declaration is unavailable;
    # a new report is never interpreted as old ancestor custody.
    data = depset(catalog_content_source_data() + [
        "//integrations/codex-upstream/siwc-native-catalog-models:inputs",
        "@omux_native_siwc_catalog_model_inputs//:inputs",
    ]).to_list()
    python_test(
        name = "codex_native_siwc_catalog_models_producer",
        main = "codex_native_siwc_catalog_models.py",
        srcs = depset(sources + original_sdk_sources).to_list(),
        data = data,
        env_inherit = ["OMUX_NATIVE_FILE_WRITER_MODELS_MODE", "OMUX_NATIVE_FILE_WRITER_MODELS_ENTRY_NS", "OMUX_NATIVE_FILE_WRITER_MODELS_DEADLINE_NS", "OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH", "OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT", "OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256"],
        tags = ["manual", "no-remote", "no-cache"],
        timeout = "long",
        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    )
    python_test(
        name = "codex_native_siwc_catalog_models_test",
        main = "codex_native_siwc_catalog_models_test.py",
        srcs = depset(sources + original_sdk_sources + ["codex_transported_sdk_inputs_test.py", "codex_native_sdk_carrier_test.py"]).to_list(),
        data = depset(controls + catalog_content_controls()).to_list() + ["//integrations/codex-upstream/siwc-native:native_preimages",
            "//integrations/codex-upstream/siwc-native-catalog:native_preimages",
            "//integrations/codex-upstream/siwc-native-catalog:BUILD.bazel",
            "//integrations/codex-upstream/siwc-native:BUILD.bazel",
            "codex_native_siwc_catalog_models_targets.bzl", "codex_native_siwc_catalog_content_source_targets.bzl", "codex_native_siwc_catalog_model_inputs.bzl", "codex_native_siwc_catalog_models_BUILD.snippet", "codex_native_siwc_catalog_models_MODULE.snippet"],
        target_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    )
