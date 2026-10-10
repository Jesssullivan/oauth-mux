"""Actual Starlark receipt namespace predicates; no selected input IO."""
load(":codex_fresh_native_package_inputs.bzl", "receipt_producer")
load(":codex_native_acquisition_package_inputs.bzl", "package_configuration_valid")

def _receipt_scope_test_impl(ctx):
    home = "/home/jess/.local/state/omux-execution-20261005/"
    fast = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/"
    epoch = "5c6a5577-0000-4000-8000-000000000000"
    cache = "cache-v2-" + "a" * 64
    test_prefix = "/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"
    source_tail = test_prefix + "codex_live_source_producer/test.outputs/codex-live-source/source-receipt.json"
    export_tail = test_prefix + "codex_retained_sdk_export_producer/test.outputs/sdk-private/sdk-export/receipt.json"
    run_tail = "/sdk-private/sdk-export/receipt.json"
    cases = [
        ("source", home + epoch + source_tail, "//tools:codex_live_source_producer"),
        ("source", home + cache + source_tail, "//tools:codex_live_source_producer"),
        ("export", home + epoch + export_tail, "//tools:codex_retained_sdk_export_producer"),
        ("export", fast + epoch + export_tail, "//tools:codex_retained_sdk_export_producer"),
        ("export", fast + epoch + run_tail, "//tools:codex_retained_sdk_export_run"),
    ]
    refused = [
        ("source", fast + epoch + source_tail),
        ("source", fast + cache + source_tail),
        ("source", fast + epoch + run_tail),
        ("source", home + epoch + export_tail),
        ("source", home + epoch + run_tail),
        ("export", home + epoch + run_tail),
        ("export", home + cache + export_tail),
        ("export", fast + cache + export_tail),
        ("export", fast + cache + run_tail),
        ("export", fast + epoch + source_tail),
        ("export", fast + epoch + "/extra" + run_tail),
        ("source", home + epoch + "/extra" + source_tail),
        ("source", "/foreign/" + epoch + source_tail),
        ("export", "/foreign/" + epoch + run_tail),
        ("source", home),
        ("export", fast),
        ("source", home + source_tail),
        ("export", fast + run_tail),
        ("other", fast + epoch + run_tail),
        ("source", None),
        ("export", 1),
    ]
    for bad in ["short", epoch.upper(), epoch + "0", "0" + epoch, "cache-v2-" + "a" * 63, "cache-v2-" + "g" * 64, ".", "..", ""]:
        refused += [
            ("source", home + bad + source_tail),
            ("export", fast + bad + run_tail),
            ("export", home + bad + export_tail),
        ]
    for role, path, expected in list(cases):
        refused += [(role, path + "/extra"), (role, path.replace("/output-base/", "/output-base/../output-base/")),
                    (role, path.replace("receipt.json", "receipt.json.bak"))] if "/output-base/" in path else [
                        (role, path + "/extra"), (role, path.replace("/sdk-private/", "/sdk-private/./")),
                        (role, path.replace("receipt.json", "receipt.json.bak")),
                    ]
    failures = []
    # Actual production Starlark selector predicate; no host paths are opened.
    pending = {"schema_version":1, "kind":"omux-native-acquisition-package-input-configuration-v1", "status":"awaiting-qualified-material", "selection":None}
    selected = dict(pending, status="selected-material", selection={"path":home + epoch + "/package-selection.json", "sha256":"a" * 64})
    selector_cases = [(pending, True), (selected, True),
        (dict(pending, selection=selected["selection"]), False),
        (dict(selected, selection=None), False),
        (dict(selected, schema_version=True), False),
        (dict(selected, extra=True), False),
        (dict(selected, selection={"path":"/foreign/package-selection.json", "sha256":"a" * 64}), False),
        (dict(selected, selection={"path":home + epoch + "/../package-selection.json", "sha256":"a" * 64}), False),
        (dict(selected, selection={"path":home + epoch + "/bad\000selection.json", "sha256":"a" * 64}), False),
        (dict(selected, selection={"path":home + "a" * 4096, "sha256":"a" * 64}), False),
        (dict(selected, selection={"path":selected["selection"]["path"], "sha256":"g" * 64}), False),
        (dict(selected, selection={"path":selected["selection"]["path"], "sha256":"a" * 64, "producer":{}}), False)]
    for index, case in enumerate(selector_cases):
        value, expected = case
        if package_configuration_valid(value) != expected:
            failures.append("package-selector-" + str(index))
    for index, case in enumerate(cases + [(role, path, None) for role, path in refused]):
        role, path, expected = case
        if receipt_producer(role, path) != expected:
            failures.append(str(index))
    return [AnalysisTestResultInfo(success = not failures, message = "receipt scope case failures: " + ",".join(failures))]

codex_fresh_native_receipt_scope_test = rule(
    implementation = _receipt_scope_test_impl,
    analysis_test = True,
)
