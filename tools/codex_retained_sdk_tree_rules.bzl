"""One genuine produced SDK TreeArtifact; no retained host-directory alias.

Creator values are action inputs. Replaying a missing old creator artifact must
refuse its expired clock; a distinct fresh dependency producer is required.
"""
load("@omux_retained_public_sdk_tree_proof_inputs//:selection.bzl", "SDK_TREE_CREATOR_CONTEXT")

RetainedSdkTreeInfo = provider(fields = ["tree", "inventory", "receipt", "recipe", "context", "layout"])
_TARGET = "codex_native_retained_sdk_tree_materialized"
_FIELDS = ["MODE", "ENTRY_NS", "DEADLINE_NS", "EPOCH", "SOURCE_COMMIT", "GRAPH_SHA256", "BOOT_ID"]
_PREFIX = "OMUX_NATIVE_SDK_TREE_"

def _need(value, reason):
    if not value:
        fail("retained SDK TreeArtifact declaration refused: " + reason)

def _boot(value):
    _need(type(value) == "string" and len(value) == 36 and
        [value[i] for i in [8, 13, 18, 23]] == ["-", "-", "-", "-"] and
        len(value.replace("-", "")) == 32 and
        all([c in "0123456789abcdef" for c in value.replace("-", "").elems()]), "boot-domain")
    return value

def _domain(environment):
    # Fixed logical path and boot-only bytes: no fresh epoch/ENTRY/source values.
    return {"schema_version": 1, "kind": "omux-sdk-tree-current-clock-domain-v1",
        "clock": "linux-CLOCK_MONOTONIC", "boot_id": _boot(environment.get(_PREFIX + "CURRENT_BOOT_ID", ""))}

def _creator(environment, selected):
    present = {name: environment.get(_PREFIX + name, "") for name in _FIELDS}
    if any([present[name] != "" for name in _FIELDS]):
        _need(all([present[name] != "" for name in _FIELDS]), "partial-fresh-context")
        chosen = present
    else:
        _need(type(selected) == "dict" and sorted(selected.keys()) == sorted(_FIELDS), "qualified-creator-required")
        chosen = selected
    _need(chosen["MODE"] == "native-sdk-tree-producer-reserved", "closed-creator-mode")
    _need(all([type(chosen[name]) == "string" for name in _FIELDS]), "context-string-fields")
    _need(int(chosen["DEADLINE_NS"]) - int(chosen["ENTRY_NS"]) == 1200 * 1000000000, "creator-original1200")
    _boot(chosen["BOOT_ID"])
    # Runtime independently authenticates every value and current original clock.
    # Both fresh and selected contexts serialize in the same closed order.
    # Dict insertion order is input data, not a cache-identity coincidence.
    return {name: chosen[name] for name in _FIELDS}

def _key(file):
    return file.short_path[3:] if file.short_path.startswith("../") else "_main/" + file.short_path

def _path(file):
    return file.path

def _basename(file):
    return file.basename

def _impl(ctx):
    _need(ctx.label.package == "tools" and ctx.label.name == _TARGET, "one-fixed-artifact-label")
    creator = _creator(ctx.configuration.default_shell_env, SDK_TREE_CREATOR_CONTEXT)
    base = ctx.label.name + "/sdk-tree-public/"
    tree = ctx.actions.declare_directory(base + "tree")
    inventory = ctx.actions.declare_file(base + "inventory.json")
    receipt = ctx.actions.declare_file(base + "receipt.json")
    recipe = ctx.actions.declare_file(base + "recipe.json")
    context = ctx.actions.declare_file(base + "creator-context.json")
    domain = ctx.actions.declare_file(base + "current-clock-domain.json")
    descriptor = ctx.actions.declare_file(base + "declared-inputs.json")
    layout = ctx.actions.declare_file("retained-sdk-tree-data.json")
    ctx.actions.write(context, json.encode(creator) + "\n")
    current_domain = _domain(ctx.configuration.default_shell_env)
    ctx.actions.write(domain, json.encode(current_domain) + "\n")
    code = sorted(ctx.files.code, key = _path)
    carrier_names = ["manifest.json", "origin-receipt.json", "payload.bin", "receipt.json"]
    carrier = sorted([file for file in ctx.files.carrier if file.basename in carrier_names], key = _basename)
    carrier_selection = [file for file in ctx.files.carrier if file.basename == "selection.json"]
    _need(len(ctx.files.carrier) == 5 and len(carrier_selection) == 1, "four-carrier-plus-selected-declaration")
    proofs = sorted(ctx.files.proofs + carrier_selection, key = _path)
    excluded = {file.path: True for file in code + carrier + proofs}
    tool_files = ctx.attr.materializer[DefaultInfo].default_runfiles.files.to_list() + ctx.attr.materializer[DefaultInfo].files.to_list()
    tools = sorted({file.path: file for file in tool_files if file.path not in excluded}.values(), key = _path)
    _need(len(code) > 0 and len(code) <= 4096 and len(proofs) > 0 and len(proofs) <= 64 and len(code) + len(tools) + len(proofs) <= 500000, "complete-bounded-closure")
    _need(sorted([file.basename for file in carrier]) == ["manifest.json", "origin-receipt.json", "payload.bin", "receipt.json"], "exact-four-carrier-leaves")
    # Actual materializer hashes every declared member, before effects, and
    # commits canonical logical inputs. This is not a protobuf Action digest.
    ctx.actions.write(descriptor, json.encode({
        "schema_version": 1,
        "kind": "omux-retained-public-sdk-tree-declared-action-inputs-v1",
        "code": [{"logical_path": _key(file), "execution_path": file.path} for file in code],
        "tools": [{"logical_path": _key(file), "execution_path": file.path} for file in tools],
        "proofs": [{"logical_path": _key(file), "execution_path": file.path} for file in proofs],
        "carrier": [{"name": file.basename, "logical_path": _key(file), "execution_path": file.path} for file in carrier],
    }) + "\n")
    argv = ctx.actions.args()
    argv.add_all(["--phase", "materialize", "--tree-output", tree.path,
        "--inventory-output", inventory.path, "--receipt-output", receipt.path,
        "--recipe-output", recipe.path, "--creator-context", context.path,
        "--input-descriptor", descriptor.path, "--clock-domain", domain.path])
    environment = {_PREFIX + name: creator[name] for name in _FIELDS}
    environment[_PREFIX + "CURRENT_BOOT_ID"] = current_domain["boot_id"]
    environment.update({"PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1",
        "RUNFILES_DIR": ctx.executable.materializer.path + ".runfiles"})
    ctx.actions.run(
        executable = ctx.executable.materializer,
        arguments = [argv],
        inputs = depset(code + carrier + proofs + tools + [context, descriptor, domain]),
        tools = [ctx.attr.materializer[DefaultInfo].files_to_run],
        outputs = [tree, inventory, receipt, recipe],
        mnemonic = "OmuxRetainedSdkTree",
        progress_message = "Materializing complete SDK/JDK under the selected creator's original deadline",
        use_default_shell_env = False,
        env = environment,
        execution_requirements = {"no-remote": "1"},
    )
    ctx.actions.write(layout, json.encode({
        "kind": "omux-retained-public-sdk-tree-declared-data-v1",
        "recipe": _key(recipe), "creator_context": _key(context),
        "artifact": {"root": _key(tree), "receipt": _key(receipt), "inventory": _key(inventory)},
    }) + "\n")
    outputs = [tree, inventory, receipt, recipe, context, descriptor, layout, domain]
    # SOURCE only receives produced SDK/metadata. The qualifier explicitly
    # requests original recipe inputs through a separate output group below.
    runfiles = ctx.runfiles(files = outputs)
    return [DefaultInfo(files = depset(outputs), runfiles = runfiles),
        OutputGroupInfo(input_descriptor = depset([descriptor]), layout = depset([layout]),
            qualification_inputs = depset(code + carrier + proofs + tools), clock_domain = depset([domain])),
        RetainedSdkTreeInfo(tree = tree, inventory = inventory, receipt = receipt,
            recipe = recipe, context = context, layout = layout)]

retained_sdk_tree = rule(
    implementation = _impl,
    attrs = {
        "materializer": attr.label(mandatory = True, executable = True, cfg = "exec"),
        "code": attr.label_list(mandatory = True, allow_files = True),
        "carrier": attr.label_list(mandatory = True, allow_files = True),
        "proofs": attr.label_list(mandatory = True, allow_files = True),
    },
)


# Inspect the actual configured materializer runfiles in Bazel analysis. This
# does not run/materialize an SDK or turn source inspection into qualification.
_MATERIALIZER_IMPORT_FILES = [
    "codex_public_sdk_custody.py",
    "codex_fresh_source.py",
    "codex_live_source.py",
    "codex_native_acquisition_binding.py",
    "codex_native_acquisition_material.py",
    "codex_native_acquisition_metadata.py",
    "codex_native_acquisition_sdk_export.py",
    "codex_native_candidate_cache.py",
    "codex_native_carrier_metadata.py",
    "codex_native_file_writer_model_source.py",
    "codex_native_fresh_completion.py",
    "codex_native_profile.py",
    "codex_native_retained_sdk_tree_producer.py",
    "codex_native_sdk_carrier.py",
    "codex_native_source_acquisition_binding.py",
    "codex_native_source_acquisition_source.py",
    "codex_native_source_context_refresh_source.py",
    "codex_native_source_context_source.py",
    "codex_native_source_file_writer.py",
    "codex_native_staged_compilation.py",
    "codex_original_sdk_inputs.py",
    "codex_owner_status_binding.py",
    "codex_owner_status_persistence_binding.py",
    "codex_owner_status_persistence_source.py",
    "codex_owner_status_source.py",
    "codex_protocol_history_metadata.py",
    "codex_protocol_history_metadata_producer.py",
    "codex_protocol_history_native.py",
    "codex_protocol_history_query_tools.py",
    "codex_protocol_history_sdk_export.py",
    "codex_protocol_history_source.py",
    "codex_query_registration.py",
    "codex_recovery_delta.py",
    "codex_retained_sdk_export.py",
    "codex_retained_sdk_tree.py",
    "codex_retained_sdk_tree_inputs.py",
    "codex_sdk_profile.py",
    "fetch_codex_archives.py",
    "guard_cache.py",
    "guard_native_acquisition_inputs_reserved.py",
    "guard_native_file_writer_source_reserved.py",
    "guard_native_sdk_tree_reserved.py",
    "guard_native_seed_plan_reserved.py",
    "guard_native_siwc_catalog_content_source_reserved.py",
    "guard_resident_observation.py",
    "guard_yoga_delivery_profile.py",
    "nar_descriptor.py",
    "native_flake_missing_plan.py",
    "native_flake_schedule.py",
    "native_flake_seed_plan.py",
    "native_flake_seed_plan_inputs.py",
    "native_flake_sources.py",
    "nix_interpreter_closure.py",
    "nix_private_store_qualification.py",
    "nix_private_store_seed.py",
    "nix_source_probe.py",
    "patch_io.py",
    "refresh_artifact.py",
    "restore_pristine_inputs.py",
    "restore_source.py",
    "verify_cached_nars.py",
    "verify_declared_nars.py",
    "yoga_delivery_settings.py",
    "yoga_executable_qualification.py"
]

def _materializer_closure_test_impl(ctx):
    files = ctx.attr.materializer[DefaultInfo].default_runfiles.files.to_list()
    names = {file.basename: True for file in files}
    project = [file for file in files if not file.short_path.startswith("../")]
    valid = all([name in names for name in _MATERIALIZER_IMPORT_FILES])
    valid = valid and all([file.basename not in ["portable.py", "portable_launcher_template.py", "pack.py"]
        and not file.basename.endswith("_test.py") and not file.basename.endswith("_fixture.py") for file in project])
    return [AnalysisTestResultInfo(success = valid,
        message = "actual SDK materializer closure is missing production imports or carries model/runtime packaging inputs")]

retained_sdk_materializer_closure_test = rule(
    implementation = _materializer_closure_test_impl,
    attrs = {"materializer": attr.label(mandatory = True, executable = True, cfg = "exec")},
    analysis_test = True,
)


def _clock_domain_analysis_test_impl(ctx):
    a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    creator = {"MODE": "native-sdk-tree-producer-reserved", "ENTRY_NS": "1",
        "DEADLINE_NS": "1200000000001", "EPOCH": "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/11111111-1111-1111-1111-111111111111",
        "SOURCE_COMMIT": "1" * 40, "GRAPH_SHA256": "2" * 64, "BOOT_ID": a}
    env = {_PREFIX + "CURRENT_BOOT_ID": a}
    fresh = dict(env)
    fresh.update({_PREFIX + name: creator[name] for name in _FIELDS})
    next_boot = {_PREFIX + "CURRENT_BOOT_ID": b}
    valid = _creator(env, creator) == creator and _creator(fresh, None) == creator
    valid = valid and json.encode(_domain(env)) == json.encode(_domain(fresh))
    valid = valid and _creator(next_boot, creator) == creator
    valid = valid and _domain(next_boot) != _domain(env)
    valid = valid and sorted(_domain(env).keys()) == ["boot_id", "clock", "kind", "schema_version"]
    return [AnalysisTestResultInfo(success = valid,
        message = "declared clock-domain stability/selected creator separation failed; no action-cache qualification")]

retained_sdk_clock_domain_analysis_test = rule(
    implementation = _clock_domain_analysis_test_impl,
    analysis_test = True,
)
