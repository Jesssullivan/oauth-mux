"""Exact offline model cohort; sampled resident kernel reservation only."""
import re
import guard_native_seed_plan_reserved as kernel

PROFILE = "resident-models-reserved"
PROFILES = (PROFILE,)
ARGUMENTS = ["test",
    "//delivery:retained_ordinary_native_tui_contract_test",
    "//delivery:native_thread_census_test",
    "//delivery:native_run_cli_failure_test",
    "//delivery:native_history_diagnostic_test",
    "//delivery:native_seed_attachment_diagnostic_test",
    "//delivery:native_terminal_failure_test",
    "//tools:codex_owner_runtime_input_test",
    "//tools:guard_owner_runtime_input_test",
    "//tools:guard_fresh_native_runtime_input_test",
    "//tools:guard_resident_models_reserved_test",
    "//tools:guard_native_seed_plan_reserved_test",
    "//tools:execution_guard_test",
    "//delivery:codex_live_contract_test",
    "//delivery:resident_codex_live_composition_test",
    "//delivery:resident_codex_live_controller_test",
    "//delivery:native_resumed_checkpoint_test",
    "//tools:guard_codex_live_profile_test",
    "//tools:guard_codex_fresh_live_profile_test",
    "//tools:guard_resident_continuity_profile_test",
    "//:docs_check"]
MEMORY, TASKS, CPU = kernel.MEMORY, kernel.TASKS, kernel.CPU
Witness = kernel.Witness
WorkloadWitness = kernel.WorkloadWitness
monitor = kernel.monitor
cleanup_retained = kernel.cleanup_retained
release_worker = kernel.release_worker
properties = kernel.properties
remaining = kernel.remaining


def require(value):
    if value is not True:
        raise ValueError("resident-models-reservation-refused")


def selected(profile, arguments):
    require(profile == PROFILE and arguments == ARGUMENTS)
    return {"PrivateNetwork": "yes"}


def request(args, arguments):
    if args.profile != PROFILE:
        return False
    selected(args.profile, arguments)
    allowed = {"profile", "manager", "arguments", "python", "systemd_run", "systemctl", "bazel",
        "closure", "bootstrap_closure", "zig_sdk", "java_home", "source_commit", "source_dirty",
        "state_dir", "initialize_state_dir", "coordination_dir", "become_file",
        "reuse_owned_cache", "repository_cache", "nixpkgs_source"}
    require(args.manager == "system" and args.reuse_owned_cache is False
        and not any(value for name, value in vars(args).items() if name not in allowed)
        and type(args.source_commit) is str
        and re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is not None
        and args.source_dirty == "false")
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(args.repository_cache, args.nixpkgs_source)
    return True


def command(builder, bazel, run, arguments, profile, entry, deadline, **kwargs):
    selected(profile, arguments)
    remaining(entry, deadline)
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(kwargs.get("repository_cache"), kwargs.get("nixpkgs_source"))
    require(kwargs.get("output_base") is None)
    result = builder(bazel, run, arguments, profile="standard", **kwargs)
    index = result.index("test") + 1
    result[index:index] = ["--repository_disable_download", "--repo_contents_cache="]
    return result


def projection(entry, deadline, verified, resident):
    kernel.envelope(entry, deadline)
    require(verified is None or type(verified) is bool)
    return {"scope": "fixed-resident-models-reserved-v1", "mode": "models",
        "original_entry_monotonic_ns": entry, "original_deadline_monotonic_ns": deadline,
        "verified_after_cleanup": verified, "resident": resident,
        "native_runtime_qualified": False, "sdk_qualified": False,
        "continuity_qualified": False}
