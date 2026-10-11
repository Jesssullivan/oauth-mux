"""Closed native peer fixture TEST lane; no native acquisition or live authority."""
import re
import guard_native_seed_plan_reserved as kernel

PROFILE = "native-peer-qualification-reserved"
PROFILES = (PROFILE,)
ARGUMENTS = ["test", "//tools:guard_native_peer_qualification_reserved_test",
    "//:native_peer_bridge_test", "//:native_peer_test", "//:format_test", "//:docs_check"]
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
        raise ValueError("native-peer-qualification-reservation-refused")


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
    return {"scope": "fixed-native-peer-qualification-reserved-v1", "mode": "native-peer-fixture-tests",
        "original_entry_monotonic_ns": entry, "original_deadline_monotonic_ns": deadline,
        "verified_after_cleanup": verified, "resident": resident,
        "peer_test_qualification": False, "peer_test_qualification_requires_matching_outer_success": True,
        "native_runtime_qualified": False, "sdk_qualified": False,
        "compiler_qualified": False, "schema_qualified": False,
        "native_source_finalized": False, "custody_qualified": False, "health_qualified": False,
        "continuity_qualified": False, "live_qualified": False,
        "context_rotation": False, "daemon_context_acquisition": False,
        "credential_acquisition": False, "native_build_qualified": False}
