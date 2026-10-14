"""Exact catalog native unit-driver cohort; input admission never proves native success."""
import errno
import os
from pathlib import Path
import re
import time
import guard_native_seed_plan_reserved as kernel
import guard_native_sdk_tree_reserved as sdk_tree

PROFILE = "native-owned-history-cli-reserved"
INPUT_MODE = "native-file-writer-models-reserved"
PROFILES = (PROFILE,)
ARGUMENTS = ["test", "//tools:codex_native_owned_history_cli_test",
    "//tools:codex_native_owned_history_cli_producer"]
MODE = "OMUX_NATIVE_FILE_WRITER_MODELS_MODE"
ENTRY = "OMUX_NATIVE_FILE_WRITER_MODELS_ENTRY_NS"
DEADLINE = "OMUX_NATIVE_FILE_WRITER_MODELS_DEADLINE_NS"
EPOCH = "OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH"
SOURCE = "OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT"
GRAPH = "OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256"
ACTION_SECONDS = 840
MEMORY, TASKS, CPU = kernel.MEMORY, kernel.TASKS, kernel.CPU
Witness = kernel.Witness
cleanup_retained = kernel.cleanup_retained
properties = kernel.properties
remaining = kernel.remaining


def require(value):
    if value is not True:
        raise ValueError("native-file-writer-models-reservation-refused")


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


def command(builder, bazel, run, arguments, profile, entry, deadline, *, graph_sha256, **kwargs):
    selected(profile, arguments)
    remaining(entry, deadline)
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(kwargs.get("repository_cache"), kwargs.get("nixpkgs_source"))
    require(kwargs.get("output_base") is None and isinstance(run, Path) and run.is_absolute()
        and run.parent in kernel.resident.PUBLIC_ROOTS
        and str(run) == os.path.normpath(str(run))
        and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",run.name) is not None
        and type(kwargs.get("source_commit")) is str
        and re.fullmatch(r"[0-9a-f]{40}",kwargs["source_commit"]) is not None
        and kwargs.get("source_dirty") == "false" and type(graph_sha256) is str
        and re.fullmatch(r"[0-9a-f]{64}",graph_sha256) is not None)
    environment = {MODE:INPUT_MODE, ENTRY:str(entry), DEADLINE:str(deadline), EPOCH:str(run),
        SOURCE:kwargs["source_commit"], GRAPH:graph_sha256}
    # Reuse only the fixed kernel capture's intrinsic original600 policy.
    # This independently selected CLI cohort neither expands SDKLease profiles
    # nor substitutes the old selected creator's recorded boot provenance.
    boot = sdk_tree.current_boot_id(entry, deadline, profile=sdk_tree.SOURCE_PROFILE)
    action_seconds = runtime_seconds(entry, deadline)
    require(action_seconds >= 1)
    result = builder(bazel, run, arguments, profile="standard", **kwargs)
    index = result.index("test") + 1
    # Repository declarations and genuine consumers bind the identical actual
    # coordinator tuple. Env presence alone never proves SDK/child readiness.
    result[index:index] = ["--repository_disable_download", "--repo_contents_cache=",
        "--test_timeout=" + str(action_seconds)] + [
        "--"+kind+"="+key+"="+value for kind in ("repo_env","test_env")
        for key,value in environment.items()] + [
        "--"+kind+"=OMUX_NATIVE_SDK_TREE_CURRENT_BOOT_ID="+boot for kind in ("action_env","test_env")]
    return result


def runtime_seconds(entry, deadline):
    return min(ACTION_SECONDS, int(remaining(entry, deadline)))


def verify_runtime(value, seconds):
    require(type(seconds) is int and 1 <= seconds <= ACTION_SECONDS)
    from yoga_delivery_settings import effective_runtime
    effective_runtime(value, seconds)


class WorkloadWitness(kernel.WorkloadWitness):
    """Only this exact new family; original kernel ownership checks unchanged."""
    def admitted_profile(self, profile):
        return profile == PROFILE


def monitor(profile, witness, readback, deadline, on_iteration, *,
            clock=time.monotonic, pause=time.sleep):
    """No routine manager reads; one terminal read still owns the exit/result fact."""
    require(profile == PROFILE and type(witness) is WorkloadWitness)
    while clock()<deadline:
        kernel.diagnostic_call("monitor-iteration", on_iteration)
        if clock()>=deadline:
            return 124
        try:
            alive=witness.alive()
        except kernel.ReservationOSError as error:
            if (type(error) is not kernel.ReservationOSError or error.reservation_phase != "worker-proc-identity"
                    or error.errno != errno.ENOENT or getattr(witness, "proc_exit_pending", False) is not True
                    or witness.bounds is None):
                raise
            try:
                return witness.confirm_proc_exit(readback, deadline, clock)
            except (kernel.ReservationOSError, kernel.ReservationValueError) as refusal:
                refusal.reservation_proc_exit = witness.proc_exit_confirmation
                raise
        if clock()>=deadline:
            return 124
        if not alive:
            actual=kernel.diagnostic_call("terminal-manager-readback", readback)
            if clock()>=deadline:
                return 124
            require(not kernel.diagnostic_call("terminal-recheck", witness.alive))
            if clock()>=deadline:
                return 124
            return witness.terminal(actual)
        left=deadline-clock()
        if left<=0:
            return 124
        pause(min(0.5,left))
    return 124


def release_worker(witness):
    """Detach new FDs before any receipt can promote success; fallback is idempotent."""
    if witness is None:
        return True
    require(type(witness) is WorkloadWitness)
    try:
        witness.close()
    except (OSError,ValueError):
        return False
    return True


def projection(entry, deadline, verified, resident):
    kernel.envelope(entry, deadline)
    require(verified is None or type(verified) is bool)
    return {"scope": "fixed-native-owned-history-cli-reserved-v1", "mode": "current-retained-sdk-history13-model60-cli-package",
        "original_entry_monotonic_ns": entry, "original_deadline_monotonic_ns": deadline,
        "action_cap_seconds": ACTION_SECONDS, "verified_after_cleanup": verified, "resident": resident,
        "native_source_finalized": False, "sdk_qualified": False, "compiler_qualified": False,
        "schema_qualified": False, "package_qualified": False, "native_runtime_qualified": False,
        "native_image_qualified": False, "custody_qualified": False, "health_qualified": False,
        "credential_acquisition_qualified": False, "issuer_qualified": False,
        "timing_fit_qualified": False, "native60_qualified_by_admission": False,
        "ordinary_launch_qualified": False, "continuity_qualified": False, "live_qualified": False}
