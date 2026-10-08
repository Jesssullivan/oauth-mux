"""Persistent installed setup dispatch; proof and setup selectors stay separate."""
from pathlib import Path
import os
import re
import stat
import guard_resident_enrollment_profile as enrollment
import guard_resident_vault_profile as vault

PROFILE = "resident-enrollment"
FIELDS = ("resident_enrollment_manifest", "resident_vault_manifest")
LABELS = (enrollment.LABEL, enrollment.LIFECYCLE_LABEL, enrollment.EXISTING_ENROLLMENT_LABEL, enrollment.PREPARE_LABEL,
          vault.STANDARD_LABEL, vault.STANDARD_UNLOCK_LABEL)
PROOF_MEMORY, PROOF_TASKS, PROOF_CPU_PERCENT = (
    enrollment.PROOF_MEMORY, enrollment.PROOF_TASKS, enrollment.PROOF_CPU_PERCENT)

def carrier(arguments):
    enrollment.require(arguments in (["run", label] for label in LABELS))
    return vault if arguments[1] in (vault.STANDARD_LABEL, vault.STANDARD_UNLOCK_LABEL) else enrollment

class Settings:
    PROFILE = PROFILE
    PROOF_MEMORY, PROOF_TASKS, PROOF_CPU_PERCENT = PROOF_MEMORY, PROOF_TASKS, PROOF_CPU_PERCENT
    def __init__(self, selected, manifest):
        self.selected = selected
        self.manifest = manifest
    def finite(self, arguments, manager, manifest, reuse, unrelated=()):
        enrollment.require(carrier(arguments) is self.selected and manifest == self.manifest)
        return self.selected.finite(arguments, manager, manifest, reuse, unrelated)
    def projection(self, actual, verified=False):
        return self.selected.projection(actual, verified)
    def rejection(self, error):
        return self.selected.rejection(error)

def select(args, arguments):
    values = tuple(getattr(args, key, None) for key in FIELDS)
    if args.profile != PROFILE:
        enrollment.require(all(value is None for value in values))
        return None
    selected = carrier(arguments)
    wanted = "resident_vault_manifest" if selected is vault else "resident_enrollment_manifest"
    other = "resident_enrollment_manifest" if selected is vault else "resident_vault_manifest"
    enrollment.require(getattr(args, wanted, None) is not None and getattr(args, other, None) is None)
    allowed = set(FIELDS) | {"profile", "manager", "arguments", "python", "systemd_run", "systemctl",
        "bazel", "closure", "bootstrap_closure", "zig_sdk", "java_home", "source_commit",
        "source_dirty", "state_dir", "initialize_state_dir", "coordination_dir", "become_file",
        "reuse_owned_cache", "repository_cache", "nixpkgs_source"}
    settings = Settings(selected, getattr(args, wanted))
    settings.finite(arguments, args.manager, getattr(args, wanted), args.reuse_owned_cache,
        tuple(value for key, value in vars(args).items() if key not in allowed))
    enrollment.repository_inputs(args.repository_cache, args.nixpkgs_source)
    enrollment.require(type(args.source_commit) is str and re.fullmatch(r"[0-9a-f]{40}", args.source_commit)
        and args.source_dirty == "false")
    return settings

class Admission:
    """Adapt the existing held setup admission to current guardian lifetime hooks."""
    setup_profile = True
    def __init__(self, selected, args, home, systemctl, deadline):
        self.inner = None
        self.run = None
        self.systemctl = systemctl
        self.vault = selected.selected is vault
        path = args.resident_vault_manifest if self.vault else args.resident_enrollment_manifest
        try:
            self.inner = selected.selected.Admission(path, home, deadline, label=args.arguments[1])
            self.manifest = self.inner.manifest
            self.inner.offline_repository_bindings = enrollment.repository_inputs(
                args.repository_cache, args.nixpkgs_source)
            self.inner.service_observation(systemctl, starting=True)
        except BaseException:
            self.close()
            raise

    @property
    def facts(self):
        return self.inner.facts

    def bind_run(self, run):
        enrollment.require(self.run is None and isinstance(run, Path))
        info = run.stat(follow_symlinks=False)
        enrollment.require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == os.getuid())
        self.run = run

    def environment(self):
        return self.inner.environment()

    def bindings(self):
        return self.inner.bindings()

    def writable_binding(self):
        return self.inner.writable_binding()

    def verify_bindings(self, actual, run):
        return self.inner.verify_bindings(actual, run)

    def recheck(self):
        return self.inner.recheck()

    def runtime_seconds(self):
        return self.inner.runtime_seconds()

    def completed(self, status, cleaned, epoch, producer_sha256, graph_sha256):
        enrollment.require(self.run is not None and self.run.name == epoch)
        if getattr(self.inner, "installation_update", None) is not None:
            self.inner.complete_owned_update(status, cleaned)
        preparing = getattr(self.inner,"selected",{}).get("action") == "prepare-owned"
        if preparing:
            self.inner.complete_owned_prepare(status,cleaned)
        inactive = getattr(self.inner,"selected",{}).get("action") == "observe-inactive"
        if inactive:
            enrollment.require(type(status) is int and status == 0 and cleaned is True
                and type(graph_sha256) is str and re.fullmatch(r"[0-9a-f]{64}",graph_sha256))
        self.inner.recheck()
        result = self.inner.service_observation(self.systemctl)
        if inactive or preparing:
            enrollment.require(type(graph_sha256) is str and re.fullmatch(r"[0-9a-f]{64}",graph_sha256))
            result = {**result,"action_epoch":epoch,"source_graph_sha256":graph_sha256,
                "verified_after_cleanup":True}
        return result

    def close(self):
        if self.inner is not None:
            self.inner.close()
            self.inner = None

def admit(settings, args, home, systemctl, deadline, arguments):
    # Normalized arguments are explicit; argparse's remainder may start with --.
    from copy import copy
    normalized = copy(args)
    normalized.arguments = arguments
    return Admission(settings, normalized, home, systemctl, deadline)
