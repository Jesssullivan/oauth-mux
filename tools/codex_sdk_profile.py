"""Validate retained adapter inputs and describe a finite SDK test command.

No process launch, provider access, or build promotion occurs here. The outer
controller supplies its pinned Bazel executable and owns containment.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from codex_fresh_source import (MANIFEST_SHA, PRISTINE_RECEIPT_SHA, PRISTINE_SHA,
                               RETIREMENT_BEFORE, RETIREMENT_SHA, VALIDATION_SHA,
                               trusted_parent, validate_paths)
from codex_recovery_delta import BASE_PATCH
from fetch_codex_archives import ARCHIVES, MAX_FILE_BYTES, MAX_RETAINED_BYTES
from restore_pristine_inputs import COMMIT, TREE, unique_object

# Root selects the exact fast controller location before enabling this profile.
FAST_STATE = Path("/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005")
PRODUCER_SUFFIX = ("output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"
                   "codex_fresh_source_producer/test.outputs/codex-adapter-epoch")
SETTINGS_SUFFIX = ("output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"
                   "codex_sdk_settings_producer/test.outputs/codex-sdk-settings")
RETAINED_HOME_SETTINGS = Path("/home/jess/.local/state/omux-execution-20261005/"
    "cache-v2-0263cddbc2fe72e072e344a70bf61fdc0e90702986c9738e791ef64375ac8aee") / SETTINGS_SUFFIX
TOOL_ORDER = ("bash", "coreutils", "python3", "git", "gawk", "gnugrep", "gnused", "findutils")
EXPORT_MODE_POLICY = "bazel-retained-export-all-regular-and-directories-0555-v1"
GIT_MODE_AUTHORITY = "sha256-bound-source-receipt-Git-modes"
BAZEL = "/nix/store/ia8gp7v2h790lwdx7a7p5clh063v0qy1-bazel-9.0.1/bin/bazel"
RECOVERY_SHA = "aa4bc7f3cdd281a34096260ff60dd17dfdc892c55e59e282989110383e701cf5"
RECOVERY_RECEIPT_SHA = "897ddcad5fac986aa5db611d1ebe4464563abe46eb74006090427f836352f521"
ARCHIVE_MANIFEST_SHA = "f44be109f043f1044473bfb93a0ad1da25f060c42d688fe182ab4b4bdb6b942a"
DEPENDENCY_SUFFIX = ("output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"
                     "codex_dependency_union_producer/test.outputs/codex-sdk-dependency-union")
DEPENDENCY_ROOTS = (FAST_STATE,
                    Path("/home/jess/.local/state/omux-execution-20261005"),
                    Path("/srv/fast-local/jess/state/codex/omux-dependency-prefetch-20261005"))
GRAPH = {
    "MODULE.bazel": "1a6c8685d241a5390ff94432581e842c2950cbe5262b47b27d8db467cebec4c2",
    "MODULE.bazel.lock": "3416c08d3ddff96ec9e0b76d7d89eaa2b75cc8d81f0a9f661d8b8466d1343657",
    "codex-rs/Cargo.lock": "72efa81ed947d07ed4fbb3e10b094715ff00626126d758aaed56733c97887e5f",
    "codex-rs/Cargo.toml": "c732c370ca012d0da7944d463601b3c834eb862a85866d3274db9d2acecea978",
}
LANES = {
    "core": ("//codex-rs/core:core-unit-tests",
             "native_owner_startup_tests::native_owner_constructor_publishes_before_ack_and_fences_work_until_commit"),
    "app-server": ("//codex-rs/app-server:app-server-unit-tests",
                   "owner_control::tests::original_frame_rejects_duplicate_and_unknown_owner_fields"),
    "protocol": ("//codex-rs/app-server-protocol:app-server-protocol-unit-tests", None),
}


def require(value, message):
    if not value:
        raise ValueError(message)


def hash_regular(directory, name, limit, capture=False, *, on_read=None):
    if on_read is not None:
        on_read(0)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and not before.st_mode & 0o022 and before.st_size <= limit, "input custody or size mismatch")
        result, parts, count = hashlib.sha256(), [], 0
        while True:
            if on_read is not None:
                on_read(0)
            chunk = os.read(fd, 1024 * 1024)
            if on_read is not None:
                on_read(len(chunk))
            if not chunk:
                break
            count += len(chunk)
            require(count <= limit, "input grew beyond bound")
            result.update(chunk)
            if capture:
                parts.append(chunk)
        after = os.fstat(fd)
        require(count == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "input changed during verification")
        if on_read is not None:
            on_read(0)
        return result.hexdigest(), count, b"".join(parts)
    finally:
        os.close(fd)


def metadata(directory, name, expected, limit=8 * 1024 * 1024, *, on_read=None):
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "noncanonical receipt digest")
    actual, _, value = hash_regular(directory, name, limit, True, on_read=on_read)
    require(actual == expected, "receipt digest mismatch")
    result = json.loads(value, object_pairs_hook=unique_object)
    if on_read is not None:
        on_read(0)
    return result


def epoch_location(root):
    require(root.is_absolute() and ".." not in root.parts, "noncanonical epoch root")
    relative = root.relative_to(FAST_STATE)
    require(relative.parts and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", relative.parts[0]),
            "source must belong to a fresh fast controller epoch")
    require(Path(*relative.parts[1:]).as_posix() == PRODUCER_SUFFIX, "source must use declared producer output")


def controller_location(root):
    root = Path(root)
    require(root.is_absolute() and ".." not in root.parts, "noncanonical controller root")
    relative = root.relative_to(FAST_STATE)
    require(len(relative.parts) == 1 and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", relative.parts[0]),
            "controller root must be an exact fast epoch UUID")
    return root


def source_provenance(root, recorded):
    """Accept relocation metadata without resolving or reading creation paths."""
    root = Path(root)
    epoch_location(root)
    if recorded == str(root / "source"):
        return
    require(isinstance(recorded, str), "source creation provenance missing")
    epoch = FAST_STATE / root.relative_to(FAST_STATE).parts[0]
    prefix = str(epoch / "output-base/sandbox/processwrapper-sandbox") + "/"
    suffix = "/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_fresh_source_producer/test.outputs/codex-adapter-epoch/source"
    require(recorded.startswith(prefix) and recorded.endswith(suffix), "source creation provenance mismatch")
    number = recorded[len(prefix):-len(suffix)]
    require(re.fullmatch(r"0|[1-9][0-9]{0,8}", number) is not None, "noncanonical source creation sandbox")


def launcher_contents(bash):
    require(re.fullmatch(r"/nix/store/[a-z0-9]{32}-bash-[^/\s]+/bin/bash", bash), "workspace status requires declared immutable Bash")
    return ("#!" + bash + "\nprintf 'STABLE_GIT_COMMIT " + COMMIT + "\\n'\n").encode()


def realized_tools(test_path):
    names = ("bash", "env", "python3", "git", "awk", "grep", "sed", "find")
    parts = test_path.split(":")
    require(len(parts) == len(names), "locked tool count mismatch")
    for directory, name in zip(parts, names):
        path = (Path(directory) / name).resolve(strict=True)
        require(path.parts[:3] == ("/", "nix", "store"), "tool resolves outside immutable store")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o222
                    and info.st_mode & 0o111, "locked tool has not been realized immutably")
        finally:
            os.close(fd)


def prepare_workspace_status(controller_root, bash):
    """Explicit controller-owned preparation; no shell or Git is invoked."""
    root = controller_location(controller_root)
    fd = trusted_parent(root)
    try:
        output = os.open("sdk-workspace-status", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500, dir_fd=fd)
        with os.fdopen(output, "wb") as stream:
            stream.write(launcher_contents(bash))
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(fd)
    finally:
        os.close(fd)
    return root / "sdk-workspace-status"


def verify_inventory(directory, expected, physical_mode_policy=None, *, on_read=None):
    if on_read is not None:
        on_read(0)
    require(isinstance(expected, dict) and 0 < len(expected) <= 50000, "inventory bound mismatch")
    require(physical_mode_policy in (None, EXPORT_MODE_POLICY), "unsupported physical mode policy")
    exported = physical_mode_policy == EXPORT_MODE_POLICY
    if exported:
        require(stat.S_IMODE(os.fstat(directory).st_mode) == 0o555, "export directory mode mismatch")
    expected_directories = set()
    for path in expected:
        if on_read is not None:
            on_read(0)
        parts = path.split("/")
        expected_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    observed_directories = set()
    observed, total, nodes = {}, 0, 0
    def walk(fd, prefix=""):
        nonlocal total, nodes
        require(prefix.count("/") <= 64, "source directory depth exceeds bound")
        if on_read is not None:
            on_read(0)
        for name in os.listdir(fd):
            if on_read is not None:
                on_read(0)
            nodes += 1
            require(nodes <= 100000, "source entry count exceeds bound")
            require(name not in (".", "..") and "/" not in name, "unsafe source entry")
            path = prefix + name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(info.st_uid == os.getuid(), "foreign source ownership")
            if stat.S_ISDIR(info.st_mode):
                require(not info.st_mode & 0o022, "writable source directory")
                if exported:
                    require(stat.S_IMODE(info.st_mode) == 0o555, "export directory mode mismatch")
                observed_directories.add(path)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    require((os.fstat(child).st_dev, os.fstat(child).st_ino) == (info.st_dev, info.st_ino), "source directory changed")
                    walk(child, path + "/")
                finally:
                    os.close(child)
            elif stat.S_ISLNK(info.st_mode):
                value = os.readlink(name, dir_fd=fd).encode()
                if on_read is not None:
                    on_read(len(value))
                observed[path] = {"mode": "120000", "sha256": hashlib.sha256(value).hexdigest()}
                total += len(value)
                validate_paths({path: ("120000", value)})
            else:
                if exported:
                    require(stat.S_IMODE(info.st_mode) == 0o555, "export regular mode mismatch")
                    require(path in expected and expected[path].get("mode") in ("100644", "100755"), "full source inventory mismatch")
                digest, size, _ = hash_regular(fd, name, 512 * 1024 * 1024 - total, on_read=on_read)
                total += size
                mode = expected[path]["mode"] if exported else ("100755" if info.st_mode & 0o111 else "100644")
                observed[path] = {"mode": mode, "sha256": digest}
            require(len(observed) <= 50000 and total <= 512 * 1024 * 1024, "source inventory exceeds bound")
    walk(directory)
    require(observed == expected and observed_directories == expected_directories, "full source inventory mismatch")
    if on_read is not None:
        on_read(0)
    return total


def validate_source(root, receipt_sha256, *, on_read=None):
    if on_read is not None:
        on_read(0)
    root = Path(root)
    epoch_location(root)
    fd = trusted_parent(root)
    try:
        report = metadata(fd, "source-receipt.json", receipt_sha256, on_read=on_read)
        require(report.get("status") == "fresh-adapter-source-uncompiled" and report.get("phase") == "prepare-adapter"
                and report.get("commit") == COMMIT and report.get("upstream_tree_oid") == TREE,
                "source receipt is not the fresh uncompiled adapter")
        pins = {"pristine_archive_sha256": PRISTINE_SHA, "pristine_receipt_sha256": PRISTINE_RECEIPT_SHA,
                "baseline_manifest_sha256": MANIFEST_SHA, "baseline_validation_sha256": VALIDATION_SHA,
                "baseline_patch_sha256": BASE_PATCH, "recovery_patch_sha256": RECOVERY_SHA,
                "baseline_base_sha256": "a794a67af4b6aecd9e91aeb4281354b90d10e10134e7cf6a6028b33f26a2f9d9",
                "baseline_binary_overlay_sha256": "9d47862cd9e7e1a911d8512dad0ad0f124c928e139b778cd1e89ecfce17c5703",
                "validation_overlay_sha256": "563bb8ac31fb17ae97e1c92d140bfe633102e4714803489b551c0d0c2e4717cb",
                "recovery_receipt_sha256": RECOVERY_RECEIPT_SHA, "retirement_implementation_sha256": RETIREMENT_SHA,
                "retirement_before_sha256": RETIREMENT_BEFORE}
        require(all(report.get(key) == value for key, value in pins.items()), "source input authority mismatch")
        source_provenance(root, report.get("source"))
        require(report.get("native_tests_passed") is False
                and report.get("native_support") is False and report.get("schema_producer_receipt") is None,
                "source receipt claims or path mismatch")
        files = report.get("files")
        require(isinstance(files, dict) and report.get("tracked_files") == len(files)
                and report.get("complete_inventory_sha256") == hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
                "source inventory receipt mismatch")
        source = os.open("source", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            require(verify_inventory(source, files, EXPORT_MODE_POLICY, on_read=on_read) == report.get("source_bytes"), "source byte count mismatch")
        finally:
            os.close(source)
        require(report.get("retirement_after_sha256") == files.get("codex-rs/core/src/thread_manager.rs", {}).get("sha256"),
                "retirement result inventory binding mismatch")
        require(report.get("graph_sha256") == GRAPH, "SDK graph provenance mismatch")
        for name, expected in GRAPH.items():
            require(files.get(name, {}).get("sha256") == expected, "graph inventory binding mismatch")
        outputs = report.get("outputs")
        require(isinstance(outputs, dict) and set(outputs) == {"full-product.patch", "product-binary-overlay.tar.gz", "validation-overlay.patch"},
                "source output set mismatch")
        for name, entry in outputs.items():
            digest, size, _ = hash_regular(fd, name, 64 * 1024 * 1024, on_read=on_read)
            require(entry == {"sha256": digest, "bytes": size}, "source product output mismatch")
        require(outputs["validation-overlay.patch"]["sha256"] == report.get("validation_overlay_sha256"), "validation binding mismatch")
        if on_read is not None:
            on_read(0)
        return {"source": str(root / "source"), "receipt_sha256": receipt_sha256, "commit": COMMIT,
                "complete_inventory_sha256": report["complete_inventory_sha256"],
                "physical_mode_policy": EXPORT_MODE_POLICY, "git_mode_authority": GIT_MODE_AUTHORITY,
                "physical_regular_modes": "0555, including receipt-nonexecutable files; only declared SDK tools are dispatchable"}
    finally:
        os.close(fd)


def validate_archives(bundle, receipt_sha256, manifest_sha256):
    require(manifest_sha256 == ARCHIVE_MANIFEST_SHA, "archive manifest authority mismatch")
    fd = trusted_parent(Path(bundle))
    try:
        report = metadata(fd, "receipt.json", receipt_sha256)
        require(report.get("status") == "complete-verified-distdir" and report.get("missing") == []
                and report.get("manifest_sha256") == manifest_sha256, "incomplete archive bundle")
        entries = report.get("verified")
        require(isinstance(entries, list) and len(entries) == 13, "archive receipt count mismatch")
        rows = {entry["name"]: entry for entry in entries}
        require(set(rows) == {name for name, _, _ in ARCHIVES}
                and set(os.listdir(fd)) == set(rows) | {"receipt.json"}, "archive set mismatch")
        total = 0
        for name, expected, _ in ARCHIVES:
            digest, size, _ = hash_regular(fd, name, MAX_FILE_BYTES)
            require(digest == expected == rows[name].get("sha256") and size == rows[name].get("bytes")
                    and rows[name].get("status") == "verified-export", "archive digest mismatch")
            total += size
        require(total <= MAX_RETAINED_BYTES, "archive bundle exceeds bound")
        return str(bundle)
    finally:
        os.close(fd)


def _test_arguments(lane, distdir, workspace_status=None):
    """Arguments only; executable/cwd/profile are supplied by the controller."""
    require(lane in LANES, "unsupported SDK test lane")
    target, test_filter = LANES[lane]
    args = ["test", "--compilation_mode=opt", "--lockfile_mode=error",
            "--repo_env=BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=1", "--repo_env=BAZEL_NO_APPLE_CPP_TOOLCHAIN=1",
            "--xcode_version_config=//:disable_xcode", "--host_platform=//:local_linux",
            "--@rules_cc//cc/toolchains/args/archiver_flags:use_libtool_on_macos=False",
            "--@llvm//config:experimental_stub_libgcc_s", "--incompatible_strict_action_env",
            "--noenable_runfiles", "--nobuild_runfile_links", "--test_env=RUST_MIN_STACK=8388608",
            "--platforms=//codex-rs/core:owner-linux",
            "--extra_toolchains=//codex-rs/core:owner-local-test-toolchain",
            "--jobs=1", "--local_test_jobs=1", "--test_env=RUST_TEST_THREADS=1",
            "--repo_env=STABLE_GIT_COMMIT=" + COMMIT, "--distdir=" + str(distdir),
            "--remote_executor=", "--remote_cache=", "--test_output=errors"]
    if test_filter:
        args.append("--test_filter=" + test_filter)
    if workspace_status is not None:
        args.append("--workspace_status_command=" + str(workspace_status))
    return tuple(args + [target])


def retained_rc_settings(value, distdir, test_path):
    require(isinstance(test_path, str) and len(test_path.split(":")) == 8
            and all(re.fullmatch(r"/nix/store/[a-z0-9]{32}-[^/:\s]+/bin", part)
                    for part in test_path.split(":")), "settings tool PATH mismatch")
    require(value == ("common --distdir=" + distdir + "\ntest --test_env=PATH=" + test_path + "\n").encode(),
            "settings RC must contain only exact retained distdir and locked test PATH")
    return test_path


def settings_location(root):
    root = Path(root)
    require(root.is_absolute() and ".." not in root.parts, "noncanonical settings root")
    if root == RETAINED_HOME_SETTINGS:
        return root
    relative = root.relative_to(FAST_STATE)
    require(relative.parts and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", relative.parts[0])
            and Path(*relative.parts[1:]).as_posix() == SETTINGS_SUFFIX, "settings must use exact declared producer output")
    return root


def validate_settings(root, receipt_sha256, distdir):
    root = settings_location(root)
    fd = trusted_parent(root)
    try:
        report = metadata(fd, "sdk-settings-receipt.json", receipt_sha256)
        pins = {"schema_version": 1, "status": "verified-locked-settings",
                "flake_sha256": "2c7fbc134cf1d46c435b5cb1fcba9b5b335745d3efff84c55e334ad2523c9d4f",
                "lock_sha256": "2dc0211d0aa355e3011a17bbfacbf81140a79bf736f9facb53d2836019a51cb8",
                "nixpkgs_source": "/nix/store/75bkaivfbwq3x8cs7155hag7hs1chjcx-source",
                "nixpkgs_revision": "0726a0ecb6d4e08f6adced58726b95db924cef57",
                "nixpkgs_nar_hash": "sha256-EHq1/OX139R1RvBzOJ0aMRT3xnWyqtHBRUBuO1gFzjI=",
                "all_tools_available": True, "realization": False, "native_support": False, "native_proof": False,
                "distdir": distdir, "tool_order": list(TOOL_ORDER)}
        require(all(report.get(name) == expected for name, expected in pins.items()), "locked settings authority mismatch")
        digest, size, value = hash_regular(fd, "sdk-settings.bazelrc", 65536, True)
        require(digest == report.get("rc_sha256") and size == report.get("rc_bytes"), "settings RC digest mismatch")
        test_path = report.get("test_path")
        retained_rc_settings(value, distdir, test_path)
        binaries = ("bash", "env", "python3", "git", "awk", "grep", "sed", "find")
        tools = {name: directory + "/" + binary for name, directory, binary in zip(TOOL_ORDER, test_path.split(":"), binaries)}
        require(report.get("tools") == tools and report.get("bash") == tools["bash"], "settings tool identity mismatch")
        realized_tools(test_path)
        return test_path, report["bash"], digest
    finally:
        os.close(fd)


class SdkDependencyNotReady(ValueError):
    """Receipt-bound diagnostics, without credential, path or descriptor output."""
    def __init__(self, counts, bindings):
        self.counts = counts
        self.bindings = bindings
        self.blockers = {
            "missing_objects": counts["missing_objects"],
            "unresolved_rows": counts["unresolved_rows"],
            "canonical_id_mapping": "unproved",
            "git_materialization": "unproved",
        }
        self.remaining_outcomes = {"offline_analysis": "unrun", "native_compile_tests": "unrun"}
        super().__init__("SDK dependencies not ready: "
                         + str(counts["missing_objects"]) + " missing objects; "
                         + str(counts["unresolved_rows"]) + " unresolved rows; "
                         "canonical-ID mapping and Git materialization unproved; offline analysis unrun")


def dependency_location(root):
    root = Path(root)
    require(root.is_absolute() and ".." not in root.parts, "noncanonical dependency root")
    for base in DEPENDENCY_ROOTS:
        if root.is_relative_to(base):
            parts = root.relative_to(base).parts
            require(len(parts) > 1 and re.fullmatch(
                r"(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|cache-v2-[0-9a-f]{64})", parts[0])
                and Path(*parts[1:]).as_posix() == DEPENDENCY_SUFFIX,
                "dependencies must use exact declared union output")
            return root
    raise ValueError("undeclared dependency producer root")


def dependency_readiness(report, *, receipt_sha256, manifest_sha256,
                         source_receipt_sha256, source_inventory_sha256,
                         tool_receipt_sha256, tool_manifest_sha256, settings_receipt_sha256):
    """Check an independently selected union's declarations before payload planning.

    The current union schema cannot authorize an SDK command: it describes only
    digest-CAS coverage. No object bytes, canonical IDs, Git repositories or
    offline repository analysis are verified by this metadata-only preflight.
    A future admission contract needs reviewed Git and canonical-ID input
    producers; setting receipt booleans to true is not such a producer. Offline
    analysis is an unrun outcome, not a prerequisite for attempting analysis.
    """
    bindings = {"union_receipt_sha256": receipt_sha256, "descriptor_sha256": manifest_sha256,
                "source_receipt_sha256": source_receipt_sha256,
                "source_inventory_sha256": source_inventory_sha256,
                "tool_receipt_sha256": tool_receipt_sha256,
                "tool_manifest_sha256": tool_manifest_sha256,
                "settings_receipt_sha256": settings_receipt_sha256}
    require(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                and value != "0" * 64 for value in bindings.values()), "dependency binding digest mismatch")
    require(isinstance(report, dict) and type(report.get("schema_version")) is int
            and report["schema_version"] == 1
            and report.get("status") == "verified-finite-dependency-union"
            and report.get("descriptor_sha256") == manifest_sha256
            and report.get("source_receipt_sha256") == source_receipt_sha256
            and report.get("source_inventory_sha256") == source_inventory_sha256,
            "dependency source or manifest binding mismatch")
    require(all(report.get(name) is False for name in (
        "closure_proved", "offline_analysis_proved", "canonical_id_metadata_exported",
        "native_support", "provider_evaluation", "ambient_cache_read")),
        "unsupported dependency proof claims")
    parents = report.get("parent_receipts")
    require(isinstance(parents, dict) and set(parents) == {"plan", "shard", "tools", "tools_manifest"}
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                    and value != "0" * 64 for value in parents.values())
            and parents["tools"] == tool_receipt_sha256
            and parents["tools_manifest"] == tool_manifest_sha256 == ARCHIVE_MANIFEST_SHA,
            "dependency tool closure binding mismatch")

    def rows(value):
        require(isinstance(value, list) and len(value) <= 30000, "dependency descriptor bound mismatch")
        for row in value:
            require(isinstance(row, dict) and set(row) == {"type", "identity", "sha256", "urls"}
                    and isinstance(row["type"], str) and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", row["type"])
                    and isinstance(row["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                    and isinstance(row["identity"], str) and 0 < len(row["identity"]) <= 4096
                    and not any(char in row["identity"] for char in "\0\r\n")
                    and isinstance(row["urls"], list) and 0 < len(row["urls"]) <= 16
                    and all(isinstance(url, str) and 0 < len(url) <= 8192 for url in row["urls"]),
                    "dependency descriptor shape mismatch")
        return value

    descriptors, missing = rows(report.get("descriptors")), rows(report.get("missing"))
    admitted = {row["sha256"] for row in descriptors}
    objects, origins = report.get("objects"), report.get("object_origins")
    require(isinstance(objects, dict) and len(objects) <= 5000
            and isinstance(origins, dict) and set(origins) == set(objects), "dependency object bound mismatch")
    total, inputs = 0, 0
    for digest, record in objects.items():
        require(digest in admitted and isinstance(record, dict) and set(record) == {"bytes"}
                and type(record["bytes"]) is int and 0 <= record["bytes"] <= 1024 * 1024 * 1024,
                "dependency object declaration mismatch")
        total += record["bytes"]
        sources = origins[digest]
        require(isinstance(sources, list) and 1 <= len(sources) <= 3
                and all(isinstance(value, str) for value in sources) and len(set(sources)) == len(sources)
                and all(isinstance(value, str) and value in (parents["plan"], parents["shard"], parents["tools"])
                        for value in sources), "dependency object origin mismatch")
        inputs += len(sources)
    require(total <= 4 * 1024 * 1024 * 1024, "dependency retained byte bound mismatch")
    descriptor_records = {json.dumps(row, sort_keys=True) for row in descriptors}
    require(len({row["sha256"] for row in missing}) == len(missing)
            and all(json.dumps(row, sort_keys=True) in descriptor_records for row in missing)
            and {row["sha256"] for row in missing} == admitted - set(objects),
            "dependency missing partition mismatch")
    require({digest for _, digest, _ in ARCHIVES} <= set(objects), "dependency tool objects absent")
    unresolved = report.get("unresolved")
    require(isinstance(unresolved, list) and len(unresolved) <= 30000
            and all(isinstance(row, dict) and isinstance(row.get("type"), str)
                    and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", row["type"]) for row in unresolved),
            "dependency unresolved bound mismatch")

    def by_type(value):
        counts = {}
        for row in value:
            counts[row["type"]] = counts.get(row["type"], 0) + 1
        return counts

    counts = {"input_objects": inputs, "unique_objects": len(objects),
              "duplicate_objects": inputs - len(objects), "missing_objects": len(missing),
              "missing_by_type": by_type(missing), "unresolved_rows": len(unresolved),
              "unresolved_by_type": by_type(unresolved)}
    recorded = report.get("counts")
    require(isinstance(recorded, dict) and set(recorded) == set(counts)
            and all(type(recorded[name]) is int for name in (
                "input_objects", "unique_objects", "duplicate_objects", "missing_objects", "unresolved_rows"))
            and all(isinstance(recorded[name], dict) and all(type(value) is int for value in recorded[name].values())
                    for name in ("missing_by_type", "unresolved_by_type"))
            and recorded == counts, "dependency coverage counts mismatch")
    raise SdkDependencyNotReady(counts, bindings)


def validate_dependency_readiness(root, receipt_sha256, manifest_sha256, **bindings):
    fd = trusted_parent(dependency_location(root))
    try:
        report = metadata(fd, "bundle-receipt.json", receipt_sha256, 16 * 1024 * 1024)
        dependency_readiness(report, receipt_sha256=receipt_sha256,
                             manifest_sha256=manifest_sha256, **bindings)
    finally:
        os.close(fd)


def command_plan(source_root, source_receipt_sha256, bundle, bundle_receipt_sha256,
                 manifest_sha256, settings_root, settings_receipt_sha256, controller_root, lane,
                 *, dependency_root=None, dependency_receipt_sha256=None, dependency_manifest_sha256=None):
    """Incomplete dependency authority refuses before argv planning; never invoke Bazel."""
    require(dependency_root is not None and dependency_receipt_sha256 is not None
            and dependency_manifest_sha256 is not None, "independently selected dependency union required")
    source = validate_source(source_root, source_receipt_sha256)
    # Settings bind the exact selected tool-bundle location. Its bytes are not
    # read until dependency admission; a partial union must never plan a payload.
    distdir = str(bundle)
    test_path, bash, rc_sha256 = validate_settings(settings_root, settings_receipt_sha256, distdir)
    validate_dependency_readiness(dependency_root, dependency_receipt_sha256, dependency_manifest_sha256,
        source_receipt_sha256=source_receipt_sha256,
        source_inventory_sha256=source["complete_inventory_sha256"],
        tool_receipt_sha256=bundle_receipt_sha256, tool_manifest_sha256=manifest_sha256,
        settings_receipt_sha256=settings_receipt_sha256)
    distdir = validate_archives(bundle, bundle_receipt_sha256, manifest_sha256)
    epoch = controller_location(controller_root)
    expected_launcher = launcher_contents(bash)
    controller_fd = trusted_parent(epoch)
    try:
        actual, _, _ = hash_regular(controller_fd, "sdk-workspace-status", 65536)
        require(actual == hashlib.sha256(expected_launcher).hexdigest(), "fixed workspace status launcher mismatch")
        info = os.stat("sdk-workspace-status", dir_fd=controller_fd, follow_symlinks=False)
        require(info.st_mode & 0o777 == 0o500, "workspace status launcher must be immutable executable")
    finally:
        os.close(controller_fd)
    args = _test_arguments(lane, distdir, epoch / "sdk-workspace-status")
    return {"status": "validated-sdk-command-unrun", "cwd": source["source"],
            # Do not pass the original rc to Bazel: repeatable --distdir can
            # accumulate rather than replace. Translate its verified PATH,
            # retaining only the independently verified bundle as distdir.
            "argv": (BAZEL, "--batch", "--ignore_all_rc_files",
                     "--output_base=" + str(epoch / "sdk-output-base"))
                    + args[:-1] + ("--test_env=PATH=" + test_path, args[-1]),
            "environment": {"PATH": test_path, "STABLE_GIT_COMMIT": COMMIT},
            "supplemental_rc_sha256": rc_sha256, "settings_receipt_sha256": settings_receipt_sha256,
            "source_receipt_sha256": source_receipt_sha256,
            "physical_mode_policy": source["physical_mode_policy"], "git_mode_authority": source["git_mode_authority"],
            "physical_regular_modes": source["physical_regular_modes"],
            "native_support": False, "provider_evaluation": False}
