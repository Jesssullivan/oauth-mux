"""Offline SDK profile refusal predicates; no native SDK invocation."""

import hashlib
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from codex_sdk_profile import (ARCHIVES, ARCHIVE_MANIFEST_SHA, DEPENDENCY_ROOTS, DEPENDENCY_SUFFIX,
    EXPORT_MODE_POLICY, FAST_STATE, PRODUCER_SUFFIX, RETAINED_HOME_SETTINGS, SETTINGS_SUFFIX,
    SdkDependencyNotReady, _test_arguments, command_plan, controller_location, dependency_location,
    dependency_readiness, epoch_location, hash_regular, launcher_contents, retained_rc_settings,
    settings_location, source_provenance, validate_dependency_readiness, validate_settings, verify_inventory)


class SdkProfileTests(unittest.TestCase):
    @staticmethod
    def dependency_fixture(available=305, missing=1410, unresolved=42):
        # Declared metadata only: these bytes do not purport to be real compiler
        # archives. The preflight must refuse without touching CAS payloads.
        bindings = {"receipt_sha256": "a" * 64, "manifest_sha256": "b" * 64,
                    "source_receipt_sha256": "c" * 64, "source_inventory_sha256": "d" * 64,
                    "tool_receipt_sha256": "e" * 64, "tool_manifest_sha256": ARCHIVE_MANIFEST_SHA,
                    "settings_receipt_sha256": "f" * 64}
        parents = {"plan": "1" * 64, "shard": "2" * 64, "tools": bindings["tool_receipt_sha256"],
                   "tools_manifest": ARCHIVE_MANIFEST_SHA}
        digests = [digest for _, digest, _ in ARCHIVES]
        digests += [hashlib.sha256(("fixture-object-" + str(index)).encode()).hexdigest()
                    for index in range(available + missing - len(digests))]
        descriptors = [{"type": "cargo-crate", "identity": "fixture-" + str(index),
                        "sha256": digest, "urls": ["https://example.invalid/fixture"]}
                       for index, digest in enumerate(digests)]
        objects = {digest: {"bytes": 0} for digest in digests[:available]}
        origins = {digest: [parents["plan"]] for digest in objects}
        for digest in digests[:3]:
            origins[digest].append(parents["tools"])
        rows = [{"type": "cargo-git", "identity": "fixture-unresolved"} for _ in range(unresolved)]
        report = {"schema_version": 1, "status": "verified-finite-dependency-union",
                  "descriptor_sha256": bindings["manifest_sha256"],
                  "source_receipt_sha256": bindings["source_receipt_sha256"],
                  "source_inventory_sha256": bindings["source_inventory_sha256"],
                  "parent_receipts": parents, "descriptors": descriptors, "objects": objects,
                  "object_origins": origins, "missing": descriptors[available:], "unresolved": rows,
                  "counts": {"unique_objects": available, "input_objects": available + 3,
                             "duplicate_objects": 3, "missing_objects": missing,
                             "missing_by_type": {"cargo-crate": missing} if missing else {},
                             "unresolved_rows": unresolved,
                             "unresolved_by_type": {"cargo-git": unresolved} if unresolved else {}},
                  **{name: False for name in ("closure_proved", "offline_analysis_proved",
                      "canonical_id_metadata_exported", "native_support", "provider_evaluation", "ambient_cache_read")}}
        return report, bindings

    def test_partial_union_refuses_exact_counts_and_keeps_input_gates_distinct(self):
        report, bindings = self.dependency_fixture()
        with self.assertRaises(SdkDependencyNotReady) as error:
            dependency_readiness(report, **bindings)
        self.assertEqual(error.exception.counts["unique_objects"], 305)
        self.assertEqual(error.exception.counts["input_objects"], 308)
        self.assertEqual(error.exception.blockers, {"missing_objects": 1410, "unresolved_rows": 42,
            "canonical_id_mapping": "unproved", "git_materialization": "unproved"})
        self.assertEqual(error.exception.remaining_outcomes["offline_analysis"], "unrun")
        self.assertEqual(error.exception.bindings["settings_receipt_sha256"], bindings["settings_receipt_sha256"])
        self.assertNotIn("fixture-unresolved", str(error.exception))

    def test_complete_declared_digest_coverage_does_not_promote_git_or_mapping(self):
        report, bindings = self.dependency_fixture(available=13, missing=0, unresolved=0)
        with self.assertRaises(SdkDependencyNotReady) as error:
            dependency_readiness(report, **bindings)
        self.assertEqual(error.exception.blockers["missing_objects"], 0)
        self.assertEqual(error.exception.blockers["unresolved_rows"], 0)
        self.assertEqual(error.exception.blockers["git_materialization"], "unproved")
        for flag in ("closure_proved", "canonical_id_metadata_exported", "offline_analysis_proved", "native_support"):
            changed = copy.deepcopy(report)
            changed[flag] = True
            with self.assertRaisesRegex(ValueError, "unsupported dependency proof claims"):
                dependency_readiness(changed, **bindings)

    def test_dependency_source_manifest_tool_and_settings_bindings_refuse_substitution(self):
        report, bindings = self.dependency_fixture(available=13, missing=1, unresolved=1)
        for key in ("manifest_sha256", "source_receipt_sha256", "source_inventory_sha256", "tool_receipt_sha256", "tool_manifest_sha256"):
            altered = dict(bindings, **{key: "9" * 64})
            with self.assertRaisesRegex(ValueError, "binding mismatch"):
                dependency_readiness(report, **altered)
        for key in bindings:
            with self.assertRaisesRegex(ValueError, "binding digest mismatch"):
                dependency_readiness(report, **dict(bindings, **{key: "0" * 64}))

    def test_dependency_counts_partition_origins_and_tool_presence_are_not_claim_flags(self):
        report, bindings = self.dependency_fixture(available=13, missing=1, unresolved=1)
        changed = copy.deepcopy(report)
        changed["counts"]["missing_objects"] = 0
        with self.assertRaisesRegex(ValueError, "coverage counts mismatch"):
            dependency_readiness(changed, **bindings)
        changed = copy.deepcopy(report)
        changed["missing"] = []
        with self.assertRaisesRegex(ValueError, "missing partition mismatch"):
            dependency_readiness(changed, **bindings)
        changed = copy.deepcopy(report)
        digest = next(iter(changed["objects"]))
        changed["object_origins"][digest] = [changed["parent_receipts"]["plan"]] * 2
        with self.assertRaisesRegex(ValueError, "origin mismatch"):
            dependency_readiness(changed, **bindings)
        changed = copy.deepcopy(report)
        changed["objects"][digest]["bytes"] = True
        with self.assertRaisesRegex(ValueError, "object declaration mismatch"):
            dependency_readiness(changed, **bindings)
        changed = copy.deepcopy(report)
        del changed["objects"][digest]
        del changed["object_origins"][digest]
        changed["missing"].append(next(row for row in changed["descriptors"] if row["sha256"] == digest))
        with self.assertRaisesRegex(ValueError, "tool objects absent"):
            dependency_readiness(changed, **bindings)

    def test_dependency_receipt_digest_and_duplicate_json_refuse_before_payload_reads(self):
        report, bindings = self.dependency_fixture(available=13, missing=1, unresolved=1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = root / "bundle-receipt.json"
            value = json.dumps(report).encode()
            receipt.write_bytes(value)
            digest = hashlib.sha256(value).hexdigest()
            real_open = os.open
            opened = []
            def recording_open(path, *args, **kwargs):
                opened.append(str(path))
                return real_open(path, *args, **kwargs)
            with patch("codex_sdk_profile.dependency_location", return_value=root), \
                 patch("codex_sdk_profile.trusted_parent", side_effect=lambda _: real_open(root, os.O_RDONLY | os.O_DIRECTORY)), \
                 patch("codex_sdk_profile.os.open", side_effect=recording_open):
                supplied = dict(bindings)
                supplied.pop("receipt_sha256")
                supplied.pop("manifest_sha256")
                with self.assertRaises(SdkDependencyNotReady):
                    validate_dependency_readiness(root, digest, bindings["manifest_sha256"], **supplied)
                self.assertEqual(opened, ["bundle-receipt.json"])
                with self.assertRaisesRegex(ValueError, "receipt digest mismatch"):
                    validate_dependency_readiness(root, "8" * 64, bindings["manifest_sha256"], **supplied)
                value = b'{"schema_version":1,"schema_version":1}'
                receipt.write_bytes(value)
                with self.assertRaises(ValueError):
                    validate_dependency_readiness(root, hashlib.sha256(value).hexdigest(), bindings["manifest_sha256"], **supplied)

    def test_dependency_location_does_not_import_arbitrary_retained_directories(self):
        for base in DEPENDENCY_ROOTS:
            for epoch in ("01234567-1234-1234-1234-0123456789ab", "cache-v2-" + "a" * 64):
                root = base / epoch / DEPENDENCY_SUFFIX
                self.assertEqual(dependency_location(root), root)
                with self.assertRaises(ValueError):
                    dependency_location(root / "nested")
        for root in (Path("/tmp") / DEPENDENCY_SUFFIX, FAST_STATE / "old" / DEPENDENCY_SUFFIX):
            with self.assertRaises(ValueError):
                dependency_location(root)

    def test_command_refuses_partial_dependencies_before_archives_or_argv(self):
        report, bindings = self.dependency_fixture()
        arguments = ("/source", bindings["source_receipt_sha256"], "/bundle", bindings["tool_receipt_sha256"],
                     ARCHIVE_MANIFEST_SHA, "/settings", bindings["settings_receipt_sha256"], "/controller", "core")
        with patch("codex_sdk_profile.validate_source") as source, \
             patch("codex_sdk_profile.validate_archives") as archives, \
             patch("codex_sdk_profile.validate_settings") as settings, \
             patch("codex_sdk_profile._test_arguments") as argv, \
             patch("codex_sdk_profile.validate_dependency_readiness", side_effect=lambda root, digest, manifest, **ties:
                   dependency_readiness(report, receipt_sha256=digest, manifest_sha256=manifest, **ties)):
            with self.assertRaisesRegex(ValueError, "independently selected dependency union required"):
                command_plan(*arguments)
            source.assert_not_called()
            source.return_value = {"complete_inventory_sha256": bindings["source_inventory_sha256"]}
            settings.return_value = ("/locked/tools", "/locked/bash", "7" * 64)
            with self.assertRaises(SdkDependencyNotReady):
                command_plan(*arguments, dependency_root="/dependencies",
                             dependency_receipt_sha256=bindings["receipt_sha256"],
                             dependency_manifest_sha256=bindings["manifest_sha256"])
            settings.assert_called_once_with("/settings", bindings["settings_receipt_sha256"], "/bundle")
            archives.assert_not_called()
            argv.assert_not_called()

    def test_export_policy_checks_bytes_paths_modes_and_preserves_git_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "plain"
            file.write_bytes(b"source")
            file.chmod(0o555)
            root.chmod(0o555)
            expected = {"plain": {"mode": "100644", "sha256": hashlib.sha256(b"source").hexdigest()}}
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(verify_inventory(fd, expected, EXPORT_MODE_POLICY), 6)
                with self.assertRaisesRegex(ValueError, "inventory mismatch"):
                    verify_inventory(fd, expected)  # Strict Git-mode default unchanged.
                file.chmod(0o444)
                with self.assertRaisesRegex(ValueError, "regular mode mismatch"):
                    verify_inventory(fd, expected, EXPORT_MODE_POLICY)
                file.chmod(0o644)
                file.write_bytes(b"altered")
                file.chmod(0o555)
                with self.assertRaisesRegex(ValueError, "inventory mismatch"):
                    verify_inventory(fd, expected, EXPORT_MODE_POLICY)
                file.chmod(0o644)
                file.write_bytes(b"source")
                file.chmod(0o555)
                root.chmod(0o755)
                with self.assertRaisesRegex(ValueError, "directory mode mismatch"):
                    verify_inventory(fd, expected, EXPORT_MODE_POLICY)
                extra = root / "extra"
                extra.write_bytes(b"extra")
                extra.chmod(0o555)
                root.chmod(0o555)
                with self.assertRaisesRegex(ValueError, "inventory mismatch"):
                    verify_inventory(fd, expected, EXPORT_MODE_POLICY)
                root.chmod(0o755)
                extra.unlink()
                file.unlink()
                root.chmod(0o555)
                with self.assertRaisesRegex(ValueError, "inventory mismatch"):
                    verify_inventory(fd, expected, EXPORT_MODE_POLICY)
            finally:
                os.close(fd)
                root.chmod(0o700)

    def test_export_policy_rejects_extra_directory_and_unsafe_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "plain"
            file.write_bytes(b"source")
            file.chmod(0o555)
            extra = root / "empty-extra"
            extra.mkdir(mode=0o555)
            root.chmod(0o555)
            expected = {"plain": {"mode": "100644", "sha256": hashlib.sha256(b"source").hexdigest()}}
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(ValueError, "inventory mismatch"):
                    verify_inventory(fd, expected, EXPORT_MODE_POLICY)
                root.chmod(0o755)
                extra.rmdir()
                (root / "link").symlink_to("../outside")
                expected["link"] = {"mode": "120000", "sha256": hashlib.sha256(b"../outside").hexdigest()}
                root.chmod(0o555)
                with self.assertRaisesRegex(ValueError, "escapes root"):
                    verify_inventory(fd, expected, EXPORT_MODE_POLICY)
            finally:
                os.close(fd)
                root.chmod(0o700)

    def test_only_exact_authorized_home_settings_cache(self):
        self.assertEqual(settings_location(RETAINED_HOME_SETTINGS), RETAINED_HOME_SETTINGS)
        for invalid in (Path(str(RETAINED_HOME_SETTINGS).replace("cache-v2-0263", "cache-v2-1263")),
                        RETAINED_HOME_SETTINGS.parent / "neighbor-settings",
                        RETAINED_HOME_SETTINGS / "nested"):
            with self.assertRaises(ValueError):
                settings_location(invalid)
        # Home authorization is settings-only: source and native output stay fast.
        with self.assertRaises(ValueError):
            epoch_location(RETAINED_HOME_SETTINGS)
        with self.assertRaises(ValueError):
            controller_location(RETAINED_HOME_SETTINGS)

    def test_relocated_creation_path_is_same_epoch_provenance_only(self):
        epoch = FAST_STATE / "cf85bdc6-5de0-4033-a57e-5e8d24301ccb"
        root = epoch / PRODUCER_SUFFIX
        recorded = str(epoch / "output-base/sandbox/processwrapper-sandbox/8/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_fresh_source_producer/test.outputs/codex-adapter-epoch/source")
        # Creation metadata must never cause a filesystem read or resolution.
        with patch("pathlib.Path.resolve", side_effect=AssertionError("recorded path followed")):
            source_provenance(root, recorded)
            source_provenance(root, str(root / "source"))
            for invalid in (recorded.replace("/8/", "/08/"), recorded.replace("/8/", "/../"),
                            recorded.replace("/8/", "/1000000000/"), recorded + "/extra",
                            recorded.replace("cf85bdc6", "af85bdc6")):
                with self.assertRaises(ValueError):
                    source_provenance(root, invalid)

    def test_settings_reject_arbitrary_path_and_blocked_receipt(self):
        with self.assertRaises(ValueError):
            validate_settings(Path("/tmp/settings"), "0" * 64, "/bundle")
        root = FAST_STATE / "01234567-1234-1234-1234-0123456789ab" / SETTINGS_SUFFIX
        with patch("codex_sdk_profile.trusted_parent", return_value=123), \
             patch("codex_sdk_profile.metadata", return_value={"status": "blocked"}), \
             patch("codex_sdk_profile.os.close"), \
             patch("codex_sdk_profile.hash_regular") as payload:
            with self.assertRaisesRegex(ValueError, "authority mismatch"):
                validate_settings(root, "0" * 64, "/bundle")
            payload.assert_not_called()

    def test_controller_and_fixed_status_never_use_git_fallback(self):
        epoch = FAST_STATE / "01234567-1234-1234-1234-0123456789ab"
        self.assertEqual(controller_location(epoch), epoch)
        with self.assertRaises(ValueError):
            controller_location(epoch / "nested")
        value = launcher_contents("/nix/store/" + "a" * 32 + "-bash-5.3/bin/bash")
        self.assertIn(b"printf 'STABLE_GIT_COMMIT ", value)
        self.assertNotIn(b"git ", value)
        with self.assertRaises(ValueError):
            launcher_contents("/bin/bash")

    def test_retained_rc_retains_declared_path_and_refuses_extra_settings(self):
        names = ("bash", "coreutils", "python3", "git", "gawk", "gnugrep", "gnused", "findutils")
        path = ":".join("/nix/store/" + "a" * 32 + "-" + name + "/bin" for name in names)
        rc = ("common --distdir=/verified/bundle\n"
              + "test --test_env=PATH=" + path + "\n").encode()
        self.assertEqual(retained_rc_settings(rc, "/verified/bundle", path), path)
        for altered, expected in ((rc + b"common --remote_executor=remote\n", path),
                                  (rc, None), (rc, path + ":/usr/bin"),
                                  (rc.replace(b"/verified/bundle", b"/tmp/bundle", 1), path)):
            with self.assertRaises(ValueError):
                retained_rc_settings(altered, "/verified/bundle", expected)

    def test_only_exact_fresh_producer_location(self):
        epoch = "01234567-1234-1234-1234-0123456789ab"
        epoch_location(FAST_STATE / epoch / PRODUCER_SUFFIX)
        for root in (Path("/tmp") / epoch / PRODUCER_SUFFIX,
                     FAST_STATE / "cache-old" / PRODUCER_SUFFIX,
                     FAST_STATE / epoch / "source"):
            with self.assertRaises(ValueError):
                epoch_location(root)

    def test_finite_labels_and_resource_flags(self):
        for lane in ("core", "app-server", "protocol"):
            args = _test_arguments(lane, "/declared/bundle")
            self.assertIn("--jobs=1", args)
            self.assertIn("--local_test_jobs=1", args)
            self.assertIn("--lockfile_mode=error", args)
            self.assertEqual(sum(arg.startswith("//") for arg in args), 1)
        with self.assertRaises(ValueError):
            _test_arguments("//...", "/declared/bundle")

    def test_inventory_rejects_added_or_modified_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "fixture"
            file.write_bytes(b"source")
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                expected = {"fixture": {"mode": "100644", "sha256": hashlib.sha256(b"source").hexdigest()}}
                self.assertEqual(verify_inventory(fd, expected), 6)
                file.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "inventory mismatch"):
                    verify_inventory(fd, expected)
                file.write_bytes(b"source")
                (root / "extra").write_bytes(b"extra")
                with self.assertRaisesRegex(ValueError, "inventory mismatch"):
                    verify_inventory(fd, expected)
            finally:
                os.close(fd)

    def test_fifo_and_symlink_payloads_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / "fifo")
            (root / "link").symlink_to("fifo")
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(ValueError):
                    hash_regular(fd, "fifo", 1024)
                with self.assertRaises(OSError):
                    hash_regular(fd, "link", 1024)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
