"""Offline repository byte export and narrow canonical-ID custody predicates."""

import copy
from contextlib import ExitStack, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import codex_dependency_bundle as bundle
import codex_dependency_union as union
import codex_repository_inputs as inputs
import codex_sdk_profile as profile
from codex_sdk_dependencies import CRATE_FACT


def digest(value):
    return hashlib.sha256(value).hexdigest()


def row(value, identity="fixture", kind="cargo-crate", urls=None):
    return {"type": kind, "identity": identity, "sha256": digest(value),
            "urls": urls or ["https://static.crates.io/crates/fixture/fixture-1.crate"]}


def write_cas(root, value):
    selected = root / "content_addressable/sha256" / digest(value)
    selected.mkdir(parents=True, mode=0o700)
    (selected / "file").write_bytes(value)
    (selected / "file").chmod(0o400)


def write_report(root, value):
    raw = bundle.encoded(value)
    (root / "bundle-receipt.json").write_bytes(raw)
    (root / "bundle-receipt.json").chmod(0o400)
    return digest(raw)


def http_fixture(value=b"archive", canonical=None, both=False, rule=None):
    urls = ["https://github.com/fixture/fixture/releases/download/v1/archive.tar.gz",
            "https://mirror.bazel.build/github.com/fixture/fixture/releases/download/v1/archive.tar.gz"]
    attributes = {"sha256": digest(value), "urls": urls}
    if both:
        attributes["url"] = "https://storage.googleapis.com/fixture/archive.tar.gz"
    if canonical is not None:
        attributes["canonical_id"] = canonical
    identity = "moduleExtensions/fixture/general/generatedRepoSpecs/archive"
    lock = {"moduleExtensions": {"fixture": {"general": {"generatedRepoSpecs": {
        "archive": {"repoRuleId": rule or sorted(inputs.HTTP_RULES)[0], "attributes": attributes}}}}}}
    return lock, row(value, identity, "generated-repository-download", urls)


class RepositoryInputsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.monitor = mock.patch.object(union.OutputCustody, "disk_check")
        self.monitor.start()
        self.addCleanup(self.monitor.stop)

    def output(self, name="output"):
        path = self.root / name
        path.mkdir(mode=0o700)
        selected = inputs.RepositoryOutput(path)
        self.addCleanup(selected.close)
        return selected

    def test_http_order_and_explicit_override_use_pinned_space_join(self):
        lock, selected = http_fixture()
        mappings, unsupported = inputs.generated_http_mappings(lock, [selected])
        expected = " ".join(selected["urls"])
        self.assertEqual(mappings[0]["canonical_id"], expected)
        self.assertEqual(mappings[0]["marker"], "id-" + digest(expected.encode()))
        self.assertEqual(unsupported, [])
        lock, selected = http_fixture(canonical="explicit-source-bound-id")
        mappings, _ = inputs.generated_http_mappings(lock, [selected])
        self.assertEqual(mappings[0]["marker"], "id-" + digest(b"explicit-source-bound-id"))
        reversed_row = copy.deepcopy(selected)
        reversed_row["urls"].reverse()
        self.assertEqual(inputs.generated_http_mappings(lock, [reversed_row])[0], [])

    def test_lost_url_attribute_and_custom_or_bcr_callers_get_no_marker(self):
        lock, selected = http_fixture(both=True)
        mappings, unsupported = inputs.generated_http_mappings(lock, [selected])
        self.assertEqual(mappings, [])
        self.assertEqual(unsupported[0]["reason"], "descriptor-lost-actual-URL-order")
        lock, selected = http_fixture(rule="@@custom//:download.bzl%http_archive")
        self.assertEqual(inputs.generated_http_mappings(lock, [selected])[0], [])
        archive = row(b"bcr", "https://bcr.bazel.build/modules/example/1/source.json", "bazel-module-archive")
        self.assertEqual(inputs.generated_http_mappings({}, [archive])[0], [])
        registry = row(b"registry", "https://bcr.bazel.build/modules/example/1/MODULE.bazel", "bazel-registry-file")
        self.assertEqual(inputs.generated_http_mappings({}, [registry]), ([], []))

    def test_wrong_http_digest_and_unsafe_explicit_id_refuse(self):
        lock, selected = http_fixture()
        selected["sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "caller digest"):
            inputs.generated_http_mappings(lock, [selected])
        lock, selected = http_fixture(canonical="unsafe\nidentifier")
        with self.assertRaisesRegex(ValueError, "canonical ID"):
            inputs.generated_http_mappings(lock, [selected])

    def test_export_copies_bytes_and_creates_only_derived_empty_markers(self):
        value = b"archive"
        lock, selected = http_fixture(value)
        mappings, _ = inputs.generated_http_mappings(lock, [selected])
        source = self.root / "archive"
        source.write_bytes(value)
        destination = self.output()
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            destination.copy(fd, selected["sha256"], bundle.Budget())
        finally:
            os.close(fd)
        report = {"objects": {selected["sha256"]: {"bytes": len(value)}}, "http_mappings": mappings,
                  "sdk_compilation_admitted": False}
        receipt = destination.publish_inputs(report)
        item = destination.root_path / "content_addressable/sha256" / selected["sha256"]
        self.assertEqual(set(os.listdir(item)), {"file", mappings[0]["marker"]})
        self.assertEqual((item / "file").read_bytes(), value)
        self.assertEqual((item / mappings[0]["marker"]).read_bytes(), b"")
        self.assertEqual((item / mappings[0]["marker"]).stat().st_mode & 0o777, 0o400)
        self.assertEqual((item / "file").stat().st_nlink, 1)
        self.assertNotEqual((item / "file").stat().st_ino, source.stat().st_ino)
        self.assertEqual(receipt, digest((destination.root_path / "repository-inputs-receipt.json").read_bytes()))

    def test_forged_marker_and_undeclared_entry_refuse(self):
        lock, selected = http_fixture()
        mappings, _ = inputs.generated_http_mappings(lock, [selected])
        mappings[0]["marker"] = "id-" + "0" * 64
        destination = self.output()
        with self.assertRaisesRegex(ValueError, "forged"):
            destination.publish_inputs({"objects": {}, "http_mappings": mappings})
        self.assertFalse((destination.root_path / "repository-inputs-receipt.json").exists())
        other = self.output("other")
        (other.root_path / "ambient-marker").write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "inventory"):
            other.publish_inputs({"objects": {}, "http_mappings": []})

    def test_ancestor_substitution_keeps_foreign_destination_unchanged(self):
        destination = self.output()
        parent = destination.root_path.parent
        retained = parent.with_name("retained")
        parent.rename(retained)
        parent.mkdir(mode=0o700)
        sentinel = parent / "foreign"
        sentinel.write_bytes(b"unchanged")
        with self.assertRaisesRegex(ValueError, "substituted"):
            destination.publish_inputs({"objects": {}, "http_mappings": []})
        self.assertEqual(sentinel.read_bytes(), b"unchanged")
        self.assertEqual(os.listdir(parent), ["foreign"])

    def test_git_dedup_retains_snapshot_and_module_evidence_without_tar_digest(self):
        commit = "a" * 40
        remote = "https://github.com/fixture/project.git"
        source = "git+" + remote + "?rev=" + commit + "#" + commit
        module = 'git_repository = use_repo_rule("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")\n'
        module += 'git_repository(name="fixture", remote="' + remote + '", commit="' + commit + '")\n'
        requirements, unsupported = inputs.git_requirements(
            {"facts": {CRATE_FACT: {source + "_fixture": "{}"}}},
            {"package": [{"source": source}, {"source": source}]}, module)
        self.assertEqual(len(requirements), 1)
        self.assertEqual(len(requirements[0]["evidence"]), 3)
        self.assertEqual(requirements[0]["commit"], commit)
        self.assertIsNone(requirements[0]["archive_sha256"])
        self.assertFalse(requirements[0]["materialized"])
        self.assertEqual(unsupported, [])
        mismatch = source[:-40] + "b" * 40
        requirements, unsupported = inputs.git_requirements({}, {"package": [{"source": mismatch}]}, "")
        self.assertEqual(requirements, [])
        self.assertNotIn(remote, json.dumps(unsupported))

    def test_git_credentials_or_nonliteral_remote_refuse_without_fetch(self):
        commit = "a" * 40
        source = "git+https://credential@github.com/fixture/project?rev=" + commit + "#" + commit
        with self.assertRaisesRegex(ValueError, "public pinned"):
            inputs.git_requirements({}, {"package": [{"source": source}]}, "")
        module = 'git_repository = use_repo_rule("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")\n'
        module += 'git_repository(remote=ambient_remote, commit="' + commit + '")\n'
        with self.assertRaises(ValueError):
            inputs.git_requirements({}, {}, module)

    def fixtures(self):
        """Real retained bytes/receipts; only production source/path pins replaced.

        This exercises the real bundle/shard/tool verification, reconstruction,
        marker derivation and export, without claiming source/SDK qualification.
        """
        module, http = http_fixture()
        registry = row(b"registry", "https://bcr.bazel.build/modules/example/1/MODULE.bazel", "bazel-registry-file",
                       ["https://bcr.bazel.build/modules/example/1/MODULE.bazel"])
        fetched, tool = row(b"fetched", "fetched"), row(b"tool", "tool", "audited-linux-tool-archive")
        descriptors = sorted([http, registry, fetched, tool], key=lambda row: (row["type"], row["identity"]))
        base = {**bundle.COMMON, "status": "offline-dependency-plan", "source_inventory_sha256": "a" * 64,
                "descriptors": descriptors, "derivations": [], "unresolved": [{"type": "cargo-git", "identity": "unmaterialized"}],
                "objects": {http["sha256"]: {"bytes": 7}, registry["sha256"]: {"bytes": 8}}, "missing": [fetched, tool]}
        paths = {name: self.root / name for name in ("legacy", "active", "shard", "tools", "union")}
        for path in paths.values():
            path.mkdir(mode=0o700)
        plan_shas = {}
        for name in ("legacy", "active"):
            for value in (b"archive", b"registry"):
                write_cas(paths[name], value)
            plan_shas[name] = write_report(paths[name], {**base, "fixture_epoch": name})
        active_plan = {**base, "fixture_epoch": "active"}
        shard = {**bundle.COMMON, "status": "verified-missing-object-shard", "source_inventory_sha256": "a" * 64,
                 "parent_plan_sha256": plan_shas["legacy"], "shard_index": 0, "shard_size": 16,
                 "descriptors": [fetched, tool], "objects": {fetched["sha256"]: {"bytes": 7}, tool["sha256"]: {"bytes": 4}},
                 "remaining_missing_objects": 0, "canonical_id_metadata_exported": False, "unresolved": base["unresolved"]}
        for value in (b"fetched", b"tool"):
            write_cas(paths["shard"], value)
        shard_sha = write_report(paths["shard"], shard)
        (paths["tools"] / "tool").write_bytes(b"tool")
        tools_report = {"status": "complete-verified-distdir", "manifest_sha256": inputs.ARCHIVE_MANIFEST_SHA,
                        "missing": [], "native_support": False, "native_proof": False,
                        "verified": [{"name": "tool", "sha256": tool["sha256"], "bytes": 4, "status": "verified-export"}]}
        tools_raw = bundle.encoded(tools_report)
        (paths["tools"] / "receipt.json").write_bytes(tools_raw)
        tools_sha = digest(tools_raw)
        parents = {"plan": plan_shas["legacy"], "active_plan": {"root": str(paths["active"]), "receipt_sha256": plan_shas["active"]},
                   "tools": tools_sha, "tools_manifest": inputs.ARCHIVE_MANIFEST_SHA,
                   "shards": [{"root": str(paths["shard"]), "receipt_sha256": shard_sha,
                               "parent_plan_sha256": plan_shas["legacy"], "shard_index": 0, "shard_size": 16}]}
        report = {**bundle.COMMON, "schema_version": 2, "status": "verified-finite-dependency-union",
                  "source_inventory_sha256": "a" * 64, "parent_receipts": parents, "descriptors": descriptors,
                  "derivations": [], "unresolved": base["unresolved"], "missing": [], "ambient_cache_read": False,
                  "canonical_id_metadata_exported": False}
        report["objects"] = {digest(value): {"bytes": len(value)} for value in (b"archive", b"registry", b"fetched", b"tool")}
        report["object_origins"] = {http["sha256"]: [plan_shas["legacy"], plan_shas["active"]],
            registry["sha256"]: [plan_shas["legacy"], plan_shas["active"]], fetched["sha256"]: [shard_sha],
            tool["sha256"]: [shard_sha, tools_sha]}
        report["counts"] = {"input_objects": 7, "unique_objects": 4, "duplicate_objects": 3,
                            "missing_objects": 0, "missing_by_type": {}, "unresolved_rows": 1, "unresolved_by_type": {"cargo-git": 1}}
        for value in (b"archive", b"registry", b"fetched", b"tool"):
            write_cas(paths["union"], value)
        union_sha = write_report(paths["union"], report)
        output = self.root / "materialized"
        output.mkdir(mode=0o700)
        options = {"plan_root": paths["active"], "plan_sha256": plan_shas["active"], "union_root": paths["union"],
                   "union_sha256": union_sha, "parent_receipts": parents, "source_receipt_sha256": inputs.SOURCE_RECEIPT_SHA,
                   "descriptor_sha256": inputs.DESCRIPTOR_SHA, "output_parent": output}
        patches = ExitStack()
        self.addCleanup(patches.close)
        for name, value in (("ACTIVE_PLAN_ROOT", paths["active"]), ("ACTIVE_PLAN_SHA", plan_shas["active"]),
                            ("PLAN_ROOT", paths["legacy"]), ("PLAN_SHA", plan_shas["legacy"]),
                            ("TOOLS_ROOT", paths["tools"]), ("TOOLS_SHA", tools_sha)):
            patches.enter_context(mock.patch.object(inputs, name, value))
        patches.enter_context(mock.patch.object(union, "SHARD_ROOT", paths["shard"]))
        patches.enter_context(mock.patch.object(union, "SHARD_SHA", shard_sha))
        patches.enter_context(mock.patch.object(bundle, "retained_location"))
        patches.enter_context(mock.patch.object(inputs, "dependency_location", side_effect=lambda path: path))
        patches.enter_context(mock.patch.object(inputs, "authority", return_value=({"artifacts": descriptors}, "a" * 64)))
        patches.enter_context(mock.patch.object(inputs, "source_graph", return_value=(module, {"package": []}, "")))
        patches.enter_context(mock.patch.object(inputs, "validate_source"))
        patches.enter_context(mock.patch.object(inputs, "read_tools", side_effect=lambda fd, checksum, budget, *, on_read=None:
            union.read_tools(fd, checksum, budget, archives=[("tool", tool["sha256"], "fixture")], on_read=on_read)))
        return options, paths, report, active_plan

    def test_actual_materialization_reverifies_parents_bytes_and_keeps_admission_false(self):
        options, paths, report, _ = self.fixtures()
        before = (paths["union"] / "bundle-receipt.json").read_bytes()
        result, checksum = inputs.materialize(**options)
        cache = Path(result["cache_root"])
        self.assertEqual(result["objects"], report["objects"])
        self.assertEqual(len(result["http_mappings"]), 1)
        self.assertEqual(result["missing"], [])
        self.assertFalse(result["sdk_compilation_admitted"])
        self.assertFalse(result["all_canonical_ids_proved"])
        self.assertFalse(result["git_materialization_proved"])
        self.assertGreater(result["read_bytes_accounted"], sum(row["bytes"] for row in report["objects"].values()))
        self.assertLess(result["read_bytes_accounted"], 1024 * 1024)
        self.assertEqual(checksum, digest((cache / "repository-inputs-receipt.json").read_bytes()))
        self.assertEqual((paths["union"] / "bundle-receipt.json").read_bytes(), before)
        for selected, record in report["objects"].items():
            copied = cache / "content_addressable/sha256" / selected / "file"
            self.assertEqual(copied.stat().st_size, record["bytes"])
            self.assertEqual(digest(copied.read_bytes()), selected)

    def test_changed_shard_payload_refuses_before_output(self):
        options, paths, _, _ = self.fixtures()
        payload = paths["shard"] / "content_addressable/sha256" / digest(b"fetched") / "file"
        payload.chmod(0o600)
        payload.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            inputs.materialize(**options)
        self.assertEqual(os.listdir(options["output_parent"]), [])

    def test_changed_union_length_or_parent_selection_refuses_before_output(self):
        options, paths, report, _ = self.fixtures()
        report["objects"][digest(b"archive")]["bytes"] += 1
        # This test owns the private sealed fixture, not a retained parent.
        # Reopen its mode deliberately before rewriting the negative input;
        # write_report reseals it to 0400 before production verification.
        (paths["union"] / "bundle-receipt.json").chmod(0o600)
        options["union_sha256"] = write_report(paths["union"], report)
        self.assertEqual((paths["union"] / "bundle-receipt.json").stat().st_mode & 0o777, 0o400)
        with self.assertRaisesRegex(ValueError, "reconstruction"):
            inputs.materialize(**options)
        self.assertEqual(os.listdir(options["output_parent"]), [])
        changed = copy.deepcopy(options["parent_receipts"])
        changed["shards"][0]["shard_size"] = 15
        options["parent_receipts"] = changed
        with self.assertRaisesRegex(ValueError, "authority|selection"):
            inputs.materialize(**options)
        self.assertEqual(os.listdir(options["output_parent"]), [])

    def test_wrong_raw_plan_pin_and_foreign_union_location_refuse_early(self):
        with mock.patch.object(inputs, "authority") as authority:
            with self.assertRaisesRegex(ValueError, "selection"):
                inputs.materialize(plan_root=inputs.ACTIVE_PLAN_ROOT, plan_sha256="0" * 64,
                    union_root=self.root, union_sha256="b" * 64, parent_receipts={},
                    source_receipt_sha256=inputs.SOURCE_RECEIPT_SHA, descriptor_sha256=inputs.DESCRIPTOR_SHA,
                    output_parent=self.root)
            authority.assert_not_called()
        with self.assertRaisesRegex(ValueError, "undeclared"):
            inputs.dependency_location(self.root)

    def test_source_callback_forwarding_and_postpass_deadline(self):
        budget = bundle.Budget()
        budget.deadline = 0
        with mock.patch.object(inputs, "validate_source") as validation:
            with self.assertRaisesRegex(ValueError, "deadline"):
                inputs.bounded_source_validation(budget)
            validation.assert_not_called()
        budget = bundle.Budget()
        def expired(*args, on_read=None):
            on_read(7)
            budget.deadline = 0
        with mock.patch.object(inputs, "validate_source", side_effect=expired):
            with self.assertRaisesRegex(ValueError, "deadline"):
                inputs.bounded_source_validation(budget)
        self.assertEqual(budget.read_bytes, 7)

    def test_exact_profile_file_and_metadata_callbacks_preserve_default_results(self):
        raw = b'{"fixture":true}\n'
        (self.root / "metadata.json").write_bytes(raw)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        default = profile.hash_regular(fd, "metadata.json", 1024, True)
        chunks = []
        counted = profile.hash_regular(fd, "metadata.json", 1024, True, on_read=chunks.append)
        self.assertEqual(default, counted)
        self.assertEqual(sum(chunks), len(raw))
        self.assertIn(0, chunks)
        chunks.clear()
        self.assertEqual(profile.metadata(fd, "metadata.json", digest(raw), on_read=chunks.append), {"fixture": True})
        self.assertEqual(sum(chunks), len(raw))
        budget = bundle.Budget()
        # Real metadata reads charge bytes, never the 1024-byte admission limit.
        profile.hash_regular(fd, "metadata.json", 1024, on_read=budget.tick)
        self.assertEqual(budget.read_bytes, len(raw))

    def test_chunk_budget_refusal_closes_file_before_another_read(self):
        (self.root / "large").write_bytes(b"x" * (1024 * 1024 + 32))
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, directory)
        budget = bundle.Budget()
        budget.read_bytes = bundle.MAX_BYTES - 1
        opened, original_open = [], os.open
        def capture(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            opened.append(fd)
            return fd
        with mock.patch.object(profile.os, "open", side_effect=capture), mock.patch.object(profile.os, "read", wraps=os.read) as read:
            with self.assertRaisesRegex(ValueError, "read budget"):
                profile.hash_regular(directory, "large", 2 * 1024 * 1024, on_read=budget.tick)
            self.assertEqual(read.call_count, 1)
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])

    def test_inventory_counts_regular_and_symlink_bytes_and_ticks_nodes(self):
        source = self.root / "source"
        source.mkdir(mode=0o700)
        (source / "file").write_bytes(b"native")
        (source / "link").symlink_to("file")
        expected = {"file": {"mode": "100644", "sha256": digest(b"native")},
                    "link": {"mode": "120000", "sha256": digest(b"file")}}
        fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        chunks = []
        self.assertEqual(profile.verify_inventory(fd, expected, on_read=chunks.append), 10)
        self.assertEqual(sum(chunks), 10)
        self.assertGreater(chunks.count(0), len(expected))
        ticks = 0
        def expires_during_walk(count):
            nonlocal ticks
            if count == 0:
                ticks += 1
                if ticks == 5:
                    raise ValueError("deadline")
        with self.assertRaisesRegex(ValueError, "deadline"):
            profile.verify_inventory(fd, expected, on_read=expires_during_walk)

    @staticmethod
    def arguments(options):
        result = []
        for name in ("plan_root", "plan_sha256", "union_root", "union_sha256", "source_receipt_sha256", "descriptor_sha256"):
            result.extend(["--" + name.replace("_", "-"), str(options[name])])
        result.extend(["--parent-receipts-json", json.dumps(options["parent_receipts"])])
        return result

    def assert_refusal(self, arguments, phase, category):
        diagnostic = io.StringIO()
        with redirect_stderr(diagnostic), self.assertRaises(inputs.ExportRefusal) as refused:
            inputs.main(arguments)
        self.assertEqual((refused.exception.phase, refused.exception.category), (phase, category))
        self.assertEqual(str(refused.exception), inputs.refusal_message(phase, category))
        self.assertTrue(refused.exception.__suppress_context__)
        self.assertEqual(diagnostic.getvalue(), "")
        self.assertNotIn("diagnostic-fixture-private-value", str(refused.exception))
        return refused.exception

    def test_main_argument_errors_never_echo_unknown_argv(self):
        with mock.patch.object(inputs, "materialize") as export:
            self.assert_refusal(["--unknown", "diagnostic-fixture-private-value"], "entry-arguments", "argument-shape")
            export.assert_not_called()

    def test_main_fixed_type_categories_discard_all_original_error_bodies(self):
        options, _, _, _ = self.fixtures()
        cases = [(PermissionError(13, "diagnostic-fixture-private-value"), "permission"),
                 (FileNotFoundError(2, "diagnostic-fixture-private-value"), "missing-input"),
                 (NotADirectoryError(20, "diagnostic-fixture-private-value"), "path-type"),
                 (IsADirectoryError(21, "diagnostic-fixture-private-value"), "path-type"),
                 (FileExistsError(17, "diagnostic-fixture-private-value"), "occupied-output"),
                 (OSError("diagnostic-fixture-private-value"), "io"),
                 (ValueError("diagnostic-fixture-private-value"), "contract"),
                 (KeyError("diagnostic-fixture-private-value"), "schema"),
                 (TypeError("diagnostic-fixture-private-value"), "schema"),
                 (RecursionError("diagnostic-fixture-private-value"), "schema"),
                 (SyntaxError("diagnostic-fixture-private-value"), "source-syntax")]
        with mock.patch.dict(os.environ, {"OMUX_EXECUTION_GUARD": "fixture", "TEST_UNDECLARED_OUTPUTS_DIR": str(options["output_parent"])}):
            for error, category in cases:
                with self.subTest(category=category, error_type=type(error).__name__):
                    def fail(**kwargs):
                        kwargs["_on_phase"]("caller-mappings")
                        raise error
                    with mock.patch.object(inputs, "materialize", side_effect=fail):
                        self.assert_refusal(self.arguments(options), "caller-mappings", category)
        self.assertEqual(os.listdir(options["output_parent"]), [])

    def test_main_real_wrong_pin_identifies_selection_without_export(self):
        options, _, _, _ = self.fixtures()
        options["plan_sha256"] = "0" * 64
        with mock.patch.dict(os.environ, {"OMUX_EXECUTION_GUARD": "fixture", "TEST_UNDECLARED_OUTPUTS_DIR": str(options["output_parent"])}):
            self.assert_refusal(self.arguments(options), "selected-authority", "contract")
        self.assertEqual(os.listdir(options["output_parent"]), [])

    def test_main_real_changed_parent_identifies_union_parent_stage(self):
        options, paths, _, _ = self.fixtures()
        payload = paths["shard"] / "content_addressable/sha256" / digest(b"fetched") / "file"
        payload.chmod(0o600)
        payload.write_bytes(b"changed")
        with mock.patch.dict(os.environ, {"OMUX_EXECUTION_GUARD": "fixture", "TEST_UNDECLARED_OUTPUTS_DIR": str(options["output_parent"])}):
            self.assert_refusal(self.arguments(options), "union-parents", "contract")
        self.assertEqual(os.listdir(options["output_parent"]), [])

    def test_main_real_occupied_output_identifies_custody_without_overwrite(self):
        options, _, _, _ = self.fixtures()
        sentinel = options["output_parent"] / "sentinel"
        sentinel.write_bytes(b"unchanged")
        with mock.patch.dict(os.environ, {"OMUX_EXECUTION_GUARD": "fixture", "TEST_UNDECLARED_OUTPUTS_DIR": str(options["output_parent"])}):
            self.assert_refusal(self.arguments(options), "output-custody", "contract")
        self.assertEqual(os.listdir(options["output_parent"]), ["sentinel"])
        self.assertEqual(sentinel.read_bytes(), b"unchanged")

    def test_main_real_missing_union_root_closes_already_open_plan(self):
        options, _, _, _ = self.fixtures()
        options["union_root"] = self.root / "absent-union"
        opened, original = [], inputs.trusted_parent
        def capture(path):
            fd = original(path)
            if Path(path) == options["plan_root"]:
                opened.append(fd)
            return fd
        with mock.patch.object(inputs, "trusted_parent", side_effect=capture), mock.patch.dict(os.environ,
                {"OMUX_EXECUTION_GUARD": "fixture", "TEST_UNDECLARED_OUTPUTS_DIR": str(options["output_parent"])}):
            self.assert_refusal(self.arguments(options), "union-receipt", "missing-input")
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])
        self.assertEqual(os.listdir(options["output_parent"]), [])

    def test_main_real_deep_parent_array_refuses_schema_without_export(self):
        options, _, _, _ = self.fixtures()
        arguments = self.arguments(options)
        depth = sys.getrecursionlimit() + 64
        self.assertLess(depth, 100000)
        arguments[-1] = "[" * depth + '"diagnostic-fixture-private-value"' + "]" * depth
        # A decoder may accept this depth. Either decoding refuses or the
        # decoded array is refused at the parent-object schema boundary.
        # This case does not establish a real decoder RecursionError.
        with mock.patch.object(inputs, "materialize", side_effect=AssertionError("unexpected export")) as export, mock.patch.dict(os.environ,
                {"OMUX_EXECUTION_GUARD": "fixture", "TEST_UNDECLARED_OUTPUTS_DIR": str(options["output_parent"])}):
            self.assert_refusal(arguments, "entry-context", "schema")
            export.assert_not_called()
        self.assertEqual(os.listdir(options["output_parent"]), [])

    def test_main_real_parent_json_syntax_duplicate_and_top_level_types_refuse_before_export(self):
        options, _, _, _ = self.fixtures()
        for raw in ('{"fixture":', '{"fixture":1,"fixture":2}', '[]', 'null', 'true', '"diagnostic-fixture-private-value"'):
            with self.subTest(raw_type=raw[:1]):
                arguments = self.arguments(options)
                arguments[-1] = raw
                with mock.patch.object(inputs, "materialize", side_effect=AssertionError("unexpected export")) as export, mock.patch.dict(os.environ,
                        {"OMUX_EXECUTION_GUARD": "fixture", "TEST_UNDECLARED_OUTPUTS_DIR": str(options["output_parent"])}):
                    self.assert_refusal(arguments, "entry-context", "schema")
                    export.assert_not_called()
        self.assertEqual(os.listdir(options["output_parent"]), [])

    def test_parent_json_boundary_classifies_controlled_decoder_failures_only_as_schema(self):
        options, _, _, _ = self.fixtures()
        for error in (ValueError("diagnostic-fixture-private-value"), TypeError("diagnostic-fixture-private-value"),
                      RecursionError("diagnostic-fixture-private-value")):
            with self.subTest(error_type=type(error).__name__):
                with mock.patch.object(inputs.json, "loads", side_effect=error), mock.patch.object(inputs, "materialize", side_effect=AssertionError("unexpected export")) as export, mock.patch.dict(os.environ,
                        {"OMUX_EXECUTION_GUARD": "fixture", "TEST_UNDECLARED_OUTPUTS_DIR": str(options["output_parent"])}):
                    self.assert_refusal(self.arguments(options), "entry-context", "schema")
                    export.assert_not_called()
        self.assertEqual(os.listdir(options["output_parent"]), [])


if __name__ == "__main__":
    unittest.main()
