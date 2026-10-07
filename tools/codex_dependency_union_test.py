"""Finite union provenance, independent reads and refusal predicates; offline."""

import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import codex_dependency_union as union
from codex_dependency_bundle import Budget, HASH, inventory


def row(value, identity="fixture", kind="cargo-crate"):
    return {"type": kind, "identity": identity, "sha256": hashlib.sha256(value).hexdigest(),
            "urls": ["https://static.crates.io/crates/fixture/fixture-1.crate"]}


def cas_object(root, selected, value):
    parent = root / "content_addressable/sha256" / selected["sha256"]
    parent.mkdir(parents=True, mode=0o700)
    path = parent / "file"
    path.write_bytes(value)
    path.chmod(0o400)
    return path


class UnionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.monitor = mock.patch.object(union.OutputCustody, "disk_check")
        self.monitor.start()
        self.addCleanup(self.monitor.stop)

    def sources(self, value=b"shared"):
        plan_root, shard_root, tools_root = [self.root / name for name in ("plan", "shard", "tools")]
        for path in (plan_root, shard_root, tools_root):
            path.mkdir(mode=0o700)
        common, fetched, tool, missing = (row(value), row(b"fetched", "fetched", "bazel-module-archive"),
            row(b"tool", "tool", "audited-linux-tool-archive"), row(b"missing", "missing"))
        common_path = cas_object(plan_root, common, value)
        fetched_path = cas_object(shard_root, fetched, b"fetched")
        (tools_root / "common-tool").write_bytes(value)
        (tools_root / "new-tool").write_bytes(b"tool")
        plan = {"source_inventory_sha256": "a" * 64, "descriptors": [common, fetched, tool, missing],
                "missing": [fetched, tool, missing], "derivations": [],
                "unresolved": [{"type": "cargo-git", "identity": "still-unresolved"},
                               {"type": "dynamic-repository-closure", "identity": "SDK Bazel graph"}]}
        descriptors = [os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                       for path in (plan_root, shard_root, tools_root)]
        for descriptor in descriptors:
            self.addCleanup(os.close, descriptor)
        sources = [("cas", descriptors[0], {common["sha256"]: {"bytes": len(value)}}, "b" * 64),
            ("cas", descriptors[1], {fetched["sha256"]: {"bytes": 7}}, "c" * 64),
            ("tools", descriptors[2], {common["sha256"]: {"bytes": len(value), "name": "common-tool"},
                tool["sha256"]: {"bytes": 4, "name": "new-tool"}}, "d" * 64)]
        return plan, sources, (common_path, fetched_path, tools_root)

    def destination(self):
        path = self.root / "output"
        path.mkdir(mode=0o700)
        custody = union.OutputCustody(path)
        self.addCleanup(custody.close)
        return custody

    def test_exact_union_deduplicates_and_preserves_remaining_unknowns_and_inputs(self):
        plan, sources, paths = self.sources()
        before = [(path.stat().st_ino, path.read_bytes(), path.stat().st_mode) for path in paths[:2]]
        destination = self.destination()
        parents = {"plan": "b" * 64, "shard": "c" * 64, "tools": "d" * 64}
        result = union.assemble(plan, sources, destination, Budget(), parents)
        self.assertEqual(result["counts"]["input_objects"], 4)
        self.assertEqual(result["counts"]["unique_objects"], 3)
        self.assertEqual(result["counts"]["duplicate_objects"], 1)
        self.assertEqual(result["counts"]["missing_objects"], 1)
        self.assertEqual(result["counts"]["missing_by_type"], {"cargo-crate": 1})
        self.assertEqual(result["counts"]["unresolved_rows"], 2)
        self.assertEqual(result["unresolved"], plan["unresolved"])
        self.assertEqual(result["parent_receipts"], parents)
        self.assertEqual(result["schema_version"], 1)
        self.assertFalse(result["closure_proved"])
        self.assertFalse(result["offline_analysis_proved"])
        self.assertFalse(result["canonical_id_metadata_exported"])
        self.assertFalse(result["ambient_cache_read"])
        common_digest = hashlib.sha256(b"shared").hexdigest()
        self.assertEqual(result["object_origins"][common_digest], ["b" * 64, "d" * 64])
        copied = destination.root_path / "content_addressable/sha256" / common_digest / "file"
        self.assertNotEqual(copied.stat().st_ino, paths[0].stat().st_ino)
        self.assertEqual(copied.stat().st_nlink, 1)
        self.assertEqual(copied.stat().st_mode & 0o777, 0o400)
        for expected, path in zip(before, paths[:2]):
            self.assertEqual(expected, (path.stat().st_ino, path.read_bytes(), path.stat().st_mode))
        digest = destination.publish(result)
        self.assertTrue(HASH.fullmatch(digest))
        inventory(destination.root_fd, result["objects"])

    def test_ancestor_replacement_refuses_without_writing_replacement(self):
        parent = self.root / "ancestor"
        parent.mkdir(mode=0o700)
        output = parent / "output"
        output.mkdir(mode=0o700)
        custody = union.OutputCustody(output)
        self.addCleanup(custody.close)
        retained = self.root / "retained-ancestor"
        parent.rename(retained)
        parent.mkdir(mode=0o700)
        replacement = parent / "output"
        replacement.mkdir(mode=0o700)
        sentinel = replacement / "sentinel"
        sentinel.write_bytes(b"unchanged")
        with self.assertRaisesRegex(ValueError, "ancestor"):
            custody.publish({"objects": {}})
        self.assertEqual(list(replacement.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b"unchanged")
        self.assertFalse((retained / "output/codex-sdk-dependency-union/bundle-receipt.json").exists())

    def test_ancestor_swap_between_check_and_create_cannot_redirect_mkdir(self):
        custody = self.destination()
        output = custody.root_path.parent
        retained = self.root / "retained-output"
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        original = os.mkdir
        digest = hashlib.sha256(b"fixture").hexdigest()
        def swap(name, mode=0o777, *, dir_fd=None):
            if name == digest:
                output.rename(retained)
                output.symlink_to(outside, target_is_directory=True)
            return original(name, mode=mode, dir_fd=dir_fd)
        with mock.patch.object(union.os, "mkdir", side_effect=swap):
            with self.assertRaisesRegex(ValueError, "ancestor"):
                custody.mkdir(custody.cas_fd, digest)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue((retained / "codex-sdk-dependency-union/content_addressable/sha256" / digest).is_dir())
        self.assertFalse((retained / "codex-sdk-dependency-union/content_addressable/sha256" / digest / "file").exists())

    def test_digest_directory_swap_refuses_without_outside_payload_write(self):
        custody = self.destination()
        digest = hashlib.sha256(b"fixture").hexdigest()
        parent_fd = custody.mkdir(custody.cas_fd, digest)
        leaf = custody.root_path / "content_addressable/sha256" / digest
        retained = leaf.with_name("retained")
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        leaf.rename(retained)
        leaf.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "directory substituted"):
            custody._create_file(parent_fd, "file")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(list(retained.iterdir()), [])

    def test_leaf_swap_during_copy_keeps_outside_file_unchanged(self):
        custody = self.destination()
        value = b"fixture"
        digest = hashlib.sha256(value).hexdigest()
        source = self.root / "source"
        source.write_bytes(value)
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        self.addCleanup(os.close, fd)
        outside = self.root / "outside-file"
        outside.write_bytes(b"unchanged")
        original = os.write
        replaced = False
        def swap(output_fd, data):
            nonlocal replaced
            if not replaced:
                replaced = True
                leaf = custody.root_path / "content_addressable/sha256" / digest / "file"
                leaf.rename(leaf.with_name("retained-file"))
                leaf.symlink_to(outside)
            return original(output_fd, data)
        with mock.patch.object(union.os, "write", side_effect=swap):
            with self.assertRaisesRegex(ValueError, "active file substituted"):
                custody.copy(fd, digest, Budget())
        self.assertEqual(outside.read_bytes(), b"unchanged")
        self.assertFalse((custody.root_path / "bundle-receipt.json").exists())

    def test_receipt_creation_race_cannot_write_replacement_namespace(self):
        custody = self.destination()
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        original = os.open
        retained = self.root / "retained-root"
        def swap(name, flags, mode=0o777, *, dir_fd=None):
            if name == "bundle-receipt.json":
                custody.root_path.rename(retained)
                custody.root_path.symlink_to(outside, target_is_directory=True)
            return original(name, flags, mode, dir_fd=dir_fd)
        with mock.patch.object(union.os, "open", side_effect=swap):
            with self.assertRaisesRegex(ValueError, "directory substituted"):
                custody.publish({"objects": {}})
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual((retained / "bundle-receipt.json").read_bytes(), b"")

    def test_published_file_substitution_and_chmod_are_detected(self):
        plan, sources, _ = self.sources()
        custody = self.destination()
        result = union.assemble(plan, sources, custody, Budget(), {})
        first = next(iter(result["objects"]))
        leaf = custody.root_path / "content_addressable/sha256" / first / "file"
        leaf.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "file substituted"):
            custody.publish(result)
        self.assertFalse((custody.root_path / "bundle-receipt.json").exists())

    def test_duplicate_source_is_rehashed_instead_of_trusting_prior_digest(self):
        plan, sources, paths = self.sources()
        (paths[2] / "common-tool").write_bytes(b"tamper")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            union.assemble(plan, sources, self.destination(), Budget(), {})

    def test_duplicate_length_unselected_digest_and_symlink_refuse(self):
        for reason in ("length", "unselected", "symlink"):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temporary:
                old_root = self.root
                self.root = Path(temporary)
                try:
                    plan, sources, paths = self.sources()
                    duplicate = hashlib.sha256(b"shared").hexdigest()
                    if reason == "length":
                        sources[2][2][duplicate]["bytes"] = 5
                    elif reason == "unselected":
                        plan["descriptors"] = plan["descriptors"][1:]
                    else:
                        path = paths[2] / "common-tool"
                        path.unlink()
                        path.symlink_to(paths[0])
                    with self.assertRaises((ValueError, OSError)):
                        union.assemble(plan, sources, self.destination(), Budget(), {})
                finally:
                    self.root = old_root

    def test_first_shard_must_match_actual_parent_and_selected_rows(self):
        rows = [row(str(index).encode(), str(index)) for index in range(17)]
        plan = {"descriptors": rows, "missing": rows, "objects": {},
                "source_inventory_sha256": "a" * 64, "unresolved": []}
        shard = {"parent_plan_sha256": "b" * 64, "source_inventory_sha256": "a" * 64,
                 "shard_index": 0, "shard_size": 16, "descriptors": rows[:16],
                 "objects": {entry["sha256"]: {"bytes": 1} for entry in rows[:16]},
                 "remaining_missing_objects": 1, "unresolved": [], "canonical_id_metadata_exported": False}
        union.verify_shard(plan, shard, "b" * 64)
        for key, replacement in (("parent_plan_sha256", "c" * 64), ("shard_index", 1),
                                 ("shard_size", 15), ("descriptors", rows[1:17]),
                                 ("unresolved", [{"type": "cargo-git"}]),
                                 ("canonical_id_metadata_exported", True),
                                 ("remaining_missing_objects", 0)):
            changed = copy.deepcopy(shard)
            changed[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                union.verify_shard(plan, changed, "b" * 64)

    @staticmethod
    def binding(number, index="1", size="16", digest=None):
        root = union.ROOTS[1] / (f"{number:08x}-0000-0000-0000-000000000000/" + union.SUFFIX
                                + "codex_dependency_bundle_producer/test.outputs/codex-dependency-bundle")
        return [str(root), digest or hashlib.sha256(str(number).encode()).hexdigest(), index, size]

    def test_multiple_bindings_preserve_first16_and_exact_metadata(self):
        entry = self.binding(1)
        bindings = union.shard_bindings(SimpleNamespace(input_shard=[entry]))
        self.assertEqual(bindings, [(union.SHARD_ROOT, union.SHARD_SHA, 0, 16),
                                   (Path(entry[0]), entry[1], 1, 16)])
        parents = union.parent_metadata(bindings)
        self.assertEqual(parents["plan"], union.PLAN_SHA)
        self.assertEqual(parents["tools"], union.TOOLS_SHA)
        self.assertEqual(parents["tools_manifest"], union.ARCHIVE_MANIFEST_SHA)
        self.assertEqual(parents["shards"][0], {"root": str(union.SHARD_ROOT),
            "receipt_sha256": union.SHARD_SHA, "shard_index": 0, "shard_size": 16})
        self.assertEqual(parents["shards"][1], {"root": entry[0], "receipt_sha256": entry[1],
                                                "shard_index": 1, "shard_size": 16})
        original = union.parent_metadata(union.shard_bindings(SimpleNamespace(input_shard=[])))
        self.assertEqual(set(original), {"plan", "shard", "tools", "tools_manifest"})
        self.assertEqual(original["shard"], union.SHARD_SHA)

    def test_binding_bounds_duplicates_noncanonical_and_wrong_producers_refuse(self):
        valid = [self.binding(index, str(index)) for index in range(1, 32)]
        self.assertEqual(len(union.shard_bindings(SimpleNamespace(input_shard=valid))), 32)
        changes = [valid + [self.binding(32, "32")], [self.binding(1), self.binding(1, "2")],
                   [self.binding(1), self.binding(2, "2", digest=self.binding(1)[1])],
                   [self.binding(1), self.binding(2)], [self.binding(1, "0")],
                   [self.binding(1, "01")], [self.binding(1, "-1")],
                   [self.binding(1, "30000")], [self.binding(1, size="65")],
                   [self.binding(1, size="0")], [self.binding(1, digest="0" * 64)],
                   [self.binding(1, digest=union.TOOLS_SHA)], [self.binding(1)[:3]]]
        arbitrary = self.binding(1)
        arbitrary[0] = str(self.root)
        changes.append([arbitrary])
        for replacement in ("codex_dependency_bundle_plan", "codex_dependency_union_producer",
                            "home_manager_acquisition_producer"):
            wrong = self.binding(1)
            wrong[0] = wrong[0].replace("codex_dependency_bundle_producer", replacement)
            changes.append([wrong])
        lexical = self.binding(1)
        lexical[0] = lexical[0].replace("/test.outputs/", "/test.outputs/../test.outputs/")
        changes.append([lexical])
        for entries in changes:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                union.shard_bindings(SimpleNamespace(input_shard=entries))

    def test_successor_shard_selection_is_independent_of_receipt_claims(self):
        rows = [row(str(index).encode(), str(index)) for index in range(35)]
        plan = {"descriptors": rows, "missing": rows, "objects": {},
                "source_inventory_sha256": "a" * 64, "unresolved": [{"type": "cargo-git"}]}
        shard = {"parent_plan_sha256": "b" * 64, "source_inventory_sha256": "a" * 64,
                 "shard_index": 1, "shard_size": 16, "descriptors": rows[16:32],
                 "objects": {entry["sha256"]: {"bytes": 2} for entry in rows[16:32]},
                 "remaining_missing_objects": 19, "unresolved": plan["unresolved"],
                 "canonical_id_metadata_exported": False}
        union.verify_shard(plan, shard, "b" * 64, 1, 16)
        with self.assertRaises(ValueError):
            union.verify_shard(plan, shard, "b" * 64, 0, 16)
        swapped = copy.deepcopy(shard)
        swapped["descriptors"] = rows[0:16]
        swapped["objects"] = {entry["sha256"]: {"bytes": 2} for entry in rows[0:16]}
        with self.assertRaises(ValueError):
            union.verify_shard(plan, swapped, "b" * 64, 1, 16)

    def test_successor_union_rehashes_overlap_and_recomputes_missing_partition(self):
        plan, sources, _ = self.sources()
        extra = self.root / "extra-shard"
        extra.mkdir(mode=0o700)
        fetched, missing = plan["descriptors"][1], plan["descriptors"][3]
        cas_object(extra, fetched, b"fetched")
        payload = cas_object(extra, missing, b"missing")
        fd = os.open(extra, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        sources.insert(2, ("cas", fd, {fetched["sha256"]: {"bytes": 7},
                                     missing["sha256"]: {"bytes": 7}}, "e" * 64))
        parents = {"plan": "b" * 64, "tools": "d" * 64, "tools_manifest": "f" * 64,
                   "shards": [{"receipt_sha256": "c" * 64, "shard_index": 0, "shard_size": 1},
                              {"receipt_sha256": "e" * 64, "shard_index": 1, "shard_size": 2}]}
        custody = self.destination()
        result = union.assemble(plan, sources, custody, Budget(), parents)
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["counts"]["input_objects"], 6)
        self.assertEqual(result["counts"]["unique_objects"], 4)
        self.assertEqual(result["counts"]["duplicate_objects"], 2)
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["unresolved"], plan["unresolved"])
        self.assertEqual(result["object_origins"][fetched["sha256"]], ["c" * 64, "e" * 64])
        self.assertEqual(result["parent_receipts"], parents)
        for key in ("closure_proved", "offline_analysis_proved", "native_support",
                    "provider_evaluation", "canonical_id_metadata_exported"):
            self.assertIs(result[key], False)
        custody.publish(result)
        self.assertEqual(payload.read_bytes(), b"missing")
        # Corrupt only the overlapping second-shard source; an earlier verified
        # source cannot conceal it, and no successful receipt is published.
        (extra / "content_addressable/sha256" / fetched["sha256"] / "file").chmod(0o600)
        (extra / "content_addressable/sha256" / fetched["sha256"] / "file").write_bytes(b"tamper!")
        fresh = self.root / "fresh-output"
        fresh.mkdir(mode=0o700)
        other = union.OutputCustody(fresh)
        self.addCleanup(other.close)
        with self.assertRaisesRegex(ValueError, "digest differs"):
            union.assemble(plan, sources, other, Budget(), parents)
        self.assertFalse((other.root_path / "bundle-receipt.json").exists())

    def test_source_receipt_duplicates_refuse_before_export(self):
        plan, sources, _ = self.sources()
        sources.insert(2, sources[1])
        custody = self.destination()
        with self.assertRaisesRegex(ValueError, "duplicate source"):
            union.assemble(plan, sources, custody, Budget(), {})
        self.assertEqual(os.listdir(custody.cas_fd), [])

    def test_source_count_bound_refuses_before_export(self):
        plan, sources, _ = self.sources()
        sources.extend(("cas", sources[1][1], {}, hashlib.sha256(str(index).encode()).hexdigest())
                       for index in range(32))
        custody = self.destination()
        with self.assertRaisesRegex(ValueError, "source count"):
            union.assemble(plan, sources, custody, Budget(), {})
        self.assertEqual(os.listdir(custody.cas_fd), [])

    def test_active_plan_requires_exact_independently_pinned_pair(self):
        args = SimpleNamespace(active_plan_root=union.ACTIVE_PLAN_ROOT,
            active_plan_sha256=union.ACTIVE_PLAN_SHA, active_shard=[])
        self.assertEqual(union.active_selection(args), (union.ACTIVE_PLAN_ROOT, union.ACTIVE_PLAN_SHA))
        self.assertIsNone(union.active_selection(SimpleNamespace()))
        for field, replacement in (("active_plan_root", None), ("active_plan_sha256", None),
                                   ("active_plan_root", union.PLAN_ROOT),
                                   ("active_plan_sha256", union.PLAN_SHA),
                                   ("active_plan_sha256", "f" * 64),
                                   ("active_plan_root", self.root)):
            changed = copy.copy(args)
            setattr(changed, field, replacement)
            with self.subTest(field=field, replacement=replacement), self.assertRaises(ValueError):
                union.active_selection(changed)
        with self.assertRaisesRegex(ValueError, "require independently"):
            union.active_selection(SimpleNamespace(active_shard=[self.binding(1)]))

    def test_mixed_shard_parents_and_total_bound_keep_selection_meanings(self):
        historical = union.shard_bindings(SimpleNamespace(input_shard=[]))
        # Identical indices under distinct independently sealed parents are
        # distinct selections, rather than aliases for historical first16.
        entry = self.binding(1, "0", "16")
        args = SimpleNamespace(active_plan_root=union.ACTIVE_PLAN_ROOT,
            active_plan_sha256=union.ACTIVE_PLAN_SHA, active_shard=[entry])
        active = union.active_shard_bindings(args, historical)
        self.assertEqual(active, [(Path(entry[0]), entry[1], 0, 16)])
        parents = union.mixed_parent_metadata(historical, active)
        self.assertEqual(parents["plan"], union.PLAN_SHA)
        self.assertEqual(parents["active_plan"], {"root": str(union.ACTIVE_PLAN_ROOT),
                                                   "receipt_sha256": union.ACTIVE_PLAN_SHA})
        self.assertEqual(parents["shards"][0]["parent_plan_sha256"], union.PLAN_SHA)
        self.assertEqual(parents["shards"][1]["parent_plan_sha256"], union.ACTIVE_PLAN_SHA)
        self.assertEqual(parents["shards"][1]["shard_index"], 0)
        args.active_shard = [self.binding(index, str(index), "64") for index in range(1, 32)]
        self.assertEqual(len(union.active_shard_bindings(args, historical)), 31)
        for entries in (args.active_shard + [self.binding(32, "32", "64")],
                        [entry, entry], [self.binding(1, "0", digest=union.SHARD_SHA)],
                        [self.binding(1, digest=union.ACTIVE_PLAN_SHA)],
                        [self.binding(1, "0", "65")], [self.binding(1, "00")]):
            changed = copy.copy(args)
            changed.active_shard = entries
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                union.active_shard_bindings(changed, historical)
        extra_old = union.shard_bindings(SimpleNamespace(input_shard=[self.binding(2)]))
        args.active_shard = [self.binding(index, str(index), "64") for index in range(3, 34)]
        with self.assertRaisesRegex(ValueError, "count exceeds"):
            union.active_shard_bindings(args, extra_old)

    def test_historical_rows_must_exactly_match_active_descriptor_authority(self):
        plan, _, _ = self.sources()
        active = copy.deepcopy(plan)
        active["descriptors"].append(row(b"active-only", "active-only"))
        active["unresolved"] = [{"type": "dynamic-repository-closure"}]
        union.historical_membership(plan, active)
        # An equal digest with substituted identity or URLs is not the same
        # descriptor authority. Missing old rows cannot be silently dropped.
        for reason in ("absent", "identity", "url", "source"):
            changed = copy.deepcopy(active)
            if reason == "absent":
                changed["descriptors"] = changed["descriptors"][1:]
            elif reason == "identity":
                changed["descriptors"][0]["identity"] = "substituted"
            elif reason == "url":
                changed["descriptors"][0]["urls"] = ["https://static.crates.io/crates/other/other-1.crate"]
            else:
                changed["source_inventory_sha256"] = "b" * 64
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                union.historical_membership(plan, changed)

    def test_active_denominator_and_unresolved_do_not_inherit_historical_counts(self):
        historical, sources, _ = self.sources()
        active = copy.deepcopy(historical)
        selected = row(b"active-only", "active-only")
        active["descriptors"].append(selected)
        active["missing"].append(selected)
        active["unresolved"] = [{"type": "dynamic-repository-closure", "identity": "still-unproved"}]
        active_root = self.root / "active-plan"
        active_root.mkdir(mode=0o700)
        cas_object(active_root, selected, b"active-only")
        fd = os.open(active_root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        sources.insert(1, ("cas", fd, {selected["sha256"]: {"bytes": 11}}, "e" * 64))
        parents = {"plan": "b" * 64, "active_plan": {"root": str(active_root), "receipt_sha256": "e" * 64},
                   "tools": "d" * 64, "tools_manifest": "f" * 64,
                   "shards": [{"receipt_sha256": "c" * 64, "parent_plan_sha256": "b" * 64,
                               "shard_index": 0, "shard_size": 1}]}
        union.historical_membership(historical, active)
        custody = self.destination()
        result = union.assemble(active, sources, custody, Budget(), parents)
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["descriptors"], active["descriptors"])
        self.assertEqual(result["counts"]["unique_objects"], 4)
        self.assertEqual(result["counts"]["input_objects"], 5)
        self.assertEqual(result["counts"]["missing_objects"], 1)
        self.assertEqual(result["counts"]["unresolved_rows"], 1)
        self.assertEqual(result["unresolved"], active["unresolved"])
        self.assertNotEqual(result["unresolved"], historical["unresolved"])
        for key in ("closure_proved", "offline_analysis_proved", "native_support",
                    "provider_evaluation", "canonical_id_metadata_exported"):
            self.assertIs(result[key], False)
        custody.publish(result)

    def test_mixed_mode_source_ceiling_is_35_and_read_budget_stays_shared(self):
        plan, sources, _ = self.sources()
        sources.extend(("cas", sources[1][1], {}, hashlib.sha256(str(index).encode()).hexdigest())
                       for index in range(32))
        self.assertEqual(len(sources), 35)
        parents = {"active_plan": {"receipt_sha256": "e" * 64}, "shards": []}
        custody = self.destination()
        budget = Budget()
        budget.read_bytes = union.MAX_BYTES - 1
        with self.assertRaisesRegex(ValueError, "read budget"):
            union.assemble(plan, sources, custody, budget, parents)
        sources.append(("cas", sources[1][1], {}, "f" * 64))
        with self.assertRaisesRegex(ValueError, "source count"):
            union.assemble(plan, sources, custody, Budget(), parents)

    def test_tool_receipt_payload_substitution_and_extra_entries_refuse(self):
        root = self.root / "tools"
        root.mkdir(mode=0o700)
        value = b"fixture-tool"
        digest = hashlib.sha256(value).hexdigest()
        archives = (("fixture-tool", digest, "https://github.com/example/releases/download/1/"),)
        path = root / "fixture-tool"
        path.write_bytes(value)
        report = {"status": "complete-verified-distdir", "manifest_sha256": "a" * 64,
                  "missing": [], "native_support": False, "native_proof": False,
                  "verified": [{"name": "fixture-tool", "sha256": digest,
                                "bytes": len(value), "status": "verified-export"}]}
        payload = json.dumps(report).encode()
        (root / "receipt.json").write_bytes(payload)
        receipt_sha = hashlib.sha256(payload).hexdigest()
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            objects = union.read_tools(fd, receipt_sha, Budget(), archives, "a" * 64)
            self.assertEqual(objects[digest]["bytes"], len(value))
            with self.assertRaisesRegex(ValueError, "receipt digest"):
                union.read_tools(fd, "b" * 64, Budget(), archives, "a" * 64)
            extra = root / "undeclared"
            extra.write_bytes(b"extra")
            with self.assertRaisesRegex(ValueError, "closed inventory"):
                union.read_tools(fd, receipt_sha, Budget(), archives, "a" * 64)
            extra.unlink()
            path.write_bytes(b"tampered!!!!")
            with self.assertRaisesRegex(ValueError, "digest differs"):
                union.read_tools(fd, receipt_sha, Budget(), archives, "a" * 64)
        finally:
            os.close(fd)

    def test_explicit_input_selection_is_the_finite_retained_triple(self):
        args = SimpleNamespace(plan_root=union.PLAN_ROOT, plan_sha256=union.PLAN_SHA,
            shard_root=union.SHARD_ROOT, shard_sha256=union.SHARD_SHA,
            tools_root=union.TOOLS_ROOT, tools_sha256=union.TOOLS_SHA)
        union.input_pins(args)
        for field, value in (("plan_root", self.root), ("shard_sha256", "f" * 64),
                             ("tools_root", union.TOOLS_ROOT / "extra")):
            changed = copy.copy(args)
            setattr(changed, field, value)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "input selection"):
                union.input_pins(changed)

    def test_read_budget_applies_across_all_union_sources(self):
        plan, sources, _ = self.sources()
        budget = Budget()
        budget.read_bytes = union.MAX_BYTES - 1
        with self.assertRaisesRegex(ValueError, "read budget"):
            union.assemble(plan, sources, self.destination(), budget, {})


if __name__ == "__main__":
    unittest.main()
