"""Digest export, metadata authority and bounded shard predicates; no network."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import codex_dependency_bundle as bundle
import fetch_codex_archives as fetch
from codex_sdk_dependencies import EXACT_BCR_ARCHIVES, sha


def row(value, identity="fixture", kind="cargo-crate", url=None):
    return {"type": kind, "identity": identity,
            "sha256": hashlib.sha256(value).hexdigest(),
            "urls": [url or "https://static.crates.io/crates/fixture/fixture-1.crate"]}


def cache_payload(root, selected, value):
    parent = root / "content_addressable/sha256" / selected["sha256"]
    parent.mkdir(parents=True, mode=0o700)
    path = parent / "file"
    path.write_bytes(value)
    path.chmod(0o400)
    return path


def manifest(rows):
    return {"artifacts": rows, "unsupported": [{"type": "cargo-git", "identity": "fixture"}]}


class BundleTests(unittest.TestCase):
    def test_exact_bcr_pairs_survive_plan_and_shard_validation_without_fetch(self):
        for url, integrity in EXACT_BCR_ARCHIVES.items():
            with self.subTest(url=url):
                selected = {"type": "bazel-module-archive", "identity": "fixture-archive",
                            "urls": [url], "sha256": sha(None, integrity)}
                self.assertEqual(bundle.row_checked(selected), selected)
                plan = {"descriptors": [selected], "missing": [selected], "objects": {}}
                self.assertEqual(bundle.selected_shard(plan, 0, 1), [selected])

    def test_exception_refusal_precedes_any_fetch_or_private_worker_creation(self):
        url = "https://www.alsa-project.org/files/pub/lib/alsa-lib-1.2.9.tar.bz2"
        digest = sha(None, "sha256-3JxkP9xMz9BXLMaFhY3UHgivtYPzBGCzF+QYgnX2FbI=")
        good = row(b"fixture", identity="first-valid")
        for candidate, expected in ((url, "0" * 64), (url + ".neighbor", digest),
                                    (url + "?token=fixture-secret", digest),
                                    (url.replace("1.2.9", "1.2.10"), digest),
                                    (url.replace(".org/", ".org:443/"), digest),
                                    (url.replace("https://", "https://fixture-secret@"), digest)):
            invalid = {"type": "bazel-module-archive", "identity": "fixture-archive",
                       "urls": [candidate], "sha256": expected}
            # Invalid later descriptors must refuse even a first-row shard,
            # before the first valid row could cause a private worker or fetch.
            plan = {"descriptors": [good, invalid], "missing": [good, invalid], "objects": {}}
            with mock.patch.object(bundle, "run_prefetch") as acquire, \
                 mock.patch.object(bundle, "prefetch_command") as command, \
                 mock.patch.object(bundle.tempfile, "TemporaryDirectory") as worker:
                with self.assertRaisesRegex(ValueError, "public URL"):
                    bundle.fetch_shard(plan, "a" * 64, 0, 1, self.root, self.root,
                                       bundle.Budget(), bundle.PINNED_NIX, bundle.PINNED_CA)
                acquire.assert_not_called()
                command.assert_not_called()
                worker.assert_not_called()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.monitor = mock.patch.object(bundle, "disk_check")
        self.monitor.start()
        self.addCleanup(self.monitor.stop)

    def plan(self, rows, caches):
        destination = self.root / "export"
        bundle.make_output(destination)
        descriptors = [(str(path), os.open(path, os.O_RDONLY | os.O_DIRECTORY)) for path in caches]
        try:
            result = bundle.build_plan(manifest(rows), "b" * 64, descriptors, destination, bundle.Budget())
        finally:
            for _, descriptor in descriptors:
                os.close(descriptor)
        return result, destination

    def test_union_deduplicates_bytes_preserves_sources_and_ignores_cache_markers(self):
        first, second = self.root / "first", self.root / "second"
        first.mkdir(mode=0o700)
        second.mkdir(mode=0o700)
        a, alias, b, missing = row(b"a"), row(b"a", "alias"), row(b"b", "second"), row(b"absent", "missing")
        source_a = cache_payload(first, a, b"a")
        source_b = cache_payload(second, b, b"b")
        marker = source_a.parent / "id-unqualified-marker"
        marker.write_bytes(b"must remain outside export")
        before = [(path.stat().st_ino, path.read_bytes(), path.stat().st_mode) for path in (source_a, source_b, marker)]
        report, destination = self.plan([a, alias, b, missing], [first, second])
        self.assertEqual(set(report["objects"]), {a["sha256"], b["sha256"]})
        self.assertEqual(report["missing"], [missing])
        self.assertEqual(len(report["descriptors"]), 4)
        self.assertEqual(report["unresolved"], manifest([])["unsupported"])
        self.assertFalse(report["closure_proved"])
        self.assertFalse(report["canonical_id_metadata_exported"])
        for original, path in zip(before, (source_a, source_b, marker)):
            self.assertEqual(original, (path.stat().st_ino, path.read_bytes(), path.stat().st_mode))
        exported = destination / "content_addressable/sha256" / a["sha256"] / "file"
        self.assertNotEqual(exported.stat().st_ino, source_a.stat().st_ino)
        self.assertEqual(exported.stat().st_nlink, 1)
        self.assertEqual(exported.stat().st_mode & 0o777, 0o400)
        self.assertEqual(set(exported.parent.iterdir()), {exported})

    def test_selected_fifo_symlink_writable_directory_and_corruption_refuse(self):
        for kind in ("fifo", "symlink", "writable", "corrupt"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                root = Path(temporary)
                selected = row(b"expected")
                path = cache_payload(root, selected, b"expected")
                if kind == "fifo":
                    path.unlink()
                    os.mkfifo(path, 0o600)
                elif kind == "symlink":
                    path.unlink()
                    path.symlink_to(self.root / "unrelated")
                elif kind == "writable":
                    path.parent.chmod(0o777)
                else:
                    path.chmod(0o600)
                    path.write_bytes(b"corrupt!")
                source = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises((OSError, ValueError)):
                        descriptor = bundle.payload_fd(source, selected["sha256"])
                        try:
                            bundle.stream_object(descriptor, selected["sha256"], bundle.Budget())
                        finally:
                            os.close(descriptor)
                finally:
                    os.close(source)

    def test_verified_bcr_derivation_and_unpinned_descriptor_injection_refusal(self):
        archive = row(b"archive", "archive")
        sri = "sha256-" + base64.b64encode(bytes.fromhex(archive["sha256"])).decode()
        value = json.dumps({"url": "https://github.com/example/example/archive/v1.tar.gz",
                            "integrity": sri, "patches": {"fix.patch": sri}}).encode()
        url = "https://bcr.bazel.build/modules/example/1/source.json"
        source = row(value, url, "bazel-registry-file", url)
        cache = self.root / "cache"
        cache.mkdir(mode=0o700)
        cache_payload(cache, source, value)
        report, destination = self.plan([source], [cache])
        self.assertEqual(len(report["derivations"]), 1)
        self.assertEqual(len(report["descriptors"]), 3)
        self.assertEqual(len(report["missing"]), 1)  # archive and patch share one immutable object
        self.assertEqual(report["missing"][0]["sha256"], archive["sha256"])
        fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
        try:
            bundle.verify_plan_authority(report, manifest([source]), fd, bundle.Budget())
            injected = copy.deepcopy(report)
            injected["descriptors"].append(row(b"unapproved", "injected"))
            with self.assertRaisesRegex(ValueError, "pinned metadata"):
                bundle.verify_plan_authority(injected, manifest([source]), fd, bundle.Budget())
            deleted = copy.deepcopy(report)
            deleted["missing"] = []
            with self.assertRaisesRegex(ValueError, "missing object set"):
                bundle.verify_plan_authority(deleted, manifest([source]), fd, bundle.Budget())
        finally:
            os.close(fd)

    def test_closed_bundle_inventory_and_receipt_payload_substitution_refuse(self):
        cache = self.root / "cache"
        cache.mkdir(mode=0o700)
        selected = row(b"fixture")
        cache_payload(cache, selected, b"fixture")
        report, destination = self.plan([selected], [cache])
        digest = bundle.publish(destination, report)
        self.assertEqual(bundle.load_bundle(destination, digest, "plan", bundle.Budget(), False), report)
        with self.assertRaisesRegex(ValueError, "receipt digest"):
            bundle.load_bundle(destination, "f" * 64, "plan", bundle.Budget(), False)
        extra = destination / "extra"
        extra.write_bytes(b"undeclared")
        with self.assertRaisesRegex(ValueError, "undeclared entries"):
            bundle.load_bundle(destination, digest, "plan", bundle.Budget(), False)
        extra.unlink()
        exported = destination / "content_addressable/sha256" / selected["sha256"] / "file"
        exported.chmod(0o600)
        exported.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            bundle.load_bundle(destination, digest, "plan", bundle.Budget(), False)

    def test_payload_growth_and_read_budget_fail_closed(self):
        path = self.root / "payload"
        path.write_bytes(b"fixture")
        fd = os.open(path, os.O_RDONLY)
        try:
            budget = bundle.Budget()
            budget.read_bytes = bundle.MAX_BYTES
            with self.assertRaisesRegex(ValueError, "read budget"):
                bundle.stream_object(fd, hashlib.sha256(b"fixture").hexdigest(), budget)
        finally:
            os.close(fd)
        fd = os.open(path, os.O_RDONLY)
        try:
            original = os.fstat(fd)
            changed = mock.Mock(st_dev=original.st_dev, st_ino=original.st_ino,
                                st_size=original.st_size, st_mtime_ns=original.st_mtime_ns + 1,
                                st_ctime_ns=original.st_ctime_ns)
            with mock.patch.object(bundle.os, "fstat", side_effect=[original, changed]):
                with self.assertRaisesRegex(ValueError, "changed"):
                    bundle.stream_object(fd, hashlib.sha256(b"fixture").hexdigest(), bundle.Budget())
        finally:
            os.close(fd)

    def test_shard_fetch_uses_only_selected_expected_hash_and_keeps_partial_scope(self):
        selected, absent = row(b"selected"), row(b"later", "later")
        cache = self.root / "empty-cache"
        cache.mkdir(mode=0o700)
        plan, _ = self.plan([selected, absent], [cache])
        # Production ordering is deterministic; fixture content follows selected row.
        data = {selected["sha256"]: b"selected", absent["sha256"]: b"later"}
        destination = self.root / "shard"
        bundle.make_output(destination)
        commands = []

        def fake_prefetch(command, environment, worker, *bounds):
            commands.append(command)
            digest = command[command.index("--expected-hash") + 1]
            logical = "/nix/store/" + "a" * 32 + "-" + digest
            path = worker / "private-store" / logical.lstrip("/")
            path.parent.mkdir(parents=True)
            path.write_bytes(data[digest])
            path.chmod(0o400)
            self.assertEqual(environment["PATH"], "")
            self.assertIn("max-jobs = 0", environment["NIX_CONFIG"])
            return {"storePath": logical,
                    "hash": "sha256-" + base64.b64encode(bytes.fromhex(digest)).decode()}

        with mock.patch.object(bundle, "run_prefetch", side_effect=fake_prefetch), \
                mock.patch.object(fetch, "disk_check"):
            report = bundle.fetch_shard(plan, "c" * 64, 0, 1, destination, self.root,
                                        bundle.Budget(), bundle.PINNED_NIX, bundle.PINNED_CA)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][-1], plan["missing"][0]["urls"][0])
        self.assertIn("--expected-hash", commands[0])
        self.assertEqual(set(report["objects"]), {plan["missing"][0]["sha256"]})
        self.assertEqual(report["remaining_missing_objects"], 1)
        self.assertFalse(report["closure_proved"])
        self.assertEqual(report["unresolved"], plan["unresolved"])
        self.assertEqual(report["parent_plan_sha256"], "c" * 64)
        digest = bundle.publish(destination, report)
        bundle.load_bundle(destination, digest, "producer", bundle.Budget(), False)

    def test_duplicate_missing_rows_oversized_shards_and_nonpublic_urls_refuse(self):
        selected = row(b"fixture")
        plan = {"descriptors": [selected], "missing": [selected], "objects": {}}
        for index, size in ((-1, 1), (0, 0), (0, 65), (1, 1)):
            with self.subTest(index=index, size=size), self.assertRaises(ValueError):
                bundle.selected_shard(plan, index, size)
        plan["missing"].append(selected)
        with self.assertRaisesRegex(ValueError, "authority"):
            bundle.selected_shard(plan, 0, 1)
        for url in ("https://github.com/example/archive?token=fixture-secret",
                    "https://user:fixture-secret@github.com/example/archive", "http://github.com/example/archive"):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "public URL"):
                bundle.row_checked(row(b"fixture", url=url))

    def test_retained_input_requires_exact_epoch_and_producer_suffix(self):
        root = bundle.ROOTS[0] / "00000000-0000-0000-0000-000000000000"
        good = root / (bundle.SUFFIX + "codex_dependency_bundle_plan/test.outputs/codex-dependency-bundle")
        bundle.retained_location(good, "plan")
        for candidate in (self.root, good / "extra", root / "arbitrary"):
            with self.subTest(path=candidate), self.assertRaises(ValueError):
                bundle.retained_location(candidate, "plan")

    def test_home_retained_selector_preserves_fast_indices_and_requires_exact_producer_epoch(self):
        self.assertEqual(bundle.ROOTS[:2], (
            Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005'),
            Path('/srv/fast-local/jess/state/codex/omux-dependency-prefetch-20261005')))
        self.assertEqual(bundle.ROOTS[2], bundle.HOME_HTTP_STATE)
        prefix = bundle.HOME_HTTP_STATE / '00000000-0000-0000-0000-000000000001'
        root = prefix / (bundle.SUFFIX + 'codex_dependency_bundle_producer/test.outputs/codex-dependency-bundle')
        bundle.retained_location(root, 'producer')
        for other, kind in ((root, 'plan'), (root.parent, 'producer'), (root / 'extra', 'producer'),
                            (prefix / (bundle.SUFFIX + 'codex_dependency_bundle_plan/test.outputs/codex-dependency-bundle'), 'plan'),
                            (Path(str(root).replace('codex_dependency_bundle_producer', 'codex_git_input_producer_0')), 'producer'),
                            (Path(str(root).replace('00000000-0000-0000-0000-000000000001', 'cache-v2-' + '0' * 64)), 'producer'),
                            (Path(str(root).replace('omux-codex-http-prefetch-20261006', 'omux-codex-http-prefetch-20261005')), 'producer')):
            with self.subTest(root=other, kind=kind), self.assertRaises(ValueError):
                bundle.retained_location(other, kind)

    def home_fixture(self):
        home = self.root / 'modeled-home-http'
        destination = home / '00000000-0000-0000-0000-000000000001' / (
            bundle.SUFFIX + 'codex_dependency_bundle_producer/test.outputs/codex-dependency-bundle')
        destination.parent.mkdir(parents=True, mode=0o700)
        bundle.make_output(destination)
        values = [b'modeled source row ' + str(index).encode() for index in range(60)]
        rows = [row(value, 'row-' + str(index)) for index, value in enumerate(values)]
        selected = bundle.selected_shard({'missing': rows, 'descriptors': rows, 'objects': {}}, 1, 30)
        for descriptor, value in zip(selected, values[30:]):
            cache_payload(destination, descriptor, value)
        report = {**bundle.COMMON, 'status': 'verified-missing-object-shard',
                  'source_inventory_sha256': 'b' * 64,
                  'parent_plan_sha256': bundle.HOME_HTTP_SHARD[0], 'shard_index': 1, 'shard_size': 30,
                  'descriptors': selected,
                  'objects': {descriptor['sha256']: {'bytes': len(value)}
                              for descriptor, value in zip(selected, values[30:])},
                  'remaining_missing_objects': 30, 'unresolved': [], 'canonical_id_metadata_exported': False}
        digest = bundle.publish(destination, report)
        return home, destination, report, digest

    def test_home_bundle_readback_requires_frozen_receipt_and_actual_selected_object_bytes(self):
        home, destination, report, digest = self.home_fixture()
        with mock.patch.object(bundle, 'HOME_HTTP_STATE', home), \
                mock.patch.object(bundle, 'ROOTS', (*bundle.ROOTS[:2], home)), \
                mock.patch.object(bundle, 'run_prefetch', side_effect=AssertionError('no network execution')):
            self.assertEqual(bundle.load_bundle(destination, digest, 'producer', bundle.Budget()), report)
            with self.assertRaisesRegex(ValueError, 'receipt digest'):
                bundle.load_bundle(destination, '0' * 64, 'producer', bundle.Budget())
            payload = destination / 'content_addressable/sha256' / report['descriptors'][0]['sha256'] / 'file'
            original = payload.read_bytes()
            payload.chmod(0o600)
            payload.write_bytes(b'x' + original[1:])
            payload.chmod(0o400)
            with self.assertRaisesRegex(ValueError, 'digest differs'):
                bundle.load_bundle(destination, digest, 'producer', bundle.Budget())

    def test_home_wrong_plan_or_slice_refuses_before_object_payloads_even_with_valid_raw_digest(self):
        home, destination, report, _ = self.home_fixture()
        with mock.patch.object(bundle, 'HOME_HTTP_STATE', home), \
                mock.patch.object(bundle, 'ROOTS', (*bundle.ROOTS[:2], home)):
            for field, value in (('parent_plan_sha256', 'a' * 64), ('shard_index', 0),
                                 ('shard_index', True), ('shard_size', 20), ('shard_size', 30.0)):
                changed = {**report, field: value}
                receipt = bundle.encoded(changed)
                path = destination / 'bundle-receipt.json'
                path.chmod(0o600)
                path.write_bytes(receipt)
                path.chmod(0o400)
                digest = hashlib.sha256(receipt).hexdigest()
                with self.subTest(field=field, value=value), \
                        mock.patch.object(bundle, 'payload_fd', side_effect=AssertionError('no payload open')), \
                        self.assertRaisesRegex(ValueError, 'HOME HTTP shard declaration differs'):
                    bundle.load_bundle(destination, digest, 'producer', bundle.Budget())

    def test_home_location_cannot_bypass_suffix_validation_using_fixture_override(self):
        home, destination, _, digest = self.home_fixture()
        with mock.patch.object(bundle, 'HOME_HTTP_STATE', home), \
                mock.patch.object(bundle, 'ROOTS', (*bundle.ROOTS[:2], home)), \
                mock.patch.object(bundle, 'trusted_parent', side_effect=AssertionError('no input open')):
            with self.assertRaisesRegex(ValueError, 'bundle producer'):
                bundle.load_bundle(destination, digest, 'plan', bundle.Budget(), False)
            with self.assertRaisesRegex(ValueError, 'suffix differs'):
                bundle.load_bundle(destination.parent, digest, 'producer', bundle.Budget(), False)

    def test_home_slice_binding_does_not_change_historical_fast_shard_readback(self):
        fast, destination, report, _ = self.home_fixture()
        historical = {**report, 'parent_plan_sha256': 'c' * 64, 'shard_index': 0, 'shard_size': 20}
        receipt = bundle.encoded(historical)
        path = destination / 'bundle-receipt.json'
        path.chmod(0o600)
        path.write_bytes(receipt)
        path.chmod(0o400)
        # Map the fixture into the original FAST slot, with HOME unchanged:
        # location validation and actual byte proof both remain enabled.
        with mock.patch.object(bundle, 'ROOTS', (fast, *bundle.ROOTS[1:])):
            self.assertEqual(bundle.load_bundle(destination, hashlib.sha256(receipt).hexdigest(),
                'producer', bundle.Budget()), historical)

    def test_home_acquisition_wrong_mode_plan_or_slice_refuses_before_output_or_network(self):
        outputs = bundle.HOME_HTTP_STATE / '00000000-0000-0000-0000-000000000001' / 'modeled-action-output'
        common = ['--mode', 'fetch', '--plan-sha256', bundle.HOME_HTTP_SHARD[0],
                  '--shard-index', '1', '--shard-size', '30']
        for selector, value in (('--mode', 'plan'), ('--plan-sha256', 'a' * 64),
                                ('--shard-index', '0'), ('--shard-size', '20')):
            arguments = common.copy()
            arguments[arguments.index(selector) + 1] = value
            with self.subTest(selector=selector), \
                    mock.patch.dict(os.environ, {'OMUX_EXECUTION_GUARD': 'modeled',
                                                 'TEST_UNDECLARED_OUTPUTS_DIR': str(outputs)}), \
                    mock.patch.object(bundle, 'authority', return_value=(manifest([]), 'b' * 64)), \
                    mock.patch.object(bundle, 'trusted_parent', side_effect=AssertionError('no output open')), \
                    mock.patch.object(bundle, 'run_prefetch', side_effect=AssertionError('no network execution')), \
                    self.assertRaisesRegex(ValueError, 'HOME HTTP acquisition declaration differs'):
                bundle.main(arguments)


if __name__ == "__main__":
    unittest.main()
