"""Injected file metadata/reads only; no allocations, tools or desktop access."""
import hashlib
import json
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yoga_proof_inputs as inputs


class InputsTest(unittest.TestCase):
    def setUp(self):
        self.uid, self.deadline = 1000, 1000 * 10**9
        self.paths = {name: "/srv/omux-proof/declared/" + name for name in inputs.INPUTS}
        self.data = {name: name.encode("ascii") for name in inputs.INPUTS}
        self.digests = {name: hashlib.sha256(data).hexdigest() for name, data in self.data.items()}
        self.nodes = {name: SimpleNamespace(st_dev=2, st_ino=100 + index, st_uid=self.uid, st_gid=self.uid,
                        st_mode=stat.S_IFREG | 0o555, st_nlink=1, st_size=len(self.data[name]),
                        st_mtime_ns=1, st_ctime_ns=1) for index, name in enumerate(sorted(inputs.INPUTS))}
        self.parent = SimpleNamespace(st_dev=2, st_ino=3, st_uid=self.uid, st_mode=stat.S_IFDIR | 0o700)
        self.files, self.positions, self.next_fd = {}, {}, 100
        self.opener = Mock(side_effect=self.open_file)
        self.close = Mock()
        self.real_open_parent = inputs.open_parent
        patches = (patch.object(inputs, "open_parent", return_value=7),
                   patch.object(inputs.os, "open", self.opener),
                   patch.object(inputs.os, "fstat", side_effect=self.fstat),
                   patch.object(inputs.os, "stat", side_effect=self.named_stat),
                   patch.object(inputs.os, "read", side_effect=self.read),
                   patch.object(inputs.os, "close", self.close))
        for selected in patches:
            selected.start()
            self.addCleanup(selected.stop)

    def open_file(self, name, flags, *, dir_fd):
        self.assertEqual(dir_fd, 7)
        self.assertTrue(flags & inputs.os.O_NOFOLLOW)
        self.assertTrue(flags & inputs.os.O_NONBLOCK)
        self.assertTrue(flags & inputs.os.O_CLOEXEC)
        descriptor, self.next_fd = self.next_fd, self.next_fd + 1
        self.files[descriptor], self.positions[descriptor] = name, 0
        return descriptor

    def fstat(self, descriptor):
        return self.parent if descriptor == 7 else self.nodes[self.files[descriptor]]

    def named_stat(self, name, *, dir_fd, follow_symlinks):
        self.assertFalse(follow_symlinks)
        self.assertEqual(dir_fd, 7)
        return self.nodes[name]

    def read(self, descriptor, maximum):
        data = self.data[self.files[descriptor]]
        position = self.positions[descriptor]
        output = data[position:position + maximum]
        self.positions[descriptor] += len(output)
        return output

    def check(self, paths=None, digests=None, now=lambda: 1):
        return inputs.check_inputs(self.paths if paths is None else paths,
                                   self.digests if digests is None else digests,
                                   self.deadline, uid=self.uid, now=now)

    def test_exact_eleven_direct_inputs_rehash_and_close_all_descriptors(self):
        self.assertEqual(self.check(), self.digests)
        self.assertEqual(self.opener.call_count, 22)
        self.assertEqual(sum(call.args[0] != 7 for call in self.close.call_args_list), 22)

    def test_declared_recorder_sources_are_readable_without_execution_bits(self):
        for name in ("recorder", "recorder_implementation"):
            self.nodes[name].st_mode = stat.S_IFREG | 0o644
        self.assertEqual(self.check(), self.digests)
        self.assertNotIn("recorder", inputs.EXECUTABLES)

    def test_invalid_key_digest_path_or_deadline_refuses_before_open(self):
        for paths, digests in (({}, self.digests), (dict(self.paths, extra="/srv/extra"), self.digests),
                               (self.paths, {}), (self.paths, dict(self.digests, node="bad")),
                               (dict(self.paths, node="/home/operator/tool"), self.digests),
                               (dict(self.paths, node="/srv/../tool"), self.digests),
                               (dict(self.paths, node="/srv//tool"), self.digests),
                               (dict(self.paths, node="/nix/store/not-a-registered-root/bin/node"), self.digests)):
            with self.assertRaises(inputs.InputError):
                self.check(paths, digests)
        with self.assertRaises(inputs.InputError):
            self.check(now=lambda: self.deadline)
        self.opener.assert_not_called()
        inputs.open_parent.assert_not_called()

    def test_fifo_symlink_foreign_owner_writable_or_nonexecutable_refuses(self):
        for changes in (dict(st_mode=stat.S_IFIFO | 0o600), dict(st_mode=stat.S_IFLNK | 0o777),
                        dict(st_uid=1001), dict(st_mode=stat.S_IFREG | 0o577),
                        dict(st_mode=stat.S_IFREG | 0o444)):
            with self.subTest(changes=changes):
                original = vars(self.nodes["chromium"]).copy()
                vars(self.nodes["chromium"]).update(changes)
                with self.assertRaisesRegex(inputs.InputError, "input_unqualified"):
                    self.check()
                vars(self.nodes["chromium"]).update(original)

    def test_independent_expected_digest_mismatch_refuses(self):
        with self.assertRaisesRegex(inputs.InputError, "input_digest_mismatch"):
            self.check(digests=dict(self.digests, bundle="0" * 64))

    def test_earlier_in_place_drift_during_later_hash_refuses_capture(self):
        original_read = self.read
        def read_then_mutate(descriptor, maximum):
            result = original_read(descriptor, maximum)
            if self.files[descriptor] == "node" and result:
                self.nodes["bundle"].st_ctime_ns += 1
            return result
        with patch.object(inputs.os, "read", side_effect=read_then_mutate):
            with self.assertRaisesRegex(inputs.InputError, "input_changed"):
                self.check()

    def test_named_file_replacement_during_final_reopen_refuses(self):
        def stat_then_replace(name, **keywords):
            value = self.named_stat(name, **keywords)
            if self.opener.call_count > 11:
                return SimpleNamespace(**dict(vars(value), st_ino=value.st_ino + 1))
            return value
        with patch.object(inputs.os, "stat", side_effect=stat_then_replace):
            with self.assertRaisesRegex(inputs.InputError, "input_changed"):
                self.check()

    def test_named_parent_replacement_during_final_walk_refuses(self):
        original_fstat = self.fstat
        def changed_fstat(descriptor):
            if descriptor == 8:
                return SimpleNamespace(**dict(vars(self.parent), st_ino=4))
            return original_fstat(descriptor)
        with patch.object(inputs, "open_parent", side_effect=[7] * 11 + [8]), \
                patch.object(inputs.os, "fstat", side_effect=changed_fstat):
            with self.assertRaisesRegex(inputs.InputError, "input_changed"):
                self.check()
        self.assertIn(8, [call.args[0] for call in self.close.call_args_list])

    def test_nofollow_ancestor_walk_rejects_foreign_directory_and_closes(self):
        root = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        foreign = SimpleNamespace(st_uid=1001, st_mode=stat.S_IFDIR | 0o700)
        with patch.object(inputs.os, "open", side_effect=[20, 21]) as opener, \
                patch.object(inputs.os, "fstat", side_effect=[root, foreign]), \
                patch.object(inputs.os, "close") as close:
            with self.assertRaisesRegex(inputs.InputError, "input_unqualified"):
                self.real_open_parent(self.paths["bundle"], self.uid, self.deadline, lambda: 1)
            self.assertTrue(opener.call_args.args[1] & inputs.os.O_DIRECTORY)
            self.assertTrue(opener.call_args.args[1] & inputs.os.O_NOFOLLOW)
            self.assertEqual([call.args[0] for call in close.call_args_list], [21, 20])

    def test_file_total_bounds_and_midread_deadline_refuse(self):
        with patch.object(inputs, "MAX_FILE", 5):
            with self.assertRaisesRegex(inputs.InputError, "input_byte_bound"):
                self.check()
        with patch.object(inputs, "MAX_TOTAL", 5):
            with self.assertRaisesRegex(inputs.InputError, "input_byte_bound"):
                self.check()
        clock = Mock(side_effect=[1, 1, self.deadline])
        with self.assertRaisesRegex(inputs.InputError, "deadline_exceeded"):
            self.check(now=clock)

    def walk_store(self, changes=None, *, path=None):
        selected = path or "/nix/store/" + "a" * 32 + "-chromium/bin/chromium"
        parts = ["/", "/nix", "/nix/store", "/nix/store/" + "a" * 32 + "-chromium",
                 "/nix/store/" + "a" * 32 + "-chromium/bin"]
        nodes = {part: SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | (0o1775 if part == "/nix/store" else 0o555)) for part in parts}
        for part, update in (changes or {}).items():
            vars(nodes[part]).update(update)
        descriptors = list(range(20, 25))
        with patch.object(inputs.os, "open", side_effect=descriptors) as opener, \
                patch.object(inputs.os, "fstat", side_effect=[nodes[part] for part in parts]), \
                patch.object(inputs.os, "close") as close:
            try:
                result = self.real_open_parent(selected, self.uid, self.deadline, lambda: 1)
                inputs.os.close(result)
            except inputs.InputError:
                result = None
            return result, opener, close

    def test_exact_root_owned_sticky_store_with_immutable_descendants_passes(self):
        descriptor, opener, close = self.walk_store()
        self.assertEqual(descriptor, 24)
        self.assertEqual([call.args[0] for call in close.call_args_list], [20, 21, 22, 23, 24])
        for call in opener.call_args_list[1:]:
            self.assertTrue(call.args[1] & inputs.os.O_NOFOLLOW)
        self.assertTrue(opener.call_args_list[-1].args[1] & inputs.os.O_DIRECTORY)

    def test_store_exception_rejects_wrong_owner_modes_and_writable_packages(self):
        package = "/nix/store/" + "a" * 32 + "-chromium"
        for changes in ({"/nix/store": {"st_uid": self.uid}},
                        {"/nix/store": {"st_mode": stat.S_IFDIR | 0o1777}},
                        {"/nix/store": {"st_mode": stat.S_IFDIR | 0o775}},
                        {package: {"st_mode": stat.S_IFDIR | 0o755}},
                        {package: {"st_uid": self.uid}},
                        {package + "/bin": {"st_mode": stat.S_IFDIR | 0o1775}}):
            descriptor, opener, close = self.walk_store(changes)
            self.assertIsNone(descriptor)
            self.assertEqual(len(close.call_args_list), opener.call_count)

    def test_sticky_write_exception_does_not_extend_to_other_ancestors(self):
        root = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o555)
        sticky = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o1775)
        with patch.object(inputs.os, "open", side_effect=[20, 21]), \
                patch.object(inputs.os, "fstat", side_effect=[root, sticky]), patch.object(inputs.os, "close") as close:
            with self.assertRaisesRegex(inputs.InputError, "input_unqualified"):
                self.real_open_parent("/srv/declared/file", self.uid, self.deadline, lambda: 1)
            self.assertEqual([call.args[0] for call in close.call_args_list], [21, 20])

    def test_selected_store_leaf_is_root_owned_and_fully_nonwritable(self):
        paths = dict(self.paths, chromium="/nix/store/" + "a" * 32 + "-chromium/bin/chromium")
        self.nodes["chromium"].st_uid = 0
        self.assertEqual(self.check(paths=paths), self.digests)
        for changes in (dict(st_uid=self.uid), dict(st_mode=stat.S_IFREG | 0o755), dict(st_mode=stat.S_IFREG | 0o775)):
            vars(self.nodes["chromium"]).update(st_uid=0, st_mode=stat.S_IFREG | 0o555)
            vars(self.nodes["chromium"]).update(changes)
            with self.assertRaisesRegex(inputs.InputError, "input_unqualified"):
                self.check(paths=paths)

    def test_failure_diagnostic_never_projects_input_path_or_contents(self):
        self.assertEqual(inputs.diagnostic(OSError("private /srv/fixture/content")),
                         {"passed": False, "gate": "input_unqualified"})
        self.assertNotIn("/srv", json.dumps(inputs.diagnostic(inputs.InputError("input_changed"))))


if __name__ == "__main__":
    unittest.main()
