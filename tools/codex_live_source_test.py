"""Meaningful exact patch source and private source-state predicates."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import codex_live_source as source


class NativeSourceTests(unittest.TestCase):
    def test_native_sha2_edge_is_explicit_and_version_pinned(self):
        name = "codex-rs/core/BUILD.bazel"
        files = {name: ("100644", b'    deps_extra = [":native-peer-bridge", "@crates//:sha2-0.10.9"],\n'),
                 "codex-rs/core/Cargo.toml": ("100644", b"retained Cargo dependencies\n")}
        result, declaration = source.declare_pinned_sha2(files)
        self.assertEqual(result[name][1], b'    deps_extra = [":native-peer-bridge", "@crates//:sha2-0.10.9"],\n')
        self.assertEqual(declaration["before_sha256"], source.sha(files[name][1]))
        self.assertEqual(declaration["after_sha256"], source.sha(result[name][1]))
        repeated, _ = source.declare_pinned_sha2(result)
        self.assertEqual(repeated, result)
        for invalid in (b'    deps_extra = [":native-peer-bridge"],\n',
                        b'    deps_extra = [":native-peer-bridge", "@crates//:sha2-0.11.0"],\n'):
            with self.assertRaises(ValueError):
                source.declare_pinned_sha2({**files, name: ("100644", invalid)})
        with self.assertRaises(ValueError):
            source.declare_pinned_sha2({**files, "codex-rs/core/Cargo.toml": ("100644", b"sha2 = { workspace = true }\n")})

    def test_native_update_refuses_ambiguous_original_context(self):
        name = "codex-rs/core/src/client.rs"
        files = {name: ("100644", b"same\nsame\n")}
        delta = b"*** Begin Patch\n*** Update File: /srv/fast-local/jess/git/oauth-mux-detach-20261007/codex-rs/core/src/client.rs\n@@\n-same\n+changed\n*** End Patch\n"
        with self.assertRaises(ValueError):
            source.apply_native_patch(files, delta)
        self.assertEqual(files[name][1], b"same\nsame\n")

    def test_ordered_changes_preserve_unrelated_original_bytes(self):
        name = "codex-rs/core/src/client.rs"
        files = {name: ("100644", b"first\nshared\nlast\n"), "keep": ("100644", b"retained\n")}
        delta = b"*** Begin Patch\n*** Update File: /srv/fast-local/jess/git/oauth-mux-detach-20261007/codex-rs/core/src/client.rs\n@@\n-first\n+prepared\n shared\n@@\n-last\n+committed\n*** End Patch\n"
        result, paths = source.apply_native_patch(files, delta)
        self.assertEqual(result[name][1], b"prepared\nshared\ncommitted\n")
        self.assertEqual(result["keep"], files["keep"])
        self.assertEqual(paths, {name})
        self.assertEqual(files[name][1], b"first\nshared\nlast\n")

    def test_native_patch_cannot_expand_the_declared_path_boundary(self):
        for name in ("../../secret", "codex-rs/config/Cargo.toml", "/private", "MODULE.bazel"):
            delta = ("*** Begin Patch\n*** Add File: /srv/fast-local/jess/git/oauth-mux-detach-20261007/" + name + "\n+x\n*** End Patch\n").encode()
            with self.subTest(name=name), self.assertRaises(ValueError):
                source.apply_native_patch({}, delta)

    def test_existing_new_module_cannot_be_replaced(self):
        name = "codex-rs/core/src/broker_text_context.rs"
        delta = ("*** Begin Patch\n*** Add File: /srv/fast-local/jess/git/oauth-mux-detach-20261007/" + name + "\n+x\n*** End Patch\n").encode()
        with self.assertRaises(ValueError):
            source.apply_native_patch({name: ("100644", b"retained\n")}, delta)

    def test_source_export_cannot_follow_a_parent_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "real").mkdir()
            (root / "link").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaises(OSError):
                source.directory(root / "link")

    def test_output_is_exclusive_and_regular_files_are_sealed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "epoch"
            files = {"src/native.rs": ("100644", b"preserved\n")}
            descriptor = source.write_source(root, files)
            source.os.close(descriptor)
            self.assertEqual((root / "source/src/native.rs").read_bytes(), b"preserved\n")
            self.assertEqual((root / "source/src/native.rs").stat().st_mode & 0o777, 0o555)
            with self.assertRaises(FileExistsError):
                source.write_source(root, files)
            # Make owned fixture directories writable so tempfile can remove.
            for name in (root / "source/src", root / "source"):
                name.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
