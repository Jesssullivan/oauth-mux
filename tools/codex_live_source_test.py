"""Meaningful exact patch source and private source-state predicates."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import codex_live_source as source
import codex_protocol_history_source as history


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
        delta = b"*** Begin Patch\n*** Update File: codex-rs/core/src/client.rs\n@@\n-same\n+changed\n*** End Patch\n"
        with self.assertRaises(ValueError):
            source.apply_native_patch(files, delta)
        self.assertEqual(files[name][1], b"same\nsame\n")

    def test_ordered_changes_preserve_unrelated_original_bytes(self):
        name = "codex-rs/core/src/client.rs"
        files = {name: ("100644", b"first\nshared\nlast\n"), "keep": ("100644", b"retained\n")}
        delta = b"*** Begin Patch\n*** Update File: codex-rs/core/src/client.rs\n@@\n-first\n+prepared\n shared\n@@\n-last\n+committed\n*** End Patch\n"
        result, paths = source.apply_native_patch(files, delta)
        self.assertEqual(result[name][1], b"prepared\nshared\ncommitted\n")
        self.assertEqual(result["keep"], files["keep"])
        self.assertEqual(paths, {name})
        self.assertEqual(files[name][1], b"first\nshared\nlast\n")

    def test_native_patch_cannot_expand_the_declared_path_boundary(self):
        for name in ("../../secret", "codex-rs/config/Cargo.toml", "/private", "MODULE.bazel"):
            delta = ("*** Begin Patch\n*** Add File: " + name + "\n+x\n*** End Patch\n").encode()
            with self.subTest(name=name), self.assertRaises(ValueError):
                source.apply_native_patch({}, delta)

    def test_existing_new_module_cannot_be_replaced(self):
        name = "codex-rs/core/src/broker_text_context.rs"
        delta = ("*** Begin Patch\n*** Add File: " + name + "\n+x\n*** End Patch\n").encode()
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




class ProtocolHistorySourceTests(unittest.TestCase):
    def fixture(self):
        files = {name: ("100644", b"unchanged graph input\n") for name in history.GRAPH}
        files.update({name: ("100644", b"retained before\n"
            + b"use codex_rollout::RolloutItem;\n"*count+b"retained after\n")
            for name,count in history.RUST_PATHS.items()})
        files[history.MANIFEST] = ("100644", b"[dependencies]\ncodex-history = { workspace = true }\ncodex-rollout = { workspace = true }\n")
        files[history.LOCK] = ("100644", b'[[package]]\nname = "codex-app-server-protocol"\nversion = "0.0.0"\ndependencies = [\n "codex-history",\n "codex-rollout",\n]\n\n[[package]]\nname = "codex-core"\ndependencies = [\n "codex-rollout",\n]\n')
        files["retained/source.rs"] = ("100644", b"unrelated retained application bytes\n")
        return files

    def test_dependency_cut_changes_only_six_paths_and_one_locked_edge(self):
        files = self.fixture()
        result = history.transform(files,history.PATCH_BYTES)
        self.assertEqual({name for name in files if files[name] != result[name]},history.ALLOWED)
        self.assertEqual(result["retained/source.rs"],files["retained/source.rs"])
        self.assertEqual(result[history.LOCK][1].count(b' "codex-rollout",\n'),1)
        self.assertIn(b'name = "codex-core"\ndependencies = [\n "codex-rollout",',result[history.LOCK][1])
        self.assertNotIn(b"codex-rollout =",result[history.MANIFEST][1])
        for name,count in history.RUST_PATHS.items():
            self.assertEqual(result[name][1].count(b"codex_history::"),count)
            self.assertNotIn(b"codex_rollout::",result[name][1])
        self.assertIn(b"codex_rollout::",files[next(iter(history.RUST_PATHS))][1])

    def test_new_declaration_cannot_expand_or_change_historical_patch_authority(self):
        files = self.fixture()
        for raw in (history.PATCH_BYTES+b"\n",history.PATCH_BYTES.replace(b"codex-history",b"other-history"),
                b"*** Begin Patch\n*** Add File: /private\n+x\n*** End Patch\n"):
            with self.assertRaises(ValueError):history.transform(files,raw)
        with self.assertRaises(ValueError):source.apply_native_patch(files,history.PATCH_BYTES)
        self.assertNotIn(history.MANIFEST,source.ALLOWED)
        self.assertNotIn(history.LOCK,source.ALLOWED)

    def test_malformed_import_manifest_lock_or_unselected_graph_change_refuses(self):
        fixtures=[]
        value=self.fixture();name=next(iter(history.RUST_PATHS))
        mode,raw=value[name];value[name]=(mode,raw+b"use codex_rollout::parse_rollout_line;\n");fixtures.append(value)
        value=self.fixture();mode,raw=value[history.MANIFEST]
        value[history.MANIFEST]=(mode,raw+b"codex-rollout = { workspace = true }\n");fixtures.append(value)
        value=self.fixture();mode,raw=value[history.LOCK]
        value[history.LOCK]=(mode,raw.replace(b'name = "codex-app-server-protocol"',b'name = "other-package"'));fixtures.append(value)
        value=self.fixture();value[history.MANIFEST]=("100755",value[history.MANIFEST][1]);fixtures.append(value)
        for value in fixtures:
            with self.assertRaises(ValueError):history.transform(value,history.PATCH_BYTES)
        files=self.fixture();result=history.transform(files,history.PATCH_BYTES)
        result["MODULE.bazel"]=("100644",b"changed unselected resolution graph\n")
        with self.assertRaises(ValueError):history.validate_transition(files,result)

    def test_distinct_sealed_source_output_explicitly_requires_actual_sdk_metadata(self):
        import json
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            patchfile=root/history.PATCH_NAME
            patchfile.write_bytes(history.PATCH_BYTES);patchfile.chmod(0o600)
            output=root/"protocol-history-source"
            parent={"patches":[{"patch_sha256":pin,"paths":[]} for pin in history.PARENT_PATCHES]}
            try:
                with patch.object(history,"PATCH_DIRECTORY",root),patch.object(history,"load_parent",
                        return_value=(self.fixture(),parent)):
                    receipt=history.produce(output,60)
                self.assertEqual(receipt["kind"],history.KIND)
                self.assertEqual(receipt["status"],"verified-protocol-history-source-pending-sdk-metadata")
                self.assertIs(receipt["sdk_metadata_qualified"],False)
                self.assertIs(receipt["native_compile_passed"],False)
                self.assertIs(receipt["provider_evaluation"],False)
                self.assertEqual(receipt["patch_sha256"],history.PARENT_PATCHES+[history.PATCH_SHA])
                self.assertEqual((output/"source-receipt.json").stat().st_mode&0o777,0o444)
                self.assertEqual(output.stat().st_mode&0o777,0o555)
                observed=json.loads((output/"source-receipt.json").read_bytes())
                self.assertEqual(observed["inventory_sha256"],receipt["inventory_sha256"])
                self.assertEqual((output/"source"/history.MANIFEST).stat().st_mode&0o777,0o555)
            finally:
                for directory,_,_ in os.walk(root):
                    Path(directory).chmod(0o700)
                source.DEADLINE=None


if __name__ == "__main__":
    unittest.main()
