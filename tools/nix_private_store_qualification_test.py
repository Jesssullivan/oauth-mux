"""Real descriptor/NAR/copy/custody models; Nix child execution is injected.

These models never qualify actual namespace availability or a native closure.
"""
import copy
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import nar_descriptor as nar
import nix_private_store_seed as seed
import nix_private_store_qualification as proof

BASH = "/nix/store/" + "1" * 32 + "-bash"
NIX = "/nix/store/" + "2" * 32 + "-nix"
LIB = "/nix/store/" + "3" * 32 + "-libc"
EXTRA = "/nix/store/" + "5" * 32 + "-unselected"
OUT = "/nix/store/" + "4" * 32 + "-" + proof.OUTPUT_NAME


class Fixture:
    def __init__(self, root):
        self.root = Path(root)
        self.physical = {}
        for logical in (BASH, NIX, LIB, EXTRA):
            physical = self.root / logical.rsplit("/", 1)[1]
            physical.mkdir()
            self.physical[logical] = physical
        for logical, relative, payload in ((BASH, "bin/bash", b"declared-bash"),
                                           (NIX, "bin/nix", b"declared-nix"),
                                           (LIB, "lib/libc.so", b"declared-libc"),
                                           (EXTRA, "extra", b"unselected-byte")):
            path = self.physical[logical] / relative
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(payload)
            os.chmod(path, 0o555)
        (self.physical[NIX] / "bin/nix-store").symlink_to("nix")
        self.descriptors = {}
        for logical, physical in self.physical.items():
            value = nar.describe(physical)
            value["root"] = logical
            self.descriptors[logical] = value
        references = {BASH: [LIB], NIX: [LIB], LIB: [], EXTRA: []}
        self.registration = ""
        for logical in sorted(self.physical):
            record = nar.hash_descriptor(self.descriptors[logical], opener=self.opener)
            self.registration += "\n".join([logical, record["narHash"], str(record["narSize"]),
                                           "", str(len(references[logical])), *references[logical]]) + "\n"
        native = {"system": "x86_64-linux", "packages": {"bash": {"out": BASH}, "nix": {"out": NIX}}}
        self.raw_native = seed.encoded(native)
        self.raw_paths = ("\n".join(sorted(self.physical)) + "\n").encode()
        self.raw_registration = self.registration.encode()
        self.value = seed.describe_seed(self.raw_native, self.raw_paths, self.raw_registration,
                                       describe=lambda logical: copy.deepcopy(self.descriptors[logical]))
        seed.validate(self.value)
        self.calls = []

    def opener(self, logical, relative):
        return nar.open_regular(str(self.physical[logical]), relative)

    def runner(self, command, environment, root, deadline, *, input_file=None, tool_fd=None):
        assert type(tool_fd) is int and os.fstat(tool_fd).st_size > 0
        self.calls.append((command, environment, root, deadline))
        if command[-1] == "--load-db":
            assert input_file.read() == self.value["registration"].encode()
            return b""
        if command[-1] == "--dump-db":
            return self.value["registration"].encode()
        private = Path(command[command.index("--store") + 1].removeprefix("local?root="))
        path = private / "nix/store" / OUT.rsplit("/", 1)[1]
        path.write_bytes(proof.RESULT)
        os.chmod(path, 0o444)
        return (OUT + "\n").encode()

    def qualify(self, runner=None, deadline=None):
        def describe(logical, physical=None):
            value = nar.describe(self.physical[logical] if physical is None else physical)
            value["root"] = logical
            return value
        with patch.object(proof, "source_opener", return_value=self.opener), \
             patch.object(proof, "describe_root", side_effect=describe):
            return proof.qualify(self.value, seed.encoded(self.value), self.root,
                                 {"flake": "a"*64, "lock": "b"*64},
                                 float(time.monotonic()+60) if deadline is None else deadline,
                                 runner=self.runner if runner is None else runner)


class PrivateStoreModels(unittest.TestCase):

    def test_finite_reachable_seed_includes_shared_runtime_and_logical_companion(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            self.assertEqual(model.value["roots"], sorted([BASH, NIX, LIB]))
            self.assertEqual(seed.resolve_member(model.value, NIX+"/bin/nix-store"), NIX+"/bin/nix")
            self.assertNotIn(EXTRA, model.value["descriptors"])
            self.assertTrue(all(not row["source"].startswith(EXTRA) for row in model.value["files"]))

    def test_missing_reference_and_duplicate_registration_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            for text in (model.registration + model.registration,
                         model.registration.replace(LIB+"\n", "/nix/store/"+"6"*32+"-missing\n", 1)):
                with self.assertRaises(ValueError):
                    seed.describe_seed(model.raw_native, model.raw_paths, text.encode(),
                                       describe=lambda root: model.descriptors[root])

    def test_external_executable_link_is_refused_without_host_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            bad = copy.deepcopy(model.value)
            link = next(row for row in bad["descriptors"][NIX]["nodes"] if row["path"] == "bin/nix-store")
            link["target"] = "/private/credential"
            with patch.object(Path, "resolve", side_effect=AssertionError("host lookup")), self.assertRaises(ValueError):
                seed.validate(bad)

    def test_nix32_little_endian_digest_and_invalid_high_bits(self):
        self.assertEqual(seed.expected_hash("sha256:"+"0"*51+"1"), "01"+"00"*31)
        with self.assertRaises(ValueError):
            seed.expected_hash("sha256:"+"z"*52)

    def test_descriptor_missing_regular_leaf_is_not_a_valid_registered_nar(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            model.value["descriptors"][LIB]["nodes"] = [
                row for row in model.value["descriptors"][LIB]["nodes"] if row["type"] != "regular"]
            model.value["files"] = []
            model.value["regular_bytes"] = 0
            for root in model.value["roots"]:
                for row in model.value["descriptors"][root]["nodes"]:
                    if row["type"] == "regular":
                        model.value["files"].append({"source": root+"/"+row["path"],
                            "alias": "private-store-inputs/"+str(len(model.value["files"]))})
                        model.value["regular_bytes"] += row["size"]
            with self.assertRaises(ValueError):
                model.qualify()
            self.assertEqual(model.calls, [])

    def test_real_copy_and_registration_readback_close_without_native_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            result = model.qualify()
            self.assertIs(result["private_root_removed"], True)
            self.assertIs(result["seed_rechecked_after_build"], True)
            self.assertIs(result["native_closure_realized"], False)
            self.assertIs(result["sdk_qualified"], False)
            self.assertEqual(result["builder"]["bytes"], len(proof.RESULT))
            self.assertEqual(len(model.calls), 3)
            self.assertEqual(list(Path(directory).glob("nix-private-build-*")), [])
            for _, _, _, deadline in model.calls:
                self.assertEqual(deadline, model.calls[0][3])

    def test_corrupt_source_nar_stops_before_store_or_child_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            (model.physical[LIB]/"lib/libc.so").write_bytes(b"corrupt")
            with self.assertRaises(ValueError), patch.object(proof, "OwnedRoot", side_effect=AssertionError("root created")):
                model.qualify()
            self.assertEqual(model.calls, [])

    def test_original_link_metadata_drift_stops_before_store_or_child(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            link = model.physical[NIX]/"bin/nix-store"
            link.unlink()
            link.symlink_to("/private/credential")
            with self.assertRaises(ValueError), patch.object(proof, "OwnedRoot", side_effect=AssertionError("root created")):
                model.qualify()
            self.assertEqual(model.calls, [])

    def test_registration_readback_substitution_stops_before_builder(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            def runner(*args, **kwargs):
                result = model.runner(*args, **kwargs)
                return result.replace(b"sha256:", b"sha257:") if args[0][-1] == "--dump-db" else result
            with self.assertRaises(ValueError):
                model.qualify(runner)
            self.assertEqual(len(model.calls), 2)
            self.assertEqual(list(Path(directory).glob("nix-private-build-*")), [])

    def test_namespace_refusal_phase_survives_successful_private_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            def runner(*args, **kwargs):
                if args[0][-1] not in ("--load-db", "--dump-db"):
                    raise ValueError("modeled namespace refusal")
                return model.runner(*args, **kwargs)
            with self.assertRaises(ValueError):
                model.qualify(runner)
            self.assertEqual(proof.PHASE, "namespace-build")
            self.assertEqual(list(Path(directory).glob("nix-private-build-*")), [])

    def test_builder_wrong_bytes_and_symlink_are_refused_and_private_root_removed(self):
        for kind in ("bytes", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                model = Fixture(directory)
                def runner(*args, **kwargs):
                    result = model.runner(*args, **kwargs)
                    if args[0][-1] not in ("--load-db", "--dump-db"):
                        command = args[0]
                        root = Path(command[command.index("--store")+1].removeprefix("local?root="))
                        output = root/"nix/store"/OUT.rsplit("/",1)[1]
                        output.unlink()
                        if kind == "symlink":
                            output.symlink_to("/private/credential")
                        else:
                            output.write_bytes(b"wrong")
                            os.chmod(output, 0o444)
                    return result
                with self.assertRaises((ValueError, OSError)):
                    model.qualify(runner)
                self.assertEqual(list(Path(directory).glob("nix-private-build-*")), [])

    def test_absolute_deadline_expiry_precedes_root_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            with self.assertRaises(ValueError), patch.object(proof, "OwnedRoot", side_effect=AssertionError("root created")):
                model.qualify(deadline=float(time.monotonic()-1))
            self.assertEqual(model.calls, [])

    def test_same_path_root_replacement_is_not_adopted_or_recursively_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = proof.OwnedRoot(directory)
            displaced = root.path.with_name(root.path.name+"-displaced")
            root.path.rename(displaced)
            root.path.mkdir(mode=0o700)
            (root.path/"foreign").write_bytes(b"preserve")
            with self.assertRaises(ValueError):
                root.close()
            self.assertEqual((root.path/"foreign").read_bytes(), b"preserve")
            self.assertIsNone(root.fd)

    def test_expired_cleanup_refuses_without_reporting_root_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = proof.OwnedRoot(directory)
            with self.assertRaises(ValueError):
                root.close(float(time.monotonic()-1))
            self.assertIsNone(root.fd)
            self.assertTrue(root.path.exists())

    def test_fixed_private_store_commands_bind_both_stores_and_disable_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            tools = {"nix": NIX+"/bin/nix", "nix_store": NIX+"/bin/nix-store", "bash": BASH+"/bin/bash"}
            commands = proof.commands(tools, private)
            for command in commands:
                self.assertEqual(command.count("--store"), 1)
                self.assertEqual(command[command.index("--store")+1], "local?root="+directory)
                options = {command[index+1]: command[index+2] for index,item in enumerate(command) if item=="--option"}
                self.assertEqual(options["builders"], "")
                self.assertEqual(options["substituters"], "")
                self.assertEqual(options["sandbox"], "true")
                self.assertEqual(options["sandbox-fallback"], "false")
                self.assertEqual(options["max-jobs"], "1")
                self.assertEqual(options["cores"], "2")
                self.assertNotIn("local://", command)
            build = commands[2]
            self.assertEqual(build[build.index("--eval-store")+1], "local?root="+directory)
            self.assertIn("--no-link", build)
            self.assertIn("--offline", build)
            self.assertIn("builtin printf", build[-1])
            self.assertIn("builtins.appendContext", build[-1])
            self.assertIn("path = true", build[-1])
            self.assertNotIn("builtins.storePath", build[-1])
            self.assertNotIn("--impure", build)
            self.assertNotIn("import ", build[-1])
            environment = proof.environment(private)
            self.assertEqual(environment["PATH"], "")
            self.assertEqual(environment["NIX_REMOTE"], "")
            self.assertNotIn("SSH_AUTH_SOCK", environment)
            self.assertNotIn("NIX_BUILD_HOOK", environment)

    def test_nonroot_no_new_privileges_and_empty_capabilities_are_required(self):
        good = "Uid:\t1000 1000 1000 1000\nNoNewPrivs:\t1\nCapEff:\t0000000000000000\n"
        self.assertIs(proof.platform(good, 1000)["no_new_privileges"], True)
        for status, uid in ((good, 0), (good.replace("NoNewPrivs:\t1","NoNewPrivs:\t0"),1000),
                            (good.replace("0000000000000000","0000000000000001"),1000)):
            with self.assertRaises(ValueError):
                proof.platform(status,uid)

    def test_bool_schema_and_alias_substitution_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            for change in (lambda value: value.update(schemaVersion=True),
                           lambda value: value["files"][0].update(alias="private-store-inputs/999999"),
                           lambda value: value.update(regular_bytes=True)):
                value = copy.deepcopy(model.value)
                change(value)
                with self.assertRaises(ValueError):
                    seed.validate(value)

    def test_selector_creation_failure_does_not_spawn_child(self):
        with patch.object(proof.os, "fstat", return_value=Mock(st_mode=0o100555)), \
             patch.object(proof.selectors, "DefaultSelector", side_effect=OSError("unavailable")), \
             patch.object(proof.subprocess, "Popen") as spawn, self.assertRaises(OSError):
            proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10), tool_fd=777)
        spawn.assert_not_called()

    def test_post_spawn_registration_fault_still_reaps_own_child_and_closes_all_streams(self):
        process = Mock()
        process.pid = 12345
        process.stdout = tempfile.TemporaryFile()
        process.stderr = tempfile.TemporaryFile()
        process.poll.return_value = None
        process.wait.return_value = 0
        selector = Mock()
        selector.register.side_effect = OSError("registration")
        selector.close.side_effect = OSError("close")
        with tempfile.TemporaryFile() as tool:
            os.fchmod(tool.fileno(), 0o555)
            with patch.object(proof.selectors, "DefaultSelector", return_value=selector), \
                 patch.object(proof.subprocess, "Popen", return_value=process) as spawn, \
                 patch.object(proof.os, "set_blocking"), patch.object(proof.os, "killpg") as kill, \
                 self.assertRaises(ValueError):
                proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10), tool_fd=tool.fileno())
            spawn.assert_called_once()
            self.assertEqual(spawn.call_args.kwargs["executable"], "/proc/self/fd/"+str(tool.fileno()))
            self.assertEqual(spawn.call_args.kwargs["pass_fds"], (tool.fileno(),))
        kill.assert_called_once_with(12345, proof.signal.SIGTERM)
        process.wait.assert_called_once()
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_zero_exit_bool_is_not_literal_success(self):
        process = Mock(stdout=tempfile.TemporaryFile(), stderr=tempfile.TemporaryFile())
        process.poll.return_value = 0
        process.wait.return_value = False
        selector = Mock()
        selector.get_map.return_value = {}
        with tempfile.TemporaryFile() as tool:
            os.fchmod(tool.fileno(), 0o555)
            with patch.object(proof.selectors, "DefaultSelector", return_value=selector), \
                 patch.object(proof.subprocess, "Popen", return_value=process) as spawn, \
                 patch.object(proof.os, "set_blocking"), self.assertRaises(ValueError):
                proof.run(["fixed"], {}, Path("/"), float(time.monotonic()+10), tool_fd=tool.fileno())
            spawn.assert_called_once()
            self.assertEqual(spawn.call_args.kwargs["pass_fds"], (tool.fileno(),))
        process.wait.assert_called_once()
        self.assertTrue(process.stdout.closed and process.stderr.closed)


if __name__ == "__main__":
    unittest.main()
