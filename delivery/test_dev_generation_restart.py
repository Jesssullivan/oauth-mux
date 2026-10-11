"""Carrier and private-context predicates; these tests launch no processes."""
import io
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import dev_generation as generation
import dev_generation_restart as restart
import test_dev_generation as generation_fixtures


class RestartCarrierTest(unittest.TestCase):
    def setUp(self):
        self.fixture = generation_fixtures.GenerationTest("test_stage_receipt_selects_frozen_exact_generation_paths")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.portable_fixture()
        self.destination = self.fixture.base / "carrier"
        self.expected = dict(self.fixture.receipt["artifacts"])

    def carrier(self):
        return restart.carrier(self.fixture.root, self.fixture.generation, self.fixture.receipt_sha256,
                               self.expected, self.destination)

    def declared_wrappers(self):
        repository = self.fixture.base / "declared-tool-repository"
        repository.mkdir(mode=0o700)
        directory = repository / "tool_wrappers"
        directory.mkdir(mode=0o700)
        bash = "/nix/store/" + "0" * 32 + "-synthetic-bash"
        manifest = {"system": "x86_64-linux", "packages": {"bash": {"out": bash}}, "tools": {}}
        args = SimpleNamespace(tool_manifest=repository / "native.json")
        for argument, key, basename in restart.PRIVATE_TOOLS:
            backend = "/nix/store/" + "1" * 32 + "-synthetic-private-tool/bin/" + basename
            manifest["tools"][key] = backend
            wrapper = directory / key
            wrapper.write_text("#!" + bash + "/bin/bash\nset -eu\nexec '" + backend + "' \"$@\"\n")
            wrapper.chmod(0o700)
            setattr(args, argument, wrapper)
        args.tool_manifest.write_text(json.dumps(manifest))
        args.tool_manifest.chmod(0o600)
        return args, manifest

    def test_carrier_preserves_exact_receipt_and_source_generation(self):
        source = self.fixture.receipt_path.read_bytes()
        current = os.readlink(self.fixture.root / "current")
        selected = self.carrier()
        self.assertEqual(selected.directory, self.destination / "generations" / self.fixture.generation)
        self.assertEqual((selected.directory / "receipt.json").read_bytes(), source)
        self.assertEqual(self.fixture.receipt_path.read_bytes(), source)
        self.assertEqual(selected.receipt_sha256, self.fixture.receipt_sha256)
        self.assertEqual(dict(selected.artifact_sha256), self.expected)
        self.assertEqual(os.readlink(self.fixture.root / "current"), current)
        self.assertFalse((self.destination / "current").exists())
        self.assertFalse((self.destination / "bin").exists())

    def complete_generation(self):
        fixture,inputs = self.fixture.complete_inputs()
        outcome = self.fixture.complete_stage(fixture,inputs)
        self.fixture.receipt = outcome.receipt
        self.fixture.generation = outcome.generation
        self.fixture.directory = self.fixture.root / "generations" / outcome.generation
        self.fixture.receipt_path = self.fixture.directory / "receipt.json"
        self.fixture.receipt_sha256 = outcome.receipt_sha256
        self.expected = dict(outcome.receipt["artifacts"])
        return inputs

    def test_optional_control_pin_is_strict_and_preserves_three_artifact_interface(self):
        legacy = SimpleNamespace(**{name+"_sha256":value for name,value in self.expected.items()})
        self.assertEqual(restart.expected_artifacts(legacy),self.expected)
        legacy.control_sha256 = None
        self.assertEqual(restart.expected_artifacts(legacy),self.expected)
        legacy.control_sha256 = "b"*64
        self.assertEqual(restart.expected_artifacts(legacy),{**self.expected,"control":"b"*64})
        for value in ("",True,64,1.0,"A"*64,"b"*63,"../control"):
            with self.subTest(value=value):
                legacy.control_sha256 = value
                with self.assertRaisesRegex(restart.RestartError,"^expected-artifact-digest-shape$"):
                    restart.expected_artifacts(legacy)
        common = ["--stage-root",str(self.fixture.root),"--generation",self.fixture.generation,
            "--receipt-sha256",self.fixture.receipt_sha256,"--session","/declared/session",
            "--bus","/declared/bus","--keyring","/declared/keyring",
            "--tool-manifest","/declared/native.json"]
        for name,value in self.expected.items():
            common.extend(["--"+name+"-sha256",value])
        self.assertEqual(restart.expected_artifacts(restart.parser().parse_args(common)),self.expected)
        self.assertEqual(restart.expected_artifacts(restart.parser().parse_args(
            common+["--control-sha256","b"*64])),{**self.expected,"control":"b"*64})

    def test_complete_carrier_binds_four_inputs_control_and_genuine_qt_namespace_without_current(self):
        self.complete_generation()
        original = self.fixture.receipt_path.read_bytes()
        current = self.fixture.root / "current"
        current.unlink()
        current.symlink_to("/unrelated/not-selected")
        selected = self.carrier()
        self.assertEqual(dict(selected.artifact_sha256),self.expected)
        self.assertEqual(selected.control,selected.directory / "bin/omux-control")
        self.assertEqual((selected.directory / "receipt.json").read_bytes(),original)
        self.assertEqual((selected.directory / "source/control").read_bytes(),
            (self.fixture.directory / "source/control").read_bytes())
        loader = self.fixture.receipt["runtime"]["details"]["qt"]["loader"]
        self.assertEqual((selected.directory / "runtime" / loader).stat().st_mode & 0o777,0o700)
        self.assertEqual(os.readlink(current),"/unrelated/not-selected")
        facts = restart.restart_facts(selected.generation,selected.receipt_sha256,self.expected,
            startup_revision_delta=3)
        self.assertEqual(facts["artifacts"],self.expected)
        for field in ("browserReloaded","nativeContinuityProved","serviceActivated",
            "providerAccess","liveExecutableAttributed","atomicExecutionWitness"):
            self.assertFalse(facts[field])

    def test_complete_carrier_refuses_missing_wrong_control_pin_and_changed_qt_before_destination(self):
        self.complete_generation()
        complete = self.expected.copy()
        for expected in ({name:value for name,value in complete.items() if name != "control"},
                {**complete,"control":"0"*64}):
            self.expected = expected
            with self.assertRaisesRegex(generation.GenerationError,"source-artifact-mismatch"):
                self.carrier()
            self.assertFalse(self.destination.exists())
        self.expected = complete
        qt = self.fixture.receipt["runtime"]["details"]["qt"]
        loader = self.fixture.directory / "runtime" / qt["loader"]
        loader.chmod(0o600)
        self.fixture.repin(update_inventory=True)
        with self.assertRaisesRegex(generation.GenerationError,"control-runtime-binding"):
            self.carrier()
        self.assertFalse(self.destination.exists())
        loader.chmod(0o700)
        control = self.fixture.directory / "source/control"
        control.write_bytes(control.read_bytes()+b"unselected structural ELF tail")
        self.fixture.repin(update_inventory=True)
        with self.assertRaisesRegex(generation.GenerationError,"generation-source-binding"):
            self.carrier()
        self.assertFalse(self.destination.exists())

    def test_actual_outer_main_propagates_four_pins_to_child_and_refuses_wrong_pin_before_launch(self):
        self.complete_generation()
        args,_ = self.declared_wrappers()
        args.stage_root,args.generation,args.receipt_sha256,args.inside = (
            self.fixture.root,self.fixture.generation,self.fixture.receipt_sha256,None)
        for name,value in self.expected.items():
            setattr(args,name+"_sha256",value)
        manifest_sha = generation.digest(args.tool_manifest.read_bytes())
        facts = restart.restart_facts(args.generation,args.receipt_sha256,self.expected,
            manifest_sha,startup_revision_delta=3)
        # Actual input qualification (apart from synthetic immutable-store
        # availability), private environment, carrier and closed result join
        # remain enabled. Only child process/collection are injected; no process
        # or service is launched, and these modeled replies are not live proof.
        with mock.patch.object(restart,"parser") as selected_parser, \
                mock.patch.object(restart,"available_store_executable"), \
                mock.patch.object(restart.subprocess,"Popen") as launched, \
                mock.patch.object(restart,"collect",return_value=(0,json.dumps(facts).encode(),b"")), \
                mock.patch.object(restart.sys,"stdout",new_callable=io.StringIO) as output:
            selected_parser.return_value.parse_args.return_value = args
            self.assertEqual(restart.main(),0)
            argv = launched.call_args.args[0]
            self.assertEqual(argv.count("--control-sha256"),1)
            for name,value in self.expected.items():
                self.assertEqual(argv[argv.index("--"+name+"-sha256")+1],value)
            self.assertEqual(generation.parse(output.getvalue()),facts)
            launched.reset_mock()
            args.control_sha256 = "0"*64
            with self.assertRaisesRegex(generation.GenerationError,"source-artifact-mismatch"):
                restart.main()
            launched.assert_not_called()

    def test_inner_complete_generation_is_checked_before_private_keyring_or_daemon_launch(self):
        self.complete_generation()
        with tempfile.TemporaryDirectory(prefix="omux-g-",dir="/tmp") as temporary:
            root = Path(temporary)
            selected = restart.carrier(self.fixture.root,self.fixture.generation,
                self.fixture.receipt_sha256,self.expected,root / "carrier")
            environment = restart.private_environment(root)
            environment["DBUS_SESSION_BUS_ADDRESS"] = "unix:abstract=omux-selected-"+root.name
            args = SimpleNamespace(stage_root=root / "carrier",generation=selected.generation,
                receipt_sha256=selected.receipt_sha256,keyring=Path("/declared/unexecuted-keyring"))
            loader = self.fixture.receipt["runtime"]["details"]["qt"]["loader"]
            (selected.directory / "runtime" / loader).chmod(0o600)
            with mock.patch.dict(os.environ,environment,clear=True), \
                    mock.patch.object(restart.subprocess,"Popen") as launched:
                with self.assertRaises(generation.GenerationError):
                    restart.inside(args,root,self.expected)
                launched.assert_not_called()

    def test_carrier_never_consults_mutable_current(self):
        current = self.fixture.root / "current"
        current.unlink()
        current.symlink_to("generations/" + "d" * 32)
        selected = self.carrier()
        self.assertEqual(selected.generation, self.fixture.generation)
        self.assertEqual(os.readlink(current), "generations/" + "d" * 32)

    def test_preexisting_destination_is_preserved(self):
        self.destination.mkdir(mode=0o700)
        unrelated = self.destination / "unrelated"
        unrelated.write_bytes(b"preserve fixture-owned unrelated data")
        with self.assertRaises(FileExistsError):
            self.carrier()
        self.assertEqual(unrelated.read_bytes(), b"preserve fixture-owned unrelated data")

    def test_carrier_revalidation_rejects_source_drift_after_selection(self):
        original_select = generation.select_generation
        calls = 0

        def select_then_modify(*args, **kwargs):
            nonlocal calls
            selected = original_select(*args, **kwargs)
            calls += 1
            if calls == 1:
                (self.fixture.directory / "runtime/bin/omuxd").write_bytes(
                    b'#!/bin/sh\nexec "../../current/lib/omuxd" "$@"\n')
            return selected

        with mock.patch.object(generation, "select_generation", side_effect=select_then_modify):
            with self.assertRaisesRegex(generation.GenerationError, "generation-inventory-mismatch"):
                self.carrier()
        self.assertEqual(calls, 1)

    def test_source_symlink_inserted_after_selection_is_not_followed(self):
        original_select = generation.select_generation
        calls = 0

        def select_then_link(*args, **kwargs):
            nonlocal calls
            selected = original_select(*args, **kwargs)
            calls += 1
            if calls == 1:
                path = self.fixture.directory / "runtime/bin/omuxd"
                path.unlink()
                path.symlink_to(self.fixture.core)
            return selected

        with mock.patch.object(generation, "select_generation", side_effect=select_then_link):
            with self.assertRaises(OSError):
                self.carrier()

    def test_destination_directory_substitution_cannot_create_external_files(self):
        outside = self.fixture.base / "outside-carrier"
        outside.mkdir(mode=0o700)
        original_mkdir = os.mkdir
        substituted = False

        def mkdir_then_substitute(name, mode=0o777, *, dir_fd=None):
            nonlocal substituted
            original_mkdir(name, mode, dir_fd=dir_fd)
            if name == self.fixture.generation and dir_fd is not None:
                os.rmdir(name, dir_fd=dir_fd)
                os.symlink(str(outside), name, dir_fd=dir_fd)
                substituted = True

        with mock.patch.object(restart.os, "mkdir", side_effect=mkdir_then_substitute):
            with self.assertRaises(OSError):
                self.carrier()
        self.assertTrue(substituted)
        self.assertEqual(list(outside.iterdir()), [])

    def test_private_environment_discards_ambient_credentials_and_configuration(self):
        root = self.fixture.base / "private"
        root.mkdir(mode=0o700)
        with mock.patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "ambient-fixture-bus",
                                         "LD_PRELOAD": "ambient-fixture-library", "OMUX_INSTANCE": "default"}):
            environment = restart.private_environment(root)
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", environment)
        self.assertNotIn("LD_PRELOAD", environment)
        self.assertEqual(environment["OMUX_INSTANCE"], "dev")
        for variable, child in restart.PRIVATE_DIRECTORIES:
            self.assertEqual(environment[variable], str(root / child))
            descriptor = generation.open_root(root / child)
            os.close(descriptor)

    def test_inner_context_cannot_use_an_ambient_home_or_state(self):
        args = SimpleNamespace(stage_root=self.fixture.root)
        with self.assertRaisesRegex(restart.RestartError, "private-fixture-root"):
            restart.inside(args, self.fixture.base, self.expected)

    def test_receipt_keeps_restart_separate_from_product_continuity(self):
        facts = restart.restart_facts(self.fixture.generation, self.fixture.receipt_sha256, self.expected,
                                      startup_revision_delta=3)
        self.assertTrue(facts["daemonRestarted"])
        self.assertEqual(facts["cleanShutdowns"], 2)
        self.assertEqual(facts["startupRevisionDelta"], 3)
        for name in ("browserReloaded", "nativeContinuityProved", "serviceActivated", "providerAccess",
                     "liveExecutableAttributed", "atomicExecutionWitness"):
            self.assertFalse(facts[name])
        encoded = json.dumps(facts).encode()
        self.assertLessEqual(len(encoded), restart.MAX_RECEIPT_OUTPUT)
        self.assertNotIn(str(self.fixture.root).encode(), encoded)

    def empty_snapshot(self, revision=3):
        return dict(revision=revision, sources=[], accounts=[], grants=[], observations=[])

    def test_empty_authority_restart_allows_increasing_lifecycle_revision(self):
        initial = self.empty_snapshot()
        initial["captured_at"] = 100
        baseline = restart.empty_snapshot_revision(initial)
        for delta in (1, 3, 7, restart.MAX_REVISION - baseline):
            with self.subTest(delta=delta):
                restarted = self.empty_snapshot(baseline + delta)
                restarted["captured_at"] = 200
                self.assertEqual(restart.empty_snapshot_revision(restarted, baseline), baseline + delta)
                facts = restart.restart_facts(self.fixture.generation, self.fixture.receipt_sha256, self.expected,
                                              startup_revision_delta=delta)
                self.assertEqual(facts["startupRevisionDelta"], delta)
        self.assertEqual(initial, dict(revision=3, sources=[], accounts=[], grants=[], observations=[], captured_at=100))

    def test_revision_shape_has_its_own_redacted_diagnostic(self):
        for revision in (None, True, 3.0, -1, 1 << 64):
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(restart.RestartError, "^private-snapshot-revision$"):
                    restart.empty_snapshot_revision(self.empty_snapshot(revision))
        snapshot = self.empty_snapshot()
        del snapshot["revision"]
        with self.assertRaisesRegex(restart.RestartError, "^private-snapshot-revision$"):
            restart.empty_snapshot_revision(snapshot)

    def assert_authority_field_refused(self, field):
        for value in (None, {}, [{"fixturePrivateValue": "unprojected-fixture-content"}]):
            with self.subTest(value=value):
                snapshot = self.empty_snapshot(6)
                snapshot[field] = value
                with self.assertRaises(restart.RestartError) as caught:
                    restart.empty_snapshot_revision(snapshot, 3)
                self.assertEqual(caught.exception.reason, "private-snapshot-" + field)
                with mock.patch.object(restart, "PHASE", "selected-empty-authority"):
                    diagnostic = restart.failure_diagnostic(caught.exception)
                self.assertEqual(diagnostic["reason"], "private-snapshot-" + field)
                self.assertNotIn("unprojected-fixture-content", json.dumps(diagnostic))
        snapshot = self.empty_snapshot(6)
        del snapshot[field]
        with self.assertRaisesRegex(restart.RestartError, "^private-snapshot-" + field + "$"):
            restart.empty_snapshot_revision(snapshot, 3)

    def test_sources_drift_has_its_own_redacted_diagnostic(self):
        self.assert_authority_field_refused("sources")

    def test_accounts_drift_has_its_own_redacted_diagnostic(self):
        self.assert_authority_field_refused("accounts")

    def test_grants_drift_has_its_own_redacted_diagnostic(self):
        self.assert_authority_field_refused("grants")

    def test_observations_drift_has_its_own_redacted_diagnostic(self):
        self.assert_authority_field_refused("observations")

    def test_reset_same_and_regressed_revisions_are_refused(self):
        for revision in (0, 2, 3):
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(restart.RestartError, "^private-restart-revision-not-advanced$"):
                    restart.empty_snapshot_revision(self.empty_snapshot(revision), 3)

    def test_observed_revision_delta_receipt_is_positive_bounded_and_integer(self):
        for delta in (None, True, 3.0, -1, 0, 1 << 64):
            with self.subTest(delta=delta):
                with self.assertRaisesRegex(restart.RestartError, "^private-restart-revision-delta$"):
                    restart.restart_facts(self.fixture.generation, self.fixture.receipt_sha256, self.expected,
                                          startup_revision_delta=delta)

    def test_failure_diagnostic_exposes_only_finite_phase_and_reason(self):
        with mock.patch.object(restart, "PHASE", "selected-daemon-startup"):
            value = restart.failure_diagnostic(OSError("arbitrary private fixture diagnostic"))
        self.assertEqual(value["phase"], "selected-daemon-startup")
        self.assertEqual(value["reason"], "private-io-refused")
        self.assertNotIn("arbitrary", json.dumps(value))
        error = restart.RestartError("unexpected diagnostic text")
        self.assertEqual(restart.failure_diagnostic(error)["reason"], "fixture-refused")

    def test_declared_generated_wrappers_are_bound_to_pinned_manifest(self):
        args, _ = self.declared_wrappers()
        wrappers = {name: getattr(args, name) for name, _, _ in restart.PRIVATE_TOOLS}
        # These are modeled immutable-store paths; actual availability remains
        # mandatory in the separately declared live fixture.
        with mock.patch.object(restart, "available_store_executable") as available:
            restart.qualify_private_tools(args)
        self.assertEqual(available.call_count, 4)
        for name, path in wrappers.items():
            self.assertEqual(getattr(args, name), path)
            self.assertFalse(str(path).startswith("/nix/store/"))
        self.assertEqual(args.tool_manifest_sha256, generation.digest(args.tool_manifest.read_bytes()))

    def test_runfile_alias_resolves_to_wrapper_without_backend_substitution(self):
        args, _ = self.declared_wrappers()
        alias = self.fixture.base / "session-runfile-alias"
        alias.symlink_to(args.session)
        args.session = alias
        with mock.patch.object(restart, "available_store_executable"):
            restart.qualify_private_tools(args)
        self.assertEqual(args.session.name, "dbus_run_session")
        self.assertEqual(args.session.parent.name, "tool_wrappers")

    def test_arbitrary_wrapper_location_is_refused(self):
        args, _ = self.declared_wrappers()
        wrong = self.fixture.base / "undeclared-session"
        wrong.write_bytes(args.session.read_bytes())
        wrong.chmod(0o700)
        args.session = wrong
        with mock.patch.object(restart, "available_store_executable"):
            with self.assertRaisesRegex(restart.RestartError, "declared-private-tool"):
                restart.qualify_private_tools(args)

    def test_extra_wrapper_environment_or_mutable_backend_is_refused(self):
        args, manifest = self.declared_wrappers()
        original = args.keyring.read_bytes()
        args.keyring.write_bytes(original.replace(b"set -eu\n", b"set -eu\nexport OMUX_INSTANCE=default\n"))
        with mock.patch.object(restart, "available_store_executable"):
            with self.assertRaisesRegex(restart.RestartError, "declared-private-tool"):
                restart.qualify_private_tools(args)
        args.keyring.write_bytes(original)
        manifest["tools"]["gnome_keyring_daemon"] = "/unqualified/bin/gnome-keyring-daemon"
        args.tool_manifest.write_text(json.dumps(manifest))
        with mock.patch.object(restart, "available_store_executable"):
            with self.assertRaisesRegex(restart.RestartError, "declared-private-tool"):
                restart.qualify_private_tools(args)

    def test_duplicate_manifest_fields_are_refused(self):
        args, _ = self.declared_wrappers()
        data = args.tool_manifest.read_bytes()
        args.tool_manifest.write_bytes(b'{"system":"aarch64-linux",' + data[1:])
        with mock.patch.object(restart, "available_store_executable"):
            with self.assertRaisesRegex(generation.GenerationError, "duplicate-json-field"):
                restart.qualify_private_tools(args)

    def test_earlier_wrapper_drift_during_later_read_is_refused(self):
        args, _ = self.declared_wrappers()
        original_read = restart.declared_bytes
        changed = False

        def read_then_modify(path, *positional, **keywords):
            nonlocal changed
            value = original_read(path, *positional, **keywords)
            if Path(path) == args.bus and not changed:
                args.session.write_bytes(b'#!/bin/sh\nexec "mutable-current" "$@"\n')
                changed = True
            return value

        with mock.patch.object(restart, "available_store_executable"), \
                mock.patch.object(restart, "declared_bytes", side_effect=read_then_modify):
            with self.assertRaisesRegex(restart.RestartError, "declared-tool-wrapper-changed"):
                restart.qualify_private_tools(args)
        self.assertTrue(changed)


if __name__ == "__main__":
    unittest.main()
