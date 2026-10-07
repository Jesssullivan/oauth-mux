"""Injected local-worker boundaries; no units, browsers, displays or subprocesses."""
import hashlib
import json
import stat
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yoga_operator_launch as launch
import yoga_operator_coordinator as support


class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.proof = "12345678-1234-4123-8123-123456789012"
        self.root = "/srv/omux-proof/" + self.proof
        self.snapshot = {"device": 4, "inode": 5, "uid": 1000, "mode": 0o700, "pid": 100, "start_ticks": 50}
        self.command = ["/nix/store/" + "a" * 32 + "-bazel/bin/bazel", "--output_base=/srv/cache", "run", support.LABEL]
        self.paths = {name: "/srv/inputs/" + name for name in support.INPUTS}
        self.fresh_coordinator()

    def fresh_coordinator(self):
        self.coordinator = Mock()
        self.coordinator.proof_id = self.proof
        self.coordinator.root = self.root
        self.coordinator.uid = 1000
        self.coordinator.deadline = 1000 * 10**9
        self.coordinator.now = lambda: 1
        self.coordinator.descriptor = 7
        self.coordinator.operator_descriptor = 8
        self.coordinator.admitted = False
        self.coordinator.digests = {name: "a" * 64 for name in support.INPUTS}
        self.coordinator.vault_wrapper_authority = {name: {'path': '/srv/yoga-meta/' + ('native.json' if name == 'nativeManifest' else name), 'sha256': 'b' * 64}
            for name in support.WRAPPER_EVIDENCE}
        self.coordinator.vault_wrapper_authority['registeredNativeManifest']['path'] = '/nix/store/' + 'b' * 32 + '-native.json'
        self.coordinator.vault_wrapper_authority['controllerTools'] = {name: '/nix/store/' + 'a' * 32 + '-controller/' + name for name in support.CONTROLLER_TOOLS}
        self.coordinator.source_root = '/srv/yoga-source'
        self.coordinator.source_files_sha256 = {name: 'c' * 64 for name in support.WRAPPER_SOURCE_FILES}
        self.coordinator.wrapper_source_sha256 = dict(self.coordinator.source_files_sha256)
        self.coordinator.witness = {"snapshot": self.snapshot}

    def prepare(self):
        return launch.prepare_worker(self.coordinator, self.command, self.paths, host_home="/home/operator", gid=1000)

    def ready(self):
        self.prepare()
        return {"schemaVersion": 1, "scope": "yoga-guard-worker-ready-v1", "proofId": self.proof,
            "planSha256": self.coordinator.launch_plan_sha256, "commandSha256": launch.command_digest(self.command),
            "pid": 200, "startTicks": 300, "coordinator": {"pid": 200, "cgroupPath": "/sys/fs/cgroup/omux-execution-" + self.proof + ".service",
                "device": 2, "inode": 3}, "displaySnapshot": self.snapshot, "inputSha256": self.coordinator.digests,
            "namespaceChecked": True,
            "vaultWrapperAuthoritySha256": hashlib.sha256(launch.canonical(self.coordinator.vault_wrapper_authority)).hexdigest()}

    def test_command_rejects_other_target_and_private_arguments(self):
        for command in (["bazel", "run", support.LABEL], self.command + ["--"],
                        self.command[:-1] + ["//:other"], self.command[:-1] + ["//:other", support.LABEL]):
            with self.assertRaises(launch.LaunchError):
                launch.command_digest(command)
        self.assertEqual(len(launch.command_digest(self.command)), 64)

    def test_prepare_requires_guard_pipe_before_private_plan(self):
        self.coordinator.operator_descriptor = None
        with self.assertRaises(launch.LaunchError):
            self.prepare()
        self.coordinator.write.assert_not_called()
        self.coordinator.operator_descriptor = 8
        self.prepare()
        name, payload = self.coordinator.write.call_args.args
        self.assertEqual(name, "worker-plan.json")
        self.assertEqual(json.loads(payload)["inputSha256"], self.coordinator.digests)
        self.assertEqual(json.loads(payload)['vaultWrapperAuthority'], self.coordinator.vault_wrapper_authority)
        self.assertNotIn("operatorDescriptor", json.loads(payload))

    def test_ready_binds_pid_cgroup_and_full_display_snapshot(self):
        ready = self.ready()
        with patch.object(launch, "bounded_read", return_value=launch.canonical(ready)), \
                patch.object(launch.display, "pid_start", return_value=300), \
                patch.object(Path, "stat", return_value=SimpleNamespace(st_dev=2, st_ino=3)), \
                patch.object(Path, "read_text", return_value="0::/omux-execution-" + self.proof + ".service\n"):
            value, digest = launch.read_worker_ready(self.coordinator, expected_pid=200)
            self.assertEqual(value, ready)
            self.assertEqual(digest, hashlib.sha256(launch.canonical(ready)).hexdigest())
            for changed in (dict(ready, pid=201), dict(ready, displaySnapshot=dict(self.snapshot, start_ticks=51)),
                            dict(ready, inputSha256={}), dict(ready, namespaceChecked=False),
                            dict(ready, vaultWrapperAuthoritySha256='0' * 64)):
                with patch.object(launch, "bounded_read", return_value=launch.canonical(changed)):
                    with self.assertRaises(launch.LaunchError):
                        launch.read_worker_ready(self.coordinator, expected_pid=200)

    def test_expired_ready_does_not_read_or_wait(self):
        self.prepare()
        self.coordinator.now = lambda: self.coordinator.deadline
        with patch.object(launch, "bounded_read") as reader, patch.object(launch.time, "sleep") as sleeper:
            with self.assertRaises(launch.LaunchError):
                launch.read_worker_ready(self.coordinator, expected_pid=200)
            reader.assert_not_called(); sleeper.assert_not_called()

    def worker_model(self, *, drift_at=None):
        self.fresh_coordinator(); self.prepare()
        plan = self.coordinator.launch_plan
        ready = []
        own = {'pid': 200, 'cgroupPath': '/sys/fs/cgroup/' + plan['unit'], 'device': 2, 'inode': 3}
        session = {'schemaVersion': 1, 'scope': 'yoga-operator-local-toolbar-v1', 'hostAlias': 'yoga',
            'proofId': self.proof, 'operatorAccess': 'local-console', 'deadlineMonotonicNs': plan['deadlineNs'],
            'coordinator': own, 'inputSha256': self.coordinator.digests,
            'vaultWrapperAuthority': self.coordinator.vault_wrapper_authority,
            'wrapperSourceSha256': self.coordinator.wrapper_source_sha256,
            'display': {'adapter': 'qualified-wayland-unix', 'socketPath': self.root + '/wayland.sock',
                'socketDevice': self.snapshot['device'], 'socketInode': self.snapshot['inode'], 'serverPid': self.snapshot['pid']}}
        session_bytes = launch.canonical(session)
        def read(directory, name, uid):
            if name == 'worker-plan.json': return launch.canonical(plan)
            if name == 'session.json': return session_bytes
            self.assertEqual(name, 'go')
            return launch.canonical({'schemaVersion': 1, 'scope': 'yoga-guard-go-v1', 'proofId': self.proof,
                'planSha256': self.coordinator.launch_plan_sha256,
                'readySha256': hashlib.sha256(ready[0]).hexdigest(),
                'sessionSha256': hashlib.sha256(session_bytes).hexdigest()})
        def write(directory, name, payload):
            if name == 'worker-ready.json': ready.append(payload)
        held = Mock()
        if drift_at is not None:
            held.check.side_effect = [None] * (drift_at - 1) + [ValueError('modeled authority drift')]
        import guard_yoga_profile as guard
        import yoga_proof_inputs as inputs
        with patch.dict(launch.os.environ, {'OMUX_EXECUTION_GUARD': self.root,
                'OMUX_YOGA_WORKER_PLAN_SHA256': self.coordinator.launch_plan_sha256}), \
                patch.object(launch.display, 'parent_descriptor', return_value=7), \
                patch.object(launch.os, 'getuid', return_value=1000), patch.object(launch.os, 'getgid', return_value=1000), \
                patch.object(launch.os, 'getpid', return_value=200), patch.object(launch.os, 'close') as closed, \
                patch.object(launch, 'bounded_read', side_effect=read), patch.object(launch, '_write', side_effect=write), \
                patch.object(launch, 'namespace_snapshot', return_value=own), \
                patch.object(launch.display, 'inspect_endpoint', return_value=self.snapshot), \
                patch.object(launch.display, 'pid_start', return_value=300), \
                patch.object(launch.time, 'monotonic_ns', return_value=1), \
                patch.object(inputs, 'check_inputs', return_value=self.coordinator.digests), \
                patch.object(guard, 'wrapper_capture', return_value=held) as capture, \
                patch.object(launch, '_execute', return_value=0) as execute:
            if drift_at is None: self.assertEqual(launch.run_worker(self.root, self.command), 0)
            else:
                with self.assertRaises(ValueError): launch.run_worker(self.root, self.command)
            held.close.assert_called_once(); closed.assert_called_once_with(7)
            capture.assert_called_once()
            self.assertEqual(capture.call_args.args[1], plan['deadlineNs'])
            return held.check.call_count, execute.call_count, len(ready)

    def test_worker_holds_authority_before_ready_before_go_and_after_workload(self):
        self.assertEqual(self.worker_model(), (3, 1, 1))

    def test_worker_authority_drift_refuses_pre_ready_pre_launch_and_post_workload(self):
        for fence, expected in ((1, (1, 0, 0)), (2, (2, 0, 1)), (3, (3, 1, 1))):
            with self.subTest(fence=fence): self.assertEqual(self.worker_model(drift_at=fence), expected)

    def test_go_requires_owned_unit_and_no_writable_binds(self):
        ready = self.ready()
        self.coordinator.worker_ready = ready
        self.coordinator.worker_ready_sha256 = "b" * 64
        props = dict(support.LIMITS, Id=self.coordinator.launch_plan["unit"], ActiveState="active", MainPID="200",
            ControlGroup=ready["coordinator"]["cgroupPath"].removeprefix("/sys/fs/cgroup"), User="1000", Group="1000",
            PrivateUsers="no", CapabilityBoundingSet="", AmbientCapabilities="", StandardInput="null")
        self.coordinator.admit.return_value = "c" * 64
        self.coordinator.write.reset_mock()
        for properties, writable in ((dict(props, MainPID="201"), []), (props, ["/srv/other"]), (dict(props, StandardInput="tty"), [])):
            with self.assertRaises(launch.LaunchError):
                launch.admit_worker(self.coordinator, ready, properties=properties, source_snapshot=self.snapshot,
                    effective_readonly_binds=[], effective_writable_binds=writable)
        self.coordinator.admit.assert_not_called(); self.coordinator.write.assert_not_called()
        with patch.object(launch.display, "pid_start", return_value=300):
            launch.admit_worker(self.coordinator, ready, properties=props, source_snapshot=self.snapshot,
                effective_readonly_binds=["/source:/destination"], effective_writable_binds=[])
        self.assertEqual(self.coordinator.write.call_args.args[0], "go")

    def test_bounded_reader_fifo_refuses_before_read(self):
        with patch.object(launch.os, "open", return_value=9), \
                patch.object(launch.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_uid=1000)), \
                patch.object(launch.os, "read") as reader, patch.object(launch.os, "close") as close:
            with self.assertRaises(launch.LaunchError):
                launch.bounded_read(7, "worker-plan.json", 1000)
            reader.assert_not_called(); close.assert_called_once_with(9)

    def test_bounded_reader_detects_named_alias_replacement(self):
        fields = dict(st_mode=stat.S_IFREG | 0o600, st_uid=1000, st_dev=2, st_ino=3,
            st_nlink=1, st_size=2, st_mtime_ns=4, st_ctime_ns=5)
        with patch.object(launch.os, "open", return_value=9), patch.object(launch.os, "fstat", return_value=SimpleNamespace(**fields)), \
                patch.object(launch.os, "stat", return_value=SimpleNamespace(**dict(fields, st_ino=4))), \
                patch.object(launch.os, "read", side_effect=[b"{}", b""]), patch.object(launch.os, "close"):
            with self.assertRaises(launch.LaunchError):
                launch.bounded_read(7, "worker-plan.json", 1000)

    def test_no_allocation_or_child_after_expired_deadline(self):
        with patch.object(launch.time, "monotonic_ns", return_value=100), \
                patch.object(launch.selectors, "DefaultSelector") as selector, \
                patch.object(launch.subprocess, "Popen") as child:
            for deadline in (100, 99, True, 101.0):
                with self.assertRaises(launch.LaunchError):
                    launch._execute(self.command, Path(self.root), deadline)
            selector.assert_not_called(); child.assert_not_called()

    def test_namespace_refuses_identity_or_capabilities_before_children(self):
        self.prepare()
        plan = self.coordinator.launch_plan
        with patch.object(launch.display, "budget"), patch.object(launch.os, "getuid", return_value=1001), \
                patch.object(launch.os, "getgid", return_value=1000), patch.object(launch.subprocess, "Popen") as child:
            with self.assertRaises(launch.LaunchError):
                launch.namespace_snapshot(plan)
            child.assert_not_called()
        status = "Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nNoNewPrivs:\t1\nCapEff:\t1\nCapPrm:\t0\nCapAmb:\t0\n"
        with patch.object(launch.display, "budget"), patch.object(launch.os, "getuid", return_value=1000), \
                patch.object(launch.os, "getgid", return_value=1000), patch.object(Path, "read_text", return_value=status), \
                patch.object(launch.subprocess, "Popen") as child:
            with self.assertRaises(launch.LaunchError):
                launch.namespace_snapshot(plan)
            child.assert_not_called()

    def observations(self):
        # Each independent observation case owns a new admission lifecycle.
        self.fresh_coordinator()
        ready = self.ready()
        self.coordinator.worker_ready = ready
        self.coordinator.worker_ready_sha256 = "b" * 64
        self.coordinator.admitted = True
        self.coordinator.events = list(support.STATEMENTS)
        session = {"schemaVersion": 1, "scope": "yoga-operator-local-toolbar-v1", "hostAlias": "yoga", "proofId": self.proof,
            "operatorAccess": "local-console", "deadlineMonotonicNs": self.coordinator.deadline,
            "coordinator": ready["coordinator"], "inputSha256": self.coordinator.digests,
            'vaultWrapperAuthority': self.coordinator.vault_wrapper_authority,
            'wrapperSourceSha256': self.coordinator.wrapper_source_sha256,
            "display": {"adapter": "qualified-wayland-unix", "socketPath": self.root + "/wayland.sock",
                "socketDevice": 4, "socketInode": 5, "serverPid": 100}}
        session_bytes = launch.canonical(session)
        sha = hashlib.sha256(session_bytes).hexdigest()
        files = {"session.json": session_bytes, "go": launch.canonical({"schemaVersion": 1, "scope": "yoga-guard-go-v1",
            "proofId": self.proof, "planSha256": self.coordinator.launch_plan_sha256,
            "readySha256": self.coordinator.worker_ready_sha256, "sessionSha256": sha})}
        cases = []
        for case in support.STATEMENTS:
            interacted = case != "reload"
            human = {"schemaVersion": 1, "scope": "human-toolbar-attestation", "proofId": self.proof, "case": case,
                "toolbarOpened": True, "consentChecked": interacted, "connectClicked": interacted, "browserPromptSeen": interacted,
                "browserDecision": {"denial": "denied", "approval": "approved", "reload": "not_requested"}[case]}
            files[case + ".json"] = launch.canonical(human)
            cases.append({"scope": "yoga-toolbar-observed-case", "case": case, "browserVersion": "Chrome/147.0.7727.116",
                "initialGateObserved": True, "optionalPermissionApproved": case != "denial", "emptyBrowserMetadata": True,
                "outcome": {"denial": "permission_denied", "approval": "open_provider_tab", "reload": "reload_gate_reset"}[case],
                "driverInteraction": False, "humanAttestationRequired": True,
                "operatorAttestationSha256": hashlib.sha256(files[case + ".json"]).hexdigest()})
        value = {"scope": "yoga-toolbar-local-observations", "proofId": self.proof, "extensionId": "a" * 32,
            "extensionVersion": "1.0", "channel": "development", "cases": cases, "providerAccess": False,
            "grantExport": False, "remoteExecution": False, "aggregateCleanupJoinRequired": True,
            "privateProfilesRemoved": True, "visibleSessionSha256": sha, "inputSha256": self.coordinator.digests}
        self.coordinator.finish.return_value = {"executionPassed": True, "operatorStatements": 3, "toolbarConsentProved": False}
        return files, value

    def join(self, files, value, **changes):
        files["workload.log"] = b"Bazel private diagnostic\n" + launch.canonical(value) + b"\n"
        with patch.object(launch, "bounded_read", side_effect=lambda directory, name, uid, **options: files[name]):
            return launch.finish_proof(self.coordinator, workload_exit=0, aggregate_empty=True, **changes)

    def test_join_requires_machine_results_and_bound_human_attestations(self):
        files, value = self.observations()
        result = self.join(files, value)
        self.assertTrue(result["machineObservationsJoined"])
        self.assertTrue(result["toolbarConsentProved"])
        self.assertEqual(result["humanGestureProvenance"], "operator-attested")
        for changed in (dict(value, proofId="another"), dict(value, inputSha256={}), dict(value, privateProfilesRemoved=False),
                        dict(value, providerAccess=True), dict(value, cases=[])):
            self.assertFalse(self.join(files, changed)["toolbarConsentProved"])

    def test_join_refuses_operator_hash_substitution_or_wrong_case(self):
        files, value = self.observations()
        value["cases"][0]["operatorAttestationSha256"] = "d" * 64
        self.assertFalse(self.join(files, value)["toolbarConsentProved"])
        files, value = self.observations()
        value["cases"].reverse()
        self.assertFalse(self.join(files, value)["toolbarConsentProved"])

    def test_exit_zero_and_empty_aggregate_without_observation_never_pass(self):
        files, value = self.observations()
        files["workload.log"] = b"Bazel exited zero\n"
        with patch.object(launch, "bounded_read", side_effect=lambda directory, name, uid, **options: files[name]):
            self.assertFalse(launch.finish_proof(self.coordinator, workload_exit=0, aggregate_empty=True)["executionPassed"])

    def test_duplicate_final_receipt_and_cleanup_failure_refuse(self):
        files, value = self.observations()
        files["workload.log"] = launch.canonical(value) + b"\n" + launch.canonical(value) + b"\n"
        with patch.object(launch, "bounded_read", side_effect=lambda directory, name, uid, **options: files[name]):
            self.assertFalse(launch.finish_proof(self.coordinator, workload_exit=0, aggregate_empty=True)["executionPassed"])
        self.coordinator.finish.return_value["executionPassed"] = False
        self.assertFalse(self.join(files, value)["toolbarConsentProved"])

    def test_progress_has_only_fixed_categories_and_no_replay(self):
        self.coordinator.admitted = True
        self.coordinator.progress_records = []
        value = {"scope": "yoga-toolbar-progress", "case": "denial", "phase": "await-toolbar"}
        with patch.object(launch, "bounded_read", return_value=launch.canonical(value) + b"\n"):
            self.assertEqual(launch.read_progress(self.coordinator), [value])
            self.assertEqual(launch.read_progress(self.coordinator), [])
        for changed in (dict(value, cookie="not-authorized"), dict(value, phase="arbitrary"), dict(value, case="other")):
            with self.assertRaises(launch.LaunchError):
                launch.progress_record(launch.canonical(changed))
        self.assertIsNone(launch.progress_record(b"private diagnostic"))

    def test_final_join_uses_runner_normalized_attestation_hash(self):
        files, value = self.observations()
        for case in support.STATEMENTS:
            files[case + ".json"] = json.dumps(json.loads(files[case + ".json"]), sort_keys=True).encode("ascii")
        self.assertTrue(self.join(files, value)["toolbarConsentProved"])

    def test_progress_only_retries_same_object_append_race(self):
        self.coordinator.admitted = True
        for reason in ("plan_invalid", "deadline_exceeded", "worker_unavailable"):
            with patch.object(launch, "bounded_read", side_effect=launch.LaunchError(reason)):
                with self.assertRaises(launch.LaunchError):
                    launch.read_progress(self.coordinator)
        with patch.object(launch, "bounded_read", side_effect=launch.LaunchError("input_changed")):
            self.assertEqual(launch.read_progress(self.coordinator), [])

    def test_join_permission_values_match_actual_denial_approval_reload(self):
        files, value = self.observations()
        self.assertEqual([case["optionalPermissionApproved"] for case in value["cases"]], [False, True, True])
        self.assertTrue(self.join(files, value)["toolbarConsentProved"])
        for index in range(3):
            files, value = self.observations()
            value["cases"][index]["optionalPermissionApproved"] = not value["cases"][index]["optionalPermissionApproved"]
            self.assertFalse(self.join(files, value)["toolbarConsentProved"])


if __name__ == "__main__":
    unittest.main()
