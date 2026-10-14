"""Offline admission boundaries only; no selected/native/material/tool reads."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import execution_guard as guard
import guard_native_seed_plan_reserved as kernel
import guard_native_acquisition_inputs_reserved as source


class AdmissionModels(unittest.TestCase):
    def test_carrier_route_models_are_declared_finite_without_selected_input_envelope(self):
        expected=('//tools:guard_native_acquisition_inputs_reserved_test',
            '//tools:codex_native_carrier_material_test',
            '//tools:codex_native_carrier_material_declaration_test',
            '//tools:codex_native_carrier_downstream_test',
            '//tools:codex_native_acquisition_metadata_source_closure_test','//:docs_check')
        self.assertEqual(source.COHORTS[source.CARRIER_MODELS],expected)
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9):
            result=source.command(guard.bazel_command,'bazel',Path('/model/epoch'),
                ['test',*expected],source.CARRIER_MODELS,100*10**9,1300*10**9,
                source_commit='a'*40,source_dirty='false')
            self.assertEqual(tuple(result[-len(expected):]),expected)
            self.assertFalse(any(value.startswith('--test_env=OMUX_NATIVE_') for value in result))
            with self.assertRaises(ValueError):
                source.command(Mock(),'bazel',Path('/model/epoch'),
                    ['test',*expected,'//tools:codex_native_carrier_runtime_package'],
                    source.CARRIER_MODELS,100*10**9,1300*10**9)

    def test_carrier_package_has_distinct_outer_and_unchanged_inner_original_clock(self):
        entry=100*10**9;until=entry+1200*10**9
        self.assertEqual(source.COHORTS[source.CARRIER_PACKAGE],
            ('//tools:codex_native_carrier_runtime_package',))
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9):
            result=source.command(guard.bazel_command,'bazel',Path('/model/epoch'),
                ['test',*source.COHORTS[source.CARRIER_PACKAGE]],source.CARRIER_PACKAGE,
                entry,until,source_commit='a'*40,source_dirty='false')
            flags=[value for value in result if value.startswith('--test_env=OMUX_NATIVE_PACKAGE_')]
            self.assertEqual(flags,['--test_env=OMUX_NATIVE_PACKAGE_MODE='+source.PACKAGE,
                '--test_env=OMUX_NATIVE_PACKAGE_ENTRY_NS='+str(entry),
                '--test_env=OMUX_NATIVE_PACKAGE_DEADLINE_NS='+str(until)])
            with self.assertRaises(ValueError):
                source.command(Mock(),'bazel',Path('/model/epoch'),
                    ['test',*source.COHORTS[source.PACKAGE]],source.CARRIER_PACKAGE,entry,until)
        projection=source.projection(source.CARRIER_PACKAGE,entry,until,True,{})
        self.assertEqual(projection['scope'],'fixed-native-sdk-carrier-package-reserved-v1')
        self.assertIs(projection['compiler_qualified'],False)
        self.assertIs(projection['native_runtime_qualified'],False)

    def test_carrier_ordinary_is_separate_singleton_with_same_caps_and_clock(self):
        profile=source.CARRIER_ORDINARY;entry=100*10**9;until=entry+1200*10**9
        self.assertEqual(source.COHORTS[profile],('//delivery:installed_carrier_native_tui_test',))
        self.assertIn(profile,kernel.WORKLOAD_PROFILES)
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9):
            command=source.command(guard.bazel_command,'bazel',Path('/model/epoch'),
                ['test',*source.COHORTS[profile]],profile,entry,until,
                source_commit='a'*40,source_dirty='false')
            self.assertEqual([v for v in command if v.startswith('--test_env=OMUX_NATIVE_ORDINARY_')],
                ['--test_env=OMUX_NATIVE_ORDINARY_MODE='+source.ORDINARY,
                 '--test_env=OMUX_NATIVE_ORDINARY_ENTRY_NS='+str(entry),
                 '--test_env=OMUX_NATIVE_ORDINARY_DEADLINE_NS='+str(until)])
            self.assertEqual([v for v in command if v.startswith('--repo_env=OMUX_NATIVE_ORDINARY_')],
                ['--repo_env=OMUX_NATIVE_ORDINARY_MODE='+source.ORDINARY,
                 '--repo_env=OMUX_NATIVE_ORDINARY_ENTRY_NS='+str(entry),
                 '--repo_env=OMUX_NATIVE_ORDINARY_DEADLINE_NS='+str(until)])
            with self.assertRaises(ValueError):source.command(Mock(),'bazel',Path('/model'),
                ['test',*source.COHORTS[source.ORDINARY]],profile,entry,until)
        self.assertEqual(source.properties({'PrivateNetwork':'yes'}),kernel.properties({'PrivateNetwork':'yes'}))
        self.assertIs(source.monitor,kernel.monitor)
        self.assertIs(source.cleanup_retained,kernel.cleanup_retained)
        self.assertEqual(kernel.envelope(entry,until),until-30*10**9)
        proof=source.projection(profile,entry,until,True,{})
        self.assertEqual(proof['scope'],'fixed-'+profile+'-v1')
        self.assertIs(proof['native_support'],False)
        self.assertIs(proof['live_handoff_proven'],False)

    def test_ordinary_is_one_real_tui_test_and_retains_original_clock(self):
        self.assertEqual(source.COHORTS[source.ORDINARY],('//delivery:installed_direct_native_tui_test',))
        entry=100*10**9;deadline=1300*10**9
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9),patch.object(guard,'graph_digest',return_value=('b'*64,{})):
            for profile,targets in source.COHORTS.items():
                command=source.command(guard.bazel_command,'bazel',Path('/model/epoch'),['test',*targets],
                    profile,entry,deadline,source_commit='a'*40,source_dirty='false')
                values=[v for v in command if v.startswith('--test_env=OMUX_NATIVE_ORDINARY_')]
                self.assertEqual(values,(['--test_env=OMUX_NATIVE_ORDINARY_MODE='+source.ORDINARY,
                    '--test_env=OMUX_NATIVE_ORDINARY_ENTRY_NS='+str(entry),
                    '--test_env=OMUX_NATIVE_ORDINARY_DEADLINE_NS='+str(deadline)] if profile in (source.ORDINARY,source.CARRIER_ORDINARY) else []))
        builder=Mock()
        for args in (['run',*source.COHORTS[source.ORDINARY]],
                     ['test',*source.COHORTS[source.ORDINARY],'//:docs_check']):
            with self.assertRaises(ValueError):source.command(builder,'bazel',Path('/model'),args,
                source.ORDINARY,entry,deadline)
        with patch.object(kernel.time,'monotonic_ns',return_value=deadline):
            with self.assertRaises(ValueError):source.command(builder,'bazel',Path('/model'),
                ['test',*source.COHORTS[source.ORDINARY]],source.ORDINARY,entry,deadline)
        builder.assert_not_called()


    def test_package_model_vector_and_private_configuration_refuse_before_io(self):
        profile=source.PACKAGE_MODELS
        vector=['test','//tools:guard_native_acquisition_inputs_reserved_test',
            '//tools:codex_fresh_native_receipt_scope_test','//:docs_check']
        self.assertEqual(['test',*source.COHORTS[profile]],vector)
        self.assertEqual(source.selected(profile,vector),{'PrivateNetwork':'yes'})
        self.assertTrue(source.request(self.args(profile),vector))
        with patch.object(guard,'immutable',side_effect=AssertionError('unexpected tool IO')) as tool, \
                patch.object(source,'Witness',side_effect=AssertionError('unexpected resident IO')) as resident:
            for arguments in (vector[:-1],vector+['//:omux'],list(reversed(vector)),
                    ['run',*vector[1:]],['test',*source.COHORTS[source.PACKAGE]],
                    vector+['--test_arg=/private/selection.json']):
                with self.assertRaises(ValueError):
                    guard.main(['--profile',profile,'--manager','system','--source-commit',
                        'a'*40,'--source-dirty','false','--',*arguments])
            for name,value in (('reuse_owned_cache',True),('source_dirty','true'),
                    ('resident_manifest',Path('/private/selection.json')),('native_mode','schema')):
                args=self.args(profile);setattr(args,name,value)
                with self.assertRaises(ValueError):source.request(args,vector)
            tool.assert_not_called();resident.assert_not_called()

    def test_package_models_use_real_offline_builder_and_original_clock_without_package_dispatch(self):
        profile=source.PACKAGE_MODELS;arguments=['test',*source.COHORTS[profile]]
        entry=100*10**9;deadline=1300*10**9
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9):
            result=source.command(guard.bazel_command,'bazel',Path('/model/epoch'),arguments,
                profile,entry,deadline,source_commit='a'*40,source_dirty='false')
        self.assertEqual(result[-3:],arguments[1:])
        for flag in ('--repository_disable_download','--repo_contents_cache=',
                '--sandbox_default_allow_network=false','--remote_executor=','--remote_cache=',
                '--nocache_test_results','--lockfile_mode=error'):
            self.assertIn(flag,result)
        self.assertFalse(any(value.startswith('--test_env=OMUX_NATIVE_') for value in result))
        builder=Mock()
        with patch.object(kernel.time,'monotonic_ns',return_value=deadline-30*10**9):
            with self.assertRaises(ValueError):
                source.command(builder,'bazel',Path('/model/epoch'),arguments,profile,entry,deadline)
        builder.assert_not_called()
        self.assertIn(profile,kernel.WORKLOAD_PROFILES)
        self.assertEqual(guard.workload_pids_observation(None,profile).expected_limit,480)
        projected=source.projection(profile,entry,deadline,True,{})
        self.assertEqual(projected['scope'],'fixed-'+profile+'-v1')
        for name in ('compiler_qualified','native_runtime_qualified','credential_acquisition',
                'provider_identity_proved','continuity_qualified','native_support'):
            self.assertIs(projected[name],False)

    def test_bridge_has_exact_producer_and_shared_closure_model_vectors(self):
        self.assertEqual(source.COHORTS[source.BRIDGE],('//tools:codex_native_acquisition_bridge_material_producer',))
        self.assertEqual(source.COHORTS[source.BRIDGE_MODELS],(
            '//tools:guard_native_acquisition_inputs_reserved_test',
            '//tools:codex_native_acquisition_bridge_material_test',
            '//tools:codex_native_acquisition_runtime_qualification_test','//:docs_check'))
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9), \
                patch.object(guard,'graph_digest',return_value=('b'*64,{})) as graph:
            result=source.command(guard.bazel_command,'bazel',Path('/model/epoch'),
                ['test',*source.COHORTS[source.BRIDGE]],source.BRIDGE,100*10**9,1300*10**9,
                source_commit='a'*40,source_dirty='false')
            values=[part for part in result if part.startswith('--test_env=OMUX_NATIVE_BRIDGE_')]
            self.assertEqual(values,['--test_env=OMUX_NATIVE_BRIDGE_MODE='+source.BRIDGE,
                '--test_env=OMUX_NATIVE_BRIDGE_ENTRY_NS='+str(100*10**9),
                '--test_env=OMUX_NATIVE_BRIDGE_DEADLINE_NS='+str(1300*10**9),
                '--test_env=OMUX_NATIVE_BRIDGE_SOURCE_COMMIT='+'a'*40,
                '--test_env=OMUX_NATIVE_BRIDGE_GRAPH_SHA256='+'b'*64])
            graph.assert_called_once()
        with patch.object(guard,'graph_digest',side_effect=AssertionError('no unadmitted source read')) as graph:
            with self.assertRaises(ValueError):
                source.command(Mock(),'bazel',Path('/model/epoch'),['test',*source.COHORTS[source.BRIDGE],'//:docs_check'],
                    source.BRIDGE,100*10**9,1300*10**9,source_commit='a'*40)
            graph.assert_not_called()

    def test_runtime_transports_only_the_original_admitted_clock(self):
        entry=100*10**9;deadline=1300*10**9
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9), patch.object(guard,'graph_digest',return_value=('b'*64,{})):
            for profile,targets in source.COHORTS.items():
                command=source.command(guard.bazel_command,'bazel',Path('/model/epoch'),
                    ['test',*targets],profile,entry,deadline,source_commit='a'*40,source_dirty='false')
                values=[v for v in command if v.startswith('--test_env=OMUX_NATIVE_RUNTIME_')]
                self.assertEqual(values,(['--test_env=OMUX_NATIVE_RUNTIME_MODE='+source.RUNTIME,
                    '--test_env=OMUX_NATIVE_RUNTIME_ENTRY_NS='+str(entry),
                    '--test_env=OMUX_NATIVE_RUNTIME_DEADLINE_NS='+str(deadline)]
                    if profile==source.RUNTIME else []))
            builder=Mock()
            for end,args in ((deadline+1,['test',*source.COHORTS[source.RUNTIME]]),
                    (deadline,['run',*source.COHORTS[source.RUNTIME]]),
                    (deadline,['test',*source.COHORTS[source.RUNTIME],'--test_env=OMUX_NATIVE_RUNTIME_ENTRY_NS=0'])):
                with self.assertRaises(ValueError):
                    source.command(builder,'bazel',Path('/model/epoch'),args,source.RUNTIME,entry,end)
            builder.assert_not_called()
        with patch.object(kernel.time,'monotonic_ns',return_value=1270*10**9):
            with self.assertRaises(ValueError):
                source.command(builder,'bazel',Path('/model/epoch'),['test',*source.COHORTS[source.RUNTIME]],
                    source.RUNTIME,entry,deadline)
        builder.assert_not_called()

    def test_package_transports_original_clock_only_after_exact_admission(self):
        entry=100*10**9;deadline=1300*10**9
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9), patch.object(guard,'graph_digest',return_value=('b'*64,{})):
            for profile,targets in source.COHORTS.items():
                arguments=['test',*targets]
                command=source.command(guard.bazel_command,'bazel',Path('/model/epoch'),arguments,
                    profile,entry,deadline,source_commit='a'*40,source_dirty='false')
                clock_flags=[part for part in command if part.startswith('--test_env=OMUX_NATIVE_PACKAGE_')]
                self.assertEqual(clock_flags,([
                    '--test_env=OMUX_NATIVE_PACKAGE_MODE='+source.PACKAGE,
                    '--test_env=OMUX_NATIVE_PACKAGE_ENTRY_NS='+str(entry),
                    '--test_env=OMUX_NATIVE_PACKAGE_DEADLINE_NS='+str(deadline)]
                    if profile in (source.PACKAGE,source.CARRIER_PACKAGE) else []))
            builder=Mock()
            for original_end,arguments in ((deadline-1,['test',*source.COHORTS[source.PACKAGE]]),
                    (deadline,['run',*source.COHORTS[source.PACKAGE]]),
                    (deadline,['test',*source.COHORTS[source.PACKAGE],'--test_env=OMUX_NATIVE_PACKAGE_ENTRY_NS=0'])):
                with self.assertRaises(ValueError):
                    source.command(builder,'bazel',Path('/model/epoch'),arguments,
                        source.PACKAGE,entry,original_end)
            builder.assert_not_called()
        with patch.object(kernel.time,'monotonic_ns',return_value=deadline-30*10**9):
            builder=Mock()
            with self.assertRaises(ValueError):
                source.command(builder,'bazel',Path('/model/epoch'),['test',*source.COHORTS[source.PACKAGE]],
                    source.PACKAGE,entry,deadline)
            builder.assert_not_called()

    def args(self, profile):
        return SimpleNamespace(profile=profile, manager="system", reuse_owned_cache=False,
            source_commit="a"*40, source_dirty="false", repository_cache=None, nixpkgs_source=None)

    def test_cross_profile_extra_selector_and_verb_refuse_before_tool_or_resident_io(self):
        with patch.object(guard,"immutable",side_effect=AssertionError("tool read")) as tool, \
             patch.object(source,"Witness",side_effect=AssertionError("resident read")) as resident:
            for profile, targets in source.COHORTS.items():
                expected=["test",*targets]
                self.assertTrue(source.request(self.args(profile),expected))
                for arguments in (["run",*targets],expected+["--test_arg=untrusted"],expected[:-1],
                                  expected+[targets[0]], ["test",*reversed(targets)] if len(targets)>1 else ["test","//tools:unrelated"], ["test","//tools:codex_retained_sdk_export"]):
                    with self.assertRaises(ValueError):
                        guard.main(["--profile",profile,"--manager","system","--source-commit",
                            "a"*40,"--source-dirty","false","--",*arguments])
                for other in source.PROFILES:
                    if other!=profile:
                        with self.assertRaises(ValueError): source.selected(other,expected)
                for name,value in (("manager","user"),("reuse_owned_cache",True),
                    ("source_dirty","true"),("source_commit","a"*39),
                    ("resident_manifest",Path("/model/private")),("native_mode","schema")):
                    args=self.args(profile);setattr(args,name,value)
                    with self.assertRaises(ValueError): source.request(args,expected)
            tool.assert_not_called();resident.assert_not_called()

    def test_real_guard_command_fresh_offline_and_original_cutoff(self):
        for profile,targets in source.COHORTS.items():
            arguments=["test",*targets]
            with patch.object(kernel.time,"monotonic_ns",return_value=200*10**9), patch.object(guard,"graph_digest",return_value=("b"*64,{})):
                command=source.command(guard.bazel_command,"bazel",Path("/model/epoch"),arguments,
                    profile,100*10**9,1300*10**9,source_commit='a'*40,source_dirty='false')
            self.assertEqual(command[-len(targets):],list(targets))
            for flag in ("--repository_disable_download","--repo_contents_cache=","--lockfile_mode=error",
                "--sandbox_default_allow_network=false","--remote_executor=","--remote_cache=",
                "--nocache_test_results","--output_base=/model/epoch/output-base"):
                self.assertIn(flag,command)
            builder=Mock()
            with patch.object(kernel.time,"monotonic_ns",return_value=1270*10**9):
                with self.assertRaises(ValueError):
                    source.command(builder,"bazel",Path("/model/epoch"),arguments,profile,100*10**9,1300*10**9,source_commit='a'*40,source_dirty='false')
                self.assertEqual(source.remaining(100*10**9,1300*10**9,cleanup=True),30)
            builder.assert_not_called()
            with patch.object(kernel.time,"monotonic_ns",return_value=1300*10**9):
                with self.assertRaises(ValueError): source.remaining(100*10**9,1300*10**9,cleanup=True)

    def test_shared_kernel_caps_and_projection_never_invent_input_or_sdk_proof(self):
        for name in ("Witness","WorkloadWitness","monitor","cleanup_retained","release_worker","remaining"):
            self.assertIs(getattr(source,name),getattr(kernel,name))
        caps=source.properties(guard.PROPERTIES)
        self.assertEqual((caps["MemoryMax"],caps["TasksMax"],caps["CPUQuotaPerSecUSec"]),
                         ("4026531840","480","1.9s"))
        for profile in source.PROFILES:
            self.assertIn(profile,kernel.WORKLOAD_PROFILES);self.assertNotIn(profile,kernel.PROFILES)
            self.assertEqual(guard.workload_pids_observation(None,profile).expected_limit,480)
            for verified in (None,False,True):
                value=source.projection(profile,100*10**9,1300*10**9,verified,{})
                self.assertIs(value['verified_after_cleanup'],verified)
                for name in ('query_tools_qualified','metadata_qualified','sdk_qualified','schema_qualified',
                             'compiler_qualified','native_runtime_qualified','continuity_qualified',
                             'custody_qualified','health_qualified','credential_acquisition',
                             'native_source_finalized','native_support','provider_identity_proved',
                             'live_handoff_proven','context_rotation','daemon_context_acquisition'):
                    self.assertIs(value[name],False)


    def test_carrier_capture_and_metadata_have_distinct_exact_admissions(self):
        expected = {
            source.SDK_CARRIER_SEAL: ("//tools:codex_native_sdk_carrier_seal_producer",),
            source.SDK_CARRIER_METADATA: ("//tools:codex_native_carrier_metadata_producer",),
        }
        for profile, targets in expected.items():
            self.assertEqual(source.COHORTS[profile], targets)
            vector = ["test", *targets]
            self.assertTrue(source.request(self.args(profile), vector))
            for other in expected:
                if other != profile:
                    with self.assertRaises(ValueError):
                        source.selected(other, vector)
            for dirty, cache in (("true", False), ("false", True)):
                args = self.args(profile)
                args.source_dirty, args.reuse_owned_cache = dirty, cache
                with self.assertRaises(ValueError):
                    source.request(args, vector)

    def test_carrier_repository_and_test_join_same_original_clock_source_epoch(self):
        entry, deadline = 100 * 10**9, 1300 * 10**9
        run = Path("/model/11111111-1111-4111-8111-111111111111")
        for profile in source.PROFILES:
            with patch.object(kernel.time, "monotonic_ns", return_value=200 * 10**9), \
                    patch.object(guard, "graph_digest", return_value=("b" * 64, {})):
                command = source.command(guard.bazel_command, "bazel", run,
                    ["test", *source.COHORTS[profile]], profile, entry, deadline,
                    source_commit="a" * 40, source_dirty="false")
            actual = {}
            for kind in ("repo", "test"):
                prefix = "--" + kind + "_env=OMUX_SDK_CARRIER_"
                flags = [part.split("=", 1)[1] for part in command if part.startswith(prefix)]
                actual[kind] = dict(part.split("=", 1) for part in flags)
                self.assertEqual(len(flags), len(actual[kind]))
            if profile not in (source.SDK_CARRIER_SEAL, source.SDK_CARRIER_METADATA):
                self.assertEqual(actual, {"repo": {}, "test": {}})
                continue
            expected = {
                "OMUX_SDK_CARRIER_MODE": profile,
                "OMUX_SDK_CARRIER_ENTRY_NS": str(entry),
                "OMUX_SDK_CARRIER_DEADLINE_NS": str(deadline),
                "OMUX_SDK_CARRIER_EPOCH": str(run),
                "OMUX_SDK_CARRIER_SOURCE_COMMIT": "a" * 40,
                "OMUX_SDK_CARRIER_GRAPH_SHA256": "b" * 64,
            }
            self.assertEqual(actual, {"repo": expected, "test": expected})
            self.assertEqual(int(actual["repo"]["OMUX_SDK_CARRIER_DEADLINE_NS"])
                - int(actual["repo"]["OMUX_SDK_CARRIER_ENTRY_NS"]), 1200 * 10**9)
            for flag in ("--repo_contents_cache=", "--remote_executor=", "--remote_cache=",
                    "--nocache_test_results", "--disk_cache=", "--repository_disable_download"):
                self.assertIn(flag, command)

    def test_carrier_deadline_or_extra_target_refuses_before_graph_and_dispatch(self):
        for profile in (source.SDK_CARRIER_SEAL, source.SDK_CARRIER_METADATA):
            vector = ["test", *source.COHORTS[profile]]
            builder = Mock()
            with patch.object(guard, "graph_digest", side_effect=AssertionError("unexpected graph IO")) as graph:
                with self.assertRaises(ValueError):
                    source.command(builder, "bazel", Path("/model/epoch"),
                        vector + ["--test_env=OMUX_SDK_CARRIER_ENTRY_NS=1"], profile,
                        100 * 10**9, 1300 * 10**9)
                with patch.object(kernel.time, "monotonic_ns", return_value=1270 * 10**9):
                    with self.assertRaises(ValueError):
                        source.command(builder, "bazel", Path("/model/epoch"), vector,
                            profile, 100 * 10**9, 1300 * 10**9)
                graph.assert_not_called()
            builder.assert_not_called()



if __name__ == "__main__": unittest.main()
