"""Offline admission boundaries only; no selected/native/material/tool reads."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import execution_guard as guard
import guard_native_seed_plan_reserved as kernel
import guard_native_metadata_sdk_reserved as source


class AdmissionModels(unittest.TestCase):
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
                                  expected+[targets[0]], ["test","//tools:codex_retained_sdk_export"]):
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
            with patch.object(kernel.time,"monotonic_ns",return_value=200*10**9):
                command=source.command(guard.bazel_command,"bazel",Path("/model/epoch"),arguments,
                    profile,100*10**9,1300*10**9)
            self.assertEqual(command[-len(targets):],list(targets))
            for flag in ("--repository_disable_download","--repo_contents_cache=","--lockfile_mode=error",
                "--sandbox_default_allow_network=false","--remote_executor=","--remote_cache=",
                "--nocache_test_results","--output_base=/model/epoch/output-base"):
                self.assertIn(flag,command)
            builder=Mock()
            with patch.object(kernel.time,"monotonic_ns",return_value=1270*10**9):
                with self.assertRaises(ValueError):
                    source.command(builder,"bazel",Path("/model/epoch"),arguments,profile,100*10**9,1300*10**9)
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
                             'compiler_qualified','native_runtime_qualified','continuity_qualified'):
                    self.assertIs(value[name],False)


if __name__ == "__main__": unittest.main()
