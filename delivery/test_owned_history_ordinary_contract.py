"""Finite ordinary clock/receipt/state refusals; genuine installed gates remain unrun."""
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch

import owned_history_runtime as proof
import owned_history_native_tui_runtime as reader
import test_installed_owned_history_native_tui as entry
import test_installed_native_tui as tui
import guard_native_owned_history_ordinary_reserved as guard


class OrdinaryContractModels(unittest.TestCase):
    def clock(self):
        start = 10**12
        return {"OMUX_NATIVE_ORDINARY_MODE":"native-acquisition-ordinary-tui-reserved",
            "OMUX_NATIVE_ORDINARY_ENTRY_NS":str(start),"OMUX_NATIVE_ORDINARY_DEADLINE_NS":str(start+1200*10**9)},start

    def test_actual_original_envelope_1170_and_canonical_expiry_no_reset(self):
        env,start=self.clock()
        first=entry.original_deadlines(env,clock_ns=lambda:start+1)
        self.assertEqual(first,(start,start+1200*10**9,(start+1170*10**9)/10**9))
        for changed in ({**env,"OMUX_NATIVE_ORDINARY_MODE":"standard"},
            {**env,"OMUX_NATIVE_ORDINARY_ENTRY_NS":"0"+str(start)},
            {**env,"OMUX_NATIVE_ORDINARY_DEADLINE_NS":str(start+1201*10**9)}):
            with self.assertRaises(ValueError): entry.original_deadlines(changed,clock_ns=lambda:start+1)
        with self.assertRaises(ValueError): entry.original_deadlines(env,clock_ns=lambda:start+1170*10**9)

    def test_ordinary_guard_exact_singleton_no_old_or_models_target(self):
        self.assertEqual(guard.ARGUMENTS,["test","//delivery:installed_owned_history_native_tui_test"])
        self.assertEqual(guard.selected(guard.PROFILE,guard.ARGUMENTS),{"PrivateNetwork":"yes"})
        for vector in (["test","//delivery:installed_retained_ordinary_native_tui_test"],
            guard.ARGUMENTS+["//:docs_check"],["build",guard.ARGUMENTS[1]],
            ["test","//tools:codex_native_owned_history_cli_producer"]):
            with self.assertRaises(ValueError): guard.selected(guard.PROFILE,vector)

    def test_actual_original_clock_builder_emits_only_old_clock_domain_values(self):
        env,start=self.clock()
        run=Path(guard.kernel.resident.PUBLIC_ROOTS[0])/"00000000-0000-0000-0000-000000000001"
        with patch.object(guard,"remaining",return_value=1200), \
                patch("guard_resident_enrollment_profile.repository_inputs"), \
                patch.object(guard,"runtime_seconds",return_value=840):
            result=guard.command(lambda *args,**kwargs:["locked-bazel","test",*guard.ARGUMENTS[1:]],
                "locked-bazel",run,guard.ARGUMENTS,guard.PROFILE,start,start+1200*10**9,graph_sha256="1"*64,
                source_commit="2"*40,source_dirty="false",repository_cache=None,nixpkgs_source=None,output_base=None)
        self.assertIn("--test_env=OMUX_NATIVE_ORDINARY_ENTRY_NS="+str(start),result)
        self.assertIn("--test_env=OMUX_NATIVE_ORDINARY_DEADLINE_NS="+str(start+1200*10**9),result)
        self.assertIn("--test_timeout=840",result)
        self.assertIn("--repo_env=OMUX_NATIVE_ORDINARY_MODE=native-acquisition-ordinary-tui-reserved",result)

    def test_unqualified_old_runtime_family_cannot_construct_reader(self):
        for value in (
            {"schema_version":1,"kind":"omux-direct-native-tui-package-pin-v1","package":{}},
            {"schema_version":1,"kind":proof.SELECTION_KIND,"status":"qualified-history13-cli-package","package":{}},
            {"schema_version":1,"kind":proof.SELECTION_KIND,"status":"PENDING-GENUINE-CLI-PACKAGE","package":None},
        ):
            with self.assertRaises(ValueError): reader.selected(proof.encoded(value))

    def test_native_resume_refuses_original_inode_metadata_or_byte_prefix_change(self):
        # Adversarial pure checkpoint inputs, no synthetic successful SQLite row.
        before=(("unchanged",),(1,2),b"hash",b"original-native-frame\n")
        for changed in ((("changed",),(1,2),b"hash",before[3]),
                        (before[0],(1,3),b"hash",before[3]),
                        (before[0],before[1],b"hash",b"replaced-native-frame\n")):
            with self.assertRaises(ValueError): tui.resumed_history(before,changed,"synthetic-thread")

    def test_full_empty_rollout_still_required_before_any_export_submission(self):
        root=Path(__file__).parent
        body=(root/"test_installed_native_tui.py").read_text()
        branch=body.split("        if ordinary_first:\n",1)[1].split("        elif live is None:",1)[0]
        self.assertLess(branch.index('terminal.send("/rename '),branch.index("before = wait_metadata"))
        self.assertLess(branch.index("before = wait_metadata"),branch.index('terminal.send("/export '))
        self.assertIn("exported == before and process_witness(first_pid) == first_witness",branch)
        self.assertIn("ordinary_first=False",body)
        self.assertIn('runtime_reader=runtime_reader, ordinary_first=ordinary_first',body)
        self.assertIn('resume=thread',body)
        self.assertIn('second["nativeRef"] != first["nativeRef"]',body)
        self.assertIn('support.private_file(config, 1024 * 1024) == configured',body)

    def test_reader_scope_declares_original_controls_and_no_sdk_per_leaf(self):
        root=Path(__file__).parent
        macro=(root/"owned_history_ordinary_targets.bzl").read_text()
        self.assertIn('"native_resumed_checkpoint.py"',macro)
        self.assertIn('"//tools:owned_history_runtime_reader_support"',macro)
        self.assertIn('"//integrations/codex-upstream/native-owned-history:expected-tests.json"',macro)
        self.assertNotIn("original_sdk_data",macro)
        self.assertNotIn("omux_codex_retained_runtime",macro)
        self.assertNotIn("omux run",macro)
        # The coordinator binary/test own their import closure independently
        # from the ordinary reader filegroup. Keep its inspected BUILD declared.
        self.assertIn('"//tools:BUILD.bazel"',macro)
        build=(root.parent/"tools"/"BUILD.bazel").read_text()
        self.assertIn('exports_files(["BUILD.bazel"])',build)
        resident=build.split("_RESIDENT_GUARD_SOURCES = ",1)[1].split("\nexports_files",1)[0]
        self.assertEqual(resident.count("'guard_native_owned_history_ordinary_reserved.py'"),1)
        for target in ('name = "execution_guard"','name = "execution_guard_test"'):
            declaration=build.split(target,1)[1].split("\n)",1)[0]
            self.assertIn("_RESIDENT_GUARD_SOURCES",declaration)


if __name__=="__main__": unittest.main()
