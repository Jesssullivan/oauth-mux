"""Offline predicates for fresh opt-in selection, public inputs and readback."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import guard_codex_fresh_live_profile as route
import guard_codex_live_profile as live
import codex_live_fresh_runtime_repository_input as declaration
from execution_guard import bazel_command

SELECTOR = route.OPERATOR_ROOTS[0]/"fresh-runtime-selection.json"
HASH = "0"*64

def selected():
    epoch = "a75d77f9-8a8c-453c-ab14-467d1d70e0e5"
    parent = str(declaration.HOME_STATE/epoch/"output-base")+declaration.PACKAGE_SUFFIX
    def pin(path):
        return {"path":path,"sha256":HASH,"bytes":1}
    return {"kind":declaration.KIND,
        "package_selection":pin(str(declaration.HOME_STATE/"package-selection.json")),
        "package_run":pin(str(declaration.HOME_STATE/epoch/"receipt.json")),
        "producer_graph_sha256":HASH,"producer_source_sha256":HASH,
        "archive":pin(parent+"/fresh-native-runtime.tar.gz"),
        "manifest":pin(parent+"/runtime-manifest.json"),
        "receipt":pin(parent+"/runtime-receipt.json"),
        "bundle_directory":parent+"/"+HASH}

class FreshBoundary(unittest.TestCase):
    def test_only_continuity_and_complete_explicit_selection(self):
        self.assertTrue(route.finite("codex-live",["test",live.LABEL],None,SELECTOR,HASH,1))
        self.assertFalse(route.finite("standard",["test","//:docs_check"],None,None,None,None))
        for values in ((SELECTOR,None,1),(None,HASH,1),(SELECTOR,HASH,None),
                (SELECTOR,HASH,True),(SELECTOR,HASH,0)):
            with self.subTest(values=values),self.assertRaises(ValueError):
                route.finite("codex-live",["test",live.LABEL],None,*values)

    def test_unrelated_targets_and_retained_cannot_select_fresh(self):
        for profile,args,retained in (
                ("standard",["test",live.LABEL],None),
                ("codex-live",["test",live.ENROLLMENT_LABEL],None),
                ("codex-live",["test",live.LABEL,"//:docs_check"],None),
                ("codex-live",["test",live.LABEL],Path("/retained"))):
            with self.subTest(profile=profile,args=args),self.assertRaises(ValueError):
                route.finite(profile,args,retained,SELECTOR,HASH,1)

    def test_operator_selector_pre_normalization(self):
        for value in ("/home/jess/.config/auth.json",
                str(SELECTOR.parent)+"/./fresh-runtime-selection.json",
                str(SELECTOR.parent)+"/child/../fresh-runtime-selection.json",
                str(SELECTOR.parent)+"/other.json"):
            with self.subTest(value=value),self.assertRaises(ValueError):
                route.finite("codex-live",["test",live.LABEL],None,value,HASH,1)

    def test_enrollment_stays_without_any_runtime(self):
        live.finite(["test",live.ENROLLMENT_LABEL],"system",Path("/private/input.json"),None,False)
        live.finite(["test",live.LABEL],"system",Path("/private/input.json"),None,False,fresh_runtime=True)
        for label,retained in ((live.ENROLLMENT_LABEL,None),(live.LABEL,Path("/retained"))):
            with self.assertRaises(ValueError):
                live.finite(["test",label],"system",Path("/private/input.json"),retained,False,fresh_runtime=True)

    def test_repository_environment_is_explicit_and_offline_cleared(self):
        for name in (route.VARIABLE,route.SHA_VARIABLE,route.BYTES_VARIABLE):
            with patch.dict("os.environ",{name:"foreign-selector"}):
                ordinary = bazel_command("/store/bazel",Path("/owned/run"),["test","//:docs_check"])
                self.assertIn("--repo_env="+name+"=",ordinary)
                self.assertNotIn(route.DEFINE,ordinary)
        fresh = bazel_command("/store/bazel",Path("/owned/run"),["test",live.LABEL],
            profile="codex-live",codex_fresh_runtime_selection=SELECTOR,
            codex_fresh_runtime_sha256=HASH,codex_fresh_runtime_bytes=1)
        self.assertIn(route.DEFINE,fresh)
        self.assertIn("--repo_env="+route.VARIABLE+"="+str(SELECTOR),fresh)
        self.assertIn("--repo_env=OMUX_CODEX_OWNER_RUNTIME_DIRECTORY=",fresh)

    def test_fixed_readonly_bind_readback_accepts_only_optional_rbind(self):
        admission = SimpleNamespace(root=Path(selected()["bundle_directory"]),selection_path=SELECTOR)
        expected = route.readonly_bindings(admission,"/private/source:/omux-live-inputs")
        actual = {"BindReadOnlyPaths":" ".join(value+":rbind" for value in expected),"BindPaths":""}
        route.verify_readonly(actual,expected)
        self.assertTrue(route.binding_facts(actual,expected)["runtime_package_and_selector_readonly"])
        for changed in (
                {"BindReadOnlyPaths":" ".join(expected[:-1]),"BindPaths":""},
                {"BindReadOnlyPaths":" ".join(expected+[expected[-1]]),"BindPaths":""},
                {"BindReadOnlyPaths":" ".join(expected)+":optional","BindPaths":""},
                {"BindReadOnlyPaths":" ".join(expected),"BindPaths":"/foreign:/foreign"}):
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                route.verify_readonly(changed,expected)

    def test_readback_facts_and_immediate_redaction_are_path_free(self):
        private = "/private/account-profile/input.json"
        actual = {"BindReadOnlyPaths":private+":/omux-live-inputs","BindPaths":""}
        redacted = live.receipt_properties(actual)
        self.assertEqual(actual["BindReadOnlyPaths"],private+":/omux-live-inputs")
        self.assertNotIn(private,str(redacted))
        self.assertNotIn(private,str(route.binding_facts(actual,["other:other"])))

    def test_inert_repository_pin_is_separate_from_receipt_claim(self):
        value = declaration.declarations(selected())
        self.assertEqual(set(value["input_pin"]),{"kind","archive_sha256","archive_bytes",
            "manifest_sha256","manifest_bytes","receipt_sha256","receipt_bytes"})
        self.assertEqual(value["input_pin"]["kind"],declaration.RUNTIME_KIND)
        self.assertEqual(value["input_pin"]["archive_sha256"],HASH)

    def test_all_foreign_outer_paths_refused_without_open(self):
        for role in ("package_selection","package_run","archive","manifest","receipt"):
            value = copy.deepcopy(selected())
            value[role]["path"] = "/home/jess/.config/auth.json"
            with self.subTest(role=role),patch.object(declaration.os,"open") as opened:
                with self.assertRaises(ValueError):
                    declaration.declarations(value)
                opened.assert_not_called()

    def test_wrong_epoch_artifact_and_selector_shape_are_refused(self):
        changes = (("bundle_directory","/home/jess/.config/"+HASH),
            ("producer_graph_sha256","bad"))
        for key,value in changes:
            candidate = selected()
            candidate[key] = value
            with self.assertRaises(ValueError):
                declaration.declarations(candidate)
        candidate = selected()
        candidate["archive"]["path"] = candidate["archive"]["path"].replace("output-base","foreign-base")
        with self.assertRaises(ValueError):
            declaration.declarations(candidate)

if __name__ == "__main__":
    unittest.main()
