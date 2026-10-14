"""Offline exact archive/role joins and delegation; no live provider or custody claim."""
import copy
import hashlib
import json
import os
from pathlib import Path
import time
import unittest
from unittest import mock
import resident_existing_enrollment as existing

HOME = Path("/home/jess")
EPOCH = "11111111-1111-4111-8111-111111111111"
ROOT = HOME/".local/state/omux-execution-20261005"/EPOCH
def manifest():
    return {"schema_version":1,"ownership":"omux-installation","action":"enroll-existing","instance":"default",
        **{key:str(path) for key,path in existing.guard.fixed_paths(HOME).items()},
        "native_context":{"application":"codex","provenance":"authorized-working-native-context","codex_home":"/native/authorized-context"},
        "permissions":{"connect_source":True,"activate_service":False,"restart_daemon":True},
        "existing_archive":{"archive_path":str(ROOT/"output-base"/existing.owned.ARCHIVE_RELATIVE),
            "archive_sha256":"a"*64,"archive_bytes":1,"manifest_sha256":"b"*64,
            "qualification":{"path":str(ROOT/"receipt.json"),"sha256":"c"*64,"bytes":1,
                "source_commit":"d"*40,"graph_sha256":"e"*64}}}

class ExistingEnrollmentContract(unittest.TestCase):
    def test_exact_owned_enrollment_role_refuses_activation_factor_missing_or_mixed_selection(self):
        value = manifest()
        existing.guard.manifest_schema(value,HOME)
        existing.guard.carrier_purpose(existing.guard.EXISTING_ENROLLMENT_LABEL,"enroll-existing",True)
        for key,field in (("ownership","home-manager"),("action","start-existing"),("factor","private-factor")):
            bad = copy.deepcopy(value)
            bad[key] = field
            with self.subTest(key=key),self.assertRaises(ValueError):
                existing.guard.manifest_schema(bad,HOME)
        for key,field in (("activate_service",True),("connect_source",False)):
            bad = copy.deepcopy(value)
            bad["permissions"][key] = field
            with self.subTest(key=key),self.assertRaises(ValueError):
                existing.guard.manifest_schema(bad,HOME)
        for label,action,selected in ((existing.guard.LABEL,"enroll-existing",True),
                (existing.guard.LIFECYCLE_LABEL,"enroll-existing",True),
                (existing.guard.EXISTING_ENROLLMENT_LABEL,"enroll-existing",False),
                (existing.guard.EXISTING_ENROLLMENT_LABEL,"install-and-enroll",True)):
            with self.subTest(label=label,action=action,selected=selected),self.assertRaises(ValueError):
                existing.guard.carrier_purpose(label,action,selected)
        bad = copy.deepcopy(value)
        bad["existing_archive"]["archive_path"] = "/native/authorized-context/auth.json"
        with self.assertRaises(ValueError):
            existing.guard.manifest_schema(bad,HOME)
        existing.guard.carrier_purpose(existing.guard.LABEL,"enroll-existing")
        existing.guard.carrier_purpose(existing.guard.LIFECYCLE_LABEL,"start-existing")

    def test_success_delegates_exact_existing_checks_and_retained_restart_without_install_or_extra_io(self):
        value = manifest()
        witness = mock.Mock(selection=value["existing_archive"])
        result = {"custody_retained":True,"restart_verified":True,"renewal_writer":"external"}
        deadline = time.monotonic_ns()+120*10**9
        with mock.patch.dict(os.environ,{"HOME":str(HOME)}), \
                mock.patch.object(existing.resident,"original_deadline",return_value=deadline), \
                mock.patch.object(existing.owned,"QualifiedExistingEnrollment",return_value=witness) as qualify, \
                mock.patch.object(existing.resident,"execute",return_value=result) as delegate, \
                mock.patch.object(existing.owned.install,"install_bundle",side_effect=AssertionError("no install")), \
                mock.patch.object(existing.owned,"RuntimeFence",side_effect=AssertionError("no private DB/lock fence")):
            self.assertIs(existing.execute_existing(Path("/declared/systemctl"),Path("/declared/session-probe"),value),result)
            base = {key:field for key,field in value.items() if key != "existing_archive"}
            delegate.assert_called_once_with(Path(value["existing_archive"]["archive_path"]),
                Path("/declared/systemctl"),Path("/declared/session-probe"),base)
            qualify.assert_called_once_with(value,HOME,deadline-existing.resident.CLEANUP_RESERVE_NS)
            witness.recheck.assert_called_once_with()
            witness.close.assert_called_once_with()
            self.assertEqual(value,manifest())

    def test_delegate_or_changed_software_failure_closes_witness_and_emits_no_success(self):
        value = manifest()
        for delegate_failure in (True,False):
            witness = mock.Mock(selection=value["existing_archive"])
            delegate = mock.Mock(side_effect=ValueError("synthetic refused provider authority") if delegate_failure else None,
                return_value={"custody_retained":True})
            if not delegate_failure:
                witness.recheck.side_effect = ValueError("synthetic changed installed software")
            with mock.patch.dict(os.environ,{"HOME":str(HOME)}), \
                    mock.patch.object(existing.resident,"original_deadline",return_value=time.monotonic_ns()+120*10**9), \
                    mock.patch.object(existing.owned,"QualifiedExistingEnrollment",return_value=witness), \
                    mock.patch.object(existing.resident,"execute",delegate):
                with self.assertRaises(ValueError):
                    existing.execute_existing(Path("/declared/systemctl"),Path("/declared/session-probe"),value)
                witness.close.assert_called_once_with()

    def test_stale_build_qualification_refuses_before_archive_installed_or_private_io(self):
        value = manifest()
        receipt = {"id":EPOCH,"artifact_epoch":EPOCH,"profile":"standard","verb":"test",
            "targets":["//delivery:resident_enrollment_contract_test"],"exit":0,"workload_exit":0,
            "descendants_empty":True,"cleanup":{"state":"empty"},"controller_failure":None,
            "source_dirty":"false","source_commit":"d"*40,"graph_sha256":"e"*64,
            "cache_reuse_requested":False,"cache_policy":None,"cache_key":None,"output_base":str(ROOT/"output-base")}
        raw = json.dumps(receipt).encode()
        value["existing_archive"]["qualification"].update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        public = mock.Mock(raw=raw)
        with mock.patch.object(existing.owned,"PublicFile",return_value=public) as opened, \
                mock.patch.object(existing.guard,"OwnedUnitCustody",side_effect=AssertionError("no installed IO")), \
                mock.patch.object(existing.owned,"RuntimeFence",side_effect=AssertionError("no private IO")):
            with self.assertRaises(ValueError):
                existing.owned.QualifiedExistingEnrollment(value,HOME,time.monotonic_ns()+120*10**9)
            self.assertEqual(opened.call_count,1)
            public.close.assert_called_once_with()

    def test_readonly_product_and_exact_qualification_archive_leaf_binds_refuse_writable_or_recursive_injection(self):
        value = manifest()
        admission = existing.guard.Admission.__new__(existing.guard.Admission)
        admission.root = Path("/private/input")
        admission.selected = value
        admission.sources = {admission.root/"bus":Path("/run/user/1000/bus"),
            admission.root/"systemd/private":Path("/run/user/1000/systemd/private")}
        admission.product_directories = [(Path(value[key]),None,None) for key in ("prefix","records","runtime_state")]
        admission.existing_enrollment = mock.Mock(files=[mock.Mock(path=Path(value["existing_archive"]["qualification"]["path"])),
            mock.Mock(path=Path(value["existing_archive"]["archive_path"]))])
        run = Path("/private/run")
        def readback(configured):
            return " ".join(token.removesuffix(":norbind") if token.endswith(":norbind") else token+":rbind" for token in configured)
        ro = readback(admission.bindings())
        actual = {"BindReadOnlyPaths":ro,"BindPaths":str(run)+":"+str(run)+":rbind"}
        admission.verify_bindings(actual,run)
        self.assertEqual(admission.writable_binding(),"")
        for path in (value["existing_archive"]["archive_path"],value["existing_archive"]["qualification"]["path"]):
            token = path+":"+path
            bad = {**actual,"BindReadOnlyPaths":ro.replace(token,token+":rbind")}
            with self.subTest(path=path),self.assertRaises(ValueError):
                admission.verify_bindings(bad,run)
        bad = {**actual,"BindPaths":actual["BindPaths"]+" "+value["runtime_state"]+":"+value["runtime_state"]+":rbind"}
        with self.assertRaises(ValueError):
            admission.verify_bindings(bad,run)

if __name__ == "__main__":
    unittest.main()
