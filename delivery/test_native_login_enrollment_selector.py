"""Synthetic metadata custody models; no native/UI/provider/service execution."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import native_login_enrollment_selector as selector
# The cross-contract test imports the declared existing consumer, not a mock.
sys.path.insert(0,str(Path(__file__).parent.parent/"tools"))
import guard_resident_enrollment_profile as resident

class SelectorModels(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)/"home"
        self.home.mkdir(mode=0o700)
        self.parent = self.home/"acquisition"
        self.parent.mkdir(mode=0o700)
        self.root = self.parent/("native-login-"+"1"*32)
        self.root.mkdir(mode=0o700)
        self.input = self.root/selector.INPUT_DIRECTORY/selector.NAME
        self.root_fd = os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        self.addCleanup(os.close,self.root_fd)
        self.auth = self.root/"auth.json"
        self.auth.write_bytes(b"synthetic-unread-auth-marker")
        self.auth.chmod(0o600)
        epoch = self.home/".local/state/omux-execution-20261005/00000000-0000-0000-0000-000000000001"
        self.template = {"ownership":"omux-installation","instance":"default",
            "prefix":str(self.home/".local/share/omux"),
            "records":str(self.home/".local/state/omux-install"),
            "runtime_state":str(self.home/".local/state/omux"),
            "service_path":str(self.home/".local/share/omux/units/ai.xoxd.omux.service"),
            "existing_archive":{"archive_path":str(epoch/"output-base/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz"),
                "archive_sha256":"a"*64,"archive_bytes":101,"manifest_sha256":"b"*64,
                "qualification":{"path":str(epoch/"receipt.json"),"sha256":"c"*64,
                    "bytes":102,"source_commit":"d"*40,"graph_sha256":"e"*64}}}

    def deadline(self):
        return time.monotonic_ns()+10*10**9

    def publish(self):
        selector.publish(self.template,self.root,self.root_fd,self.home,self.deadline())

    def verify(self):
        return selector.verify_generated(self.parent,self.template,self.home,self.deadline())

    def test_real_publish_is_exact_existing_consumer_manifest_and_not_enrollment(self):
        self.publish()
        raw = self.input.read_bytes()
        value = json.loads(raw)
        self.assertEqual(resident.manifest_schema(value,self.home),value)
        self.assertEqual(value["native_context"]["codex_home"],str(self.root))
        self.assertEqual(value["permissions"],{"connect_source":True,"activate_service":False,"restart_daemon":False})
        self.assertEqual(os.stat(self.input).st_mode & 0o777,0o600)
        self.assertEqual(self.verify(),{"selector_ready":True,"identity_verified":False,
            "resident_enrollment_completed":False,"renewal_owner":"native","native_support":False})
        self.assertNotIn(b"synthetic-unread-auth-marker",raw)

    def test_second_profile_does_not_change_first_context_or_native_auth(self):
        self.publish()
        first = self.input.read_bytes()
        auth_before = self.auth.stat()
        other_parent = self.home/"second-acquisition"
        other_parent.mkdir(mode=0o700)
        other = other_parent/("native-login-"+"2"*32)
        other.mkdir(mode=0o700)
        fd = os.open(other,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            (other/"auth.json").write_bytes(b"second-synthetic-unread-marker")
            (other/"auth.json").chmod(0o600)
            selector.publish(self.template,other,fd,self.home,self.deadline())
            selector.verify_generated(other_parent,self.template,self.home,self.deadline())
        finally:
            os.close(fd)
        self.assertEqual(self.input.read_bytes(),first)
        self.assertEqual(self.auth.stat().st_mtime_ns,auth_before.st_mtime_ns)
        self.assertEqual(json.loads(first)["native_context"]["codex_home"],str(self.root))

    def test_no_auth_payload_is_read_and_invalid_metadata_refuses_before_publish(self):
        pread = os.pread
        def metadata_only(fd,*args):
            # Auth is held O_PATH; no pread on its inode is permitted.
            self.assertNotEqual(os.fstat(fd).st_ino,self.auth.stat().st_ino)
            return pread(fd,*args)
        with patch.object(selector.os,"pread",side_effect=metadata_only):
            self.publish()
            self.verify()
        self.input.unlink()
        self.input.parent.rmdir()
        self.auth.chmod(0o644)
        with self.assertRaises(ValueError):
            self.publish()
        self.assertFalse(self.input.exists())

    def test_publication_is_exclusive_and_failed_partial_is_never_success(self):
        self.publish()
        first = self.input.read_bytes()
        with self.assertRaises(FileExistsError):
            self.publish()
        self.assertEqual(self.input.read_bytes(),first)
        self.input.write_bytes(b"{")
        with self.assertRaises(ValueError):
            self.verify()

    def test_rewritten_permissions_source_or_archive_cannot_borrow_template_authority(self):
        self.publish()
        path = self.input
        original = path.read_bytes()
        for change in ("permissions","source","archive"):
            value = json.loads(original)
            if change == "permissions":
                value["permissions"]["restart_daemon"] = True
            elif change == "source":
                value["native_context"]["codex_home"] = str(self.home/"different-profile")
            else:
                value["existing_archive"]["archive_sha256"] = "f"*64
            path.write_bytes(selector.encoded(value))
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify()
        path.write_bytes(original)
        self.verify()

    def test_exact_template_types_namespaces_and_disjointness(self):
        for changed in ("archive_bool","receipt_bool","extra_permission","home_manager","wrong_unit","wrong_archive_namespace"):
            value = copy.deepcopy(self.template)
            if changed == "archive_bool": value["existing_archive"]["archive_bytes"] = True
            elif changed == "receipt_bool": value["existing_archive"]["qualification"]["bytes"] = True
            elif changed == "extra_permission": value["permissions"] = {"restart_daemon":True}
            elif changed == "home_manager": value["ownership"] = "home-manager"
            elif changed == "wrong_unit": value["service_path"] = str(self.home/".config/systemd/user/other.service")
            else: value["existing_archive"]["archive_path"] = str(self.home/"archive.tar.gz")
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                selector.validate_template(value,self.home)
        with self.assertRaises(ValueError):
            selector.generated(self.template,self.home/".local/share/omux/source",self.home)

    def test_same_inode_ancestor_redirect_refuses_publication_and_verification(self):
        self.publish()
        moved = self.home/"moved"
        self.parent.rename(moved)
        self.parent.symlink_to(moved,target_is_directory=True)
        # Following stat would still find the original held root inode.
        self.assertEqual(self.root.stat().st_ino,os.fstat(self.root_fd).st_ino)
        with self.assertRaises(OSError):
            self.verify()
        with self.assertRaises(OSError):
            self.publish()

    def test_extra_profiles_or_linked_selector_refuse(self):
        self.publish()
        extra = self.parent/("native-login-"+"3"*32)
        extra.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.verify()
        extra.rmdir()
        unexpected = self.input.parent/"extra.json"
        unexpected.write_bytes(b"{}")
        with self.assertRaises(ValueError):
            self.verify()
        unexpected.unlink()
        saved = self.root/"saved.json"
        self.input.rename(saved)
        self.input.symlink_to(saved)
        with self.assertRaises(OSError):
            self.verify()

    def test_expired_original_deadline_has_no_publication_and_no_success(self):
        with self.assertRaises(ValueError):
            selector.publish(self.template,self.root,self.root_fd,self.home,time.monotonic_ns()-1)
        self.assertFalse(self.input.exists())
        self.publish()
        with self.assertRaises(ValueError):
            selector.verify_generated(self.parent,self.template,self.home,time.monotonic_ns()-1)
        with self.assertRaises(ValueError):
            selector.verify_generated(self.parent,self.template,self.home,True)

if __name__ == "__main__":
    unittest.main()
