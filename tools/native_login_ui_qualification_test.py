"""Provider-free preparation models. No SSH/Nix/GUI/provider process is invoked."""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch

import native_login_ui_qualification as local
import native_login_ui_prepare_remote as remote
import yoga_portal_worker as worker


class Preparation(unittest.TestCase):
    def test_wrong_actual_registry_refuses_before_any_physical_hash(self):
        rows = local.subset(Path(self.inventory).read_bytes())
        wrong = {row["path"]:{"narSize":row["narSize"],"narHash":row["narHash"],"references":row["references"]} for row in rows}
        wrong[rows[0]["path"]]["narSize"] = True
        for actual in ({},wrong):
            with patch.object(Path,"resolve",autospec=True,side_effect=lambda path,*a,**kw:path),\
                patch.object(remote.os,"open",return_value=42),patch.object(remote.os,"close"),\
                patch.object(remote.os,"fstat",return_value=SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o555,
                    st_dev=1,st_ino=2,st_mtime_ns=3,st_ctime_ns=4)),\
                patch.object(remote,"nix_operation",return_value=json.dumps(actual).encode()) as call:
                with self.assertRaisesRegex(ValueError,"destination_registration_"):
                    remote.verify_rows(worker,3,rows,time.monotonic()+1)
            self.assertEqual(call.call_count,1)
            self.assertEqual(call.call_args.args[2][:6],["path-info","--store","daemon","--offline","--json",rows[0]["path"]])

    def test_exact_existing_inventory_projects_reference_closed_181(self):
        data = Path(self.inventory).read_bytes()
        rows = local.subset(data)
        names = {row["path"] for row in rows}
        self.assertEqual(len(rows),181)
        self.assertEqual(sum(row["narSize"] for row in rows),869166464)
        self.assertTrue(local.ROOTS <= names)
        self.assertTrue(all(set(row["references"]) <= names for row in rows))
        with self.assertRaisesRegex(worker.Refusal,"fixed_inventory_required"):
            local.subset(data+b" ")

    def test_generated_os_identity_reads_actual_bytes_despite_size_zero(self):
        generated = b"SYNTHETIC-BOOT-IDENTITY\n"
        with patch.object(remote.os,"open",return_value=77),patch.object(remote.os,"close") as release,\
            patch.object(remote.os,"fstat",return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_size=0)),\
            patch.object(remote.os,"read",side_effect=[generated,b""]):
            self.assertEqual(remote.os_identity_digest("/proc/sys/kernel/random/boot_id"),hashlib.sha256(generated).hexdigest())
        release.assert_called_once_with(77)

    def stage_model(self,wrong=False):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)/".local/state"
            state.mkdir(parents=True,mode=0o700)
            data = b"\x7fELFsynthetic-nonexecuted-comparison-bytes"
            pieces = [data[:1],data[1:3],data[3:]]
            config = {"task_id":"11111111-1111-4111-8111-111111111111","control_bytes":len(data),
                "control_sha256":"0"*64 if wrong else hashlib.sha256(data).hexdigest()}
            import pwd
            with patch.object(pwd,"getpwuid",return_value=SimpleNamespace(pw_dir=folder)),\
                patch.object(remote.select,"select",return_value=([0],[],[])),\
                patch.object(remote.os,"read",side_effect=pieces),patch.object(worker,"read_line",return_value=None):
                if wrong:
                    with self.assertRaisesRegex(ValueError,"control_digest_mismatch"):
                        remote.stage(worker,config,time.monotonic()+1)
                    self.assertEqual(list((state/"omux-native-login-ui").iterdir()),[])
                else:
                    path,identity = remote.stage(worker,config,time.monotonic()+1)
                    self.assertEqual(Path(path).read_bytes(),data)
                    info = os.stat(path,follow_symlinks=False)
                    self.assertEqual(stat.S_IMODE(info.st_mode),0o500)
                    self.assertEqual(stat.S_IMODE(Path(path).parent.stat().st_mode),0o700)
                    self.assertEqual((info.st_dev,info.st_ino),identity)

    def test_stage_accepts_segmented_elf_prefix_and_creates_only_new_public_file(self):
        self.stage_model()

    def test_stage_digest_failure_removes_only_new_task(self):
        self.stage_model(wrong=True)

    def test_nix_constructor_failure_reaps_only_still_owned_child(self):
        process = Mock(pid=4321)
        process.stdout = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("owned-model",5),0]
        with patch.object(remote.subprocess,"Popen",return_value=process),\
            patch.object(remote.os,"pidfd_open",side_effect=OSError("synthetic")),\
            patch.object(remote.os.path,"lexists",return_value=False):
            with self.assertRaises(OSError):
                remote.nix_operation(worker,3,["hash","path"],time.monotonic()+1,128)
        self.assertEqual([call.args[0] for call in process.send_signal.call_args_list],[signal.SIGTERM,signal.SIGKILL])
        process.stdout.close.assert_called_once()

    def test_receipt_publish_is_exclusive_and_existing_output_remains(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
            try:
                local.publish(directory,{"closure.json":b'{"synthetic":true}',"seat.json":b'{}',"ui-qualification.json":b'{}'})
                for path in Path(folder).iterdir():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
                before = {path.name:path.read_bytes() for path in Path(folder).iterdir()}
                with self.assertRaisesRegex(worker.Refusal,"new_empty_output_required"):
                    local.publish(directory,{"closure.json":b'{}'})
                self.assertEqual({path.name:path.read_bytes() for path in Path(folder).iterdir()},before)
            finally:
                os.close(directory)


if __name__ == "__main__":
    Preparation.inventory = sys.argv.pop(1)
    unittest.main()
