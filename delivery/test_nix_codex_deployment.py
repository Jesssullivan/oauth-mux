import hashlib
import unittest
import tempfile
import time
from pathlib import Path
import nix_codex_deployment as deployment

class DeploymentInventoryTests(unittest.TestCase):
    def test_real_bounded_metadata_reader_refuses_size_expiry_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'metadata'
            path.write_bytes(b'actual synthetic metadata')
            self.assertEqual(deployment.bounded_read(path,64,time.monotonic()+30),b'actual synthetic metadata')
            with self.assertRaises(ValueError):deployment.bounded_read(path,1,time.monotonic()+30)
            with self.assertRaises(ValueError):deployment.bounded_read(path,64,time.monotonic()-1)
            alias=Path(directory)/'alias'
            alias.symlink_to(path)
            with self.assertRaises(ValueError):deployment.bounded_read(alias,64,time.monotonic()+30)
    def fixture(self):
        value={'schema_version':1,'kind':'omux-native-acquisition-package-output-v1',
            'purpose':'evaluation-only','acquisitionContract':'unsupported',
            'files':{name:{'sha256':'a'*64,'bytes':1} for name in deployment.OUTPUTS}}
        raw=deployment.encoded(value)
        marker=b'omux-native-package-output-sha256='+hashlib.sha256(raw).hexdigest().encode()+b'\n'
        return value,raw,marker
    def test_exact_guardian_log_binding_accepts_only_one_closed_inventory_marker(self):
        value,raw,marker=self.fixture()
        self.assertEqual(deployment.closed_inventory(raw,b'ordinary test output\n'+marker),value)
        for log in (b'',marker+marker,b'prefix '+marker,marker+b'omux-native-package-output-sha256=invalid\n',marker.upper()):
            with self.assertRaises(ValueError):deployment.closed_inventory(raw,log)
    def test_inventory_rejects_role_escape_extra_missing_length_and_duplicate_json(self):
        value,raw,marker=self.fixture()
        changes=[]
        for field in ('../runtime-manifest.json','extra.json'):
            changed={**value,'files':{**value['files'],field:{'sha256':'a'*64,'bytes':1}}}
            changes.append(deployment.encoded(changed))
        changed={**value,'files':{name:row for name,row in value['files'].items() if name!=deployment.OUTPUTS[0]}}
        changes.append(deployment.encoded(changed))
        value['files'][deployment.OUTPUTS[0]]['bytes']=True
        changes.append(deployment.encoded(value))
        changes.append(b'{"schema_version":1,"schema_version":1}')
        for body in changes:
            exact=b'omux-native-package-output-sha256='+hashlib.sha256(body).hexdigest().encode()+b'\n'
            with self.assertRaises(ValueError):deployment.closed_inventory(body,exact)

if __name__=='__main__':unittest.main()
