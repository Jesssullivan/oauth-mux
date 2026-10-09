"""Bazel-only synthetic installed inventory models; no process/IPC/provider IO."""
from contextlib import ExitStack
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

import guard_yoga_installed_workspace as installed


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


class InstalledInventoryTests(unittest.TestCase):
    def fixture(self,root):
        # Synthetic closed producer shape exercises real file/descriptor custody.
        # Hard actual origin pins are patched ONLY in this synthetic test fixture.
        origin={name:None for name in installed.ORIGIN_FIELDS}
        origin.update(id=installed.BUILD_ID,artifact_epoch=installed.BUILD_ID,verb='build',profile='standard',
            source_commit='c106a52523d2161063a6a58d6d29a8f86039f827',source_dirty='false',exit=0,
            workload_exit=0,descendants_empty=True,controller_failure=None,
            graph_sha256='a'*64,targets=['//delivery:yoga_toolbar_consent_proof'])
        launcher=b'#!/fixed-public-bash\n_main/delivery/yoga_toolbar_consent.py\n'
        files={'origin-build-receipt.json':encoded(origin),'origin-runfiles.MANIFEST':b'public manifest',
               'installed-launcher.sh':launcher,'runtime/native.json':b'{"public":"synthetic"}\n'}
        for target in ('execution_guard','yoga_session_qualification'):
            files[target+'.sh']=launcher.replace(b'_main/delivery/yoga_toolbar_consent.py',('_main/tools/'+target+'.py').encode())
        package={name:'b'*64 for name in ('execution_guard.py','guard_yoga_installed_workspace.py',
            'guard_yoga_profile.py','yoga_operator_launch.py','yoga_operator_coordinator.py','yoga_session_qualification.py')}
        for name in package:
            files['tools/'+name]=b'"""synthetic inert source"""\n'
            package[name]=hashlib.sha256(files['tools/'+name]).hexdigest()
        modes={name:0o555 if name.endswith('.sh') else 0o444 for name in files}
        record={'schemaVersion':1,'scope':installed.SCOPE,'origin':origin,
            'buildReceiptSha256':hashlib.sha256(files['origin-build-receipt.json']).hexdigest(),
            'launcherSha256':hashlib.sha256(launcher).hexdigest(),
            'runfilesManifestSha256':hashlib.sha256(files['origin-runfiles.MANIFEST']).hexdigest(),
            'workspaceGraphSha256':'a'*64,'sourceFilesSha256':{},'inputSha256':{},
            'nativeManifestSha256':hashlib.sha256(files['runtime/native.json']).hexdigest(),'declaredStoreFiles':{},'declaredRunfiles':{},
            'controllerPackageSha256':package,
            'omittedRunfileKeys':['_repo_mapping','_main/delivery/yoga_toolbar_consent_proof.sh'],
            'workspaceFiles':{name:{'sha256':hashlib.sha256(content).hexdigest(),'bytes':len(content),'mode':modes[name]}
                for name,content in files.items()},'executionAuthority':False,'destinationRegistrationVerified':False,
            'seatQualified':False,'toolbarConsentProved':False,'embeddedArtifactProvenanceRewritten':False}
        files['installed-workspace.json']=encoded(record)
        for name,content in files.items():
            path=root/name; path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            path.write_bytes(content); path.chmod(modes.get(name,0o444))
        root.chmod(0o700)
        pin={'path':str(root/'installed-workspace.json'),'sha256':hashlib.sha256(files['installed-workspace.json']).hexdigest()}
        return record,pin

    def read_fixture(self,path,maximum,deadline,*,expected):
        # Only the /tmp namespace selector/ancestor policy is a fixture exemption;
        # actual no-follow leaf, bytes, digest and all Capture fences remain.
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            data=os.read(fd,maximum+1)
        finally:
            os.close(fd)
        self.assertLessEqual(len(data),maximum)
        self.assertEqual(hashlib.sha256(data).hexdigest(),expected)
        return data

    def open_fixture(self,root,record,pin,stack):
        stack.enter_context(patch.object(installed,'workspace_root',side_effect=lambda path:Path(path)))
        stack.enter_context(patch.object(installed,'BUILD_SHA',record['buildReceiptSha256']))
        stack.enter_context(patch.object(installed,'LAUNCHER_SHA',record['launcherSha256']))
        stack.enter_context(patch.object(installed,'MANIFEST_SHA',record['runfilesManifestSha256']))
        stack.enter_context(patch.object(installed,'ARTIFACTS',{}))
        stack.enter_context(patch.object(installed,'ORIGIN_SOURCE_SHA',{}))
        stack.enter_context(patch.object(installed,'SOURCE_READER_SHA',{}))
        capture=installed.Capture(root,pin,time.monotonic_ns()+30*10**9,self.read_fixture)
        stack.callback(capture.close); return capture

    def test_real_held_inventory_projection_and_metadata_drift(self):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            root=Path(directory); record,pin=self.fixture(root)
            capture=self.open_fixture(root,record,pin,stack)
            capture.recheck()
            view=capture.projection(True)
            self.assertEqual(view['workspace_receipt_sha256'],pin['sha256'])
            self.assertTrue(view['whole_inventory_verified_after_cleanup'])
            self.assertFalse(view['embedded_artifact_provenance_rewritten'])
            (root/'tools/execution_guard.py').chmod(0o644)
            with self.assertRaises(ValueError): capture.recheck()

    def test_extra_file_symlink_and_same_bytes_inode_replacement_refuse(self):
        for change in ('extra','symlink','replacement'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
                root=Path(directory); record,pin=self.fixture(root)
                capture=self.open_fixture(root,record,pin,stack)
                target=root/'tools/execution_guard.py'
                if change=='extra': (root/'extra').write_bytes(b'public')
                elif change=='symlink': target.unlink(); target.symlink_to('/unselected/private')
                else:
                    replacement=root/'new'; replacement.write_bytes(target.read_bytes()); replacement.chmod(0o444)
                    os.replace(replacement,target)
                with self.assertRaises(ValueError): capture.recheck()

    def test_qualified_maps_actual_controller_path_and_whole_graph_must_agree(self):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            root=Path(directory); record,pin=self.fixture(root)
            capture=self.open_fixture(root,record,pin,stack)
            value={'sourceFilesSha256':{},'inputSha256':{},'inputPaths':{},
                'vaultWrapperAuthority':{'nativeManifest':{'path':str(root/'runtime/native.json'),
                    'sha256':record['nativeManifestSha256']}}}
            # Only loaded-source pathname is substituted in this synthetic fixture;
            # Capture still enforces actual graph/maps and actual held inventory.
            with patch.object(installed,'__file__',str(root/'tools/guard_yoga_installed_workspace.py')):
                self.assertTrue(capture.qualify(value,'a'*64))
                with self.assertRaises(ValueError): capture.qualify(value,'d'*64)
                value['sourceFilesSha256']={'delivery/foreign.py':'e'*64}
                with self.assertRaises(ValueError): capture.qualify(value,'a'*64)
            value['sourceFilesSha256']={}
            with self.assertRaises(ValueError): capture.qualify(value,'a'*64)

    def test_wrong_whole_receipt_pin_refuses_before_inventory_open(self):
        with patch.object(installed,'workspace_root',return_value=Path('/srv/fixture')), \
             patch.object(installed.os,'open') as opened, \
             self.assertRaises(ValueError):
            installed.Capture('/srv/fixture',{'path':'/srv/other/installed-workspace.json','sha256':'a'*64},
                time.monotonic_ns()+30*10**9,lambda *args,**kwargs:b'')
        opened.assert_not_called()

    def test_constructor_refusal_closes_every_held_descriptor(self):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            root=Path(directory); record,pin=self.fixture(root)
            stack.enter_context(patch.object(installed,'workspace_root',side_effect=lambda path:Path(path)))
            stack.enter_context(patch.object(installed,'BUILD_SHA',record['buildReceiptSha256']))
            stack.enter_context(patch.object(installed,'LAUNCHER_SHA',record['launcherSha256']))
            stack.enter_context(patch.object(installed,'MANIFEST_SHA',record['runfilesManifestSha256']))
            stack.enter_context(patch.object(installed,'ARTIFACTS',{}))
            stack.enter_context(patch.object(installed,'ORIGIN_SOURCE_SHA',{}))
            stack.enter_context(patch.object(installed,'SOURCE_READER_SHA',{}))
            observed=[]; real_open=os.open
            def tracked(*args,**kwargs):
                fd=real_open(*args,**kwargs); observed.append(fd); return fd
            (root/'tools/yoga_session_qualification.py').chmod(0o644)
            with patch.object(installed.os,'open',side_effect=tracked),self.assertRaises(ValueError):
                installed.Capture(root,pin,time.monotonic_ns()+30*10**9,self.read_fixture)
            for fd in set(observed):
                with self.assertRaises(OSError): os.fstat(fd)

    def test_marker_only_admission_and_legacy_receipt_are_not_installed_authority(self):
        for admission in ({'installedCapture':object()},{'installedCapture':True},{'receipt':{}}):
            with self.assertRaises(ValueError): installed.verified(admission)

    def test_self_consistent_reader_or_observer_substitution_cannot_change_origin_pin(self):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            record,_=self.fixture(Path(directory))
            reader,observer='delivery/reader.py','delivery/observer.mjs'
            reader_sha,observer_sha='a'*64,'b'*64
            record['sourceFilesSha256']={reader:reader_sha}
            record['workspaceFiles'][reader]={'sha256':reader_sha,'bytes':32,'mode':0o444}
            record['workspaceFiles'][observer]={'sha256':observer_sha,'bytes':32,'mode':0o444}
            stack.enter_context(patch.object(installed,'BUILD_SHA',record['buildReceiptSha256']))
            stack.enter_context(patch.object(installed,'LAUNCHER_SHA',record['launcherSha256']))
            stack.enter_context(patch.object(installed,'MANIFEST_SHA',record['runfilesManifestSha256']))
            stack.enter_context(patch.object(installed,'ARTIFACTS',{}))
            # Nonempty synthetic immutable source policy, separate from this
            # candidate's rewritten manifest/source maps; no real c106 proof.
            stack.enter_context(patch.object(installed,'ORIGIN_SOURCE_SHA',{reader:reader_sha,observer:observer_sha}))
            stack.enter_context(patch.object(installed,'SOURCE_READER_SHA',{reader:reader_sha}))
            self.assertIs(installed.shape(record),record)
            changed=copy.deepcopy(record)
            changed['sourceFilesSha256'][reader]='c'*64
            changed['workspaceFiles'][reader]['sha256']='c'*64
            with self.assertRaises(ValueError): installed.shape(changed)
            changed=copy.deepcopy(record)
            changed['workspaceFiles'][observer]['sha256']='c'*64
            with self.assertRaises(ValueError): installed.shape(changed)
            changed=copy.deepcopy(record); changed['sourceFilesSha256']={}
            with self.assertRaises(ValueError): installed.shape(changed)


    def test_version2_support_is_distinct_and_inventory_pinned(self):
        import yoga_installed_controller_support as support
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            record,_ = self.fixture(Path(temporary))
            for name,value in (('BUILD_SHA',record['buildReceiptSha256']),
                ('LAUNCHER_SHA',record['launcherSha256']),('MANIFEST_SHA',record['runfilesManifestSha256']),
                ('SOURCE_READER_SHA',{}),('ORIGIN_SOURCE_SHA',{}),('ARTIFACTS',{})):
                stack.enter_context(patch.object(installed,name,value))
            record.update(schemaVersion=support.SCHEMA,scope=support.WORKSPACE_SCOPE,
                controllerDeliverySha256={'codex_device_acquisition_component.py':'d'*64})
            record['controllerPackageSha256']['yoga_installed_controller_support.py']='c'*64
            record['workspaceFiles']['tools/yoga_installed_controller_support.py']={
                'sha256':'c'*64,'bytes':1,'mode':0o444}
            record['workspaceFiles']['delivery/codex_device_acquisition_component.py']={
                'sha256':'d'*64,'bytes':1,'mode':0o444}
            self.assertIs(installed.shape(record),record)
            origin=copy.deepcopy(record['origin'])
            for change in ('missing','different','foreign'):
                bad=copy.deepcopy(record)
                if change=='missing': bad['workspaceFiles'].pop('delivery/codex_device_acquisition_component.py')
                elif change=='different': bad['workspaceFiles']['delivery/codex_device_acquisition_component.py']['sha256']='e'*64
                else: bad['controllerDeliverySha256']['foreign.py']='d'*64
                with self.assertRaises(ValueError): installed.shape(bad)
                self.assertEqual(bad['origin'],origin)
            bad=copy.deepcopy(record);bad['schemaVersion']=1;bad['scope']=installed.SCOPE
            with self.assertRaises(ValueError): installed.shape(bad)

if __name__=='__main__':
    unittest.main()
