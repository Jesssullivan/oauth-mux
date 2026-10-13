"""Real public archive/FD/installer predicates; no real producer/service proof."""
import copy
import json
import io
import os
from pathlib import Path
import stat
import time
import types
import unittest
from unittest.mock import patch
import install
import pack
import public_package_retention as retained
import retained_public_install as frontend
import test_delivery as delivery_fixture
import guard_resident_owned_update as owned
import guard_resident_enrollment_profile as guard


class PublicPackageTests(delivery_fixture.DeliveryFixture):
    def setUp(self):
        super().setUp()
        self.until=time.monotonic_ns()+600*10**9
        self.home=self.root/'home';self.home.mkdir(mode=0o700)
        self.paths=guard.fixed_paths(self.home)
        reference=json.loads(self.reference.read_bytes())
        reference['api']={'version':2,'methods':[{'name':'custody.reopen'}]}
        self.reference.write_bytes(pack.json_bytes(reference))
        self.payload=self.portable_bundle('release')
        self.archive_root=self.home/'.local/state/omux-execution-20261005'/'11111111-1111-1111-1111-111111111111'
        self.archive_path=self.archive_root/'output-base'/owned.ARCHIVE_RELATIVE
        self.archive_path.parent.mkdir(mode=0o700,parents=True)
        self.archive_path.write_bytes(self.payload);self.archive_path.chmod(0o444)
        # Synthetic closed receipt predicates only, never an executed producer.
        q={'id':self.archive_root.name,'artifact_epoch':self.archive_root.name,'profile':'standard',
            'verb':'build','targets':['//delivery:default_instance_archive'],'exit':0,'workload_exit':0,
            'descendants_empty':True,'cleanup':{'state':'empty'},'controller_failure':None,'source_dirty':'false',
            'source_commit':'a'*40,'graph_sha256':'b'*64,'cache_reuse_requested':False,'cache_policy':None,
            'cache_key':None,'output_base':str(self.archive_root/'output-base')}
        self.qraw=retained.encoded(q);self.qpath=self.archive_root/'receipt.json'
        self.qpath.write_bytes(self.qraw);self.qpath.chmod(0o600)
        manifest,files=pack.verify_bundle(self.payload)
        self.original={'archive_path':str(self.archive_path),'archive_sha256':retained.sha(self.payload),
            'archive_bytes':len(self.payload),'manifest_sha256':retained.sha(files['release-manifest.json']),
            'qualification':{'path':str(self.qpath),'sha256':retained.sha(self.qraw),'bytes':len(self.qraw),
                'source_commit':'a'*40,'graph_sha256':'b'*64}}

    def selection(self,qualified=True):
        return {'schema_version':1,'action':'retain-and-install-public','ownership':'omux-installation','instance':'default',
            **{key:str(path) for key,path in self.paths.items()},'archive_path':str(self.archive_path),
            'original':copy.deepcopy(self.original) if qualified else None,
            'permissions':{'install_public_files':True,'activate_service':False,'connect_source':False,'restart_daemon':False}}

    def observe(self,reference):
        start={**copy.deepcopy(self.original),'retention':reference,
            'archive_path':str(Path(reference['path']).parent/'archive.tar.gz')}
        return {'schema_version':1,'ownership':'omux-installation','action':'observe-custody-existing','instance':'default',
            **{key:str(path) for key,path in self.paths.items()},'native_context':None,
            'permissions':{'connect_source':False,'activate_service':False,'restart_daemon':False},'start':start}

    def fixture_directory(self,path,private=False):
        # Real nofollow fixture ancestry, exempt only the canonical root sticky
        # temp parent. The installed observer's original predicates remain real.
        owner=retained.Directory(path,self.until,private=False)
        fd=owner.chain.pop()[1]
        try:
            if private:self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode),0o700)
            owner.close();return fd
        except BaseException:
            os.close(fd);owner.close();raise

    def fragment(self):
        folder=self.home/'.config/systemd/user';folder.mkdir(mode=0o700,parents=True)
        (folder/self.paths['service_path'].name).symlink_to(self.paths['service_path'])

    def test_complete_qualified_install_retains_exact_raw_public_inputs_and_fresh_observer(self):
        result=frontend.execute(self.selection(),self.home,self.until);reference=result['retention']
        self.fragment()
        package=retained.HeldPackage(Path(reference['path']).parent,self.until)
        try:
            self.assertEqual(package.archive.raw,self.payload);self.assertEqual(package.qualification.raw,self.qraw)
            self.assertEqual(package.document['original'],self.original)
            manifest,files=pack.verify_bundle(self.payload)
            self.assertEqual(package.manifest.raw,files['release-manifest.json'])
            for name in ('share/omux/reference.json','share/omux/services/omux.service.in','share/omux/services/dev.xoxd.omux.plist.in'):
                self.assertEqual(package.document['members'][name]['sha256'],retained.sha(files[name]))
            self.assertFalse(package.document['old_physical_witness_restored'])
        finally:package.close()
        self.archive_path.unlink();self.qpath.unlink()
        selected=self.observe(reference)
        guard.manifest_schema(selected,self.home)
        with patch.object(guard,'open_directory',side_effect=self.fixture_directory):
            witness=owned.QualifiedExistingEnrollment({**selected,'existing_archive':selected['start']},self.home,self.until)
            try:
                witness.recheck();self.assertIsNotNone(witness.retention)
                self.assertEqual(witness.files[1].raw,self.payload)
                self.assertEqual(json.loads(witness.unit.files[0][4])['publicRetention'],reference)
                fds=[witness.retention.archive.fd,witness.retention.qualification.fd]
            finally:witness.close()
        for fd in fds:
            with self.assertRaises(OSError):os.fstat(fd)
        self.assertFalse(result['installed_image_qualified']);self.assertFalse(result['custody_verified'])

    def test_original_public_owner_policy_keeps_root_or_user_and_refuses_alias_and_hardlink(self):
        parent=retained.Directory(self.qpath.parent,self.until,private=False)
        actual_stat,actual_fstat=os.stat,os.fstat;inode=self.qpath.stat().st_ino
        def publisher(info):
            if info.st_ino != inode:return info
            fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            values={name:getattr(info,name) for name in fields};values['st_uid']=0
            return types.SimpleNamespace(**values)
        try:
            with patch.object(retained.os,'stat',side_effect=lambda *a,**k:publisher(actual_stat(*a,**k))),patch.object(retained.os,'fstat',side_effect=lambda fd:publisher(actual_fstat(fd))):
                source=retained.File(parent,'receipt.json',retained.MAX_QUALIFICATION,owned=False)
                try:source.recheck();self.assertEqual(source.raw,self.qraw)
                finally:source.close()
                if os.getuid() != 0:
                    with self.assertRaises(ValueError):retained.File(parent,'receipt.json',retained.MAX_QUALIFICATION)
        finally:parent.close()
        alias=self.archive_path.with_name('archive-real.tar.gz');self.archive_path.rename(alias)
        self.archive_path.symlink_to(alias)
        with self.assertRaises(ValueError):retained.Source(self.archive_path,self.until,original=self.original,home=self.home)
        self.archive_path.unlink();alias.rename(self.archive_path)
        os.link(self.qpath,self.qpath.with_name('receipt-copy.json'))
        with self.assertRaises(ValueError):retained.Source(self.archive_path,self.until,original=self.original,home=self.home)
        self.assertFalse(self.paths['records'].exists())

    def test_unqualified_retention_persists_but_never_supplies_producer_authority(self):
        result=frontend.execute(self.selection(False),self.home,self.until)
        package=retained.HeldPackage(Path(result['retention']['path']).parent,self.until)
        try:
            self.assertFalse(package.document['producer_qualified']);self.assertIsNone(package.document['original'])
            self.assertEqual(package.qualification.raw,b'null\n')
        finally:package.close()
        selected=self.observe(result['retention'])
        with self.assertRaises(ValueError):guard.manifest_schema(selected,self.home)
        self.assertFalse(result['producer_qualified'])

    def test_retained_selector_refuses_all_unsupported_start_update_and_enrollment_purposes(self):
        result=frontend.execute(self.selection(),self.home,self.until);selected=self.observe(result['retention'])
        for action in ('start-existing','observe-existing','observe-inactive','stop-idle-owned','reopen-existing'):
            with self.subTest(action=action):
                changed=copy.deepcopy(selected);changed['action']=action
                changed['permissions']['activate_service']=action=='start-existing'
                if action=='stop-idle-owned':changed['permissions']['stop_service']=True
                with self.assertRaises(ValueError):guard.manifest_schema(changed,self.home)
        with self.assertRaises(ValueError):owned.start_pins(selected['start'],self.home)
        with self.assertRaises(ValueError):owned.pins(selected['start'],self.home)

    def test_activation_is_a_named_blocking_gate_even_with_original_public_output_present(self):
        result=frontend.execute(self.selection(),self.home,self.until)
        selected=self.observe(result['retention']);selected['action']='start-existing'
        selected['permissions']['activate_service']=True
        selected['start'].pop('retention');selected['start']['archive_path']=str(self.archive_path)
        guard.manifest_schema(selected,self.home)
        self.fragment();before=(self.paths['records']/install.RECORD).read_bytes()
        with patch.object(guard,'open_directory',side_effect=self.fixture_directory):
            with self.assertRaises(ValueError):owned.OwnedFirstStart(selected,self.home,self.until)
        self.assertEqual((self.paths['records']/install.RECORD).read_bytes(),before)
        self.assertEqual(self.archive_path.read_bytes(),self.payload)
        self.assertFalse(result['service_started']);self.assertFalse(result['installed_image_qualified'])

    def test_prior_active_owned_record_is_untouched_before_any_retention_write(self):
        install.install_bundle(self.payload,self.paths['prefix'],self.paths['records'],self.paths['service_path'],
            daemon_state_dir=self.paths['runtime_state'])
        record=self.paths['records']/install.RECORD;before=record.read_bytes()
        binary=self.paths['prefix']/'bin/omux';raw=binary.read_bytes()
        with self.assertRaises(ValueError):frontend.execute(self.selection(),self.home,self.until)
        self.assertEqual(record.read_bytes(),before);self.assertEqual(binary.read_bytes(),raw)
        self.assertFalse((self.paths['records']/'public-packages').exists())

    def test_retention_partial_write_and_collision_leave_no_installed_record_or_ready_claim(self):
        original=os.write;seen=[]
        def refuse(fd,data):
            if seen:raise OSError('synthetic public retention write failure')
            seen.append(fd);return original(fd,data[:max(1,min(17,len(data)))])
        with patch.object(retained.os,'write',refuse):
            with self.assertRaises(OSError):frontend.execute(self.selection(),self.home,self.until)
        self.assertFalse((self.paths['records']/install.RECORD).exists())
        self.assertFalse((self.paths['prefix']/'bin/omux').exists())
        root=retained.location(self.paths['records'],retained.sha(self.payload),retained.sha(self.qraw))
        with self.assertRaises(ValueError):retained.HeldPackage(root,self.until)
        with self.assertRaises(ValueError):frontend.execute(self.selection(),self.home,self.until)
        self.assertEqual(self.archive_path.read_bytes(),self.payload);self.assertEqual(self.qpath.read_bytes(),self.qraw)
        for fd in seen:
            with self.assertRaises(OSError):os.fstat(fd)

    def test_current_retained_payload_replacement_mode_byte_and_extra_namespace_refuse(self):
        result=frontend.execute(self.selection(),self.home,self.until);root=Path(result['retention']['path']).parent
        for fault in ('same-byte-inode','mode','extra'):
            with self.subTest(fault=fault):
                package=retained.HeldPackage(root,self.until);leaf=root/'archive.tar.gz';raw=leaf.read_bytes()
                try:
                    root.chmod(0o700)
                    if fault=='same-byte-inode':
                        leaf.unlink();leaf.write_bytes(raw);leaf.chmod(0o444)
                    elif fault=='mode':leaf.chmod(0o600)
                    else:(root/'extra').write_bytes(b'unselected public bytes')
                    root.chmod(0o555)
                    with self.assertRaises(ValueError):package.full()
                    fd=package.archive.fd
                finally:package.close()
                with self.assertRaises(OSError):os.fstat(fd)
                root.chmod(0o700)
                if fault=='extra':(root/'extra').unlink()
                leaf.chmod(0o444);root.chmod(0o555)

    def test_original_source_late_drift_refuses_before_installation_commit(self):
        actual=os.fsync;armed=[True]
        def drift(fd):
            actual(fd)
            if armed[0]:
                armed[0]=False;self.archive_path.chmod(0o600)
                self.archive_path.write_bytes(self.payload);self.archive_path.chmod(0o444)
        with patch.object(retained.os,'fsync',drift):
            with self.assertRaises(ValueError):frontend.execute(self.selection(),self.home,self.until)
        self.assertFalse(armed[0]);self.assertFalse((self.paths['records']/install.RECORD).exists())
        self.assertFalse((self.paths['prefix']/'bin/omux').exists())

    def test_installer_rollback_preserves_retained_package_and_removal_never_retires_it(self):
        original=install._write
        def refused(path,data,mode):
            if path.name==install.RECORD:raise OSError('synthetic ownership-record write refusal')
            return original(path,data,mode)
        with patch.object(install,'_write',refused):
            with self.assertRaises(OSError):frontend.execute(self.selection(),self.home,self.until)
        self.assertFalse((self.paths['records']/install.RECORD).exists())
        self.assertFalse((self.paths['prefix']/'bin/omux').exists())
        result=frontend.execute(self.selection(),self.home,self.until);root=Path(result['retention']['path']).parent
        binary=self.paths['prefix']/'bin/omux';binary.write_bytes(b'changed user-owned image')
        removed=install.uninstall(self.paths['prefix'],self.paths['records'])
        self.assertIn(str(binary),removed['preserved']);self.assertEqual(binary.read_bytes(),b'changed user-owned image')
        package=retained.HeldPackage(root,self.until)
        try:package.full();self.assertEqual(package.archive.raw,self.payload)
        finally:package.close()

    def test_retained_object_drift_at_ownership_commit_rolls_back_every_new_managed_file(self):
        actual=install._write;armed=[True]
        root=retained.location(self.paths['records'],retained.sha(self.payload),retained.sha(self.qraw))
        def drift(path,data,mode):
            actual(path,data,mode)
            if path.name==install.RECORD and armed[0]:
                armed[0]=False;root.chmod(0o700)
                leaf=root/'archive.tar.gz';leaf.chmod(0o600);leaf.write_bytes(self.payload);leaf.chmod(0o444)
                root.chmod(0o555)
        with patch.object(install,'_write',drift):
            with self.assertRaises(ValueError):frontend.execute(self.selection(),self.home,self.until)
        self.assertFalse(armed[0]);self.assertFalse((self.paths['records']/install.RECORD).exists())
        manifest,files=pack.verify_bundle(self.payload)
        for path,unused,unused_mode in install.installation_plan(manifest,files,self.paths['prefix'],self.paths['records'],
                self.paths['service_path'],'linux',daemon_state_dir=self.paths['runtime_state']):
            self.assertFalse(path.exists())
        self.assertEqual(self.archive_path.read_bytes(),self.payload)
        self.assertTrue((root/'descriptor.json').exists())

    def test_first_metadata_fault_and_owner_registration_failures_close_actual_fds_once(self):
        opened=[];closed=[];actual_open,actual_close,actual_stat=os.open,os.close,os.fstat
        primary=OSError('synthetic first held metadata refusal')
        def created(*args,**kwargs):fd=actual_open(*args,**kwargs);opened.append(fd);return fd
        def closed_once(fd):closed.append(fd);return actual_close(fd)
        with patch.object(retained.os,'open',created),patch.object(retained.os,'close',closed_once),patch.object(retained.os,'fstat',side_effect=primary):
            with self.assertRaises(OSError) as error:retained.Directory(self.paths['records'],self.until)
        self.assertIs(error.exception,primary);self.assertEqual(closed,opened)
        for fd in opened:
            with self.assertRaises(OSError):actual_stat(fd)
        for after in (False,True):
            owners=retained.Owners();live=retained.Directory(self.home,self.until,private=False)
            fds=[row[1] for row in live.chain]
            class FailedList(list):
                def append(self,value):
                    if after:super().append(value)
                    raise MemoryError('synthetic registered owner allocation refusal')
            owners.values=FailedList()
            with self.assertRaises(MemoryError):owners.add(live)
            owners.close();self.assertIsNone(owners.pending);self.assertEqual(owners.values,[])
            for fd in fds:
                with self.assertRaises(OSError):actual_stat(fd)

    def test_owned_unit_pending_registration_preserves_first_cause_and_closes_once(self):
        result=frontend.execute(self.selection(),self.home,self.until);selected=self.observe(result['retention'])
        setter=object.__setattr__;actual_close=os.close
        for after in (False,True):
            primary=MemoryError('synthetic public unit owner enrollment refusal')
            cleanup=OSError('synthetic completed unit owner close refusal');parents=[];attempts=[]
            class FailedList(list):
                def append(self,fd):
                    if after:super().append(fd)
                    raise primary
            def enrolled(instance,name,value):
                setter(instance,name,FailedList() if name=='held' and value==[] else value)
            def directory(path,private=False):
                fd=self.fixture_directory(path,private);parents.append(fd);return fd
            def close(fd):
                if fd in parents:
                    attempts.append(fd);actual_close(fd);raise cleanup
                return actual_close(fd)
            with patch.object(guard,'open_directory',directory),patch.object(guard.OwnedUnitCustody,'__setattr__',enrolled),patch.object(guard.os,'close',close):
                with self.assertRaises(MemoryError) as error:guard.OwnedUnitCustody(selected)
            self.assertIs(error.exception,primary);self.assertIs(error.exception.__cause__,cleanup)
            self.assertEqual(attempts,parents);self.assertEqual(len(attempts),1)
            with self.assertRaises(OSError):os.fstat(parents[0])

    def test_original_cutoff_and_record_reference_tamper_refuse(self):
        with self.assertRaises(ValueError):frontend.execute(self.selection(),self.home,time.monotonic_ns())
        self.assertFalse(self.paths['records'].exists())
        result=frontend.execute(self.selection(),self.home,self.until);selected=self.observe(result['retention'])
        self.fragment();record=self.paths['records']/install.RECORD
        value=json.loads(record.read_bytes());value['publicRetention']['sha256']='0'*64
        record.write_bytes(pack.json_bytes(value));record.chmod(0o600)
        with patch.object(guard,'open_directory',side_effect=self.fixture_directory):
            with self.assertRaises(ValueError):owned.QualifiedExistingEnrollment({**selected,'existing_archive':selected['start']},self.home,self.until)

    def test_wrong_original_source_graph_and_retention_digest_never_qualify_copied_content(self):
        result=frontend.execute(self.selection(),self.home,self.until)
        for name in ('source_commit','graph_sha256'):
            selected=self.observe(result['retention'])['start']
            selected['qualification'][name]='c'*(40 if name=='source_commit' else 64)
            with self.assertRaises(ValueError):retained.qualified_retained(selected,self.paths['records'],self.home,self.until)
        selected=self.observe(result['retention'])['start'];selected['retention']['sha256']='0'*64
        with self.assertRaises(ValueError):retained.qualified_retained(selected,self.paths['records'],self.home,self.until)
        self.assertEqual(self.qpath.read_bytes(),self.qraw)

    def test_resealed_valid_foreign_archive_cannot_substitute_original_producer_tuple(self):
        result=frontend.execute(self.selection(),self.home,self.until)
        root=Path(result['retention']['path']).parent
        reference=json.loads(self.reference.read_bytes());reference['product']['version']='0.2.0-dev.foreign'
        self.reference.write_bytes(pack.json_bytes(reference));foreign=self.portable_bundle('release')
        doc=retained.descriptor(foreign,self.original,self.qraw)
        unused,files=pack.verify_bundle(foreign)
        root.chmod(0o700)
        for name,raw in (('archive.tar.gz',foreign),('release-manifest.json',files['release-manifest.json']),
                         ('descriptor.json',retained.encoded(doc))):
            leaf=root/name;leaf.chmod(0o600);leaf.write_bytes(raw);leaf.chmod(0o444)
        root.chmod(0o555)
        selected=self.observe({'path':str(root/'descriptor.json'),
            'sha256':retained.sha(retained.encoded(doc)),'bytes':len(retained.encoded(doc))})['start']
        with self.assertRaises(ValueError):retained.qualified_retained(selected,self.paths['records'],self.home,self.until)
        self.assertNotEqual(retained.sha(foreign),self.original['archive_sha256'])

    def test_actual_main_late_stdout_flush_refuses_terminal_success_after_all_fds_close(self):
        document=self.home/'install-input.json';document.write_bytes(retained.encoded(self.selection()));document.chmod(0o600)
        clock=[time.monotonic_ns()];outer=clock[0]+600*10**9;opened=[];actual_open=os.open
        def created(*args,**kwargs):fd=actual_open(*args,**kwargs);opened.append(fd);return fd
        class ExpiredFlush(io.StringIO):
            def flush(self):clock[0]=outer
        stdout=ExpiredFlush()
        with patch.dict(os.environ,{'HOME':str(self.home),'OMUX_RESIDENT_ORIGINAL_DEADLINE_NS':str(outer)}),patch.object(frontend.sys,'argv',['retained_public_install','--manifest',str(document)]),patch.object(frontend.sys,'stdout',stdout),patch.object(retained.time,'monotonic_ns',side_effect=lambda:clock[0]),patch.object(retained.os,'open',created):
            with self.assertRaises(ValueError):frontend.main()
        provisional=json.loads(stdout.getvalue());self.assertFalse(provisional['custody_verified'])
        self.assertFalse(provisional['service_started']);self.assertFalse(provisional['installed_image_qualified'])
        self.assertTrue(opened)
        for fd in set(opened):
            with self.assertRaises(OSError):os.fstat(fd)

    def test_owned_runtime_close_error_still_drains_current_retained_software_once(self):
        result=frontend.execute(self.selection(),self.home,self.until);self.fragment()
        self.paths['runtime_state'].mkdir(mode=0o700,parents=True)
        lock=self.paths['runtime_state']/'daemon.lock';lock.write_bytes(b'');lock.chmod(0o600)
        with patch.object(guard,'open_directory',side_effect=self.fixture_directory):
            witness=owned.OwnedCustodyReopen(self.observe(result['retention']),self.home,self.until)
            lockfd=witness.lock;archivefd=witness.software.retention.archive.fd
            original=os.close;attempts=[];first=OSError('synthetic successful runtime close refusal')
            def refuse(fd):
                attempts.append(fd);original(fd)
                if fd==lockfd:raise first
            with patch.object(owned.os,'close',refuse):
                with self.assertRaises(OSError) as error:witness.close()
            self.assertIs(error.exception,first);self.assertIn(archivefd,attempts)
            self.assertEqual(len(attempts),len(set(attempts)));self.assertIsNone(witness.software)
            for fd in (lockfd,archivefd):
                with self.assertRaises(OSError):os.fstat(fd)
            witness.close()


if __name__ == '__main__':unittest.main()
