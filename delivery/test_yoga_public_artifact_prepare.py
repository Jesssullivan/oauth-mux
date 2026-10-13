"""Real bounded public artifact/FD fixtures; no candidate executable or seat.

Run only through the declared Bazel target. Production Nix registration/custody
is not modeled as a success: one explicit roots-only seam avoids store access.
Archive verification, complete manifest/alias reads and byte inventories are real.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

import yoga_public_artifact_prepare as model
import test_delivery as artifacts
import test_browser_runtime_authority as proof


ZIP = RULE = None


class PreparationModels(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.epoch = self.root/'state/12345678-1234-4234-8234-123456789abc'
        self.base = self.epoch/'output-base'
        self.source = self.root/'source'; self.source.mkdir(mode=0o700)
        self.physical = self.base/'execroot/_main/bazel-out/k8-fastbuild/bin/delivery'
        self.physical.mkdir(parents=True,mode=0o700)
        self.controls = self.physical/'yoga_public_artifact_prepare_producer.sh.runfiles'
        self.controls.mkdir(mode=0o700)
        self.runner = self.physical/'yoga_toolbar_consent_proof.sh.runfiles'
        self.runner.mkdir(mode=0o700)
        self.output = self.base/'execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_public_artifact_prepare_producer/test.outputs'
        self.output.mkdir(parents=True,mode=0o700)
        self.entry = 1000*10**9; self.deadline = self.entry+1200*10**9; self.now=self.entry+10**9
        self.context = {'epoch':str(self.epoch),'entryNs':self.entry,'deadlineNs':self.deadline,
            'sourceCommit':'a'*40,'graphSha256':'b'*64,'sourceRoot':str(self.source)}
        self.env = {model.VARIABLE+name:value for name,value in {
            'EPOCH':str(self.epoch),'ENTRY_NS':str(self.entry),'DEADLINE_NS':str(self.deadline),
            'SOURCE_COMMIT':'a'*40,'GRAPH_SHA256':'b'*64,'SOURCE_ROOT':str(self.source)}.items()}
        self.env.update(TEST_SRCDIR=str(self.controls),TEST_UNDECLARED_OUTPUTS_DIR=str(self.output))
        self.addCleanup(patch.stopall)
        patch.object(model.time,'monotonic_ns',side_effect=lambda:self.now).start()
        actual = model.directory_custody
        patch.object(model,'directory_custody',side_effect=lambda path,info:
            actual(path,info) or path==Path('/tmp') and info.st_uid==0 and bool(info.st_mode&stat.S_ISVTX)).start()
        def declared_roots(owner,values):
            # Only production Nix inode/registration access is omitted. These
            # fixtures never add a foreign filesystem root to resolver authority.
            model.require(type(values) is list and values==sorted(set(values))
                and all(model.STORE.fullmatch(value) for value in values))
        patch.object(model.Inputs,'add_nix_roots',new=declared_roots).start()
        distribution=artifacts.DeliveryFixture(methodName='runTest'); distribution.setUp()
        self.addCleanup(distribution.doCleanups)
        authority=proof.AuthorityTests(methodName='runTest'); authority.setUp()
        self.addCleanup(authority.doCleanups)
        self.nix='/nix/store/'+'0'*32+'-fixture'
        shell=self.nix+'/bin/bash'
        native={'system':'x86_64-linux','packages':{'bash':{'out':self.nix},'python':{'out':self.nix}},
            'tools':{key:self.nix+'/bin/'+name for key,name in
                [('dbus_run_session','dbus-run-session'),('dbus_daemon','dbus-daemon'),
                 ('gnome_keyring_daemon','gnome-keyring-daemon')]}}
        self.data={'bundle':distribution.portable_bundle('development'), 'extension':ZIP,
            'runtime_authority':model.canonical(authority.joined()),'native_manifest':model.canonical(native),
            'native_store_paths':(self.nix+'\n').encode(),'interpreter_closures':b'{"schemaVersion":1,"groups":{"python":{}}}',
            'rules_source':RULE,'observer':b'passive declared fixture observer',
            'recorder':b'health-only declared fixture','recorder_implementation':b'fixture data only',
            'chromium':b'candidate fixture bytes, never executable invocation', 'node':b'candidate fixture bytes'}
        for role,name in [('dbus_session','dbus_run_session'),('dbus_daemon','dbus_daemon'),('keyring','gnome_keyring_daemon')]:
            self.data[role]=('#!'+shell+'\nset -eu\nexec \''+native['tools'][name]+'\' "$@"\n').encode()
        self.data['python_wrapper']=('#!'+shell+'\nset -eu\nexec \''+self.nix+'/bin/python3\' "$@"\n').encode()
        roles={role:'_main/delivery/fixture-'+role for role in model.ROLES}
        roles['runner_manifest']='_main/delivery/yoga_toolbar_consent_proof.sh.runfiles_manifest'
        roles['launcher']='_main/delivery/yoga_toolbar_consent_proof.sh'
        self.roles=roles
        self.data['launcher']=('#!'+shell+'\nset -eu\n'
            "printf '%s' 'Omux executable requires Bazel directory runfiles.'\n"
            'unset NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONHOME\n'+
            '\n'.join(flag+' "$RUNFILES_ROOT/'+roles[role]+'"' for role,flag in model.FLAGS.items())+
            '\nexec "$RUNFILES_ROOT/'+roles['python_wrapper']+'" -I -B -X utf8 -c fixture '
            '"$RUNFILES_ROOT/_main/delivery/yoga_toolbar_consent.py" "$@"\n').encode()
        self.paths={}; rows=[]; manifest=[]
        for role in sorted(model.ROLES):
            key=roles[role]; name=Path(key).name; physical=self.physical/name
            self.paths[role]=physical
            if role=='runner_manifest': continue
            physical.write_bytes(self.data[role]); physical.chmod(0o555)
        for role in sorted(model.ROLES):
            key=roles[role]; physical=self.paths[role]
            control=self.controls/key; control.parent.mkdir(parents=True,exist_ok=True); control.symlink_to(physical)
            in_runner=role not in ('runner_manifest','rules_source','native_store_paths')
            if in_runner:
                alias=self.runner/key; alias.parent.mkdir(parents=True,exist_ok=True); alias.symlink_to(physical)
                manifest.append(key+' '+str(physical))
            rows.append({'key':key,'executionPath':str(physical.relative_to(self.base/'execroot/_main')),'inRunner':in_runner})
        for key in sorted(model.REQUIRED_RUNFILES):
            physical=self.physical/Path(key).name;physical.write_bytes(b'model source data, not invoked\n');physical.chmod(0o555)
            for root in (self.controls,self.runner):
                alias=root/key;alias.parent.mkdir(parents=True,exist_ok=True);alias.symlink_to(physical)
            manifest.append(key+' '+str(physical))
            rows.append({'key':key,'executionPath':str(physical.relative_to(self.base/'execroot/_main')),'inRunner':True})
        self.paths['runner_manifest'].write_text('\n'.join(sorted(manifest))+'\n')
        self.paths['runner_manifest'].chmod(0o555)
        self.declared={'schemaVersion':1,'scope':'yoga-current-toolbar-declaration-v1','runnerLabel':model.RUNNER,
            'preparationSource':'a'*40,'preparationSourceDirty':False,'roles':roles,
            'files':sorted(rows,key=lambda row:row['key'])}
        self.declaration=self.controls/'_main/delivery/inputs.json'
        self.declaration.write_bytes(model.canonical(self.declared)); self.declaration.chmod(0o555)

    def prepare(self):
        return model.prepare(self.declaration,self.env)

    def mutate_fixture(self,role,raw):
        # Only these directly created synthetic leaves become writable. Never
        # relax producer custody checks or depend on root bypassing mode0555.
        self.assertIn(role,('runner_manifest','bundle','dbus_session'))
        path=self.paths[role];information=path.lstat()
        self.assertTrue(stat.S_ISREG(information.st_mode))
        self.assertEqual(information.st_uid,os.getuid())
        self.assertEqual(stat.S_IMODE(information.st_mode),0o555)
        path.chmod(0o600)
        try:path.write_bytes(raw)
        finally:path.chmod(0o555)
        self.assertEqual(stat.S_IMODE(path.lstat().st_mode),0o555)

    def test_actual_complete_artifact_and_original_runfiles_retained_without_execution(self):
        result=self.prepare()
        product=self.output/'yoga-public-toolbar'
        inventory=model.decode((product/'runfiles-inventory.json').read_bytes())
        self.assertEqual(result['inventorySha256'],hashlib.sha256((product/'runfiles-inventory.json').read_bytes()).hexdigest())
        self.assertEqual(result['metadata']['embeddedArchiveProvenance'],{'sourceRevision':None,'sourceDirty':True})
        self.assertEqual(result['context']['sourceCommit'],'a'*40)
        self.assertEqual(result['originalRunfilesRoot'],str(self.runner))
        self.assertEqual(inventory['declaredFileCount'],len(self.declared['files']))
        self.assertTrue(all(result[name] is False for name in model.FALSE))
        self.assertTrue(result['freshConsumerQualificationRequired'])
        self.assertTrue(self.paths['bundle'].exists())

    def test_changed_source_dirty_and_duplicate_binding_refuse_without_complete_product(self):
        for change in ('source','dirty','duplicate'):
            value=copy.deepcopy(self.declared)
            if change=='source':value['preparationSource']='c'*40
            elif change=='dirty':value['preparationSourceDirty']=True
            else:value['files'].append(value['files'][0])
            with self.subTest(change=change),self.assertRaises(ValueError):
                model.declaration(model.canonical(value),self.context)
        self.assertFalse((self.output/'yoga-public-toolbar').exists())

    def test_processwrapper_alias_never_becomes_retained_runfiles_authority(self):
        action=self.base/'sandbox/processwrapper-sandbox/1/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_public_artifact_prepare_producer.sh.runfiles'
        alias=action/'_main/delivery/inputs.json';alias.parent.mkdir(parents=True)
        alias.symlink_to(self.declaration)
        env=dict(self.env,TEST_SRCDIR=str(action))
        result=model.prepare(alias,env)
        self.assertEqual(result['originalControlRunfilesRoot'],str(self.controls))
        self.assertEqual(result['originalRunfilesRoot'],str(self.runner))
        self.assertNotIn('/sandbox/',result['originalControlRunfilesRoot'])

    def test_missing_actual_runner_manifest_refuses(self):
        self.paths['runner_manifest'].unlink()
        with self.assertRaises(FileNotFoundError):self.prepare()

    def test_missing_main_or_protected_import_cannot_be_called_complete(self):
        value=copy.deepcopy(self.declared)
        value['files']=[row for row in value['files'] if row['key']!='_main/delivery/yoga_toolbar_consent.py']
        with self.assertRaises(ValueError):model.declaration(model.canonical(value),self.context)

    def test_missing_actual_runner_tree_refuses_even_when_controls_are_complete(self):
        self.runner.rename(self.runner.with_name('retired-runfiles'))
        with self.assertRaises(FileNotFoundError):self.prepare()

    def test_unknown_manifest_alias_and_changed_physical_target_refuse(self):
        path=self.paths['runner_manifest']; original=path.read_text()
        for text in (original+'unknown '+str(self.paths['bundle'])+'\n',
                original.replace(str(self.paths['bundle']),str(self.paths['extension']))):
            self.mutate_fixture('runner_manifest',text.encode('utf-8'))
            with self.assertRaises(ValueError):self.prepare()
        self.assertFalse((self.output/'yoga-public-toolbar').exists())

    def test_foreign_symlink_destination_refuses_before_read(self):
        foreign=self.root/'foreign';foreign.write_bytes(b'outside selection')
        alias=self.runner/self.roles['observer'];alias.unlink();alias.symlink_to(foreign)
        with self.assertRaises(ValueError):self.prepare()

    def test_mutation_of_earlier_held_wrapper_during_later_io_refuses(self):
        real=os.read;changed=False
        def read(fd,count):
            nonlocal changed
            block=real(fd,count)
            if block and not changed and os.fstat(fd).st_ino==self.paths['rules_source'].stat().st_ino:
                self.mutate_fixture('dbus_session',self.data['dbus_session']+b'changed')
                changed=True
            return block
        with patch.object(model.os,'read',side_effect=read):
            with self.assertRaises(ValueError):self.prepare()
        self.assertTrue(changed)

    def test_mutated_alias_during_read_refuses_same_content_substitution(self):
        alias=self.runner/self.roles['observer'];real=os.read;changed=False
        def read(fd,count):
            nonlocal changed
            block=real(fd,count)
            if block and not changed and os.fstat(fd).st_ino==self.paths['observer'].stat().st_ino:
                changed=True;alias.unlink();alias.symlink_to(self.paths['observer'])
            return block
        with patch.object(model.os,'read',side_effect=read):
            with self.assertRaises(ValueError):self.prepare()
        self.assertTrue(changed)

    def test_original_cutoff_during_actual_read_refuses_no_clock_reset(self):
        real=os.read
        def read(fd,count):
            block=real(fd,count);self.now=self.deadline-30*10**9;return block
        with patch.object(model.os,'read',side_effect=read):
            with self.assertRaises(ValueError):self.prepare()

    def test_partial_or_tampered_archive_refuses_real_verifier(self):
        self.mutate_fixture('bundle',self.data['bundle'][:-20])
        with self.assertRaises((ValueError,EOFError,OSError)):self.prepare()

    def test_wrapper_injection_and_unsafe_launcher_refuse(self):
        bad=dict(self.data);bad['dbus_daemon']+=b'echo unexpected\n'
        with self.assertRaises(ValueError):model.tuple_metadata(bad,self.declared)
        bad=dict(self.data);bad['launcher']=bad['launcher'].replace(b'-I -B -X utf8',b'-B')
        with self.assertRaises(ValueError):model.tuple_metadata(bad,self.declared)

    def test_old_or_unexpected_context_env_refuses(self):
        for env in (dict(self.env,OMUX_YOGA_PUBLIC_PREP_EXTRA='x'),
                dict(self.env,OMUX_YOGA_PUBLIC_PREP_DEADLINE_NS=str(self.deadline+1))):
            with self.assertRaises(ValueError):model.prepare(self.declaration,env)

    def test_enrollment_and_close_faults_preserve_primary_attempt_all_once(self):
        owners=model.Owned();read,write=os.pipe();owners.enroll(read);owners.enroll(write)
        actual=os.close;closed=[];primary=MemoryError('fixture body');secondary=OSError(5,'fixture close')
        def close(fd):
            closed.append(fd);actual(fd)
            if len(closed)==1:raise secondary
        with patch.object(model.os,'close',side_effect=close):
            with self.assertRaises(MemoryError) as error:owners.drain(primary)
        self.assertIs(error.exception,primary);self.assertIs(error.exception.__cause__,secondary)
        self.assertEqual(closed,[write,read]);self.assertFalse(owners)

    def test_allocated_descriptor_enrollment_before_and_after_insert_closes_once(self):
        class FailingOwners(model.Owned):
            def append(owner,fd):
                if inserted:list.append(owner,fd)
                raise MemoryError('fixture enrollment')
        for inserted in (False,True):
            read,write=os.pipe();os.close(write);owner=FailingOwners();closed=[];actual=os.close
            def close(fd):closed.append(fd);actual(fd)
            with self.subTest(inserted=inserted),patch.object(model.os,'close',side_effect=close):
                with self.assertRaises(MemoryError):owner.enroll(read)
                owner.drain()
            self.assertEqual(closed,[read]);self.assertFalse(owner)

    def test_output_write_failure_remains_first_cause_and_drains_all_descriptors(self):
        primary=OSError(28,'fixture output full');closed=[];actual=os.close
        def close(fd):closed.append(fd);actual(fd)
        with patch.object(model.os,'write',side_effect=primary),patch.object(model.os,'close',side_effect=close):
            with self.assertRaises(OSError) as error:
                model.publish(self.output/'failed-publication',(('artifact.json',b'{}'),),model.Clock(self.context))
        self.assertIs(error.exception,primary);self.assertEqual(len(closed),2)
        self.assertEqual(len(set(closed)),2)
        self.assertFalse((self.output/'failed-publication/runfiles-inventory.json').exists())

    def test_original_cutoff_after_successful_output_close_refuses_terminal_success(self):
        actual=os.close;closed=[]
        def close(fd):
            closed.append(fd);actual(fd)
            if len(closed)==3:self.now=self.deadline-30*10**9
        with patch.object(model.os,'close',side_effect=close):
            with self.assertRaises(ValueError):
                model.publish(self.output/'late-publication',(('artifact.json',b'{}'),('runfiles-inventory.json',b'{}')),model.Clock(self.context))
        self.assertEqual(len(closed),3)

    def test_named_runner_root_replacement_during_last_tuple_io_refuses(self):
        actual=os.read;changed=False
        def read(fd,count):
            nonlocal changed
            block=actual(fd,count)
            if block and not changed and os.fstat(fd).st_ino==self.paths['rules_source'].stat().st_ino:
                changed=True;self.runner.rename(self.runner.with_name('held-original'))
                self.runner.mkdir(mode=0o700)
            return block
        with patch.object(model.os,'read',side_effect=read):
            with self.assertRaises((ValueError,FileNotFoundError)):self.prepare()
        self.assertTrue(changed)

    def actual_main(self, phase):
        owner=self
        class SlowOutput(io.StringIO):
            def write(stream,text):
                result=super().write(text)
                if phase=='write' and 'OMUX_YOGA_CURRENT_PUBLIC_TOOLBAR_PREPARED_NO_EXECUTION' in text:
                    owner.now=owner.deadline-30*10**9
                return result
            def flush(stream):
                super().flush()
                if phase=='flush':owner.now=owner.deadline-30*10**9
        output=SlowOutput();diagnostic=io.StringIO()
        with patch.dict(model.os.environ,self.env,clear=True),patch.object(model.sys,'argv',
                ['prepare','--declaration',str(self.declaration)]),patch.object(model.sys,'stdout',output),patch.object(model.sys,'stderr',diagnostic):
            status=model.main()
        self.assertEqual(status,125)
        self.assertIn('OMUX_YOGA_CURRENT_PUBLIC_TOOLBAR_PREPARED_NO_EXECUTION',output.getvalue())
        self.assertEqual(diagnostic.getvalue(),'toolbar-public-preparation-refused\n')
        self.assertTrue((self.output/'yoga-public-toolbar/artifact.json').is_file())
        # Complete metadata plus a provisional marker is not a successful
        # producer receipt; guard retention still requires workload exit zero.

    def test_actual_main_late_success_marker_write_refuses_original_cutoff(self):
        self.actual_main('write')

    def test_actual_main_late_success_marker_flush_refuses_original_cutoff(self):
        self.actual_main('flush')


if __name__=='__main__':
    ZIP=Path(sys.argv.pop(1)).read_bytes()
    RULE=Path(sys.argv.pop(1)).read_bytes()
    unittest.main()
