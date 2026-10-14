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
        self.declared={'schemaVersion':2,'scope':'yoga-current-toolbar-declaration-v2','repoMappingKey':None,'runnerLabel':model.RUNNER,
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
        lines=diagnostic.getvalue().splitlines()
        self.assertEqual(lines[0],'toolbar-public-preparation-refused')
        details=json.loads(lines[1].removeprefix('toolbar-public-preparation-diagnostic '))
        self.assertEqual(details['errorType'],'ValueError')
        self.assertIn('tick',[row['function'] for row in details['ownedFrames']])
        self.assertTrue((self.output/'yoga-public-toolbar/artifact.json').is_file())
        # Complete metadata plus a provisional marker is not a successful
        # producer receipt; guard retention still requires workload exit zero.

    def test_actual_main_late_success_marker_write_refuses_original_cutoff(self):
        self.actual_main('write')

    def test_actual_main_late_success_marker_flush_refuses_original_cutoff(self):
        self.actual_main('flush')

    def assert_redacted_main_refusal(self,env,declaration):
        output=io.StringIO();diagnostic=io.StringIO()
        with patch.dict(model.os.environ,env,clear=True),patch.object(model.sys,'argv',
                ['prepare','--declaration',str(declaration)]),patch.object(model.sys,'stdout',output),                patch.object(model.sys,'stderr',diagnostic):
            status=model.main()
        self.assertEqual(status,125);self.assertEqual(output.getvalue(),'')
        lines=diagnostic.getvalue().splitlines();self.assertEqual(len(lines),2)
        self.assertEqual(lines[0],'toolbar-public-preparation-refused')
        self.assertTrue(lines[1].startswith('toolbar-public-preparation-diagnostic '))
        record=json.loads(lines[1].removeprefix('toolbar-public-preparation-diagnostic '))
        self.assertEqual(set(record),{'errorType','ownedFrames'})
        self.assertLessEqual(len(lines[1].encode('ascii')),4096+len('toolbar-public-preparation-diagnostic '))
        self.assertTrue(1 <= len(record['ownedFrames']) <= 12)
        for row in record['ownedFrames']:
            self.assertEqual(set(row),{'file','function','line'})
            self.assertIn(row['file'],model.REFUSAL_FILES);self.assertNotIn('/',row['file'])
            self.assertTrue(1 <= row['line'] <= 100000)
        self.assertFalse((self.output/'yoga-public-toolbar').exists())
        self.assertNotIn(str(self.root),diagnostic.getvalue())
        self.assertNotIn('PRIVATE_DIAGNOSTIC_CANARY',diagnostic.getvalue())
        return record

    def test_actual_main_context_conversion_refusal_reports_owned_coordinates_without_environment(self):
        env=dict(self.env);env[model.VARIABLE+'ENTRY_NS']='PRIVATE_DIAGNOSTIC_CANARY'
        record=self.assert_redacted_main_refusal(env,self.declaration)
        self.assertEqual(record['errorType'],'ValueError')
        self.assertIn('prepare',[row['function'] for row in record['ownedFrames']])

    def test_actual_main_missing_declared_leaf_reports_owned_coordinates_without_private_filename(self):
        absent=self.declaration.with_name('PRIVATE_DIAGNOSTIC_CANARY.json')
        record=self.assert_redacted_main_refusal(self.env,absent)
        self.assertEqual(record['errorType'],'FileNotFoundError')
        self.assertIn('resolve',[row['function'] for row in record['ownedFrames']])

    def test_actual_main_diagnostic_write_failure_stays_refused_without_raw_exception(self):
        class RefusingDiagnostic(io.StringIO):
            def write(stream,text):
                if 'toolbar-public-preparation-diagnostic ' in text:
                    raise OSError('PRIVATE_DIAGNOSTIC_CANARY')
                return super().write(text)
        env=dict(self.env);env[model.VARIABLE+'ENTRY_NS']='PRIVATE_DIAGNOSTIC_CANARY'
        diagnostic=RefusingDiagnostic();output=io.StringIO()
        with patch.dict(model.os.environ,env,clear=True),patch.object(model.sys,'argv',
                ['prepare','--declaration',str(self.declaration)]),patch.object(model.sys,'stdout',output),                patch.object(model.sys,'stderr',diagnostic):
            self.assertEqual(model.main(),125)
        self.assertEqual(diagnostic.getvalue(),'toolbar-public-preparation-refused\n')
        self.assertEqual(output.getvalue(),'');self.assertFalse((self.output/'yoga-public-toolbar').exists())

    def actual_public_space_fixture(self):
        # Exact BA1520 public row5902. Only this bounded synthetic fixture is
        # constructed; actual declaration/manifest evidence remains untouched.
        row={'key':'+cached_site_repository+omux_cached_site/closure/2ahpi3w4gh6l039bs3ai7isv7ga4n0y6-openal-soft-1.24.3/share/openal/hrtf/Default HRTF.mhr',
            'executionPath':'external/+cached_site_repository+omux_cached_site/closure/2ahpi3w4gh6l039bs3ai7isv7ga4n0y6-openal-soft-1.24.3/share/openal/hrtf/Default HRTF.mhr',
            'inRunner':True}
        declared=copy.deepcopy(self.declared);declared['files'].append(row)
        declared['files'].sort(key=lambda value:value['key'])
        self.declaration.chmod(0o600)
        try:self.declaration.write_bytes(model.canonical(declared))
        finally:self.declaration.chmod(0o555)
        physical=self.base/'execroot/_main'/row['executionPath'];physical.parent.mkdir(parents=True)
        content=b'bounded public filename fixture with ASCII space, never executed'
        physical.write_bytes(content);physical.chmod(0o555)
        for root in (self.controls,self.runner):
            alias=root/row['key'];alias.parent.mkdir(parents=True);alias.symlink_to(physical)
        original=self.paths['runner_manifest'].read_text().splitlines()
        record=' '+row['key'].replace(' ',r'\s')+' '+str(physical)
        pairs=[(line.partition(' ')[0],line) for line in original]+[(row['key'],record)]
        manifest=('\n'.join(line for key,line in sorted(pairs))+'\n').encode('ascii')
        self.mutate_fixture('runner_manifest',manifest)
        return row,physical,content,record,manifest

    def test_actual_public_space_row_complete_prepare_preserves_filename_fd_digest_and_manifest_binding(self):
        row,physical,content,record,manifest=self.actual_public_space_fixture()
        value,files=model.declaration(self.declaration.read_bytes(),self.context)
        self.assertEqual(files[row['key']],row);self.assertIn(row,value['files'])
        self.assertIn(r'\s',record);self.assertIn('Default HRTF.mhr',record)
        result=self.prepare();product=self.output/'yoga-public-toolbar'
        inventory=model.decode((product/'runfiles-inventory.json').read_bytes())
        bound=next(value for value in inventory['files'] if value['key']==row['key'])
        self.assertEqual(bound['physical'],str(physical));self.assertEqual(bound['bytes'],len(content))
        self.assertEqual(bound['sha256'],hashlib.sha256(content).hexdigest())
        self.assertEqual(bound['witness'],list(model.witness(physical.lstat())))
        self.assertEqual((self.runner/row['key']).name,'Default HRTF.mhr')
        self.assertEqual(self.paths['runner_manifest'].read_bytes(),manifest)
        self.assertEqual(result['inventorySha256'],hashlib.sha256((product/'runfiles-inventory.json').read_bytes()).hexdigest())
        self.assertTrue(all(result[name] is False for name in model.FALSE))
        self.assertTrue(result['freshConsumerQualificationRequired'])

    def test_declaration_space_support_keeps_control_nonascii_backslash_absolute_and_traversal_refusals(self):
        invalid=(None,'','a'*4097,'/absolute/name','a/../name','a/./name','a//name',
            'a\\name','a\tname','a\nname','a\rname','a\x00name','a\x1fname','a\x7fname','a\u00a0name','a\u00e9name')
        for field in ('key','executionPath'):
            for name in invalid:
                declared=copy.deepcopy(self.declared);declared['files'][0][field]=name
                with self.subTest(field=field,name=name),self.assertRaises(ValueError):
                    model.declaration(model.canonical(declared),self.context)
        self.assertFalse((self.output/'yoga-public-toolbar').exists())

    def test_complete_prepare_refuses_malformed_noncanonical_duplicate_traversing_and_substituted_records(self):
        row,physical,content,record,manifest=self.actual_public_space_fixture()
        wire=row['key'].replace(' ',r'\s')
        self.assertEqual(model.manifest_unescape(r'Default\bsHRTF.mhr',key=True),r'Default\sHRTF.mhr')
        other=physical.with_name('different declared filename.mhr');other.write_bytes(content);other.chmod(0o555)
        invalid=(
            record.replace(r'\s',r'\q',1),  # Unknown escape.
            ' '+wire+'\\ '+str(physical),  # Truncated key escape.
            ' '+wire+' '+str(physical).replace(' ',r'\s'),  # Target does not escape spaces.
            ' _main/ordinary '+str(physical),  # Unnecessary escaped marker.
            ' '+wire, ' '+wire+' ', '  '+wire+' '+str(physical),  # Missing fields/extra separator.
            r' ../space\sname '+str(physical),
            r' _main/bad\nname '+str(physical),
            r' _main/bad\bname '+str(physical),
            record.replace(r'\s',r'\bs',1),  # Decode once, never \b then \s.
            ' '+wire+' '+str(physical.parent)+'/../'+physical.name,
            ' '+wire+' '+str(physical)+'\r',
            ' '+wire+' '+str(physical).replace('Default HRTF',r'Default\nHRTF'),
            ' '+wire+' '+str(other))  # Valid syntax, wrong actual File binding.
        for malformed in invalid:
            raw=manifest.replace((record+'\n').encode('ascii'),(malformed+'\n').encode('ascii'),1)
            self.mutate_fixture('runner_manifest',raw)
            with self.subTest(record=malformed),self.assertRaises(ValueError):self.prepare()
            self.assertFalse((self.output/'yoga-public-toolbar').exists())
        for raw in (manifest.replace((record+'\n').encode('ascii'),((record+'\n')*2).encode('ascii'),1),
                manifest.rstrip(b'\n'),b'\n'+manifest,manifest+b'_main/late /relative\n'):
            self.mutate_fixture('runner_manifest',raw)
            with self.subTest(raw_bytes=len(raw)),self.assertRaises(ValueError):self.prepare()
            self.assertFalse((self.output/'yoga-public-toolbar').exists())

    def test_actual_manifest_decode_keeps_original_cutoff_and_drains_all_held_input_descriptors(self):
        self.actual_public_space_fixture();actual_decode=model.manifest_unescape;actual_open=os.open;actual_close=os.close
        decoded=False;opened=[];closed=[]
        def decode(value,*,key):
            nonlocal decoded
            result=actual_decode(value,key=key)
            if key and not decoded:self.now=self.deadline-30*10**9;decoded=True
            return result
        def open_fd(*args,**kwargs):
            fd=actual_open(*args,**kwargs);opened.append(fd);return fd
        def close_fd(fd):closed.append(fd);actual_close(fd)
        with patch.object(model,'manifest_unescape',side_effect=decode),patch.object(model.os,'open',side_effect=open_fd),\
                patch.object(model.os,'close',side_effect=close_fd):
            with self.assertRaises(ValueError):self.prepare()
        self.assertTrue(decoded);self.assertGreater(len(opened),3)
        self.assertEqual(closed,list(reversed(opened)));self.assertEqual(len(closed),len(set(closed)))
        for fd in opened:
            with self.assertRaises(OSError):os.fstat(fd)
        self.assertFalse((self.output/'yoga-public-toolbar').exists())



    def repo_mapping_fixture(self):
        # Synthetic representation of the actual provider File and its standard
        # Bazel alias; this helper never deploys or repairs production runfiles.
        key='_main/delivery/yoga_toolbar_consent_proof.sh.repo_mapping'
        target=self.physical/'yoga_toolbar_consent_proof.sh.repo_mapping'
        raw=b'_main,fixture_repo,fixture_repo\n'
        target.write_bytes(raw);target.chmod(0o555)
        (self.controls/key).symlink_to(target)
        (self.runner/'_repo_mapping').symlink_to(target)
        self.declared['repoMappingKey']=key
        self.declared['files'].append({'key':key,
            'executionPath':str(target.relative_to(self.base/'execroot/_main')),'inRunner':False})
        self.declared['files'].sort(key=lambda row:row['key'])
        self.declaration.chmod(0o600)
        try:self.declaration.write_bytes(model.canonical(self.declared))
        finally:self.declaration.chmod(0o555)
        lines=self.paths['runner_manifest'].read_text().splitlines()
        lines.append('_repo_mapping '+str(target))
        self.mutate_fixture('runner_manifest',('\n'.join(sorted(lines))+'\n').encode())
        return key,target,raw

    def test_actual_provider_mapping_file_and_reserved_alias_join_byte_inventory(self):
        key,target,raw=self.repo_mapping_fixture()
        result=self.prepare()
        inventory=model.decode((self.output/'yoga-public-toolbar/runfiles-inventory.json').read_bytes())
        rows={row['key']:row for row in inventory['files']}
        for selected in (key,'_repo_mapping'):
            self.assertEqual(rows[selected]['physical'],str(target))
            self.assertEqual(rows[selected]['sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual(rows[selected]['bytes'],len(raw))
            self.assertEqual(rows[selected]['witness'],list(model.witness(target.lstat())))
        self.assertEqual(inventory['declaredFileCount'],len(self.declared['files']))
        self.assertEqual(inventory['boundFileCount'],len(self.declared['files'])+1)
        self.assertTrue(all(result[name] is False for name in model.FALSE))
        self.assertTrue(result['freshConsumerQualificationRequired'])

    def test_missing_mapping_file_and_dangling_reserved_alias_refuse(self):
        key,target,raw=self.repo_mapping_fixture()
        target.unlink()
        with self.assertRaises(FileNotFoundError):self.prepare()
        target.write_bytes(raw);target.chmod(0o555)
        alias=self.runner/'_repo_mapping';alias.unlink();alias.symlink_to(self.physical/'absent-mapping')
        with self.assertRaises(FileNotFoundError):self.prepare()
        self.assertFalse((self.output/'yoga-public-toolbar').exists())

    def test_coordinated_mapping_alias_and_manifest_substitution_refuses_before_bytes(self):
        key,target,raw=self.repo_mapping_fixture()
        other=self.physical/'other-owned-mapping';other.write_bytes(raw);other.chmod(0o555)
        for alias in (self.controls/key,self.runner/'_repo_mapping'):
            alias.unlink();alias.symlink_to(other)
        text=self.paths['runner_manifest'].read_text().replace('_repo_mapping '+str(target),
            '_repo_mapping '+str(other))
        self.mutate_fixture('runner_manifest',text.encode())
        real=os.read;reads=[];inode=other.stat().st_ino
        def read(fd,count):
            if os.fstat(fd).st_ino==inode:reads.append(fd)
            return real(fd,count)
        with patch.object(model.os,'read',side_effect=read):
            with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(reads,[])
        self.assertFalse((self.output/'yoga-public-toolbar').exists())

    def test_control_mapping_alias_substitution_refuses_original_provider_binding(self):
        key,target,raw=self.repo_mapping_fixture()
        other=self.physical/'other-owned-control-mapping';other.write_bytes(raw);other.chmod(0o555)
        alias=self.controls/key;alias.unlink();alias.symlink_to(other)
        with self.assertRaises(ValueError):self.prepare()
        self.assertFalse((self.output/'yoga-public-toolbar').exists())

    def test_nullable_provider_mapping_and_current_schema_must_agree(self):
        key,target,raw=self.repo_mapping_fixture()
        for change in ('none','unknown','runner','legacy'):
            value=copy.deepcopy(self.declared)
            if change=='none':value['repoMappingKey']=None
            elif change=='unknown':value['repoMappingKey']='_main/delivery/unknown-mapping'
            elif change=='runner':next(row for row in value['files'] if row['key']==key)['inRunner']=True
            else:
                value.pop('repoMappingKey');value['schemaVersion']=1
                value['scope']='yoga-current-toolbar-declaration-v1'
            with self.subTest(change=change):
                if change=='none':
                    self.declaration.chmod(0o600)
                    try:self.declaration.write_bytes(model.canonical(value))
                    finally:self.declaration.chmod(0o555)
                    with self.assertRaises(ValueError):self.prepare()
                else:
                    with self.assertRaises(ValueError):model.declaration(model.canonical(value),self.context)
        self.declaration.chmod(0o600)
        try:self.declaration.write_bytes(model.canonical(self.declared))
        finally:self.declaration.chmod(0o555)
        lines=[line for line in self.paths['runner_manifest'].read_text().splitlines()
            if not line.startswith('_repo_mapping ')]
        self.mutate_fixture('runner_manifest',('\n'.join(lines)+'\n').encode())
        with self.assertRaises(ValueError):self.prepare()
        self.assertFalse((self.output/'yoga-public-toolbar').exists())

    def test_actual_mapping_read_uses_original_cutoff_and_drains_all_descriptors(self):
        key,target,raw=self.repo_mapping_fixture()
        real_open=os.open;real_close=os.close;real_read=os.read;opened=[];closed=[];changed=False
        inode=target.stat().st_ino
        def opening(*args,**kwargs):
            fd=real_open(*args,**kwargs);opened.append(fd);return fd
        def closing(fd):
            closed.append(fd);return real_close(fd)
        def read(fd,count):
            nonlocal changed
            block=real_read(fd,count)
            if block and os.fstat(fd).st_ino==inode:
                self.now=self.deadline-30*10**9;changed=True
            return block
        with patch.object(model.os,'open',side_effect=opening),patch.object(model.os,'close',side_effect=closing),\
                patch.object(model.os,'read',side_effect=read):
            with self.assertRaises(ValueError):self.prepare()
        self.assertTrue(changed)
        self.assertEqual(closed,list(reversed(opened)))
        for fd in opened:
            with self.assertRaises(OSError):os.fstat(fd)
        self.assertFalse((self.output/'yoga-public-toolbar').exists())

    def test_mapping_alias_change_during_final_fd_retirement_refuses_provisional_product(self):
        key,target,raw=self.repo_mapping_fixture()
        other=self.physical/'later-owned-mapping';other.write_bytes(raw);other.chmod(0o555)
        alias=self.runner/'_repo_mapping'
        real_open=os.open;real_close=os.close;real_publish=model.publish
        opened=[];closed=[];armed=False;changed=False
        def opening(*args,**kwargs):
            fd=real_open(*args,**kwargs);opened.append(fd);return fd
        def publishing(*args,**kwargs):
            nonlocal armed
            result=real_publish(*args,**kwargs);armed=True;return result
        def closing(fd):
            nonlocal changed
            closed.append(fd)
            if armed and not changed:
                alias.unlink();alias.symlink_to(other);changed=True
            return real_close(fd)
        with patch.object(model.os,'open',side_effect=opening),patch.object(model.os,'close',side_effect=closing),\
                patch.object(model,'publish',side_effect=publishing):
            with self.assertRaises(ValueError):self.prepare()
        self.assertTrue(armed and changed)
        self.assertEqual(sorted(opened),sorted(closed))
        for fd in set(opened):
            with self.assertRaises(OSError):os.fstat(fd)
        # Publication may precede the final refusal: only a genuine zero-exit
        # outer receipt can accept the product, never mere file existence.
        self.assertTrue((self.output/'yoga-public-toolbar/artifact.json').exists())


    def test_one_read_joins_same_lexical_manifest_name_and_keeps_real_byte_witnesses(self):
        owner=model.Inputs(model.Clock(self.context),self.base,self.source)
        target=self.paths['observer'];alias=self.runner/self.roles['observer']
        real=owner.resolve;walks=[]
        def resolve(path):
            walks.append(Path(path));return real(path)
        try:
            with patch.object(owner,'resolve',side_effect=resolve):
                raw=owner.read('joined-observer',alias,target,aliases=(str(target),),content=True)
            self.assertEqual(raw,self.data['observer'])
            self.assertEqual(walks,[target,alias])
            row=owner.rows['joined-observer']
            self.assertEqual(row['sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual(row['witness'],list(model.witness(target.lstat())))
            self.assertEqual(owner.links[str(alias)][1],str(target))
            owner.recheck()
        finally:owner.close()

    def test_join_is_not_a_cross_file_cache_and_replaced_same_bytes_alias_refuses(self):
        target=self.paths['observer'];alias=self.runner/self.roles['observer']
        other=self.physical/'same-bytes-next-observer'
        other.write_bytes(self.data['observer']);other.chmod(0o555)
        owner=model.Inputs(model.Clock(self.context),self.base,self.source)
        real_read=os.read;reads=[]
        try:
            self.assertEqual(owner.read('first-observer',alias,target,aliases=(str(target),),content=True),
                self.data['observer'])
            alias.unlink();alias.symlink_to(other)
            def read(fd,count):
                reads.append(fd);return real_read(fd,count)
            with patch.object(model.os,'read',side_effect=read):
                with self.assertRaises(ValueError):
                    owner.read('second-observer',alias,target,aliases=(str(target),),content=True)
            self.assertEqual(reads,[])
            self.assertNotIn('second-observer',owner.rows)
        finally:owner.close(ValueError('synthetic already-refused alias'))

    def test_join_does_not_hide_expected_name_replacement_during_real_fd_read(self):
        target=self.paths['observer'];alias=self.runner/self.roles['observer']
        other=self.physical/'replacement-observer';other.write_bytes(self.data['observer']);other.chmod(0o555)
        owner=model.Inputs(model.Clock(self.context),self.base,self.source)
        real_open=os.open;real_close=os.close;real_read=os.read
        opened=[];closed=[];changed=False;inode=target.stat().st_ino
        def opening(*args,**kwargs):
            fd=real_open(*args,**kwargs);opened.append(fd);return fd
        def closing(fd):
            closed.append(fd);return real_close(fd)
        def read(fd,count):
            nonlocal changed
            raw=real_read(fd,count)
            if raw and not changed and os.fstat(fd).st_ino==inode:
                other.replace(target);changed=True
            return raw
        try:
            with patch.object(model.os,'open',side_effect=opening),patch.object(model.os,'close',side_effect=closing),\
                    patch.object(model.os,'read',side_effect=read):
                with self.assertRaises(ValueError):
                    owner.read('replaced-observer',alias,target,aliases=(str(target),),content=True)
                owner.close(ValueError('synthetic already-refused replacement'))
            self.assertTrue(changed)
            self.assertEqual(closed,list(reversed(opened)))
            self.assertNotIn('replaced-observer',owner.rows)
            for fd in opened:
                with self.assertRaises(OSError):os.fstat(fd)
        finally:owner.close(ValueError('synthetic refusal cleanup'))

    def test_join_expiry_after_last_distinct_alias_walk_keeps_original_cutoff_and_fd_cleanup(self):
        target=self.paths['observer'];alias=self.runner/self.roles['observer']
        owner=model.Inputs(model.Clock(self.context),self.base,self.source)
        real_resolve=owner.resolve;real_open=os.open;real_close=os.close;real_read=os.read
        opened=[];closed=[];reads=[];expired=False
        def resolve(path):
            nonlocal expired
            physical=real_resolve(path)
            if Path(path)==alias:
                self.now=self.deadline-30*10**9;expired=True
            return physical
        def opening(*args,**kwargs):
            fd=real_open(*args,**kwargs);opened.append(fd);return fd
        def closing(fd):
            closed.append(fd);return real_close(fd)
        def read(fd,count):
            reads.append(fd);return real_read(fd,count)
        try:
            with patch.object(owner,'resolve',side_effect=resolve),\
                    patch.object(model.os,'open',side_effect=opening),patch.object(model.os,'close',side_effect=closing),\
                    patch.object(model.os,'read',side_effect=read):
                with self.assertRaises(ValueError):
                    owner.read('late-observer',alias,target,aliases=(str(target),),content=True)
                owner.close(ValueError('synthetic original-cutoff refusal'))
            self.assertTrue(expired)
            self.assertEqual(reads,[])
            self.assertEqual(closed,list(reversed(opened)))
            self.assertNotIn('late-observer',owner.rows)
            for fd in opened:
                with self.assertRaises(OSError):os.fstat(fd)
        finally:owner.close(ValueError('synthetic refusal cleanup'))


    def test_live_root_membership_matches_legacy_prefix_rule_and_scales_with_depth(self):
        owner=model.Inputs(model.Clock(self.context),self.base,self.source)
        class Membership(dict):
            def __contains__(self,key):
                self.probes.append(key);return super().__contains__(key)
        roots={Path('/nix/store/'+str(index).zfill(32)+'-fixture'):None for index in range(4096)}
        roots.update(owner.roots);selected=Path('/nix/store/'+str(4095).zfill(32)+'-fixture')
        owner.roots=Membership(roots);owner.roots.probes=[]
        paths=(selected,selected/'lib/actual-file',Path(str(selected)+'-suffix/file'),
            Path('/nix/store'),Path('/nix/store/foreign/file'),self.base,self.base/'real/file',
            Path(str(self.base)+'-suffix/file'),self.source/'file',Path('relative/file'))
        try:
            for path in paths:
                with self.subTest(path=str(path)):
                    expected=any(path==root or path.is_relative_to(root) for root in roots)
                    owner.roots.probes=[]
                    self.assertEqual(owner.allowed(path),expected)
                    self.assertLessEqual(len(owner.roots.probes),1+len(path.parents))
            self.assertEqual(len(owner.roots),4098)
        finally:owner.close()

    def test_root_membership_updates_never_reuse_a_previous_positive_decision(self):
        owner=model.Inputs(model.Clock(self.context),self.base,self.source)
        target=self.source/'actual-root-member';target.write_bytes(b'actual root member');target.chmod(0o555)
        alias=self.runner/'root-member';alias.symlink_to(target)
        try:
            self.assertEqual(owner.resolve(alias),target)
            del owner.roots[self.source]
            self.assertFalse(owner.allowed(target))
            with self.assertRaises(ValueError):owner.resolve(alias)
            owner.roots[self.source]=None
            self.assertEqual(owner.resolve(alias),target)
            owner.roots.clear()
            self.assertFalse(owner.allowed(target))
            with self.assertRaises(ValueError):owner.resolve(alias)
        finally:owner.close(ValueError('synthetic removed authority'))

    def test_live_membership_does_not_authorize_foreign_alias_or_skip_real_content_checks(self):
        owner=model.Inputs(model.Clock(self.context),self.base,self.source)
        target=self.source/'actual-authorized-leaf';target.write_bytes(b'root-bound bytes');target.chmod(0o555)
        alias=self.runner/'authorized-leaf';alias.symlink_to(target)
        foreign=self.root/'unselected';foreign.mkdir(mode=0o700)
        replacement=foreign/'same-bytes';replacement.write_bytes(b'root-bound bytes');replacement.chmod(0o555)
        real=os.read;reads=[]
        try:
            self.assertEqual(owner.read('root-bound',alias,target,content=True),b'root-bound bytes')
            self.assertEqual(owner.rows['root-bound']['sha256'],hashlib.sha256(b'root-bound bytes').hexdigest())
            alias.unlink();alias.symlink_to(replacement)
            def read(fd,count):reads.append(fd);return real(fd,count)
            with patch.object(model.os,'read',side_effect=read):
                with self.assertRaises(ValueError):owner.read('foreign',alias,target,content=True)
            self.assertEqual(reads,[])
        finally:owner.close(ValueError('synthetic foreign alias refusal'))

    def test_root_membership_keeps_actual_directory_mode_and_final_alias_rechecks(self):
        owner=model.Inputs(model.Clock(self.context),self.base,self.source)
        target=self.source/'actual-mode-leaf';target.write_bytes(b'kept checks');target.chmod(0o555)
        alias=self.runner/'mode-leaf';alias.symlink_to(target)
        try:
            self.assertTrue(owner.allowed(target))
            self.source.chmod(0o777)
            with self.assertRaises(ValueError):owner.resolve(alias)
            self.source.chmod(0o700)
            self.assertEqual(owner.read('mode-leaf',alias,target,content=True),b'kept checks')
            replacement=self.source/'same-mode-bytes';replacement.write_bytes(b'kept checks');replacement.chmod(0o555)
            alias.unlink();alias.symlink_to(replacement)
            with self.assertRaises(ValueError):owner.recheck()
        finally:
            self.source.chmod(0o700)
            owner.close(ValueError('synthetic final alias refusal'))

    def test_root_membership_preserves_original_cutoff_before_any_file_bytes(self):
        owner=model.Inputs(model.Clock(self.context),self.base,self.source)
        target=self.paths['observer'];alias=self.runner/self.roles['observer']
        self.assertTrue(owner.allowed(target));self.now=self.deadline-30*10**9
        real=os.read;reads=[]
        def read(fd,count):reads.append(fd);return real(fd,count)
        try:
            with patch.object(model.os,'read',side_effect=read):
                with self.assertRaises(ValueError):owner.read('expired-root',alias,target,content=True)
            self.assertEqual(reads,[])
            self.assertEqual(owner.rows,{})
        finally:owner.close(ValueError('synthetic original cutoff refusal'))


    def compact_inventory_fixture(self):
        self.prepare()
        raw=(self.output/'yoga-public-toolbar/runfiles-inventory.json').read_bytes()
        return model.decode(raw),raw

    def test_compact_inventory_real_prepare_roundtrip_and_literal_relative_link_targets(self):
        value,wire=self.compact_inventory_fixture()
        self.assertEqual(json.loads(wire)['schemaVersion'],2)
        self.assertEqual(json.loads(wire)['scope'],model.INVENTORY_WIRE_SCOPE)
        self.assertEqual(model.canonical(model.inventory_compact(value)),wire)
        legacy=model.canonical(value)
        self.assertEqual(model.decode(legacy),value)
        self.assertNotEqual(hashlib.sha256(legacy).digest(),hashlib.sha256(wire).digest())
        value['symlinks'][0]['target']='../../opaque/../relative-target'
        altered=model.canonical(model.inventory_compact(value))
        self.assertEqual(model.decode(altered),value)
        # Declaration schema2 remains an ordinary declaration, not inventory.
        self.assertEqual(model.decode(model.canonical(self.declared)),self.declared)
        wrong_scope=json.loads(wire);wrong_scope['scope']='another-json-schema-v2'
        self.assertEqual(model.decode(model.canonical(wrong_scope)),wrong_scope)
        with self.assertRaises(ValueError):model.inventory_expand(wrong_scope)
        duplicate=wire.replace(b'"schemaVersion":2',b'"schemaVersion":2,"schemaVersion":2',1)
        with self.assertRaises(ValueError):model.decode(duplicate)

    def test_compact_inventory_refuses_duplicate_unknown_unused_and_forward_table_facts(self):
        value,raw=self.compact_inventory_fixture();wire=json.loads(raw)
        for change in ('unknown','duplicate-atom','unused-atom','forward','duplicate-path',
                'negative-ref','bool-ref','float-root','unknown-ref','target-forward','target-negative','target-bool',
                'duplicate-target','duplicate-file','duplicate-link','bool-version','version',
                'bad-witness','bad-bytes','missing','traversal','absolute-key','relative-physical'):
            changed=copy.deepcopy(wire)
            if change=='unknown':changed['unknown']=True
            elif change=='duplicate-atom':changed['strings'].append(changed['strings'][0])
            elif change=='unused-atom':changed['strings'].append('unused unique atom')
            elif change=='forward':changed['paths'][2][0]=len(changed['paths'])
            elif change=='duplicate-path':changed['paths'].append(copy.deepcopy(changed['paths'][2]))
            elif change=='negative-ref':changed['files'][0][0]=-1
            elif change=='bool-ref':changed['files'][0][0]=True
            elif change=='float-root':changed['paths'][0][0]=-1.0
            elif change=='unknown-ref':changed['symlinks'][0][2]=len(changed['targets'])
            elif change=='bool-version':changed['schemaVersion']=True
            elif change=='version':changed['schemaVersion']=1
            elif change=='target-negative':changed['symlinks'][0][2]=-1
            elif change=='target-bool':changed['symlinks'][0][2]=True
            elif change=='target-forward':changed['targets'][1][0]=len(changed['targets'])
            elif change=='duplicate-target':changed['targets'].append(copy.deepcopy(changed['targets'][1]))
            elif change=='duplicate-file':changed['files'].append(copy.deepcopy(changed['files'][0]))
            elif change=='duplicate-link':changed['symlinks'].append(copy.deepcopy(changed['symlinks'][0]))
            elif change=='bad-witness':changed['files'][0][4][0]=True
            elif change=='bad-bytes':changed['files'][0][3]=-1
            elif change=='missing':changed.pop('paths')
            elif change=='traversal':changed['strings'][changed['paths'][2][1]]='..'
            elif change=='absolute-key':changed['files'][0][0]=changed['files'][0][1]
            else:changed['files'][0][1]=changed['files'][0][0]
            with self.subTest(change=change),self.assertRaises(ValueError):
                model.decode(model.canonical(changed))

    def test_compact_inventory_keeps_original_clock_and_all_size_depth_and_count_limits(self):
        value,raw=self.compact_inventory_fixture()
        clock=model.Clock(self.context);self.now=self.deadline-30*10**9
        with self.assertRaises(ValueError):model.inventory_compact(value,clock)
        with self.assertRaises(ValueError):model.inventory_expand(json.loads(raw),clock)
        self.now=self.entry+10**9
        for change in ('depth','component','expanded','count','wire'):
            with self.subTest(change=change):
                changed=copy.deepcopy(value)
                if change=='depth':changed['files'][0]['physical']='/'+'/'.join('x' for _ in range(257))
                elif change=='component':changed['symlinks'][0]['target']='x'*4097
                if change in ('depth','component'):
                    with self.assertRaises(ValueError):model.inventory_compact(changed,clock)
                elif change=='expanded':
                    with patch.object(model,'MAX_INVENTORY_EXPANDED',1):
                        with self.assertRaises(ValueError):model.inventory_compact(changed,clock)
                elif change=='count':
                    with patch.object(model,'MAX_INVENTORY_PATHS',2):
                        with self.assertRaises(ValueError):model.inventory_compact(changed,clock)
                else:
                    with patch.object(model,'MAX_METADATA',len(raw)-1):
                        with self.assertRaises(ValueError):model.decode(raw)

    def test_compact_inventory_63675_full_shape_is_lossless_deterministic_and_below_original_envelope(self):
        # BA0720 public declaration census:63675 rows,235-char maximum key,
        #244-char executionPath,9767 directory prefixes,580 Nix roots. These
        #synthetic full witnesses/digests/aliases are a size-shape model only;
        #they are not the failed run's missing inventory or physical authority.
        count=63675;files=[];links=[]
        epoch=Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/12345678-1234-4234-8234-123456789abc')
        base=epoch/'output-base';execroot=base/'execroot/_main'
        controls=execroot/'bazel-out/k8-fastbuild/bin/delivery/yoga_public_artifact_prepare_producer.sh.runfiles'
        runner=execroot/'bazel-out/k8-fastbuild/bin/delivery/yoga_toolbar_consent_proof.sh.runfiles'
        for index in range(count):
            prefix='+cached_site_repository+omux_cached_site/closure/'+str(index%580).zfill(32)+'-fixture/files'+str(index%9767).zfill(4)+'/'
            name='file'+str(index).zfill(8)+'-'+'x'*(235-len(prefix)-13)
            key=prefix+name;self.assertEqual(len(key),235)
            expected='external/'+key;self.assertEqual(len(expected),244)
            physical=str(execroot/expected)
            witness=[2049,10000000+index,1000,1000,0o100555,1,index%4096,
                1791936000123456789,1791936000123456789]
            files.append({'key':key,'physical':physical,'sha256':hashlib.sha256(key.encode()).hexdigest(),
                'bytes':witness[6],'witness':witness})
            for root in (controls,runner):
                path=str(root/key);target=physical
                links.append({'path':path,'target':target,'witness':[2049,20000000+len(links),
                    1000,1000,0o120777,1,len(target),1791936000123456789,1791936000123456789]})
        files.sort(key=lambda row:row['key']);links.sort(key=lambda row:row['path'])
        context=dict(self.context,epoch=str(epoch),sourceRoot='/home/jess/public-source')
        value={'schemaVersion':1,'scope':'yoga-original-toolbar-runfiles-byte-inventory-v1',
            'context':context,'originalOutputBase':str(base),'originalRunfilesRoot':str(runner),
            'originalControlRunfilesRoot':str(controls),'declarationSha256':'a'*64,
            'files':files,'symlinks':links,'roles':dict(zip(sorted(model.ROLES),[row['key'] for row in files])),
            'declaredFileCount':count,'boundFileCount':count,'totalBytes':sum(row['bytes'] for row in files)}
        wire=model.canonical(model.inventory_compact(value))
        self.assertLess(len(wire),model.MAX_METADATA)
        self.assertGreater(len(model.canonical(value)),model.MAX_METADATA)
        restored=model.decode(wire)
        self.assertEqual(restored,value)
        self.assertEqual(len(restored['files']),count)
        self.assertEqual(len(restored['symlinks']),2*count)
        self.assertEqual(model.canonical(model.inventory_compact(restored)),wire)
        self.assertEqual(hashlib.sha256(wire).digest(),hashlib.sha256(model.canonical(model.inventory_compact(value))).digest())


    def test_compact_encoder_depth_component_boundaries_are_inverse_and_overflow_refuses(self):
        value,raw=self.compact_inventory_fixture()
        for domain,boundary in (('key-depth',256),('physical-component',4096),('alias-component',4096)):
            for extra in (0,1):
                changed=copy.deepcopy(value)
                if domain=='key-depth':
                    old=changed['files'][0]['key'];key='/'.join('k' for _ in range(boundary+extra))
                    changed['files'][0]['key']=key
                    changed['roles']={role:key if selected==old else selected
                        for role,selected in changed['roles'].items()}
                    changed['files'].sort(key=lambda row:row['key'])
                elif domain=='physical-component':changed['files'][0]['physical']='/'+'x'*(boundary+extra)
                else:
                    changed['symlinks'][0]['path']='/'+'x'*(boundary+extra)
                    changed['symlinks'].sort(key=lambda row:row['path'])
                with self.subTest(domain=domain,extra=extra):
                    if extra:
                        with self.assertRaises(ValueError):model.inventory_compact(changed)
                    else:
                        wire=model.canonical(model.inventory_compact(changed))
                        self.assertEqual(model.decode(wire),changed)
                        self.assertEqual(model.canonical(model.inventory_compact(model.decode(wire))),wire)

    def test_compact_encoder_enforces_same_cumulative_prefix_budgets_as_decoder(self):
        value,raw=self.compact_inventory_fixture()
        for domain in ('paths','targets'):
            changed=copy.deepcopy(value)
            # One long shared first component makes the sum of reconstructed
            # prefixes exceed scalar-row bytes; no giant fixture is needed.
            deep='p'*3000+'/'+'/'.join('x' for _ in range(180))
            if domain=='paths':changed['files'][0]['physical']='/'+deep
            else:changed['symlinks'][0]['target']=deep
            wire_object=model.inventory_compact(changed)
            table=wire_object[domain];atoms=wire_object['strings']
            names=['','/'] if domain=='paths' else [None]
            for parent,atom in table[len(names):]:
                prior=names[parent];part=atoms[atom]
                if domain=='paths':name=prior.rstrip('/')+'/'+part if prior else part
                else:name=part if prior is None else prior+'/'+part
                names.append(name)
            prefixes=sum(len(os.fsencode(name)) for name in names[2 if domain=='paths' else 1:])
            scalars=sum(len(model.canonical(row)) for row in changed['files']+changed['symlinks'])
            self.assertGreater(prefixes,scalars)
            with self.subTest(domain=domain),patch.object(model,'MAX_INVENTORY_EXPANDED',prefixes):
                self.assertEqual(model.inventory_expand(model.inventory_compact(changed)),changed)
            with self.subTest(domain=domain,overflow=True),patch.object(model,'MAX_INVENTORY_EXPANDED',prefixes-1):
                model.inventory_check(changed)  # Scalar facts still fit; trie sum does not.
                with self.assertRaises(ValueError):model.inventory_compact(changed)
                with self.assertRaises(ValueError):model.inventory_expand(wire_object)
        with patch.object(model,'MAX_METADATA',len(raw)-1):
            with self.assertRaises(ValueError):model.inventory_compact(value)

    def test_compact_prepare_preserves_actual_pre_epoch_file_mtime_and_full_fd_witness(self):
        path=self.paths['observer'];before=path.read_bytes()
        os.utime(path,ns=(-10**9,-10**9))
        self.assertEqual(path.stat().st_mtime_ns,-10**9)
        value,raw=self.compact_inventory_fixture()
        row=next(row for row in value['files'] if row['key']==self.roles['observer'])
        self.assertEqual(row['witness'][7],-10**9)
        self.assertEqual(row['witness'],list(model.witness(path.lstat())))
        self.assertEqual(row['sha256'],hashlib.sha256(before).hexdigest())
        self.assertEqual(row['bytes'],len(before))
        self.assertEqual(model.decode(model.canonical(model.inventory_compact(value))),value)
        self.assertEqual(model.canonical(model.inventory_compact(value)),raw)

    def test_compact_signed_timestamp_bounds_reject_bool_overflow_and_unsigned_negatives(self):
        value,raw=self.compact_inventory_fixture()
        for position in (7,8):
            for number in (-2**127,2**127-1):
                changed=copy.deepcopy(value);changed['files'][0]['witness'][position]=number
                with self.subTest(position=position,number=number):
                    self.assertEqual(model.decode(model.canonical(model.inventory_compact(changed))),changed)
            for number in (-2**127-1,2**127,True):
                changed=copy.deepcopy(value);changed['files'][0]['witness'][position]=number
                with self.subTest(position=position,refusal=number),self.assertRaises(ValueError):
                    model.inventory_compact(changed)
        changed=copy.deepcopy(value);changed['files'][0]['witness'][0]=-1
        with self.assertRaises(ValueError):model.inventory_compact(changed)


    def test_public_descriptor_commits_original_held_named_directory_witnesses(self):
        result=self.prepare()
        self.assertEqual(result['schemaVersion'],2)
        expected=sorted((self.base,self.source,self.controls,self.runner),key=str)
        self.assertEqual(result['directoryWitnesses'],[
            {'path':str(path),'witness':list(model.witness(path.lstat()))} for path in expected])
        self.assertTrue(all(result[flag] is False for flag in model.FALSE))

    def test_original_directory_same_content_replacement_during_publication_refuses(self):
        real=model.publish;changed=False
        def publish(*args,**kwargs):
            nonlocal changed
            value=real(*args,**kwargs)
            self.source.rename(self.source.with_name('prior-source-directory'))
            self.source.mkdir(mode=0o700);changed=True
            return value
        with patch.object(model,'publish',side_effect=publish):
            with self.assertRaises(ValueError):self.prepare()
        self.assertTrue(changed)
        # Provisional files are not producer success after terminal refusal.
        self.assertTrue((self.output/'yoga-public-toolbar/artifact.json').exists())

    def test_directory_acquisition_boundary_mode_change_refuses_and_drains_registered_fds(self):
        real_open=os.open;real_close=os.close;opened=[];closed=[];changed=False
        def opening(path,*args,**kwargs):
            nonlocal changed
            if Path(path)==self.source and not changed:
                self.source.chmod(0o777);changed=True
            fd=real_open(path,*args,**kwargs);opened.append(fd);return fd
        def closing(fd):closed.append(fd);return real_close(fd)
        try:
            with patch.object(model.os,'open',side_effect=opening),patch.object(model.os,'close',side_effect=closing):
                with self.assertRaises(ValueError):self.prepare()
            self.assertTrue(changed);self.assertEqual(closed,list(reversed(opened)))
            for fd in opened:
                with self.assertRaises(OSError):os.fstat(fd)
        finally:self.source.chmod(0o700)

    def test_empty_fd_slot_registration_faults_precede_acquisition(self):
        real=model.Owned.append
        for phase in ('entry','before','after'):
            opened=[];real_open=os.open
            def opening(*args,**kwargs):
                fd=real_open(*args,**kwargs);opened.append(fd);return fd
            def append(owner,slot):
                if phase=='before':raise MemoryError('synthetic pre-insertion')
                real(owner,slot);raise MemoryError('synthetic post-insertion')
            seam=patch.object(model.Owned,'empty_directory',side_effect=MemoryError('synthetic entry')) if phase=='entry' else patch.object(model.Owned,'append',new=append)
            with self.subTest(phase=phase),seam,patch.object(model.os,'open',side_effect=opening):
                with self.assertRaises(MemoryError):self.prepare()
            self.assertEqual(opened,[])

if __name__=='__main__':
    ZIP=Path(sys.argv.pop(1)).read_bytes()
    RULE=Path(sys.argv.pop(1)).read_bytes()
    unittest.main()
