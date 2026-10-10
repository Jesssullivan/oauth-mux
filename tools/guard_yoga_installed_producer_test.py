"""Synthetic held-file/command tests, declared Bazel only; no service or action.

Fixture walker admits only its owned temporary root after Python creates it;
production's root-to-leaf non-writable ancestor policy is unchanged.
"""
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import guard_yoga_installed_producer as producer


def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


class ProducerBridgeTest(unittest.TestCase):
    def test_exact_selection_and_ordinary_build(self):
        self.assertTrue(producer.selected('standard','system',['run',producer.LABEL],'a'*64))
        self.assertFalse(producer.selected('standard','system',['build',producer.LABEL],None))
        self.assertFalse(producer.selected('standard','system',['run','//other:target'],None))
        cases=[('standard','user',['run',producer.LABEL],'a'*64,False,()),
            ('yoga-toolbar','system',['run',producer.LABEL],'a'*64,False,()),
            ('standard','system',['run',producer.LABEL],None,False,()),
            ('standard','system',['run',producer.LABEL,'--','--output=/tmp'],'a'*64,False,()),
            ('standard','system',['build',producer.LABEL],'a'*64,False,()),
            ('standard','system',['run',producer.LABEL],'A'*64,False,()),
            ('standard','system',['run',producer.LABEL],'a'*64,True,()),
            ('standard','system',['run',producer.LABEL],'a'*64,False,('/private/selector',))]
        for args in cases:
            with self.subTest(args=args),self.assertRaises(ValueError):producer.selected(*args)

    @contextmanager
    def fixture(self, *, reserved=False):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            root=Path(directory); os.chmod(root,0o700)
            values={'browser-inventory.json':b'{"synthetic":"browser"}\n',
                'controller-inventory.json':b'{"synthetic":"controller"}\n'}
            pins={name:hashlib.sha256(value).hexdigest() for name,value in values.items()}
            checkout=producer.support.ROOT if reserved else Path('/srv/fast-local/jess/git/oauth-mux-fixture')
            value={key:{} for key in ('buildReceipt','launcher','runfilesManifest','inputPaths',
                'inputSha256','nativeManifest','nativeManifestSha256','fileSha256')}
            value.update(schemaVersion=1,scope='yoga-installed-toolbar-selection-v1',
                controllerPackage={'root':str(checkout/'tools'),'files':{
                    'execution_guard.py':{'sha256':'b'*64,'bytes':17}}},
                browserInventory={'path':str(root/'browser-inventory.json'),'sha256':pins['browser-inventory.json']},
                controllerInventory={'path':str(root/'controller-inventory.json'),'sha256':pins['controller-inventory.json']})
            if reserved:
                value.update(schemaVersion=producer.support.SCHEMA,scope=producer.support.SELECTION_SCOPE,
                    controllerDelivery={'root':str(producer.support.DELIVERY),'files':{
                        'codex_device_acquisition_component.py':{'sha256':'c'*64,'bytes':19}}})
            values['selection.json']=encoded(value)
            for name,data in values.items():
                (root/name).write_bytes(data); os.chmod(root/name,0o600)
            def walk(path):
                self.assertEqual(Path(path),root)
                fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                info=os.fstat(fd)
                self.assertEqual(info.st_uid,os.getuid());self.assertEqual(stat.S_IMODE(info.st_mode),0o700)
                return fd
            for name,replacement in {'STAGING':root,'SELECTION':root/'selection.json',
                'OUTPUT_PARENT':root/'outputs','OUTPUT':root/'outputs/workspace',
                'INVENTORIES':pins,'parent':walk}.items():stack.enter_context(patch.object(producer,name,replacement))
            yield root,checkout,hashlib.sha256(values['selection.json']).hexdigest(),time.monotonic_ns()+1200*10**9

    def test_actual_owned_inputs_and_fixed_command(self):
        with self.fixture() as (root,checkout,sha,deadline):
            admission=producer.Admission(sha,checkout,deadline)
            try:
                base=Mock(return_value=['bazel','--batch','run-avoiding-startup','build','--jobs=2',producer.LABEL])
                command=producer.command('bazel',root/'epoch',['run',producer.LABEL],admission,base,repository_cache='declared-cache')
                base.assert_called_once_with('bazel',root/'epoch',['build',producer.LABEL],repository_cache='declared-cache')
                self.assertEqual(command[-9:],['--','--selection',str(root/'selection.json'),
                    '--selection-sha256',sha,'--output',str(root/'outputs/workspace'),
                    '--deadline-monotonic-ns',str(deadline)])
                self.assertIn('--repository_disable_download',command)
                self.assertIn('--repo_contents_cache=',command)
                self.assertIn('--symlink_prefix='+str(root/'epoch/bazel-'),command)
                self.assertNotIn('build',command);self.assertIn('--jobs=2',command)
                self.assertEqual(stat.S_IMODE((root/'outputs').stat().st_mode),0o700)
            finally:admission.close()
            self.assertFalse((root/'outputs').exists())
            self.assertEqual(set(os.listdir(root)),{'selection.json','browser-inventory.json','controller-inventory.json'})

    def test_reserved_physical_controller_input_custody_and_exact_command(self):
        with self.fixture(reserved=True) as (root,checkout,sha,deadline):
            self.assertEqual(checkout,Path(producer.support.__file__).resolve().parent.parent)
            admission=producer.Admission(sha,checkout,deadline,required_schema=2)
            try:
                self.assertEqual(admission.selection_schema,2)
                command=admission.argv()
                self.assertEqual(command,['--selection',str(root/'selection.json'),
                    '--selection-sha256',sha,'--output',str(root/'outputs/workspace'),
                    '--deadline-monotonic-ns',str(deadline)])
                original=(root/'selection.json').read_bytes()
                (root/'selection.json').unlink();(root/'selection.json').write_bytes(original)
                os.chmod(root/'selection.json',0o600)
                with self.assertRaises(ValueError): admission.recheck()
            finally: admission.close()
            self.assertFalse((root/'outputs').exists())

    def test_reserved_foreign_roots_refuse_before_staging_or_output_reads(self):
        with self.fixture(reserved=True) as (root,checkout,sha,deadline):
            roots=(checkout.parent/(checkout.name+'-foreign'),Path('/home/jess/foreign'),
                   Path('/srv/fast-local/jess/git/oauth-mux-fixture'))
            for foreign in roots:
                with self.subTest(root=foreign),patch.object(producer,'parent') as walk:
                    with self.assertRaises(ValueError): producer.Admission(sha,foreign,deadline,required_schema=2)
                    walk.assert_not_called()
                self.assertFalse((root/'outputs').exists())
            # Current root and v2 metadata must join, not merely pass the root gate.
            value=json.loads((root/'selection.json').read_bytes())
            value['controllerPackage']['root']=str(checkout.parent/(checkout.name+'-foreign')/'tools')
            raw=encoded(value);(root/'selection.json').write_bytes(raw)
            with self.assertRaises(ValueError):
                producer.Admission(hashlib.sha256(raw).hexdigest(),checkout,deadline,required_schema=2)
            self.assertFalse((root/'outputs').exists())

    def test_wrong_digest_existing_output_and_extra_input_refuse(self):
        with self.fixture() as (root,checkout,sha,deadline):
            # Legacy v1 remains usable by standard admission, but reserved v2
            # cannot create outputs from that weaker import-closure envelope.
            with self.assertRaises(ValueError):
                producer.Admission(sha,checkout,deadline,required_schema=2)
            self.assertFalse((root/'outputs').exists())
        with self.fixture() as (root,checkout,sha,deadline):
            with self.assertRaises(ValueError):producer.Admission('0'*64,checkout,deadline)
            self.assertFalse((root/'outputs').exists())
            (root/'outputs').mkdir(mode=0o700)
            with self.assertRaises(ValueError):producer.Admission(sha,checkout,deadline)
            self.assertTrue((root/'outputs').is_dir())
            (root/'outputs').rmdir();(root/'extra').write_bytes(b'public-extra')
            with self.assertRaises(ValueError):producer.Admission(sha,checkout,deadline)

    def test_held_input_replacement_is_refused(self):
        with self.fixture() as (root,checkout,sha,deadline):
            admission=producer.Admission(sha,checkout,deadline)
            try:
                data=(root/'selection.json').read_bytes();(root/'selection.json').unlink()
                (root/'selection.json').write_bytes(data);os.chmod(root/'selection.json',0o600)
                with self.assertRaises(ValueError):admission.recheck()
            finally:admission.close()

    def test_completed_output_is_retained_and_foreign_replacement_not_removed(self):
        with self.fixture() as (root,checkout,sha,deadline):
            admission=producer.Admission(sha,checkout,deadline)
            (root/'outputs/workspace').mkdir(mode=0o700)
            admission.recheck();admission.close()
            self.assertTrue((root/'outputs/workspace').is_dir())
        with self.fixture() as (root,checkout,sha,deadline):
            admission=producer.Admission(sha,checkout,deadline)
            (root/'outputs').rename(root/'saved-output');(root/'outputs').mkdir(mode=0o700)
            with self.assertRaises(ValueError):admission.recheck()
            admission.close();self.assertTrue((root/'outputs').is_dir())

    def test_exact_readonly_writable_scope_and_readback(self):
        with self.fixture() as (root,checkout,sha,deadline):
            admission=producer.Admission(sha,checkout,deadline)
            try:
                readonly,writable=admission.bindings();run=root/'epoch'
                observed={'BindReadOnlyPaths':readonly,'BindPaths':writable,'ProtectSystem':'strict',
                    'ReadWritePaths':str(run)+' '+str(root/'outputs')}
                admission.verify(observed,run)
                for key,value in [('BindReadOnlyPaths',readonly.removesuffix(':rbind')),
                    ('BindPaths',writable+' /other:/other:rbind'),('ProtectSystem','no'),
                    ('ReadWritePaths',str(run)+' '+str(root/'outputs')+' /srv'),
                    ('ReadWritePaths',str(run)+' '+str(root/'outputs')+' '+str(run))]:
                    with self.subTest(key=key),self.assertRaises(ValueError):admission.verify({**observed,key:value},run)
            finally:admission.close()

    def test_deadline_is_original_and_setup_consumes_budget(self):
        admission=producer.Admission.__new__(producer.Admission);admission.deadline=1200*10**9
        with patch.object(producer.time,'monotonic_ns',return_value=100*10**9):
            self.assertEqual(admission.runtime_seconds(),1070)
        with patch.object(producer.time,'monotonic_ns',return_value=1171*10**9):
            with self.assertRaises(ValueError):admission.runtime_seconds()
        with patch.object(producer.time,'monotonic_ns',return_value=0):
            with self.assertRaises(ValueError):producer.budget(1201*10**9)
        forged=Mock();forged.recheck=Mock()
        with self.assertRaises(ValueError):producer.command('bazel','/owned/run',['run',producer.LABEL],forged,Mock())
        forged.recheck.assert_not_called()


if __name__=='__main__':unittest.main()
