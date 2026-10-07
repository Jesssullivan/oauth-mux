"""Finite public path, full JSON inventory and ELF-edge models; no tools invoked."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import codex_fresh_native_runtime as fresh


def elf(needed=(), interpreter=None, rpath=()):
    strings, references = bytearray(b'\0'), []
    for tag, value in [(1,n) for n in needed] + ([(29,':'.join(rpath))] if rpath else []):
        references.append((tag,len(strings)))
        strings.extend(value.encode()+b'\0')
    count = 2+(interpreter is not None)
    dyn = 64+56*count
    size = 16*(len(references)+3)
    off = dyn+size
    interp = b'' if interpreter is None else interpreter.encode()+b'\0'
    ioff, base = off+len(strings), 0x400000
    length = ioff+len(interp)
    header = b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',3,62,1,0,64,0,0,64,56,count,0,0,0)
    heads = struct.pack('<IIQQQQQQ',1,5,0,base,base,length,length,4096)
    heads += struct.pack('<IIQQQQQQ',2,4,dyn,base+dyn,0,size,size,8)
    if interpreter is not None:
        heads += struct.pack('<IIQQQQQQ',3,4,ioff,base+ioff,0,len(interp),len(interp),1)
    return header+heads+b''.join(struct.pack('<qQ',t,v) for t,v in references+[(5,base+off),(10,len(strings)),(0,0)])+strings+interp


class FreshRuntimeModels(unittest.TestCase):
    def bundle(self, outside=False):
        r = fresh.runtime
        loader = r.PREFIX+'lib/ld-linux-x86-64.so.2'
        libc = r.PREFIX+'lib/libc.so.6'
        backend = elf(('outside.so' if outside else 'libc.so.6',),
            fresh.portable._BACKEND_INTERPRETER,('$ORIGIN/../lib',))
        files = {r.BACKEND:backend,loader:elf(),libc:elf(),
            r.CA:b'-----BEGIN CERTIFICATE-----\ncHVibGlj\n-----END CERTIFICATE-----\n',
            'bin/codex':r.codex_launcher('ld-linux-x86-64.so.2')}
        inventory = {n:{'sha256':fresh.digest(v),'bytes':len(v),'mode':0o644 if n==r.CA else 0o755} for n,v in files.items()}
        manifest = {'kind':fresh.KIND,'status':fresh.STATUS,'native_support':False,'provider_evaluation':False,
            'experimental_text_policy_compiled':True,'chain':{'fixture':'ELF-model-only'},
            'executable':{'packaged_sha256':fresh.digest(backend),'packaged_bytes':len(backend)},
            'selection_sha256':'a'*64,'producer_source_sha256':'b'*64,
            'producer_target':'//tools:codex_fresh_native_runtime_package','files':inventory,
            'runtime':{'dependencies':sorted((loader,libc)),'loader':loader,'caBundle':r.CA,
                'backendInterpreter':fresh.portable._BACKEND_INTERPRETER}}
        payload = r.archive_bytes(files,manifest)
        receipt = {k:manifest[k] for k in ('kind','status','native_support','provider_evaluation',
            'experimental_text_policy_compiled','chain','executable','selection_sha256',
            'producer_source_sha256','producer_target')}
        receipt.update(archive_bytes=len(payload),archive_sha256=fresh.digest(payload),
            manifest_sha256=fresh.digest(fresh.encoded(manifest)),
            runtime_inventory={n:{'sha256':row['sha256'],'bytes':row['bytes'],
                'mode':0o444 if n==r.CA else 0o555} for n,row in inventory.items()})
        return payload,receipt,files

    def test_archive_accepts_closed_fixture_and_refuses_outside_elf_or_inventory(self):
        payload,receipt,files = self.bundle()
        self.assertEqual(fresh.verify_runtime_files(payload,receipt)[1],files)
        for field,value in (('archive_sha256','0'*64),('native_support',True),
                ('experimental_text_policy_compiled',False),('kind','retained009')):
            with self.assertRaises(ValueError):
                fresh.verify_runtime_files(payload,{**receipt,field:value})
        changed = copy.deepcopy(receipt)
        changed['runtime_inventory'][fresh.runtime.BACKEND]['mode'] = 0o755
        with self.assertRaises(ValueError):
            fresh.verify_runtime_files(payload,changed)
        payload,receipt,_ = self.bundle(outside=True)
        with self.assertRaises(ValueError):
            fresh.verify_runtime_files(payload,receipt)

    def test_complete_generated_json_inventory_refuses_extra_missing_and_links(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(fresh,'STATE',Path(temporary)):
            roots, files = {}, {}
            prefix = Path(temporary)/('cache-v2-'+'a'*64)/'output-base/execroot/_main/bazel-out/k8-opt/bin/bazel/schema'
            for mode in ('stable','experimental'):
                root = prefix/('public-schema-bundle.'+mode)/'json'
                root.mkdir(parents=True)
                (root/'ClientRequest.json').write_bytes(b'{}')
                (root/'ClientRequest.json').chmod(0o400)
                roots[mode] = str(root)
                files[mode+'/json/ClientRequest.json'] = {}
            selected = {'protocol_schema_roots':roots,'protocol_schema_files':files}
            for folder,_,_ in os.walk(temporary):
                Path(folder).chmod(0o700)
            fresh.validate_protocol_inventory(selected)
            root = Path(roots['stable'])
            (root/'extra.json').write_bytes(b'{}')
            (root/'extra.json').chmod(0o400)
            with self.assertRaises(ValueError):
                fresh.validate_protocol_inventory(selected)
            (root/'extra.json').unlink()
            (root/'ClientRequest.json').unlink()
            with self.assertRaises(ValueError):
                fresh.validate_protocol_inventory(selected)
            (root/'ClientRequest.json').symlink_to(Path(roots['experimental'])/'ClientRequest.json')
            with self.assertRaises(ValueError):
                fresh.validate_protocol_inventory(selected)

    def test_export_producer_binding_and_empty_epoch(self):
        home = '/home/jess/.local/state/omux-execution-20261005'
        fast = '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005'
        epoch = '5c6a5577-0000-4000-8000-000000000000'
        direct = fast+'/'+epoch+'/sdk-private/sdk-export/receipt.json'
        historical = home+'/'+epoch+'/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_retained_sdk_export_producer/test.outputs/sdk-private/sdk-export/receipt.json'
        with patch.object(fresh,'canonical_path',side_effect=Path):
            for path,producer in ((direct,'//tools:codex_retained_sdk_export_run'),
                    (historical,'//tools:codex_retained_sdk_export_producer')):
                selected = {'files':{'export':{'path':path}}}
                fresh.validate_export_producer(selected,{'producer':producer})
                for wrong in (None,'//tools:codex_retained_sdk_export_run' if 'producer' in producer else '//tools:codex_retained_sdk_export_producer','//tools:other'):
                    with self.subTest(path=path,wrong=wrong), self.assertRaises(ValueError):
                        fresh.validate_export_producer(selected,{'producer':wrong})
            for role,path in (('export',fast),('export',home),('source',fast),
                    ('source',direct),('export',home+'/'+epoch+'/sdk-private/sdk-export/receipt.json')):
                with self.subTest(role=role,path=path), self.assertRaises(ValueError):
                    fresh.validate_public_receipt_path(role,path)

    def test_foreign_role_paths_are_refused_before_any_file_read(self):
        selection = {'kind':fresh.SELECTION_KIND,
            'files':{role:{'path':'/private/credentials.json'} for role in fresh.ROLES},
            'protocol_schema_files':{}}
        with self.assertRaises(ValueError):
            fresh.validate_selection_paths(selection)

    def test_exact_source_cache_and_public_export_namespaces(self):
        home = '/home/jess/.local/state/omux-execution-20261005/'
        fast = '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/'
        epoch = '5c6a5577-0000-4000-8000-000000000000'
        cache = 'cache-v2-'+'a'*64
        prefix = '/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/'
        source_tail = prefix+'codex_live_source_producer/test.outputs/codex-live-source/source-receipt.json'
        export_tail = prefix+'codex_retained_sdk_export_producer/test.outputs/sdk-private/sdk-export/receipt.json'
        run_tail = '/sdk-private/sdk-export/receipt.json'
        accepted = (('source',home+epoch+source_tail,'//tools:codex_live_source_producer'),
                    ('source',home+cache+source_tail,'//tools:codex_live_source_producer'),
                    ('export',home+epoch+export_tail,'//tools:codex_retained_sdk_export_producer'),
                    ('export',fast+epoch+export_tail,'//tools:codex_retained_sdk_export_producer'),
                    ('export',fast+epoch+run_tail,'//tools:codex_retained_sdk_export_run'))
        refused = [('source',fast+epoch+source_tail),('source',fast+cache+source_tail),
                   ('source',home+epoch+export_tail),('source',home+epoch+run_tail),
                   ('export',home+epoch+run_tail),('export',home+cache+export_tail),
                   ('export',fast+cache+export_tail),('export',fast+cache+run_tail),
                   ('export',fast+epoch+source_tail),('export',fast+epoch+'/extra'+run_tail),
                   ('source',home+epoch+'/extra'+source_tail),('source','/foreign/'+epoch+source_tail)]
        for bad in ('short',epoch.upper(),epoch+'0','cache-v2-'+'a'*63,'cache-v2-'+'g'*64,'cache-'+'a'*64):
            refused.extend((('source',home+bad+source_tail),('export',fast+bad+run_tail)))
        with patch.object(fresh,'canonical_path',side_effect=Path):
            for role,path,producer in accepted:
                with self.subTest(role=role,path=path):
                    self.assertEqual(fresh.validate_public_receipt_path(role,path),producer)
                    for changed in (path+'/extra',path.replace('receipt.json','receipt.json.bak')):
                        with self.assertRaises(ValueError): fresh.validate_public_receipt_path(role,changed)
            for role,path in refused:
                with self.subTest(role=role,path=path),self.assertRaises(ValueError):
                    fresh.validate_public_receipt_path(role,path)


if __name__ == '__main__':
    unittest.main()
