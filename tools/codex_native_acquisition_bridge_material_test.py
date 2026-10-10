"""Real parser, original-clock, authority and descriptor refusal models."""
import copy
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import codex_native_acquisition_bridge_material as source
import guard_native_acquisition_inputs_reserved as admission

def image():
    # Minimal actual ELF64 program-header layout with no runtime dependencies.
    raw=bytearray(120);raw[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQQIHHHHHH',raw,16,3,62,1,0,64,0,0,64,56,1,0,0,0)
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0,0,len(raw),len(raw),4096)
    return bytes(raw)

class BridgeMaterialModels(unittest.TestCase):
    def test_actual_duplicate_soname_inodes_refuse_mapped_authority(self):
        raw=bytearray(256);raw[:7]=b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHIQQQIHHHHHH',raw,16,3,62,1,0,64,0,0,64,56,2,0,0,0)
        struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0,0,len(raw),len(raw),4096)
        struct.pack_into('<IIQQQQQQ',raw,120,2,4,176,176,0,64,64,8)
        for offset,(tag,value) in enumerate(((5,240),(10,16),(14,1),(0,0))):
            struct.pack_into('<qQ',raw,176+16*offset,tag,value)
        raw[240:256]=b'\0libsame.so\0'.ljust(16,b'\0')
        self.assertEqual(source.soname(bytes(raw)),'libsame.so')
        root='/nix/store/'+'0'*32+'-declared'
        maps=('1000-2000 r-xp 0 00:01 2 '+root+'/a\n2000-3000 r-xp 0 00:01 3 '+root+'/b\n').encode()
        def info(path):return SimpleNamespace(st_mode=0o100444,st_dev=1,st_ino=2 if path.name=='a' else 3)
        with patch.object(source.compilation,'tick'), \
                patch.object(source,'bounded',side_effect=lambda path,*args:maps if str(path)=='/proc/self/maps' else bytes(raw)), \
                patch.object(Path,'lstat',info):
            with self.assertRaises(ValueError):source.mapped_authority({'registration_rows':[{'path':root}],'files':[]},1)

    def test_consumer_loader_overrides_refuse_before_producer_or_cdll(self):
        value={'root':'/model/output','producer':{},'receipt_sha256':'a'*64}
        for key in ('LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT'):
            with patch.dict(os.environ,{key:'/model/foreign.so'}), \
                    patch.object(source.material,'producer_success') as producer, \
                    patch.object(source.native,'Bridge') as loader:
                with self.assertRaises(ValueError):source.load_registered_bridge(value,1)
                producer.assert_not_called();loader.assert_not_called()

    def test_foreign_executable_mapping_refuses_before_reading_its_elf(self):
        proof={'registration_rows':[{'path':'/nix/store/'+'0'*32+'-declared'}],'files':[]}
        with patch.object(source.compilation,'tick'), \
                patch.object(source,'bounded',return_value=b'1000-2000 r-xp 00000000 00:01 2 /tmp/foreign.so\n') as read:
            with self.assertRaises(ValueError):source.mapped_authority(proof,1)
            read.assert_called_once_with('/proc/self/maps',1,8*1024*1024)

    def test_dependency_size_mismatch_releases_all_original_descriptors_before_loader(self):
        value={'root':'/model/output','producer':{},'receipt_sha256':'a'*64}
        receipt={'source_commit':'b'*40,'graph_sha256':'c'*64}
        metadata={'source_commit':'b'*40,'graph_sha256':'c'*64,'bridge':{'sha256':'d'*64,'bytes':120},
            'closure':{'files':[{'path':'/model/dependency','sha256':'e'*64,'bytes':2}]}}
        with tempfile.TemporaryDirectory() as temporary:
            file=Path(temporary)/'file';file.write_bytes(image())
            opened=[]
            def acquire(*args):
                fd=os.open(file,os.O_RDONLY);opened.append(fd)
                return fd,source.process.identity(fd)
            with patch.object(source.material,'producer_success',return_value=receipt), \
                    patch.object(source.compilation,'read_bytes',return_value=b'{}'), \
                    patch.object(source,'schema',return_value=metadata),patch.object(source,'marker'), \
                    patch.object(source.process,'held_file',side_effect=acquire), \
                    patch.object(source.native,'Bridge') as loader:
                with self.assertRaises(ValueError):source.load_registered_bridge(value,1)
                loader.assert_not_called()
            self.assertEqual(len(opened),3)
            for fd in opened:
                with self.assertRaises(OSError):os.fstat(fd)

    def test_real_elf_parser_preserves_dependency_free_shared_image_and_rejects_wrong_headers(self):
        raw=image();self.assertEqual(source.elf(raw)['needed'],[])
        for offset,value in ((0,0),(4,1),(5,2),(16,1),(18,183)):
            changed=bytearray(raw);changed[offset]=value
            with self.assertRaises(ValueError):source.elf(bytes(changed))
        with self.assertRaises(ValueError):source.elf(raw[:63])

    def test_original_envelope_refuses_unselected_or_extended_clock(self):
        value={'OMUX_NATIVE_BRIDGE_MODE':admission.BRIDGE,
            'OMUX_NATIVE_BRIDGE_ENTRY_NS':str(100*10**9),'OMUX_NATIVE_BRIDGE_DEADLINE_NS':str(1300*10**9)}
        with patch.object(admission.kernel.time,'monotonic_ns',return_value=200*10**9):
            self.assertEqual(source.envelope(value),(100*10**9,1300*10**9,1270))
            for key,bad in (('OMUX_NATIVE_BRIDGE_MODE',admission.RUNTIME),
                    ('OMUX_NATIVE_BRIDGE_ENTRY_NS','-1'),('OMUX_NATIVE_BRIDGE_DEADLINE_NS',str(1300*10**9+1))):
                changed=dict(value);changed[key]=bad
                with self.assertRaises(ValueError):source.envelope(changed)
        with patch.object(admission.kernel.time,'monotonic_ns',return_value=1270*10**9):
            with self.assertRaises(ValueError):source.envelope(value)

    def test_pending_selection_refuses_before_any_producer_or_loader_access(self):
        with patch.object(source.material,'producer_success',side_effect=AssertionError('producer')) as producer, \
                patch.object(source.native,'Bridge',side_effect=AssertionError('loader')) as loader:
            for selection in (None,{}, {'qualified':True}, {'path':'/tmp/library.so','sha256':'a'*64}):
                with self.assertRaises(ValueError):source.load_registered_bridge(selection,1)
            producer.assert_not_called();loader.assert_not_called()

    def test_genuine_outer_refusal_precedes_cdll(self):
        value={'root':'/model/output','producer':{},'receipt_sha256':'a'*64}
        with patch.object(source.material,'producer_success',side_effect=ValueError('wrong original guardian')) as producer, \
                patch.object(source.native,'Bridge') as loader:
            with self.assertRaises(ValueError):source.load_registered_bridge(value,1)
            producer.assert_called_once_with(value,source.TARGET,'bridge-material',1)
            loader.assert_not_called()

    def test_held_original_descriptor_identity_detects_same_named_replacement_and_late_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'bridge.so';path.write_bytes(image())
            fd=os.open(path,os.O_RDONLY)
            try:
                identity=source.process.identity(fd)
                self.assertEqual(identity,source.named_identity(path))
                old=Path(temporary)/'old';path.rename(old);path.write_bytes(image())
                self.assertNotEqual(identity,source.named_identity(path))
                self.assertEqual(identity,source.process.identity(fd))
                old.write_bytes(b'late-corruption')
                self.assertNotEqual(source.digest(os.pread(fd,4096,0)),source.digest(image()))
            finally:os.close(fd)

    def test_logmarker_is_exact_single_original_receipt_digest(self):
        receipt={'test_evidence':{'sha256':'b'*64}}
        selection={'producer':{'receipt':'/model/epoch/receipt.json'}}
        evidence={'results':[{'target':source.TARGET,'files':[{'source':'test.log','state':'copied',
            'file':'c.evidence','sha256':'c'*64}]}]}
        with patch.object(source.compilation,'read_json',return_value=evidence), \
                patch.object(source.compilation,'read_bytes',return_value=(source.MARKER+'a'*64+'\n').encode()):
            source.marker(selection,receipt,'a'*64,1)
        for raw in (b'no marker', (source.MARKER+'d'*64+'\n').encode(),
                ((source.MARKER+'a'*64+'\n')*2).encode()):
            with patch.object(source.compilation,'read_json',return_value=evidence), \
                    patch.object(source.compilation,'read_bytes',return_value=raw):
                with self.assertRaises(ValueError):source.marker(selection,receipt,'a'*64,1)

if __name__=='__main__':unittest.main()
