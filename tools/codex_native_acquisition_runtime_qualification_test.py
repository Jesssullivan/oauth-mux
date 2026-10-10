"""Real bounded synthetic descriptor/image fixtures; no compiled CLI execution."""
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import struct
import socket
import array
import stat
import tempfile
import time
import unittest
from unittest.mock import patch
import codex_native_acquisition_runtime_qualification as runtime
from codex_native_acquisition_peer_test import PeerTests

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.deadline=time.monotonic()+10.0

    def test_missing_registration_refuses_before_context_or_launch(self):
        with patch.object(runtime,'isolated_context',side_effect=AssertionError('no context IO')):
            with self.assertRaises(ValueError):runtime.registration()

    def test_fresh_synthetic_context_never_reuses_home(self):
        key,payload,capability=runtime.isolated_context(self.root/'private')
        self.assertEqual(len(key),32);self.assertEqual(capability.stat().st_mode&0o777,0o600)
        self.assertEqual((capability.parent.parent/'home/auth.json').read_bytes(),payload)
        with self.assertRaises(ValueError):runtime.isolated_context(self.root/'private')

    def test_actual_pt_interp_and_duplicate_or_non_nix_loader_refused(self):
        path=('/nix/store/'+'a'*32+'-glibc/lib/ld-linux-x86-64.so.2').encode()+b'\0'
        raw=bytearray(64+56+len(path));raw[:6]=b'\x7fELF\x02\x01';raw[18:20]=b'\x3e\x00'
        struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,1)
        struct.pack_into('<I',raw,64,3);struct.pack_into('<Q',raw,72,120)
        struct.pack_into('<Q',raw,96,len(path));raw[120:]=path
        self.assertEqual(runtime.interpreter(bytes(raw)),path[:-1].decode())
        wrong=bytearray(raw);wrong[120:125]=b'/tmp/'
        with self.assertRaises(ValueError):runtime.interpreter(bytes(wrong))
        struct.pack_into('<HH',raw,54,56,129)
        with self.assertRaises(ValueError):runtime.interpreter(bytes(raw))

    def test_loader_cannot_substitute_for_primary_actual_main_exe(self):
        image=self.root/'image';loader=self.root/'loader';image.write_bytes(b'image');loader.write_bytes(b'loader')
        first=os.open(image,os.O_RDONLY);second=os.open(loader,os.O_RDONLY)
        try:
            self.assertTrue(runtime.primary_identity(first,first,second,second))
            with self.assertRaises(ValueError):runtime.primary_identity(first,second,second,second)
        finally:os.close(first);os.close(second)

    def test_real_sealed_readonly_payload_and_mutable_fd_refusal(self):
        payload=b'{"tokens":{"access_token":"synthetic-access"},"expires_at":null}'
        fd=os.memfd_create('synthetic-runtime-fixture',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        readonly=None
        try:
            os.fchmod(fd,0o600);os.write(fd,payload)
            with self.assertRaises(ValueError):runtime.received_payload(fd,payload,self.deadline)
            seals=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE
            fcntl.fcntl(fd,fcntl.F_ADD_SEALS,seals)
            readonly=os.open('/proc/self/fd/'+str(fd),os.O_RDONLY|os.O_CLOEXEC)
            proof=runtime.received_payload(readonly,payload,self.deadline)
            self.assertEqual(proof['sha256'],hashlib.sha256(payload).hexdigest())
            with self.assertRaises(ValueError):runtime.received_payload(readonly,b'wrong',self.deadline)
            with self.assertRaises(ValueError):runtime.received_payload(readonly,payload,time.monotonic()-1.0)
        finally:
            if readonly is not None:os.close(readonly)
            os.close(fd)

    def test_v3_exact_canonical_request_rejects_extra_key_zero_handle_and_generation(self):
        params={name:'a'*64 if name in runtime.OPAQUE else '1' for name in runtime.REQUEST_FIELDS}
        params['forgetEpoch']='0';key=b'\x01'*32
        raw,value=runtime.acquisition_frame(params,key)
        self.assertIn(b'owner/source/acquire',raw)
        self.assertTrue(runtime.canonical(value,'omux-native-source-acquire-v1').startswith(b'omux-native-source-acquire-v1\n2\n'))
        for change in ({'unknown':True},{'ownerId':'0'*64},{'endpointGeneration':'01'},{'custodySeconds':'3601'}):
            with self.assertRaises(ValueError):runtime.request_fields({**value,**change})

    def test_actual_received_right_is_closed_on_malformed_native_reply(self):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        fd=os.memfd_create('synthetic-right-fixture',os.MFD_CLOEXEC)
        try:
            left.sendmsg([b'{}'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
            original=os.close
            with patch.object(runtime.os,'close',wraps=original) as close:
                with self.assertRaises(ValueError):
                    runtime.receive_acquisition(right,{},b'\x01'*32,b'synthetic',self.deadline)
                self.assertEqual(close.call_count,1)
            self.assertTrue(stat.S_ISREG(os.fstat(fd).st_mode))
        finally:left.close();right.close();os.close(fd)

    def test_closed_refusal_projection_cannot_promote_runtime_or_provider(self):
        inputs={'kind':'omux-native-acquisition-compiled-runtime-inputs-v1',
            'compiled_receipt_sha256':'a'*64,'primary_elf_sha256':'b'*64,
            'config_schema_sha256':'c'*64,'backend':'native-owner-source-acquisition-v3',
            'acquisition_contract':'unsupported','runtime_qualified':False}
        receipt=runtime.unavailable_receipt(inputs)
        self.assertFalse(receipt['runtime_qualified']);self.assertFalse(receipt['outer_cleanup_qualified'])
        self.assertTrue(all(receipt[name] is False for name in runtime.FALSE_FLAGS))
        with self.assertRaises(ValueError):runtime.unavailable_receipt({**inputs,'runtime_qualified':True})

if __name__=='__main__':unittest.main()
