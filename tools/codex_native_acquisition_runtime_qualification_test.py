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
from codex_native_acquisition_process_test import ProcessTests

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


class MainCallerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.deadline=time.monotonic()+10.0

    def test_unconfigured_selection_refuses_before_any_selected_role_io(self):
        raw=b'{"schema_version":1,"kind":"omux-native-acquisition-runtime-inputs-v1","status":"unconfigured","selection":null}'
        with patch.object(runtime,'qualify_runtime',side_effect=AssertionError('no runtime IO')):
            with self.assertRaises(ValueError):runtime.runtime_selection(raw)
        for value in (raw.replace(b'null',b'{}'),raw.replace(b'"unconfigured"',b'"selected"')):
            with self.assertRaises(ValueError):runtime.runtime_selection(value)

    def test_original_runtime_clock_requires_exact_guard_mode_and_pair(self):
        now=time.monotonic_ns();entry=now-1_000_000
        env={'OMUX_NATIVE_RUNTIME_MODE':runtime.PROFILE,'OMUX_NATIVE_RUNTIME_ENTRY_NS':str(entry),
            'OMUX_NATIVE_RUNTIME_DEADLINE_NS':str(entry+1200*10**9)}
        self.assertEqual(runtime.runtime_deadline(env),(entry+1170*10**9)/10**9)
        self.assertEqual(runtime.runtime_envelope(env),(entry,entry+1200*10**9,
            (entry+1170*10**9)/10**9))
        for change in ({'OMUX_NATIVE_RUNTIME_MODE':'standard'},
            {'OMUX_NATIVE_RUNTIME_DEADLINE_NS':str(entry+1201*10**9)},
            {'OMUX_NATIVE_RUNTIME_ENTRY_NS':'01'}):
            with self.assertRaises(ValueError):runtime.runtime_deadline({**env,**change})
        with self.assertRaises(ValueError):runtime.runtime_deadline({})

    def test_main_missing_clock_refuses_before_declaration_and_launch(self):
        with patch.object(runtime.sys,'argv',['producer']),patch.dict(runtime.os.environ,{},clear=True),\
                patch.object(runtime,'qualify_runtime',side_effect=AssertionError('no native IO')):
            with self.assertRaises(ValueError):runtime.main()

    def test_actual_main_joins_original_envelope_declares_then_qualifies_without_renewal(self):
        import codex_native_acquisition_binding as binding
        import codex_native_acquisition_material as material
        query=runtime.query_tools;events=[];selected={'fixture':'runtime-selection'}
        env={'OMUX_NATIVE_RUNTIME_MODE':runtime.PROFILE,'OMUX_NATIVE_RUNTIME_ENTRY_NS':str(100*10**9),
            'OMUX_NATIVE_RUNTIME_DEADLINE_NS':str(1300*10**9)}
        def declared(path,maximum):
            phase=query._CONSUMER_PHASE.get()
            self.assertEqual((phase.entry_ns,phase.original_deadline_ns),(100*10**9,1300*10**9))
            events.append(('selection',phase.query_deadline));return b'fixture-input'
        def controller(deadline):
            events.append(('controller',deadline,query.verification_deadline(deadline)))
        def qualify(document,deadline,original):
            self.assertIs(document,selected)
            events.append(('qualification',deadline,original,query.verification_deadline(deadline)))
            raise RuntimeError('fixture-stop-before-runtime')
        with patch.object(runtime.sys,'argv',['producer']),patch.dict(runtime.os.environ,env), \
                patch.object(runtime.time,'monotonic_ns',return_value=400*10**9), \
                patch.object(runtime.time,'monotonic',return_value=400.0), \
                patch.object(binding.ninth.parent,'declared',side_effect=declared), \
                patch.object(runtime,'runtime_selection',return_value=selected), \
                patch.object(material,'declared_controller',side_effect=controller), \
                patch.object(runtime,'qualify_runtime',side_effect=qualify), \
                patch.object(query,'consumer_phase',wraps=query.consumer_phase) as capture:
            with self.assertRaisesRegex(RuntimeError,'fixture-stop-before-runtime'):runtime.main()
            capture.assert_called_once_with(100*10**9,1300*10**9)
        self.assertEqual(events,[('selection',700.0),('controller',1270.0,700.0),
            ('qualification',1270.0,1300.0,700.0)])
        self.assertIsNone(query._CONSUMER_PHASE.get())

    def test_main_expired_phase_or_wrong_clock_join_refuses_before_declaration(self):
        import codex_native_acquisition_binding as binding
        import codex_native_acquisition_material as material
        env={'OMUX_NATIVE_RUNTIME_MODE':runtime.PROFILE,'OMUX_NATIVE_RUNTIME_ENTRY_NS':str(100*10**9),
            'OMUX_NATIVE_RUNTIME_DEADLINE_NS':str(1300*10**9)}
        with patch.object(runtime.sys,'argv',['producer']),patch.dict(runtime.os.environ,env), \
                patch.object(runtime.time,'monotonic_ns',return_value=701*10**9), \
                patch.object(runtime.time,'monotonic',return_value=701.0), \
                patch.object(binding.ninth.parent,'declared',side_effect=AssertionError('no selected IO')), \
                patch.object(material,'declared_controller',side_effect=AssertionError('no repository IO')), \
                patch.object(runtime,'qualify_runtime',side_effect=AssertionError('no runtime IO')):
            with self.assertRaises(ValueError):runtime.main()
        for envelope in ((100*10**9,1300*10**9,1271.0),(100*10**9,1301*10**9,1270.0)):
            with self.subTest(envelope=envelope),patch.object(runtime.sys,'argv',['producer']), \
                    patch.object(runtime,'runtime_envelope',return_value=envelope), \
                    patch.object(runtime.time,'monotonic',return_value=400.0), \
                    patch.object(runtime.time,'monotonic_ns',return_value=400*10**9), \
                    patch.object(binding.ninth.parent,'declared',side_effect=AssertionError('no selected IO')):
                with self.assertRaises(ValueError):runtime.main()
        self.assertIsNone(runtime.query_tools._CONSUMER_PHASE.get())

    def test_actual_main_preserves_nonround_large_envelope_entry_and_cutoffs(self):
        import codex_native_acquisition_binding as binding
        import codex_native_acquisition_material as material
        query=runtime.query_tools
        for entry in ((1<<53)+123456789,10**18+123456789):
            until=entry+1200*10**9;now=entry+300*10**9;seen=[]
            env={'OMUX_NATIVE_RUNTIME_MODE':runtime.PROFILE,'OMUX_NATIVE_RUNTIME_ENTRY_NS':str(entry),
                'OMUX_NATIVE_RUNTIME_DEADLINE_NS':str(until)}
            def controller(deadline):
                phase=query._CONSUMER_PHASE.get()
                self.assertEqual((phase.entry_ns,phase.original_deadline_ns),(entry,until))
                self.assertEqual(phase.query_deadline_ns,entry+600*10**9)
                seen.append(query.verification_deadline(deadline))
            def qualify(selected,deadline,original):
                self.assertEqual(deadline,(until-30*10**9)/10**9)
                self.assertEqual(original,until/10**9)
                seen.append(query.verification_deadline(deadline))
                raise RuntimeError('fixture-no-runtime')
            with self.subTest(entry=entry),patch.object(runtime.sys,'argv',['producer']), \
                    patch.dict(runtime.os.environ,env), \
                    patch.object(runtime.time,'monotonic_ns',return_value=now), \
                    patch.object(runtime.time,'monotonic',return_value=now/10**9), \
                    patch.object(binding.ninth.parent,'declared',return_value=b'fixture-input'), \
                    patch.object(runtime,'runtime_selection',return_value={}), \
                    patch.object(material,'declared_controller',side_effect=controller), \
                    patch.object(runtime,'qualify_runtime',side_effect=qualify):
                with self.assertRaisesRegex(RuntimeError,'fixture-no-runtime'):runtime.main()
            self.assertEqual(seen,[(entry+600*10**9)/10**9]*2)
            self.assertIsNone(query._CONSUMER_PHASE.get())

    def test_metadata_duplicate_wrong_id_error_and_extra_payload_refuse(self):
        self.assertEqual(runtime.metadata_reply(b'{"jsonrpc":"2.0","id":"owner/source/context","result":{}}',
            'owner/source/context'),{})
        for raw in (b'{"jsonrpc":"2.0","id":"x","id":"owner/source/context","result":{}}',
            b'{"jsonrpc":"2.0","id":"x","result":{}}',
            b'{"jsonrpc":"2.0","id":"owner/source/context","error":{}}',
            b'{"jsonrpc":"2.0","id":"owner/source/context","result":{},"payload":"unexpected"}'):
            with self.assertRaises(ValueError):runtime.metadata_reply(raw,'owner/source/context')

    def test_real_private_fixture_cleanup_and_replaced_root_refusal(self):
        root=self.root/'owned';root.mkdir(mode=0o700);(root/'home').mkdir(mode=0o700)
        (root/'home/auth.json').write_bytes(b'synthetic-fixture')
        info=root.lstat();witness=(info.st_dev,info.st_ino,info.st_uid,info.st_mode)
        runtime.cleanup_fixture(root,witness,self.deadline);self.assertFalse(root.exists())
        root.mkdir(mode=0o700);info=root.lstat();witness=(info.st_dev,info.st_ino,info.st_uid,info.st_mode)
        root.rename(self.root/'old');root.mkdir(mode=0o700);(root/'foreign').write_bytes(b'preserve')
        with self.assertRaises(ValueError):runtime.cleanup_fixture(root,witness,self.deadline)
        self.assertEqual((root/'foreign').read_bytes(),b'preserve')

    def test_fixture_symlink_never_reads_or_removes_foreign_target(self):
        root=self.root/'owned';root.mkdir(mode=0o700);foreign=self.root/'foreign';foreign.write_bytes(b'preserve')
        (root/'link').symlink_to(foreign)
        info=root.lstat();witness=(info.st_dev,info.st_ino,info.st_uid,info.st_mode)
        with self.assertRaises(ValueError):runtime.cleanup_fixture(root,witness,self.deadline)
        self.assertEqual(foreign.read_bytes(),b'preserve');self.assertTrue((root/'link').is_symlink())

    def test_expired_cleanup_retains_owned_fixture_and_no_positive_receipt(self):
        root=self.root/'owned';root.mkdir(mode=0o700)
        info=root.lstat();witness=(info.st_dev,info.st_ino,info.st_uid,info.st_mode)
        with self.assertRaises(ValueError):runtime.cleanup_fixture(root,witness,time.monotonic()-1.0)
        self.assertTrue(root.is_dir())


    def test_authenticated_fresh_context_drives_request_not_initial_hint(self):
        hint={'ownerId':'a'*64,'processNonce':'b'*64,'endpointGeneration':'1','contextId':'c'*64}
        owner={name:hint[name] for name in ('ownerId','processNonce','endpointGeneration')}
        context={'protocolVersion':2,**owner,'status':'available','sourceContextId':'d'*64,
            'sourceContextGeneration':'2','storePresent':True,'credentialAcquisitionAuthorized':False}
        capability={'protocolVersion':2,**owner,'nativeVersion':'fixture-only','capabilities':
            {'protocol_version':1,**{name:True for name in ('late_thread_binding','per_request_auth',
                'exclusive_refresh_owner','preacceptance_failure','account_transport_invalidation','native_context_reconstruction')}}}
        key=b'\x01'*32
        origin={'protocolVersion':2,**owner,'sourceContextId':'d'*64,'sourceContextGeneration':'2',
            'sourceOriginId':'e'*64,'status':'available','credentialAcquisitionAuthorized':False}
        body=('\n'.join(('omux-native-source-origin-v1','2','a'*64,'b'*64,'1','d'*64,'2','e'*64,'available','false'))+'\n').encode()
        import hmac
        origin['originProof']=hmac.new(key,body,hashlib.sha256).hexdigest()
        with patch.object(runtime,'metadata_exchange',side_effect=[capability,context,origin]) as exchange:
            request=runtime.source_request(None,None,hint,None,None,key,self.deadline)
            self.assertEqual(exchange.call_count,3)
            self.assertEqual(request['sourceContextId'],'d'*64);self.assertEqual(request['sourceContextGeneration'],'2')
            self.assertNotEqual(request['sourceContextId'],hint['contextId'])
        with patch.object(runtime,'metadata_exchange',side_effect=[capability,context,{**origin,'originProof':'0'*64}]):
            with self.assertRaises(ValueError):runtime.source_request(None,None,hint,None,None,key,self.deadline)
        with patch.object(runtime,'metadata_exchange',side_effect=[capability,{**context,'storePresent':False}]) as exchange:
            with self.assertRaises(ValueError):runtime.source_request(None,None,hint,None,None,key,self.deadline)
            self.assertEqual(exchange.call_count,2)

    def test_failed_final_proof_closes_exchange_without_accepting_metadata(self):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.addCleanup(left.close);self.addCleanup(right.close)
        endpoint=self.root/'endpoint';endpoint.write_bytes(b'fixture-witness');original=endpoint.lstat()
        from unittest.mock import Mock
        peer=Mock();peer.receive_packet.return_value=b'{"jsonrpc":"2.0","id":"owner/source/context","result":{}}'
        child=Mock();child.registered.check.side_effect=ValueError('fixture-final-proof-refused')
        with patch.object(runtime,'owner_connection',return_value=(left,peer,original)):
            with self.assertRaises(ValueError):runtime.metadata_exchange(child,Mock(),{'ownerEndpoint':str(endpoint)},
                None,None,'owner/source/context',{},self.deadline)
        peer.close.assert_called_once();self.assertEqual(left.fileno(),-1)
        child.registered.check.assert_called_once()

    def test_peer_close_failure_still_closes_socket_and_checks_both_materials(self):
        from unittest.mock import Mock
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.addCleanup(left.close);self.addCleanup(right.close)
        peer=Mock();peer.close.side_effect=OSError('fixture-peer-close')
        child=Mock();bridge=Mock()
        with self.assertRaises(OSError):runtime.finish_exchange(child,bridge,peer,left,self.deadline)
        self.assertEqual(left.fileno(),-1)
        child.registered.check.assert_called_once();bridge.recheck.assert_called_once()

    def test_registered_close_failure_still_closes_bridge(self):
        from unittest.mock import Mock
        registered=Mock();bridge=Mock();registered.close.side_effect=OSError('fixture-registered-close')
        with self.assertRaises(OSError):runtime.close_materials(registered,bridge)
        bridge.close.assert_called_once()

    def test_postproof_failure_still_checks_bridge_without_accepting_result(self):
        from unittest.mock import Mock
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.addCleanup(left.close);self.addCleanup(right.close)
        child=Mock();bridge=Mock();peer=Mock()
        child.registered.check.side_effect=ValueError('fixture-full-proof')
        with self.assertRaises(ValueError):runtime.finish_exchange(child,bridge,peer,left,self.deadline)
        self.assertEqual(left.fileno(),-1);bridge.recheck.assert_called_once()

    def test_fixture_close_failure_attempts_every_owned_descriptor(self):
        root=self.root/'owned';root.mkdir(mode=0o700);(root/'leaf').write_bytes(b'fixture')
        info=root.lstat();witness=(info.st_dev,info.st_ino,info.st_uid,info.st_mode)
        real_close=os.close;attempts=[]
        def close(descriptor):
            attempts.append(descriptor);real_close(descriptor)
            if len(attempts)==1:raise OSError('fixture-close-after-release')
        with patch.object(runtime.os,'close',side_effect=close):
            with self.assertRaises(OSError):runtime.cleanup_fixture(root,witness,self.deadline)
        self.assertGreaterEqual(len(attempts),2);self.assertFalse(root.exists())

    def test_unsafe_temporary_parent_refuses_before_acquiring_bridge(self):
        from unittest.mock import Mock
        import codex_native_acquisition_bridge_material as bridge_material
        unsafe=Mock(st_mode=stat.S_IFDIR|0o777,st_uid=0)
        with patch.object(runtime.compilation,'selected_document',return_value={}), \
                patch.object(runtime.compilation,'readback'), \
                patch.object(runtime.Path,'lstat',return_value=unsafe), \
                patch.object(bridge_material,'load_registered_bridge',side_effect=AssertionError('no owned bridge')) as load:
            with self.assertRaises(ValueError):runtime.qualify_runtime(
                {'compiler_document':{'path':'/model-input','sha256':'a'*64},'compiler_result':{},'bridge':{}},
                self.deadline,self.deadline+30.0)
        load.assert_not_called()

    def test_hint_root_close_after_release_still_closes_runtime_descriptor_once(self):
        from types import SimpleNamespace
        root=self.root/'hint-owned';root.mkdir(mode=0o700);(root/'runtime').mkdir(mode=0o700)
        info=root.lstat()
        child=SimpleNamespace(private_root=root,private_identity=(info.st_dev,info.st_ino,info.st_uid,info.st_mode),
            pidfd=None,reaped=False)
        real_open=os.open;real_close=os.close;opened=[];attempts=[]
        def opened_fd(*args,**kwargs):
            descriptor=real_open(*args,**kwargs);opened.append(descriptor);return descriptor
        def close(descriptor):
            attempts.append(descriptor);real_close(descriptor)
            if descriptor==opened[0]:raise OSError('fixture-root-close-after-release')
        try:
            with patch.object(runtime.os,'open',side_effect=opened_fd),patch.object(runtime.os,'close',side_effect=close):
                with self.assertRaisesRegex(OSError,'fixture-root-close-after-release'):
                    runtime.private_hint(root,child,self.deadline)
            self.assertEqual(len(opened),2)
            self.assertCountEqual(attempts,opened)
            self.assertEqual(len(attempts),len(set(attempts)))
        finally:
            # Test teardown owns any leaked fixture fd if the regression returns.
            for descriptor in opened:
                if descriptor not in attempts:real_close(descriptor)

if __name__=='__main__':unittest.main()
