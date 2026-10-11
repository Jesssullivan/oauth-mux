"""Ownership models plus real declared bridge self-peer fixture; no CLI launch."""
import ctypes
import array
import hashlib
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch
import codex_native_acquisition_peer as native

class Library:
    def __init__(self):self.closed=[];self.rechecks=0;self.fail_after=False;self.fd=None;self.receives=0
    def omux_runtime_capture(self,socket_fd,uid,image,out):out._obj.value=123;return 0
    def omux_runtime_recheck(self,handle):
        self.rechecks+=1
        return 8 if self.fail_after and self.rechecks>=2 else 0
    def omux_runtime_receive(self,handle,buffer,maximum,count,fd):
        self.receives+=1
        buffer.value=b'actual-fixture';count._obj.value=len(buffer.value);fd._obj.value=self.fd;return 0
    def omux_runtime_close(self,handle):self.closed.append(handle.value)
    def omux_runtime_packet(self,handle,buffer,maximum,count):
        self.receives+=1;buffer.value=b'metadata-fixture';count._obj.value=len(buffer.value);return 0

class PeerTests(unittest.TestCase):
    def setUp(self):
        self.left,self.right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.addCleanup(self.left.close);self.addCleanup(self.right.close)
        self.library=Library();self.bridge=type('BridgeFixture',(),{'library':self.library})()
        self.deadline=time.monotonic()+10.0

    def test_opaque_handle_close_once_and_original_deadline(self):
        peer=native.Peer(self.bridge,self.left,-1,self.deadline)
        self.assertEqual(peer.deadline,self.deadline);peer.recheck();peer.close();peer.close()
        self.assertEqual(self.library.closed,[123])
        with self.assertRaises(ValueError):peer.recheck()

    def test_capture_refusal_closes_partial_handle(self):
        def refuse(socket_fd,uid,image,out):out._obj.value=777;return 8
        self.library.omux_runtime_capture=refuse
        with self.assertRaises(ValueError):native.Peer(self.bridge,self.left,-1,self.deadline)
        self.assertEqual(self.library.closed,[777])

    def test_post_receive_image_refusal_closes_delivered_right(self):
        fd=os.memfd_create('synthetic-peer-model',os.MFD_CLOEXEC)
        self.library.fd=fd;self.library.fail_after=True
        peer=native.Peer(self.bridge,self.left,-1,self.deadline)
        try:
            with patch.object(native.select,'select',return_value=([self.left],[],[])):
                with self.assertRaises(ValueError):peer.receive(self.left)
            with self.assertRaises(OSError):os.fstat(fd)
        finally:peer.close()

    def test_success_transfers_exact_right_without_closing_it(self):
        fd=os.memfd_create('synthetic-peer-model',os.MFD_CLOEXEC);self.library.fd=fd
        peer=native.Peer(self.bridge,self.left,-1,self.deadline)
        try:
            with patch.object(native.select,'select',return_value=([self.left],[],[])):
                raw,owned=peer.receive(self.left)
            self.assertEqual(raw,b'actual-fixture');self.assertEqual(owned,fd);os.fstat(owned)
        finally:os.close(fd);peer.close()

    def test_expired_original_clock_never_captures_peer(self):
        with self.assertRaises(ValueError):native.Peer(self.bridge,self.left,-1,time.monotonic()-1.0)
        self.assertEqual(self.library.closed,[])

    def test_fixed_exchange_cutoff_after_select_prevents_native_receive(self):
        clock={'now':0.0}
        def ready(*args):clock['now']=9.0;return [self.left],[],[]
        with patch.object(native.time,'monotonic',side_effect=lambda:clock['now']):
            peer=native.Peer(self.bridge,self.left,-1,100.0)
            try:
                with patch.object(native.select,'select',side_effect=ready):
                    with self.assertRaises(ValueError):peer.receive(self.left)
                self.assertEqual(self.library.receives,0)
            finally:peer.close()

    def test_fixed_exchange_cutoff_after_native_receive_closes_owned_fd(self):
        clock={'now':0.0};fd=os.memfd_create('synthetic-late-native',os.MFD_CLOEXEC)
        self.library.fd=fd;original=self.library.omux_runtime_receive
        def late(*args):
            result=original(*args);clock['now']=9.0;return result
        self.library.omux_runtime_receive=late
        with patch.object(native.time,'monotonic',side_effect=lambda:clock['now']):
            peer=native.Peer(self.bridge,self.left,-1,100.0)
            try:
                with patch.object(native.select,'select',return_value=([self.left],[],[])):
                    with self.assertRaises(ValueError):peer.receive(self.left)
                self.assertEqual(self.library.receives,1)
                with self.assertRaises(OSError):os.fstat(fd)
                self.assertEqual(peer.deadline,100.0)
            finally:peer.close()

    def test_fixed_exchange_cutoff_after_final_recheck_closes_owned_fd(self):
        clock={'now':0.0};fd=os.memfd_create('synthetic-late-recheck',os.MFD_CLOEXEC)
        self.library.fd=fd;original=self.library.omux_runtime_recheck
        def late(handle):
            result=original(handle)
            if self.library.rechecks==2:clock['now']=9.0
            return result
        self.library.omux_runtime_recheck=late
        with patch.object(native.time,'monotonic',side_effect=lambda:clock['now']):
            peer=native.Peer(self.bridge,self.left,-1,100.0)
            try:
                with patch.object(native.select,'select',return_value=([self.left],[],[])):
                    with self.assertRaises(ValueError):peer.receive(self.left)
                self.assertEqual(self.library.rechecks,2)
                with self.assertRaises(OSError):os.fstat(fd)
            finally:peer.close()

    def test_real_declared_bridge_abi_and_closed_kernel_capture_profile(self):
        root=Path(os.environ['TEST_SRCDIR'])
        path=(root/'_main/native_peer_runtime_bridge.so').resolve(strict=True)
        raw=path.read_bytes();selected={'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
        bridge=native.Bridge(path,selected,self.deadline)
        status=bridge.library.omux_runtime_enable(self.left.fileno())
        # Unsupported locked kernel/UAPI is an explicit refusal fixture, never
        # a runtime-qualified receipt. This test launches no candidate process.
        if status!=0:
            self.assertIn(status,(1,2,3,12));return
        self.assertEqual(bridge.library.omux_runtime_enable(self.right.fileno()),0)
        image=os.open('/proc/self/exe',os.O_RDONLY|os.O_CLOEXEC)
        try:
            handle=ctypes.c_void_p()
            status=bridge.library.omux_runtime_capture(self.left.fileno(),os.getuid(),image,ctypes.byref(handle))
            if status!=0:
                self.assertFalse(handle.value);return
            self.assertTrue(handle.value)
            try:self.assertEqual(bridge.library.omux_runtime_recheck(handle),0)
            finally:bridge.library.omux_runtime_close(handle)
        finally:os.close(image)

    def test_metadata_uses_only_authenticated_packet_abi(self):
        self.library.omux_runtime_receive=lambda *args:(_ for _ in ()).throw(AssertionError('no descriptor ABI'))
        peer=native.Peer(self.bridge,self.left,-1,self.deadline)
        try:
            with patch.object(native.select,'select',return_value=([self.left],[],[])):
                self.assertEqual(peer.receive_packet(self.left),b'metadata-fixture')
            self.assertEqual(self.library.receives,1);self.assertEqual(self.library.rechecks,2)
        finally:peer.close()

    def test_metadata_native_refusal_never_returns_buffer(self):
        def refuse(handle,buffer,maximum,count):
            buffer.value=b'untrusted';count._obj.value=9;return 9
        self.library.omux_runtime_packet=refuse
        peer=native.Peer(self.bridge,self.left,-1,self.deadline)
        try:
            with patch.object(native.select,'select',return_value=([self.left],[],[])):
                with self.assertRaises(ValueError):peer.receive_packet(self.left)
        finally:peer.close()

    def test_metadata_fixed_cutoff_at_every_late_boundary(self):
        for stage in ('select','native','recheck'):
            with self.subTest(stage=stage):
                clock={'now':0.0};library=Library()
                bridge=type('Fixture',(),{'library':library})()
                original_packet=library.omux_runtime_packet;original_recheck=library.omux_runtime_recheck
                def ready(*args):
                    if stage=='select':clock['now']=9.0
                    return [self.left],[],[]
                def packet(*args):
                    result=original_packet(*args)
                    if stage=='native':clock['now']=9.0
                    return result
                def recheck(*args):
                    result=original_recheck(*args)
                    if stage=='recheck' and library.rechecks>=2:clock['now']=9.0
                    return result
                library.omux_runtime_packet=packet;library.omux_runtime_recheck=recheck
                with patch.object(native.time,'monotonic',side_effect=lambda:clock['now']):
                    peer=native.Peer(bridge,self.left,-1,100.0)
                    try:
                        with patch.object(native.select,'select',side_effect=ready):
                            with self.assertRaises(ValueError):peer.receive_packet(self.left)
                        self.assertEqual(peer.deadline,100.0)
                        self.assertEqual(library.receives,0 if stage=='select' else 1)
                    finally:peer.close()

    def test_metadata_wrong_socket_refuses_before_native_receive(self):
        peer=native.Peer(self.bridge,self.left,-1,self.deadline)
        try:
            with self.assertRaises(ValueError):peer.receive_packet(self.right)
            self.assertEqual(self.library.receives,0)
        finally:peer.close()

    def test_real_declared_packet_metadata_and_unexpected_rights_refusal(self):
        path=(Path(os.environ['TEST_SRCDIR'])/'_main/native_peer_runtime_bridge.so').resolve(strict=True)
        raw=path.read_bytes();bridge=native.Bridge(path,
            {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)},self.deadline)
        if bridge.library.omux_runtime_enable(self.left.fileno())!=0:return
        self.assertEqual(bridge.library.omux_runtime_enable(self.right.fileno()),0)
        image=os.open('/proc/self/exe',os.O_RDONLY|os.O_CLOEXEC);handle=ctypes.c_void_p()
        try:
            status=bridge.library.omux_runtime_capture(self.left.fileno(),os.getuid(),image,ctypes.byref(handle))
            if status!=0:self.assertFalse(handle.value);return
            self.right.send(b'actual-metadata')
            buffer=ctypes.create_string_buffer(65536);count=ctypes.c_size_t()
            self.assertEqual(bridge.library.omux_runtime_packet(handle,buffer,65536,ctypes.byref(count)),0)
            self.assertEqual(buffer.raw[:count.value],b'actual-metadata')
            fd=os.memfd_create('synthetic-unexpected-right',os.MFD_CLOEXEC)
            try:
                self.right.sendmsg([b'forbidden-right'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                    array.array('i',[fd]).tobytes())])
                self.assertNotEqual(bridge.library.omux_runtime_packet(handle,buffer,65536,ctypes.byref(count)),0)
                self.assertEqual(count.value,0);self.assertEqual(buffer.raw,b'\0'*65536)
                os.fstat(fd) # sender retains its original; C consumes receiver rights.
            finally:os.close(fd)
        finally:
            if handle.value:bridge.library.omux_runtime_close(handle)
            os.close(image)

if __name__=='__main__':unittest.main()
