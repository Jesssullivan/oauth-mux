"""Declared opaque native bridge registration; no launch/resume authority."""
import ctypes
import os
import select
import socket
import time
import hashlib
import stat
import threading
from pathlib import Path
import codex_native_acquisition_compilation as compilation

def require(value):
    if value is not True:raise ValueError('native-acquisition-peer-refused')

class Bridge:
    def __init__(self, declared_path, selected, deadline):
        runfiles=os.environ.get('TEST_SRCDIR')
        require(type(runfiles) is str and Path(runfiles).is_absolute())
        expected=Path(runfiles)/'_main/native_peer_runtime_bridge.so'
        require(Path(declared_path)==expected.resolve(strict=True))
        require(type(selected) is dict and set(selected)=={'path','sha256','bytes'}
            and selected['path']==str(declared_path) and type(selected['bytes']) is int)
        raw=compilation.read_bytes(declared_path,selected['sha256'],deadline,8*1024*1024)
        require(len(raw)==selected['bytes'] and raw[:6]==b'\x7fELF\x02\x01')
        # Caller must supply the declared Bazel artifact and qualified runtime
        # NAR/loader closure BEFORE this load. Hashing alone is not that proof.
        held=os.open(declared_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(held)
            require(stat.S_ISREG(info.st_mode) and info.st_size==selected['bytes']
                and info.st_mode&0o022==0)
            held_raw=os.pread(held,8*1024*1024+1,0)
            require(held_raw==raw and hashlib.sha256(held_raw).hexdigest()==selected['sha256'])
            self.library=ctypes.CDLL('/proc/self/fd/'+str(held),mode=os.RTLD_LOCAL|os.RTLD_NOW)
            require(os.pread(held,8*1024*1024+1,0)==held_raw)
        finally:os.close(held)
        signatures={
            'omux_runtime_abi_version':(ctypes.c_uint,[]),
            'omux_runtime_enable':(ctypes.c_int,[ctypes.c_int]),
            'omux_runtime_capture':(ctypes.c_int,[ctypes.c_int,ctypes.c_uint,ctypes.c_int,ctypes.POINTER(ctypes.c_void_p)]),
            'omux_runtime_recheck':(ctypes.c_int,[ctypes.c_void_p]),
            'omux_runtime_child':(ctypes.c_int,[ctypes.c_void_p,ctypes.c_int]),
            'omux_runtime_receive':(ctypes.c_int,[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t),ctypes.POINTER(ctypes.c_int)]),
            'omux_runtime_close':(None,[ctypes.c_void_p]),
        }
        for name,(result,args) in signatures.items():
            function=getattr(self.library,name);function.restype=result;function.argtypes=args
        require(self.library.omux_runtime_abi_version()==1)
        require(compilation.read_bytes(declared_path,selected['sha256'],deadline,8*1024*1024)==raw)

    def enable(self,connection):
        # Socket option/UAPI constants remain exclusively in compiled C.
        require(connection.family==socket.AF_UNIX and connection.type&socket.SOCK_SEQPACKET==socket.SOCK_SEQPACKET)
        require(self.library.omux_runtime_enable(connection.fileno())==0)

class Peer:
    def __init__(self,bridge,connection,held_image,deadline):
        compilation.tick(deadline);self.bridge=bridge;self.deadline=deadline
        self.lock=threading.RLock()
        self.handle=ctypes.c_void_p();self.closed=False
        info=os.fstat(connection.fileno());self.socket_identity=(info.st_dev,info.st_ino)
        try:
            status=bridge.library.omux_runtime_capture(connection.fileno(),os.getuid(),held_image,
                ctypes.byref(self.handle))
            require(status==0 and bool(self.handle.value))
        except BaseException:
            if self.handle.value:bridge.library.omux_runtime_close(self.handle)
            self.closed=True;self.handle=ctypes.c_void_p();raise

    def recheck(self):
        with self.lock:
            compilation.tick(self.deadline);require(not self.closed)
            require(self.bridge.library.omux_runtime_recheck(self.handle)==0)

    def receive(self,connection,maximum=65536):
        with self.lock:return self._receive(connection,maximum)

    def fence_child(self,original_pidfd):
        with self.lock:
            self.recheck()
            require(self.bridge.library.omux_runtime_child(self.handle,original_pidfd)==0)
            self.recheck()

    def _receive(self,connection,maximum):
        require(type(maximum) is int and 0<maximum<=65536)
        info=os.fstat(connection.fileno());require((info.st_dev,info.st_ino)==self.socket_identity)
        self.recheck();cutoff=min(self.deadline,time.monotonic()+8)
        remaining=cutoff-time.monotonic();require(remaining>0)
        readable,_,_=select.select([connection],[],[],remaining);require(bool(readable))
        require(time.monotonic()<cutoff)
        buffer=ctypes.create_string_buffer(maximum);count=ctypes.c_size_t();fd=ctypes.c_int(-1)
        try:
            status=self.bridge.library.omux_runtime_receive(self.handle,buffer,maximum,ctypes.byref(count),ctypes.byref(fd))
            require(status==0 and 0<count.value<=maximum and fd.value>=0)
            require(time.monotonic()<cutoff)
            self.recheck()
            require(time.monotonic()<cutoff)
            result=fd.value;fd.value=-1
            return buffer.raw[:count.value],result
        finally:
            if fd.value>=0:os.close(fd.value)

    def close(self):
        with self.lock:
            if not self.closed:
                self.closed=True;self.bridge.library.omux_runtime_close(self.handle)
                self.handle=ctypes.c_void_p()

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
