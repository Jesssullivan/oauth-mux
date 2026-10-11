"""Bounded immutable Nix runtime declaration, never PACKAGE qualification.

The consuming TEST independently authenticates the genuine PACKAGE and complete
runtime NAR. This helper supplies only its finite nofollow declaration inventory.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

MAX_ROOTS=32
MAX_NODES=100000
MAX_BYTES=256*1024*1024
MAX_DOCUMENT=16*1024*1024
MAX_DEPTH=128
OWNER=0
STORE=re.compile(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+')
MODE='native-acquisition-ordinary-tui-reserved'
PUBLIC=re.compile(r'(?:/home/jess/\.local/state/omux-execution-20261005|'
    r'/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005)/'
    r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/output-base/execroot/_main/bazel-out/'
    r'[A-Za-z0-9_-]+/testlogs/tools/codex_native_carrier_runtime_package/test\.outputs/'
    r'fresh-native-runtime/registration-receipt\.json')

def need(value):
    if value is not True:raise ValueError('ordinary-runtime-declaration-refused')

def unique(pairs):
    out={}
    for key,value in pairs:
        need(key not in out);out[key]=value
    return out

def directory_identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)

def identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
        info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

class Clock:
    def __init__(self,entry,until):
        need(type(entry) is int and type(until) is int and 0<entry<until<2**63
            and until-entry==1200*10**9)
        self.entry=entry;self.until=until;self.work=until-30*10**9
        self.tick()
    def tick(self):need(self.entry<=time.monotonic_ns()<self.work)

def envelope(environment):
    need(environment.get('OMUX_NATIVE_ORDINARY_MODE')==MODE)
    values=[]
    for name in ('OMUX_NATIVE_ORDINARY_ENTRY_NS','OMUX_NATIVE_ORDINARY_DEADLINE_NS'):
        value=environment.get(name)
        need(type(value) is str and re.fullmatch('[1-9][0-9]{0,18}',value) is not None)
        values.append(int(value))
    return Clock(*values)

def path(value):
    value=Path(value)
    need(value.is_absolute() and str(value)==os.path.normpath(str(value))
        and len(os.fsencode(value))<=4096 and '..' not in value.parts
        and not any(c in str(value) for c in '\\\0\r\n\t'))
    return value

class Anchor:
    def __init__(self,value,clock,*,immutable=False):
        self.path=path(value);self.clock=clock;self.chain=[];self.fd=None
        try:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.chain.append((None,fd,directory_identity(os.fstat(fd))))
            for name in self.path.parts[1:]:
                clock.tick();before=os.stat(name,dir_fd=fd,follow_symlinks=False)
                need(stat.S_ISDIR(before.st_mode) and before.st_uid in ((OWNER,) if immutable else (0,os.getuid()))
                    and (not before.st_mode&0o022 or (not immutable and bool(before.st_mode&stat.S_ISVTX))))
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                try:need(identity(before)==identity(os.fstat(child))==identity(os.stat(name,dir_fd=fd,follow_symlinks=False)))
                except BaseException:os.close(child);raise
                self.chain.append((name,child,directory_identity(before)));fd=child
            self.fd=fd
            if immutable:need(os.fstat(fd).st_uid==OWNER and not os.fstat(fd).st_mode&0o222)
            self.check()
        except BaseException:self.close();raise
    def check(self):
        for n,(name,fd,witness) in enumerate(self.chain):
            self.clock.tick();need(directory_identity(os.fstat(fd))==witness)
            if n:need(directory_identity(os.stat(name,dir_fd=self.chain[n-1][1],follow_symlinks=False))==witness)
    def close(self):
        failure=None
        for _,fd,_ in reversed(self.chain):
            try:os.close(fd)
            except OSError as error:
                if failure is None:failure=error
        self.chain=[]
        if failure is not None:raise failure
    def __enter__(self):return self
    def __exit__(self,*_):self.close()

def read_control(value,clock):
    value=path(value)
    with Anchor(value.parent,clock) as parent:
        before=os.stat(value.name,dir_fd=parent.fd,follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and before.st_nlink==1
            and stat.S_IMODE(before.st_mode) in (0o444,0o555) and 0<before.st_size<=MAX_DOCUMENT)
        fd=os.open(value.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent.fd)
        try:
            need(identity(os.fstat(fd))==identity(before));chunks=[];offset=0
            while offset<before.st_size:
                clock.tick();raw=os.pread(fd,min(65536,before.st_size-offset),offset)
                need(bool(raw));chunks.append(raw);offset+=len(raw)
            need(identity(os.fstat(fd))==identity(before)==identity(os.stat(value.name,dir_fd=parent.fd,follow_symlinks=False)))
            parent.check();return b''.join(chunks)
        finally:os.close(fd)

def scan(roots,clock):
    need(type(roots) is list and 0<len(roots)<=MAX_ROOTS and len(set(roots))==len(roots)
        and all(type(root) is str and STORE.fullmatch(root) is not None for root in roots))
    members=[];count=0;byte_count=0;metadata_bytes=0
    base={'schema_version':1,'kind':'omux-direct-carrier-runtime-closure-inputs-v1',
        'roots':roots,'members':[],'original_entry_monotonic_ns':clock.entry,
        'original_deadline_monotonic_ns':clock.until}
    encoded_bytes=len((json.dumps(base,sort_keys=True,separators=(',',':'))+'\n').encode())
    need(encoded_bytes<=MAX_DOCUMENT)
    def visit(fd,root,relative,depth,root_number,expected=None):
        nonlocal count,byte_count,metadata_bytes,encoded_bytes
        clock.tick();need(depth<=MAX_DEPTH)
        held=identity(os.fstat(fd));need(expected is None or held==expected)
        # Global admission occurs on the streamed dirent before retaining a
        # name. Child stat is nofollow; symbolic targets are never opened.
        names=[]
        with os.scandir(fd) as stream:
            for item in stream:
                clock.tick();count+=1;need(count<=MAX_NODES)
                need(depth+1<=MAX_DEPTH)
                name=item.name
                need(name not in ('','.','..') and '/' not in name and len(os.fsencode(name))<=255
                    and not any(c in name for c in '\\\0\r\n\t'))
                child=relative+'/'+name if relative else name
                need(len(os.fsencode(root+'/'+child))<=4096)
                info=os.stat(name,dir_fd=fd,follow_symlinks=False)
                need(info.st_uid==OWNER and (stat.S_ISLNK(info.st_mode) or not info.st_mode&0o222))
                metadata_bytes+=len(os.fsencode(root))+len(os.fsencode(child))+len(os.fsencode(name))+256
                need(metadata_bytes<=MAX_DOCUMENT)
                witness=identity(info)
                if stat.S_ISREG(info.st_mode):
                    need(info.st_nlink>=1 and info.st_size>=0)
                    byte_count+=info.st_size;need(byte_count<=MAX_BYTES)
                    kind='regular';target=None
                elif stat.S_ISDIR(info.st_mode):kind='directory';target=None
                elif stat.S_ISLNK(info.st_mode):
                    kind='symlink';target=os.readlink(name,dir_fd=fd)
                    need(len(os.fsencode(target))<=4096)
                    metadata_bytes+=len(os.fsencode(target));need(metadata_bytes<=MAX_DOCUMENT)
                else:raise ValueError('ordinary-runtime-special-file')
                need(identity(os.stat(name,dir_fd=fd,follow_symlinks=False))==witness)
                names.append((name,child,kind,witness,target))
        for name,child,kind,witness,target in sorted(names,key=lambda row:os.fsencode(row[0])):
            clock.tick();need(identity(os.stat(name,dir_fd=fd,follow_symlinks=False))==witness)
            if kind=='directory':
                nested=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                try:visit(nested,root,child,depth+1,root_number,witness)
                finally:os.close(nested)
            elif kind=='regular':
                row={'alias':'runtime-closure/root-'+str(root_number)+'/'+child,'path':root+'/'+child}
                encoded_bytes+=len(json.dumps(row,sort_keys=True,separators=(',',':')).encode())+(1 if members else 0)
                need(encoded_bytes<=MAX_DOCUMENT)
                members.append(row)
            else:need(os.readlink(name,dir_fd=fd)==target)
            need(identity(os.stat(name,dir_fd=fd,follow_symlinks=False))==witness)
        need(identity(os.fstat(fd))==held)
    for number,root in enumerate(roots):
        count+=1;need(count<=MAX_NODES)
        with Anchor(root,clock,immutable=True) as held:
            visit(held.fd,root,'',0,number);held.check()
    clock.tick()
    base['members']=members
    return base

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--registration',required=True)
    args=parser.parse_args()
    clock=envelope(os.environ)
    need(PUBLIC.fullmatch(args.registration) is not None)
    original=read_control(args.registration,clock)
    proof=json.loads(original,object_pairs_hook=unique)
    rows=proof['registration_rows'];need(type(rows) is list and 0<len(rows)<=MAX_ROOTS)
    total=0;roots=[]
    for row in rows:
        clock.tick();need(type(row) is dict and type(row['narSize']) is int and 0<row['narSize']<=MAX_BYTES)
        total+=row['narSize'];need(total<=MAX_BYTES);roots.append(row['path'])
    document=scan(roots,clock)
    need(read_control(args.registration,clock)==original)
    # Counted path-length bounds precede serialization; output itself is also
    # bounded. No unbounded JSON or generic filesystem listing enters this lane.
    raw=(json.dumps(document,sort_keys=True,separators=(',',':'))+'\n').encode()
    need(0<len(raw)<=MAX_DOCUMENT)
    # The repository consumes this captured exact map, never an independently
    # reread output file. A complete successful helper return is mandatory.
    offset=0
    while offset<len(raw):
        clock.tick();made=sys.stdout.buffer.write(raw[offset:offset+65536])
        need(type(made) is int and made>0);offset+=made
    sys.stdout.buffer.flush();clock.tick()

if __name__=='__main__':main()
