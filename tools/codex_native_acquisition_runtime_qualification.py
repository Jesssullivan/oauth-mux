"""Provider-free ninth runtime predicates. Unregistered witness refuses launch.

This family does not borrow the historical runtime image validator. Registration
must implement actual main-exe + held pidfd + bound PT_INTERP + complete runtime
NAR inventory authority before any compiled CLI can be launched here.
"""
import array
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import time
import codex_native_acquisition_compilation as compilation

KIND='omux-native-acquisition-runtime-qualification-v1'
TARGET='//tools:codex_native_acquisition_runtime_qualification_producer'
PROFILE='native-acquisition-runtime-qualification-reserved'
# Deliberately absent, rather than a false positive inherited from old validator.
NATIVE_PRIMARY_IMAGE_REGISTRATION=None
MAX_PACKET=64*1024
MAX_PAYLOAD=16*1024
REQUEST_FIELDS=('ownerId','processNonce','endpointGeneration','sourceOriginId',
    'sourceContextId','sourceContextGeneration','operationId','consentId',
    'consentGeneration','consentExpiresAt','sourceId','sourceGeneration',
    'forgetEpoch','custodySeconds')
OPAQUE=frozenset(('ownerId','processNonce','sourceOriginId','sourceContextId',
    'operationId','consentId','sourceId'))
FALSE_FLAGS=('provider_identity_qualified','provider_evaluation','live_handoff_proven',
    'continuity_qualified','custody_qualified','health_qualified')

def require(value):
    if value is not True:raise ValueError('native-acquisition-runtime-refused')

def generation(value,zero=False):
    require(type(value) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}',value) is not None)
    number=int(value);require(number<2**64 and (zero or number>0));return number

def request_fields(value):
    require(type(value) is dict and set(value)=={'protocolVersion',*REQUEST_FIELDS,'proof'}
        and type(value['protocolVersion']) is int and value['protocolVersion']==2)
    for name in REQUEST_FIELDS:
        if name in OPAQUE:
            require(type(value[name]) is str and re.fullmatch(r'[0-9a-f]{64}',value[name]) is not None
                and value[name]!='0'*64)
        else:generation(value[name],name=='forgetEpoch')
    require(generation(value['custodySeconds'])<=3600
        and generation(value['consentExpiresAt'])<=2**63-1
        and type(value['proof']) is str and re.fullmatch(r'[0-9a-f]{64}',value['proof']) is not None)
    return value

def canonical(value,domain):
    return ('\n'.join((domain,'2',*(value[name] for name in REQUEST_FIELDS)))+'\n').encode()

def acquisition_frame(params,key):
    require(type(key) is bytes and len(key)==32 and any(key))
    value={**params,'protocolVersion':2,'proof':'1'*64};request_fields(value)
    value['proof']=hmac.new(key,canonical(value,'omux-native-source-acquire-v1'),hashlib.sha256).hexdigest()
    raw=compilation.encoded({'jsonrpc':'2.0','id':1,'method':'owner/source/acquire','params':value})
    require(len(raw)<=MAX_PACKET);return raw,value

def interpreter(raw):
    """Actual ELF64 little-endian x86_64 PT_INTERP, no loader-as-primary alias."""
    require(type(raw) is bytes and len(raw)>=64 and raw[:6]==b'\x7fELF\x02\x01'
        and raw[18:20]==b'\x3e\x00')
    offset=struct.unpack_from('<Q',raw,32)[0]
    size,count=struct.unpack_from('<HH',raw,54)
    require(size==56 and 0<count<=128 and offset+size*count<=len(raw))
    found=[]
    for index in range(count):
        kind=struct.unpack_from('<I',raw,offset+index*size)[0]
        if kind!=3:continue
        start=struct.unpack_from('<Q',raw,offset+index*size+8)[0]
        length=struct.unpack_from('<Q',raw,offset+index*size+32)[0]
        require(1<length<=4096 and start+length<=len(raw))
        text=raw[start:start+length];require(text[-1:]==b'\0' and b'\0' not in text[:-1])
        path=text[:-1].decode('ascii')
        require(re.fullmatch(r'/nix/store/[a-z0-9]{32}-[^/\s]+/[^\s]+',path) is not None
            and '..' not in Path(path).parts)
        found.append(path)
    require(len(found)==1);return found[0]

def primary_identity(held_image,actual_main_exe,held_interp,actual_interp):
    """Compare kernel inode identities, never authorize by basename/loader image."""
    identities=[]
    for fd in (held_image,actual_main_exe,held_interp,actual_interp):
        value=os.fstat(fd);require(stat.S_ISREG(value.st_mode))
        identities.append((value.st_dev,value.st_ino,value.st_size))
    require(identities[0]==identities[1] and identities[2]==identities[3]
        and identities[0]!=identities[2]);return True

def received_payload(fd,expected_payload,deadline):
    compilation.tick(deadline)
    require(type(expected_payload) is bytes and 0<len(expected_payload)<=MAX_PAYLOAD)
    info=os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600
        and info.st_size==len(expected_payload)
        and fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY)
    seals=fcntl.fcntl(fd,fcntl.F_GET_SEALS)
    required=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE
    require(seals&required==required)
    raw=os.pread(fd,MAX_PAYLOAD+1,0);compilation.tick(deadline)
    require(hmac.compare_digest(raw,expected_payload))
    return {'format':'omux-codex-access-v1','bytes':len(raw),
        'sha256':hashlib.sha256(raw).hexdigest(),'sealed_readonly_descriptor':True}

def receive_acquisition(connection,request,key,expected_payload,deadline):
    """Every received right is owned and closed even on malformed/truncated reply."""
    compilation.tick(deadline);connection.settimeout(min(8,deadline-time.monotonic()))
    raw,controls,flags,address=connection.recvmsg(MAX_PACKET,socket.CMSG_SPACE(4*16),socket.MSG_CMSG_CLOEXEC)
    owned=[]
    try:
        for level,kind,data in controls:
            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                descriptors=array.array('i');descriptors.frombytes(data[:len(data)//4*4]);owned.extend(descriptors)
        require(all(level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS and len(data)%4==0
            for level,kind,data in controls))
        require(flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC)==0 and len(owned)==1 and not address)
        response=json.loads(raw,object_pairs_hook=compilation.unique)
        require(type(response) is dict and set(response)=={'jsonrpc','id','result'}
            and response['jsonrpc']=='2.0' and type(response['id']) is int and response['id']==1)
        result=response['result'];fields=set(request)-{'proof'}
        require(type(result) is dict and set(result)==fields|{'payloadFormat','payloadBytes',
            'renewalOwner','credentialAcquisitionAuthorized','payloadSha256','replyProof'}
            and all(result[name]==request[name] for name in fields)
            and result['payloadFormat']=='omux-codex-access-v1'
            and result['payloadBytes']==str(len(expected_payload)) and result['renewalOwner']=='external'
            and result['credentialAcquisitionAuthorized'] is True
            and result['payloadSha256']==hashlib.sha256(expected_payload).hexdigest())
        signed=canonical(request,'omux-native-source-acquire-reply-v1')+(
            '\n'.join((result['payloadFormat'],result['payloadBytes'],'external','true',result['payloadSha256']))+'\n').encode()
        require(type(result['replyProof']) is str and hmac.compare_digest(result['replyProof'],
            hmac.new(key,signed,hashlib.sha256).hexdigest()))
        return received_payload(owned[0],expected_payload,deadline)
    finally:
        for fd in owned:os.close(fd)

def isolated_context(root):
    """Fresh synthetic context only; never opens a default HOME or database."""
    require(isinstance(root,Path) and root.is_absolute() and not root.exists())
    root.mkdir(mode=0o700)
    for name in ('home','runtime','cache','config','state'):(root/name).mkdir(mode=0o700)
    key=os.urandom(32)
    capability=root/'runtime/codex.capability'
    with capability.open('xb') as stream:
        stream.write(key.hex().encode());stream.flush();os.fchmod(stream.fileno(),0o600);os.fsync(stream.fileno())
    # This literal is synthetic nonauthority and is never emitted in a receipt.
    payload=b'{"tokens":{"access_token":"synthetic-access"},"expires_at":null}'
    auth=root/'home/auth.json'
    with auth.open('xb') as stream:
        stream.write(payload);stream.flush();os.fchmod(stream.fileno(),0o600);os.fsync(stream.fileno())
    return key,payload,capability

def registration(document=None,selection=None,package=None,deadline=None):
    # Configuration is deliberately unset; a typed genuine package/compiler
    # selection is required. The implementation never discovers HOME inputs.
    require(document is not None and selection is not None and package is not None
        and type(deadline) is float)
    import codex_native_acquisition_process as process
    return process.register(document,selection,package,deadline)

def capture_owned_peer(child,bridge,connection,document,selection,deadline):
    """Actual direct child kernel identity joins the native authenticated peer."""
    require(deadline==child.registered.deadline)
    peer,inputs=capture_selected_peer(bridge,connection,child.registered.image,
        document,selection,deadline)
    try:
        child.fence(peer)
        return peer,inputs
    except BaseException:peer.close();raise

def receive_owned_acquisition(child,peer,connection,request,key,expected_payload,deadline):
    require(deadline==child.registered.deadline)
    child.fence(peer)
    result=receive_authenticated_acquisition(peer,connection,request,key,expected_payload,deadline)
    child.fence(peer)
    return result

def capture_selected_peer(bridge,connection,held_image,document,selection,deadline):
    """Register genuine compiled image custody; no ordinary-resume promotion.

    Bridge.enable must have run BEFORE connect. Direct-main launch ownership,
    exact runtime NAR inventory and native resume authorities are downstream
    gates; this method cannot launch a process or turn runtime flags true.
    """
    import codex_native_acquisition_peer as native
    import codex_native_acquisition_material as material
    material.declared_controller(deadline)
    inputs=compiled_inputs(document,selection,deadline)
    receipt=compilation.read_json(selection['path'],selection['sha256'],deadline)
    row=next(value for value in receipt['artifacts'] if value['role']=='native-cli')
    info=os.fstat(held_image)
    require(stat.S_ISREG(info.st_mode) and info.st_size==row['bytes']
        and 64<=info.st_size<=512*1024*1024 and info.st_mode&0o111!=0
        and info.st_mode&0o022==0 and fcntl.fcntl(held_image,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY)
    digest=hashlib.sha256();offset=0
    while offset<info.st_size:
        compilation.tick(deadline);raw=os.pread(held_image,min(1024*1024,info.st_size-offset),offset)
        require(bool(raw));digest.update(raw);offset+=len(raw)
    after=os.fstat(held_image)
    require((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        ==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
        and digest.hexdigest()==inputs['primary_elf_sha256']==row['sha256'])
    peer=native.Peer(bridge,connection,held_image,deadline)
    try:
        captured=os.fstat(held_image)
        require((info.st_dev,info.st_ino,info.st_size,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_mtime_ns,info.st_ctime_ns)==
            (captured.st_dev,captured.st_ino,captured.st_size,captured.st_mode,captured.st_uid,captured.st_gid,
            captured.st_nlink,captured.st_mtime_ns,captured.st_ctime_ns))
        require(compiled_inputs(document,selection,deadline)==inputs)
        peer.recheck()
        return peer,inputs
    except BaseException:
        peer.close();raise

def receive_authenticated_acquisition(peer,connection,request,key,expected_payload,deadline):
    """Native credential/writer-pidfd checks precede v3 reply/FD parsing."""
    require(deadline==peer.deadline)
    raw,fd=peer.receive(connection,MAX_PACKET)
    handed=False
    # Existing bounded typed parser owns the authenticated descriptor and closes
    # it on every success/refusal. Adapter introduces no unauthenticated bytes.
    class Packet:
        def settimeout(self,value):pass
        def recvmsg(self,*args):
            nonlocal handed
            handed=True
            return raw,[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]).tobytes())],0,None
    try:
        result=receive_acquisition(Packet(),request,key,expected_payload,deadline)
    except BaseException:
        # Parser owns fd immediately after its initial deadline check. If that
        # check refuses before recvmsg, explicitly release our still-owned right.
        if not handed:os.close(fd)
        raise
    peer.recheck()
    return result

def compiled_inputs(document,selection,deadline):
    """Same actual ninth backend/config/ELF, never a legacy role alias."""
    report=compilation.readback(document,selection,deadline)
    receipt=compilation.read_json(selection['path'],selection['sha256'],deadline)
    images=[row for row in receipt['artifacts'] if row['role']=='native-cli']
    schemas=[row for row in receipt['artifacts'] if row['role']=='config-schema']
    require(len(images)==len(schemas)==1)
    raw=compilation.read_bytes(images[0]['path'],images[0]['sha256'],deadline,1024*1024*1024)
    loader=interpreter(raw)
    return {'kind':'omux-native-acquisition-compiled-runtime-inputs-v1',
        'material':report['material'],'compiled_receipt_sha256':selection['sha256'],
        'compiled_outer_receipt_sha256':selection['producer']['sha256'],
        'primary_elf_sha256':images[0]['sha256'],'config_schema_sha256':schemas[0]['sha256'],
        'pt_interp':loader,'backend':'native-owner-source-acquisition-v3',
        'acquisition_contract':'unsupported','runtime_qualified':False,
        **{name:False for name in FALSE_FLAGS}}

def unavailable_receipt(inputs):
    """Closed refusal projection contains no auth payload/key/account/path data."""
    require(type(inputs) is dict and inputs['kind']=='omux-native-acquisition-compiled-runtime-inputs-v1'
        and inputs['acquisition_contract']=='unsupported' and inputs['runtime_qualified'] is False)
    return {'schema_version':1,'kind':KIND,'status':'primary-image-registration-unavailable',
        'compiled_receipt_sha256':inputs['compiled_receipt_sha256'],
        'primary_elf_sha256':inputs['primary_elf_sha256'],'config_schema_sha256':inputs['config_schema_sha256'],
        'backend':inputs['backend'],'acquisition_contract':'unsupported',
        'pidfd_qualified':False,'primary_main_exe_qualified':False,
        'pt_interp_and_runtime_nar_inventory_qualified':False,'received_fd_qualified':False,
        'owned_child_cleanup_qualified':False,'outer_cleanup_qualified':False,
        'runtime_qualified':False,**{name:False for name in FALSE_FLAGS}}

def main():
    require(len(sys.argv)==1)
    # Refuse before any child/provider/default-home IO while primary authority is
    # unregistered. Future registration must own original child pidfd/cleanup and
    # compiler.readback joins; this packet alone cannot prove runtime readiness.
    registration()

if __name__=='__main__':main()
