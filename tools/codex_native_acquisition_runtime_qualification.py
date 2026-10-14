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
import codex_protocol_history_query_tools as query_tools

KIND='omux-native-acquisition-runtime-qualification-v1'
TARGET='//tools:codex_native_acquisition_runtime_qualification_producer'
PROFILE='native-acquisition-runtime-qualification-reserved'
# Deliberately absent, rather than a false positive inherited from old validator.
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

def metadata_identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
        info.st_size,info.st_mtime_ns,info.st_ctime_ns)


RUNTIME_CONFIG='integrations/codex-upstream/native-acquisition-runtime-inputs.json'
RUNTIME_INPUT_KIND='omux-native-acquisition-runtime-inputs-v1'


def runtime_envelope(environment):
    """The existing guardian's original absolute clock; no restarted budget."""
    import guard_native_seed_plan_reserved as kernel
    require(environment.get('OMUX_NATIVE_RUNTIME_MODE')==PROFILE)
    raw=[environment.get('OMUX_NATIVE_RUNTIME_'+name+'_NS') for name in ('ENTRY','DEADLINE')]
    require(all(type(value) is str and re.fullmatch('[1-9][0-9]{0,18}',value) for value in raw))
    entry,until=map(int,raw)
    kernel.remaining(entry,until)
    require(until-entry==1200*10**9)
    deadline=(until-30*10**9)/10**9
    compilation.tick(deadline)
    return entry,until,deadline


def runtime_deadline(environment):
    return runtime_envelope(environment)[2]


def runtime_selection(raw):
    """Tracked selection is independent of outputs; null refuses before role IO."""
    require(type(raw) is bytes and 0<len(raw)<=16384)
    value=json.loads(raw,object_pairs_hook=compilation.unique)
    require(type(value) is dict and set(value)=={'schema_version','kind','status','selection'}
        and type(value['schema_version']) is int and value['schema_version']==1
        and value['kind']==RUNTIME_INPUT_KIND)
    require(value['status']=='selected' and type(value['selection']) is dict)
    selected=value['selection']
    require(set(selected)=={'compiler_document','compiler_result','package','bridge'})
    for name in ('compiler_document','compiler_result'):
        row=selected[name]
        require(type(row) is dict and set(row)==({'path','sha256'} if name=='compiler_document'
            else {'path','sha256','producer'}) and type(row['path']) is str
            and Path(row['path']).is_absolute() and '..' not in Path(row['path']).parts
            and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None)
    require(type(selected['package']) is dict and set(selected['package'])=={'root','producer','receipt','registration','outputs'})
    require(type(selected['bridge']) is dict)
    return selected


def private_hint(root,child,deadline):
    """Bounded own fixture namespace only. The hint is a locator, not authority."""
    compilation.tick(deadline)
    require(root==child.private_root and tuple(child.private_identity[:2])==
        (root.lstat().st_dev,root.lstat().st_ino))
    root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    runtime_fd=None
    try:
        info=os.fstat(root_fd)
        require((info.st_dev,info.st_ino,info.st_uid,info.st_mode)==tuple(child.private_identity))
        runtime_fd=os.open('runtime',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root_fd)
        runtime_info=os.fstat(runtime_fd)
        require(runtime_info.st_uid==os.getuid() and stat.S_IMODE(runtime_info.st_mode)==0o700)
        cutoff=min(deadline,time.monotonic()+8.0)
        while True:
            compilation.tick(cutoff)
            require(child.pidfd is not None and not child.reaped)
            import select
            require(not select.select([child.pidfd],[],[],0)[0])
            try:
                held=os.open('omux-native-owners',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=runtime_fd)
            except FileNotFoundError:
                time.sleep(min(0.01,max(0.0,cutoff-time.monotonic())))
                continue
            try:
                anchor=os.fstat(held)
                require(anchor.st_uid==os.getuid() and stat.S_IMODE(anchor.st_mode)==0o700)
                import itertools
                with os.scandir(held) as scan:names=list(itertools.islice(scan,2))
                require(len(names)<=1)
                if not names:
                    time.sleep(min(0.01,max(0.0,cutoff-time.monotonic())))
                    continue
                name=names[0].name
                require(re.fullmatch('[0-9a-f]{64}\\.json',name) is not None)
                leaf=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=held)
                try:
                    before=os.fstat(leaf)
                    require(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid()
                        and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
                        and 0<before.st_size<=16384)
                    raw=os.read(leaf,16385)
                    require(len(raw)==before.st_size and metadata_identity(before)==metadata_identity(os.fstat(leaf))
                        and metadata_identity(before)==metadata_identity(os.stat(name,dir_fd=held,follow_symlinks=False)))
                    hint=json.loads(raw,object_pairs_hook=compilation.unique)
                    require(type(hint) is dict and set(hint)=={'protocolVersion','contextId','contextGeneration',
                        'ownerId','processNonce','endpointGeneration','ownerEndpoint'} and type(hint['protocolVersion']) is int
                        and hint['protocolVersion']==1)
                    for field in ('contextId','ownerId','processNonce'):
                        require(type(hint[field]) is str and re.fullmatch('[0-9a-f]{64}',hint[field])
                            and hint[field]!='0'*64)
                    generation(hint['contextGeneration']);generation(hint['endpointGeneration'])
                    require(name==hint['contextId']+'.json'
                        and hint['ownerEndpoint']==str(root/'home'/('omux-owner-'+hint['ownerId'][:16])/'owner.sock')
                        and len(os.fsencode(hint['ownerEndpoint']))<=107
                        and (anchor.st_dev,anchor.st_ino)==(os.stat('omux-native-owners',dir_fd=runtime_fd,follow_symlinks=False).st_dev,os.stat('omux-native-owners',dir_fd=runtime_fd,follow_symlinks=False).st_ino))
                    compilation.tick(cutoff)
                    return hint
                finally:os.close(leaf)
            finally:os.close(held)
    finally:
        # Each owned numeric descriptor gets one close attempt, even if another
        # close releases its descriptor and then reports failure.
        try:
            if runtime_fd is not None:os.close(runtime_fd)
        finally:os.close(root_fd)


def metadata_reply(raw,request_id):
    require(type(raw) is bytes and 0<len(raw)<=MAX_PACKET)
    value=json.loads(raw,object_pairs_hook=compilation.unique)
    require(type(value) is dict and set(value)=={'jsonrpc','id','result'}
        and value['jsonrpc']=='2.0' and type(value['id']) is str and value['id']==request_id
        and type(value['result']) is dict)
    return value['result']


def owner_connection(child,bridge,hint,document,selection,deadline):
    compilation.tick(deadline)
    child.registered.check()  # full retained proof BEFORE native connection's deadline starts
    compilation.tick(deadline)
    endpoint=Path(hint['ownerEndpoint'])
    before=endpoint.lstat()
    require(stat.S_ISSOCK(before.st_mode) and before.st_uid==os.getuid()
        and stat.S_IMODE(before.st_mode)==0o600)
    connection=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
    peer=None
    try:
        bridge.enable(connection)  # credential/writer-pidfd delivery enabled BEFORE connect
        connection.settimeout(min(8.0,deadline-time.monotonic()))
        connection.connect(str(endpoint))
        require(metadata_identity(before)==metadata_identity(endpoint.lstat()))
        peer=child.capture_peer(bridge,connection)
        return connection,peer,before
    except BaseException:
        close_exchange(peer,connection)
        raise


def close_exchange(peer,connection):
    """Attempt both owned closes; a close refusal never becomes acceptance."""
    try:
        if peer is not None:peer.close()
    finally:
        connection.close()


def close_materials(registered,bridge_owner):
    try:
        if registered is not None:registered.close()
    finally:
        bridge_owner.close()


def finish_exchange(child,bridge_owner,peer,connection,deadline):
    try:
        close_exchange(peer,connection)
    finally:
        # Even failed close attempts cannot skip either full post-exchange proof.
        try:
            child.registered.check()
        finally:
            try:bridge_owner.recheck()
            finally:compilation.tick(deadline)


def metadata_exchange(child,bridge_owner,hint,document,selection,method,params,deadline):
    bridge_owner.recheck()
    connection,peer,original=owner_connection(child,bridge_owner.bridge,hint,document,selection,deadline)
    try:
        raw=json.dumps({'jsonrpc':'2.0','id':method,'method':method,'params':params},
            sort_keys=True,separators=(',',':')).encode()
        require(len(raw)<=MAX_PACKET)
        child.fence(peer)
        require(connection.send(raw)==len(raw))
        result=metadata_reply(peer.receive_packet(connection,MAX_PACKET),method)
        child.fence(peer)
        require(metadata_identity(Path(hint['ownerEndpoint']).lstat())==metadata_identity(original))
        compilation.tick(deadline)
        return result
    finally:
        finish_exchange(child,bridge_owner,peer,connection,deadline)


def source_request(child,bridge,hint,document,selection,key,deadline):
    owner={field:hint[field] for field in ('ownerId','processNonce','endpointGeneration')}
    capabilities=metadata_exchange(child,bridge,hint,document,selection,'owner/capabilities',
        {'protocolVersion':2},deadline)
    require(set(capabilities)=={'protocolVersion','ownerId','processNonce','endpointGeneration','nativeVersion','capabilities'}
        and type(capabilities['nativeVersion']) is str and 0<len(capabilities['nativeVersion'])<=256
        and type(capabilities['capabilities']) is dict
        and set(capabilities['capabilities'])=={'protocol_version','late_thread_binding','per_request_auth',
            'exclusive_refresh_owner','preacceptance_failure','account_transport_invalidation','native_context_reconstruction'}
        and type(capabilities['capabilities']['protocol_version']) is int
        and capabilities['capabilities']['protocol_version']==1
        and all(value is True for field,value in capabilities['capabilities'].items() if field!='protocol_version')
        and all(capabilities.get(field)==value for field,value in owner.items())
        and type(capabilities.get('protocolVersion')) is int and capabilities['protocolVersion']==2)
    context=metadata_exchange(child,bridge,hint,document,selection,'owner/source/context',
        {'protocolVersion':2,**owner},deadline)
    require(set(context)=={'protocolVersion','ownerId','processNonce','endpointGeneration','status',
        'sourceContextId','sourceContextGeneration','storePresent','credentialAcquisitionAuthorized'}
        and type(context['protocolVersion']) is int and context['protocolVersion']==2
        and all(context[field]==value for field,value in owner.items()) and context['status']=='available'
        and context['storePresent'] is True and context['credentialAcquisitionAuthorized'] is False)
    require(type(context['sourceContextId']) is str and re.fullmatch('[0-9a-f]{64}',context['sourceContextId'])
        and context['sourceContextId']!='0'*64)
    generation(context['sourceContextGeneration'])
    selector={field:context[field] for field in ('sourceContextId','sourceContextGeneration')}
    origin=metadata_exchange(child,bridge,hint,document,selection,'owner/source/origin',
        {'protocolVersion':2,**owner,**selector},deadline)
    require(set(origin)=={'protocolVersion','ownerId','processNonce','endpointGeneration','sourceContextId',
        'sourceContextGeneration','sourceOriginId','status','credentialAcquisitionAuthorized','originProof'}
        and type(origin['protocolVersion']) is int and origin['protocolVersion']==2
        and all(origin[field]==value for field,value in {**owner,**selector}.items())
        and origin['status']=='available' and origin['credentialAcquisitionAuthorized'] is False)
    require(type(origin['sourceOriginId']) is str and re.fullmatch('[0-9a-f]{64}',origin['sourceOriginId'])
        and origin['sourceOriginId']!='0'*64 and type(origin['originProof']) is str)
    canonical_origin=('\n'.join(('omux-native-source-origin-v1','2',owner['ownerId'],owner['processNonce'],
        owner['endpointGeneration'],selector['sourceContextId'],selector['sourceContextGeneration'],
        origin['sourceOriginId'],'available','false'))+'\n').encode()
    require(hmac.compare_digest(origin['originProof'],hmac.new(key,canonical_origin,hashlib.sha256).hexdigest()))
    compilation.tick(deadline)
    return {**owner,**selector,'sourceOriginId':origin['sourceOriginId'],
        'operationId':os.urandom(32).hex(),'consentId':os.urandom(32).hex(),'sourceId':os.urandom(32).hex(),
        'consentGeneration':'1','sourceGeneration':'1','forgetEpoch':'0','custodySeconds':'60',
        'consentExpiresAt':str(int(time.time())+60)}


def cleanup_fixture(root,original,deadline):
    """After owned child terminal: remove only bounded retained own identities."""
    compilation.tick(deadline)
    held=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    descriptors=[held];entries=[];payload_bytes=0
    def unchanged_directory(info,expected):
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022
            and (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)==
                (expected.st_dev,expected.st_ino,expected.st_mode,expected.st_uid,expected.st_gid))
    try:
        initial=os.fstat(held)
        require((initial.st_dev,initial.st_ino,initial.st_uid,initial.st_mode)==tuple(original))
        unchanged_directory(root.lstat(),initial)
        def capture(parent,depth):
            nonlocal payload_bytes
            require(depth<=16)
            with os.scandir(parent) as scan:
                for item in scan:
                    compilation.tick(deadline);require(len(entries)<4096)
                    info=os.stat(item.name,dir_fd=parent,follow_symlinks=False)
                    require(info.st_uid==os.getuid() and not stat.S_ISLNK(info.st_mode)
                        and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISSOCK(info.st_mode)))
                    if stat.S_ISREG(info.st_mode):
                        payload_bytes+=info.st_size;require(payload_bytes<=512*1024*1024)
                    fd=os.open(item.name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                    descriptors.append(fd);require(metadata_identity(info)==metadata_identity(os.fstat(fd)))
                    entries.append((parent,item.name,fd,info))
                    if stat.S_ISDIR(info.st_mode):
                        child=os.open(item.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                        descriptors.append(child);unchanged_directory(os.fstat(child),info)
                        capture(child,depth+1)
        capture(held,0)
        for parent,name,fd,info in reversed(entries):
            compilation.tick(deadline)
            current=os.stat(name,dir_fd=parent,follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                unchanged_directory(current,info);unchanged_directory(os.fstat(fd),info)
                os.rmdir(name,dir_fd=parent)
            else:
                require(metadata_identity(current)==metadata_identity(info) and metadata_identity(os.fstat(fd))==metadata_identity(info))
                os.unlink(name,dir_fd=parent)
        unchanged_directory(root.lstat(),initial);unchanged_directory(os.fstat(held),initial)
        os.rmdir(root)
        compilation.tick(deadline)
        require(not root.exists())
    finally:
        failure=None
        for descriptor in reversed(descriptors):
            try:os.close(descriptor)
            except OSError as error:
                if failure is None:failure=error
        if failure is not None:raise failure


def qualify_runtime(selected,deadline,original_deadline):
    """Actual selected compiler + package + bridge; no fixture authority carriers."""
    import codex_native_acquisition_process as process
    import codex_native_acquisition_bridge_material as bridge_material
    require(type(original_deadline) is float and original_deadline-deadline==30.0)
    document=compilation.selected_document(selected['compiler_document']['path'],
        selected['compiler_document']['sha256'],deadline)
    compilation.readback(document,selected['compiler_result'],deadline)
    # This genuine producer verifier must qualify full bridge bytes and its
    # selected dynamic runtime before any ctypes load or child/profile IO.
    registered=child=None;root=Path('/tmp')/('omux-nq-'+os.urandom(8).hex())
    result=None
    temporary_parent=Path('/tmp').lstat()
    require(stat.S_ISDIR(temporary_parent.st_mode) and temporary_parent.st_uid==0
        and temporary_parent.st_mode&stat.S_ISVTX and not stat.S_ISLNK(temporary_parent.st_mode))
    bridge_owner=bridge_material.load_registered_bridge(selected['bridge'],deadline)
    try:
        registered=registration(document,selected['compiler_result'],selected['package'],deadline)
        compilation.tick(deadline)
        child=process.OwnedChild(registered,cleanup_deadline=original_deadline)
        child.launch(('codex','app-server'),root)
        hint=private_hint(root,child,deadline)
        key,payload,_=child.context
        request=source_request(child,bridge_owner,hint,document,selected['compiler_result'],key,deadline)
        frame,request=acquisition_frame(request,key)
        bridge_owner.recheck()
        connection,peer,original=owner_connection(child,bridge_owner.bridge,hint,document,
            selected['compiler_result'],deadline)
        try:
            child.fence(peer);require(connection.send(frame)==len(frame))
            result=receive_owned_acquisition(child,peer,connection,request,key,payload,deadline)
            require(metadata_identity(Path(hint['ownerEndpoint']).lstat())==metadata_identity(original))
            child.fence(peer);compilation.tick(deadline)
        finally:
            finish_exchange(child,bridge_owner,peer,connection,deadline)
        inputs=dict(registered.inputs)
    finally:
        # Do not turn attempted cancellation into terminal cleanup evidence.
        try:
            if child is not None:
                child.close()
                require((child.pid is None or child.reaped) and child.pidfd is None)
                if getattr(child,'private_identity',None) is not None:
                    cleanup_fixture(root,child.private_identity,original_deadline)
        finally:
            close_materials(registered,bridge_owner)
    require(result is not None and child.reaped and child.pid is not None and child.pidfd is None)
    compilation.tick(deadline)
    return {'schema_version':1,'kind':KIND,'status':'isolated-native-protocol-qualified',
        'purpose':'provider-free-runtime-evaluation','launch_artifact':'compiler-native-cli',
        'installed_package_primary_qualified':False,'ordinary_tui_qualified':False,'native_support':False,
        'native_source_finalized':False,'material':inputs['material'],
        'compiled_receipt_sha256':inputs['compiled_receipt_sha256'],
        'primary_elf_sha256':inputs['primary_elf_sha256'],'config_schema_sha256':inputs['config_schema_sha256'],
        'backend':inputs['backend'],'acquisition_contract':'unsupported',
        'pidfd_qualified':True,'primary_main_exe_qualified':True,
        'pt_interp_and_runtime_nar_inventory_qualified':True,'received_fd_qualified':True,
        'owned_child_cleanup_qualified':True,'fixture_cleanup_qualified':True,
        'outer_cleanup_qualified':False,'runtime_qualified':True,
        'owned_child_exit':child.status,'payload':result,**{name:False for name in FALSE_FLAGS}}


def main():
    require(len(sys.argv)==1)
    entry,until,deadline=runtime_envelope(os.environ)
    import codex_native_acquisition_binding as binding
    import codex_native_acquisition_material as material
    with query_tools.consumer_phase(entry,until) as phase:
        require(deadline==phase.work_deadline)
        selected=runtime_selection(binding.ninth.parent.declared(RUNTIME_CONFIG,16384))
        # Fresh process readback needs this genuine repository qualification
        # before controller_inputs can join the compiler inventory.
        material.declared_controller(deadline)
        receipt=qualify_runtime(selected,deadline,phase.original_deadline)
    compilation.tick(deadline)
    output=os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR')
    require(type(output) is str and Path(output).is_absolute())
    directory=Path(output)/'native-acquisition-runtime-qualification'
    directory.mkdir(mode=0o700)
    raw=compilation.encoded(receipt)
    with (directory/'receipt.json').open('xb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    os.chmod(directory/'receipt.json',0o444);os.chmod(directory,0o555)
    compilation.tick(deadline)
    require((directory/'receipt.json').read_bytes()==raw)
    print('omux-native-runtime-output-sha256='+hashlib.sha256(raw).hexdigest(),flush=True)

if __name__=='__main__':main()
