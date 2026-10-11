"""Typed current artifact transport; canonical mode restoration owns no authority."""
import base64
from contextlib import contextmanager
import hashlib
import io
import os
from pathlib import Path
import stat
import home_manager_current_artifact as current

artifact,acquired=current.artifact,current.acquired
require=current.require


def retained_tree(root,inventory,receipt,deadline):
    # Existing strict scanner enforces complete readonly regular-only structure.
    # Its physical NAR is deliberately not the original canonical NAR.
    files,nodes,facts,_,_=artifact.tree_bytes(root,deadline)
    acquired.fields(inventory,('schemaVersion','nodes'))
    require(type(inventory['schemaVersion']) is int and inventory['schemaVersion']==1,
        'current-hm-retained-inventory-schema')
    descriptor={'schemaVersion':1,'root':str(root),'nodes':inventory['nodes']}
    acquired.validate_descriptor(descriptor)
    expected=inventory['nodes']
    require(len(expected)==len(nodes) and all(n['type'] in ('regular','directory') for n in expected),
        'current-hm-retained-complete-inventory')
    for actual,canonical in zip(nodes,expected):
        if actual['type']=='regular':
            require({k:v for k,v in actual.items() if k!='executable'}=={k:v for k,v in canonical.items() if k!='executable'}
                and stat.S_IMODE(facts[actual['path']][2])==0o555,'current-hm-retained-0555-transport')
        else:require(actual==canonical,'current-hm-retained-directory-inventory')
    digest=hashlib.sha256();size=0
    def emit(data):
        nonlocal size
        acquired.check_deadline(deadline);size+=len(data)
        require(size<=artifact.MAX_BYTES+4*1024*1024,'artifact-nar-byte-bound');digest.update(data)
    @contextmanager
    def opener(unused,path):
        acquired.check_deadline(deadline)
        yield io.BytesIO(files[path])
    acquired.serialize(descriptor,emit,opener=opener,deadline=deadline)
    nar='sha256-'+base64.b64encode(digest.digest()).decode()
    current.inventory_binding(inventory,expected,nar,size,receipt)
    require(artifact.tree_bytes(root,deadline)[2]==facts,'current-hm-retained-tree-drift')
    return files,expected,facts


def selected_transport(selection,deadline):
    root=Path(selection['root'])
    raw,receipt_capture=current.read(root/'receipt.json',65536,deadline,selection['receiptSha256'])
    receipt=current.validate_receipt(raw,selection['receiptSha256'])
    captures=current.producer_authority(selection,receipt,deadline)
    data,inventory_capture=current.read(root/'inventory.json',16*1024*1024,deadline,selection['inventorySha256'])
    inventory=acquired.decode(data,16*1024*1024)
    files,nodes,facts=retained_tree(root/'artifact',inventory,receipt,deadline)
    manifest=artifact.verify_copied_bundle(files,nodes)
    require(manifest['target']=='x86_64-linux' and manifest['channel']=='development'
        and manifest['distribution']=='portable-linux' and manifest['product']['status']=='experimental'
        and manifest['provenance']=={'sourceRevision':receipt['sourceRevision'],'sourceDirty':receipt['sourceDirty']}
        and 'qt' in manifest['runtime'] and all(name in files for name in artifact.NATIVE_BINS)
        and current.sha(files['release-manifest.json'])==receipt['manifestSha256'],'current-hm-archive-manifest')
    archive,archive_capture=current.read(root.parent/'current-home-manager.tar.gz',artifact.MAX_BYTES,deadline,
        receipt['archiveSha256'],readonly=False)
    require(len(archive)==receipt['archiveBytes'] and artifact.pack.verify_bundle(archive)[1]==files,
        'current-hm-original-archive-binding')
    extension,extension_capture=current.read(root/'extension.zip',artifact.MAX_BYTES,deadline,receipt['extensionSha256'])
    metadata,metadata_capture=current.read(root/'extension-metadata.json',artifact.MAX_BYTES,deadline,
        receipt['extensionMetadataSha256'])
    require(len(extension)==receipt['extensionBytes'],'current-hm-extension-size')
    captures.update({str(root/'receipt.json'):(receipt_capture,65536,True),
        str(root/'inventory.json'):(inventory_capture,16*1024*1024,True),
        str(root.parent/'current-home-manager.tar.gz'):(archive_capture,artifact.MAX_BYTES,False),
        str(root/'extension.zip'):(extension_capture,artifact.MAX_BYTES,True),
        str(root/'extension-metadata.json'):(metadata_capture,artifact.MAX_BYTES,True)})
    with artifact.HeldDirectory(root) as owner:
        require(set(os.listdir(owner.fd))=={'artifact','receipt.json','inventory.json','extension.zip','extension-metadata.json'},
            'current-hm-envelope-members');owner.check()
    require(artifact.tree_bytes(root/'artifact',deadline)[2]==facts,'current-hm-retained-tree-drift')
    for path,(witness,maximum,readonly) in captures.items():
        require(current.read(path,maximum,deadline,readonly=readonly)[1]==witness,'current-hm-authority-late-change')
    proof={**receipt,'fullQt':True,'selectedAuthoritySha256':current.sha(artifact.encoded(selection)),
        'retainedTransportCommitment':current.sha(artifact.encoded(facts)),
        'executionAuthority':False,'activationPerformed':False}
    return proof,files,inventory,captures


class CanonicalArtifact:
    """Owned canonical copy bound to one full original selected transport proof."""
    def __init__(self,selection,worker,deadline,account):
        self.selection=selection;self.worker=worker;self.deadline=deadline;self.account=account
        self.path=worker.path/'current-artifact';self.tree=None;self.parent=None
        self.proof,self.files,self.inventory,self.captures=selected_transport(selection,deadline)
        try:
            self.parent=artifact.HeldDirectory(worker.path)
            owner=self
            class Fence:
                def check(self,unused):
                    acquired.check_deadline(deadline);worker.check();owner.parent.check();acquired.check_deadline(deadline)
            class AccountedTree(artifact.ExportTree):
                def enroll(self,ledger,path,fd,parent,name):
                    # Ownership precedes every metadata syscall/proof. On the
                    # sole pre-enrollment error, close once without retrying a
                    # possibly stale descriptor; keep the active primary error.
                    try:ledger[path]=(fd,None,parent,name)
                    except BaseException:
                        import home_manager_bundle as resources
                        resources.close_resources(fd)
                        raise

                def directory(self,path):
                    if path in self.dirs:return self.dirs[path][0]
                    require(len(self.dirs)+len(self.files)<artifact.MAX_NODES,'artifact-node-bound')
                    parts=path.split('/')
                    require(0<len(parts)<=64 and all(part not in ('','.','..') for part in parts)
                        and len(os.fsencode(path))<=4096,'artifact-output-path')
                    parent=self.parent.fd if len(parts)==1 else self.directory('/'.join(parts[:-1]))
                    self.check();os.mkdir(parts[-1],0o700,dir_fd=parent)
                    created=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
                    fd=os.open(parts[-1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                    self.enroll(self.dirs,path,fd,parent,parts[-1])
                    require(acquired.snapshot(os.fstat(fd))==acquired.snapshot(created)
                        and stat.S_IMODE(created.st_mode)==0o700,'artifact-created-directory-replaced')
                    self.dirs[path]=(fd,artifact.identity(os.fstat(fd)),parent,parts[-1])
                    self.check();return fd

                def write(self,path,payload,executable=False):
                    artifact.pack.checked_name(path)
                    require(path not in self.files and isinstance(payload,bytes)
                        and len(self.dirs)+len(self.files)<artifact.MAX_NODES
                        and self.logical_bytes+len(payload)<=artifact.MAX_BYTES+65536,'artifact-output-byte-bound')
                    parent_path,name=path.rsplit('/',1);parent=self.directory(parent_path)
                    self.check(len(payload))
                    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
                        0o600,dir_fd=parent)
                    self.enroll(self.files,path,fd,parent,name)
                    self.files[path]=(fd,acquired.snapshot(os.fstat(fd)),parent,name)
                    self.logical_bytes+=len(payload);offset=0
                    while offset<len(payload):
                        self.check(len(payload)-offset)
                        count=os.write(fd,payload[offset:offset+65536]);require(count>0,'artifact-short-write')
                        offset+=count;self.files[path]=(fd,acquired.snapshot(os.fstat(fd)),parent,name)
                    self.check();os.fchmod(fd,0o555 if executable else 0o444)
                    self.files[path]=(fd,acquired.snapshot(os.fstat(fd)),parent,name)
                    self.check();os.fsync(fd);self.check()
                def check(self,allocation=0):
                    super().check(allocation)
                    account.record(os.fstat(self.parent.fd))
                    for fd,*_ in self.dirs.values():account.record(os.fstat(fd))
                    for fd,*_ in self.files.values():account.record(os.fstat(fd))
                    acquired.check_deadline(deadline)
            self.tree=AccountedTree(self.parent,Fence(),deadline)
            self.tree.directory('current-artifact')
            for node in self.inventory['nodes']:
                if node['type']=='regular':
                    self.tree.write('current-artifact/'+node['path'],self.files[node['path']],node['executable'])
            self.tree.seal('current-artifact');self.tree.check();self.verify(deadline)
        except BaseException:
            self.close();raise

    def verify(self,deadline):
        require(self.tree is not None,'current-hm-canonical-owner-closed')
        self.worker.check();self.tree.check()
        proof,files,inventory,captures=selected_transport(self.selection,deadline)
        require(proof==self.proof and files==self.files and inventory==self.inventory and captures==self.captures,
            'current-hm-retained-authority-through-canonical')
        actual,nodes,facts,nar,size=artifact.tree_bytes(self.path,deadline)
        current.inventory_binding(inventory,nodes,nar,size,proof)
        require(actual==files,'current-hm-canonical-byte-binding')
        artifact.verify_copied_bundle(actual,nodes)
        self.tree.check();self.worker.check()
        return {**proof,'metadataCommitment':current.sha(artifact.encoded(facts))}

    def __enter__(self):return self

    def __exit__(self,*unused):self.close()

    def close(self):
        import home_manager_bundle as resources
        tree,parent=self.tree,self.parent;self.tree=None;self.parent=None
        descriptors=[]
        if tree is not None:
            descriptors.extend(row[0] for row in tree.files.values())
            descriptors.extend(row[0] for row in reversed(list(tree.dirs.values())))
            tree.files.clear();tree.dirs.clear()
        if parent is not None:
            descriptors.extend(row[2] for row in reversed(parent.chain));parent.chain=[]
        # One close drain attempts ALL owned files/directories/ancestor FDs,
        # retaining an active primary failure rather than masking it.
        resources.close_resources(*descriptors)
