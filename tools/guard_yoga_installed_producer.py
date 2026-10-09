"""One contained provider-free workspace producer; no general RUN admission."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import yoga_installed_controller_support as support

LABEL='//delivery:yoga_installed_workspace'
STAGING=Path('/srv/fast-local/jess/state/codex/omux-installed-toolbar-public-20261008')
SELECTION=STAGING/'selection.json'
OUTPUT_PARENT=STAGING/'outputs'
OUTPUT=OUTPUT_PARENT/'workspace'
SHA=re.compile(r'[0-9a-f]{64}')
RESERVE=30*10**9
MAX_METADATA=16*1024*1024
INVENTORIES={'browser-inventory.json':'1c1d555f3124479d30972c05ce025f6d0f008dffb25698e085524421e16ac931',
    'controller-inventory.json':'2be4ecfe05837c67a7267aa216dbae683f2d44d07e96198d3475f3fbd124c7f8'}


def require(value):
    if not value: raise ValueError('installed-toolbar-producer-refused')


def budget(deadline,reserve=0):
    require(type(deadline) is int and reserve < deadline-time.monotonic_ns() <= 1200*10**9)


def selected(profile,manager,arguments,digest,reuse=False,unrelated=()):
    requested=digest is not None or (arguments[:1]==['run'] and LABEL in arguments)
    if not requested: return False
    require(profile=='standard' and manager=='system' and arguments==['run',LABEL]
            and type(digest) is str and SHA.fullmatch(digest) and not reuse
            and not any(value is not None for value in unrelated))
    return True


def parent(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in Path(path).parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd); fd=child; info=os.fstat(fd)
            require(info.st_uid in (0,os.getuid()) and not info.st_mode&0o022)
        return fd
    except BaseException:
        os.close(fd); raise


def inode(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)


def full(info):
    return inode(info)+(info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def decode(data):
    def unique(pairs):
        value={}
        for key,item in pairs: require(key not in value); value[key]=item
        return value
    return json.loads(data,object_pairs_hook=unique,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('installed-toolbar-producer-refused')))


def metadata(value,source_root,digest):
    # Actual full producer performs its narrower source/artifact/schema checks.
    # This preallocation check rejects raw factor/account fields and binds the
    # controller package to this exact declared source checkout.
    fields={'schemaVersion','scope','buildReceipt','launcher','runfilesManifest','inputPaths','inputSha256',
        'nativeManifest','nativeManifestSha256','browserInventory','controllerInventory','fileSha256','controllerPackage'}
    version2 = type(value) is dict and value.get('schemaVersion') == support.SCHEMA
    if version2: fields.add('controllerDelivery')
    require(type(value) is dict and set(value)==fields and type(value['schemaVersion']) is int
            and value['schemaVersion']==(support.SCHEMA if version2 else 1)
            and value['scope']==(support.SELECTION_SCOPE if version2 else 'yoga-installed-toolbar-selection-v1'))
    if version2:
        support.support(value['controllerDelivery'])
        support.controller(value['controllerPackage'], source_root)
    package=value['controllerPackage']
    require(type(package) is dict and set(package)=={'root','files'} and package['root']==str(source_root/'tools')
            and type(package['files']) is dict and 0<len(package['files'])<=512)
    for name,pin in package['files'].items():
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_-]+\.py',name)
                and type(pin) is dict and set(pin)=={'sha256','bytes'} and type(pin['sha256']) is str
                and SHA.fullmatch(pin['sha256']) and type(pin['bytes']) is int and 0<pin['bytes']<=1024*1024)
    for name,filename in (('browserInventory','browser-inventory.json'),('controllerInventory','controller-inventory.json')):
        require(value[name]=={'path':str(STAGING/filename),'sha256':INVENTORIES[filename]})
    require(type(digest) is str and SHA.fullmatch(digest))
    return value


class Admission:
    def __init__(self,digest,source_root,deadline,*,required_schema=None):
        self.root_fd,self.output_fd=None,None
        self.files=[]; self.created=False; self.closed=False; self.output_identity=None
        self.deadline,self.digest=deadline,digest
        try:
            budget(deadline,RESERVE)
            require(type(digest) is str and SHA.fullmatch(digest))
            source_root=Path(source_root)
            require(re.fullmatch(r'/srv/fast-local/jess/git/oauth-mux(?:-[A-Za-z0-9_-]{1,100})?',str(source_root)))
            self.root_fd=parent(STAGING)
            info=os.fstat(self.root_fd)
            require(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700)
            self.root_identity=inode(info)
            require(set(os.listdir(self.root_fd))=={'selection.json',*INVENTORIES})
            captured={}
            for name,sha in {'selection.json':digest,**INVENTORIES}.items():
                budget(deadline,RESERVE)
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.root_fd)
                self.files.append((name,fd,None))
                info=os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022
                        and info.st_nlink==1 and 0<info.st_size<=MAX_METADATA)
                self.files[-1]=(name,fd,full(info))
                content=bytearray()
                while len(content)<info.st_size:
                    budget(deadline,RESERVE); block=os.read(fd,min(65536,info.st_size-len(content)))
                    require(block); content.extend(block)
                require(hashlib.sha256(content).hexdigest()==sha)
                captured[name]=bytes(content)
            value = metadata(decode(captured['selection.json']),source_root,digest)
            self.selection_schema = value['schemaVersion']
            require(required_schema is None or (type(required_schema) is int
                and required_schema == support.SCHEMA and self.selection_schema == required_schema))
            self.recheck(expect_output=False)
            # Only this new owned metadata directory is created by admission.
            # Never adopt/remove an old workspace or another session's output.
            os.mkdir('outputs',0o700,dir_fd=self.root_fd); self.created=True
            self.output_identity=inode(os.stat('outputs',dir_fd=self.root_fd,follow_symlinks=False))
            self.output_fd=os.open('outputs',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.root_fd)
            require(self.output_identity==inode(os.fstat(self.output_fd))
                    and self.output_identity[2]==os.getuid() and stat.S_IMODE(self.output_identity[4])==0o700
                    and not os.listdir(self.output_fd))
            self.recheck()
        except BaseException:
            self.close(); raise

    def recheck(self,expect_output=True):
        budget(self.deadline); require(not self.closed)
        named=parent(STAGING)
        try:
            require(self.root_identity==inode(os.fstat(self.root_fd))==inode(os.fstat(named)))
            require(set(os.listdir(self.root_fd))==({'selection.json',*INVENTORIES,'outputs'}
                if expect_output else {'selection.json',*INVENTORIES}))
            for name,fd,saved in self.files:
                require(saved is not None and full(os.fstat(fd))==saved==full(os.stat(name,dir_fd=named,follow_symlinks=False)))
            if expect_output:
                require(self.output_identity==inode(os.fstat(self.output_fd))==inode(
                    os.stat('outputs',dir_fd=named,follow_symlinks=False)))
                require(set(os.listdir(self.output_fd)).issubset({'workspace'}))
                if 'workspace' in os.listdir(self.output_fd):
                    info=os.stat('workspace',dir_fd=self.output_fd,follow_symlinks=False)
                    require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700)
        finally: os.close(named)
        return self.facts()

    def facts(self):
        return {'scope':'yoga-installed-toolbar-producer-input-v1','selection_sha256':self.digest,
            'original_deadline_monotonic_ns':self.deadline,'browser_invocation':False,'provider_invocation':False}

    def runtime_seconds(self):
        budget(self.deadline,RESERVE)
        seconds=(self.deadline-time.monotonic_ns()-RESERVE)//10**9
        require(1<=seconds<=1200); return seconds

    def bindings(self):
        self.recheck()
        return str(STAGING)+':'+str(STAGING)+':rbind',str(OUTPUT_PARENT)+':'+str(OUTPUT_PARENT)+':rbind'

    def verify(self,properties,run):
        readonly,writable=self.bindings()
        paths=properties.get('ReadWritePaths','').split()
        require(properties.get('BindReadOnlyPaths','').split()==[readonly]
                and properties.get('BindPaths','').split()==[writable]
                and properties.get('ProtectSystem')=='strict'
                and len(paths)==2 and set(paths)=={str(run),str(OUTPUT_PARENT)})
        self.recheck()

    def argv(self):
        self.recheck()
        return ['--selection',str(SELECTION),'--selection-sha256',self.digest,
                '--output',str(OUTPUT),'--deadline-monotonic-ns',str(self.deadline)]

    def close(self):
        if self.closed:return
        self.closed=True
        # Only an unchanged, still-empty directory created here may be removed.
        try:
            if self.output_fd is not None:
                if self.created and not os.listdir(self.output_fd):
                    named=os.stat('outputs',dir_fd=self.root_fd,follow_symlinks=False)
                    if inode(named)==self.output_identity==inode(os.fstat(self.output_fd)):
                        os.rmdir('outputs',dir_fd=self.root_fd)
        except OSError: pass
        finally:
            if self.output_fd is not None:os.close(self.output_fd); self.output_fd=None
            for _,fd,_ in self.files:os.close(fd)
            self.files=[]
            if self.root_fd is not None:os.close(self.root_fd); self.root_fd=None


def command(bazel,run,arguments,admission,base,**options):
    require(arguments==['run',LABEL] and type(admission) is Admission)
    admission.recheck()
    result=base(bazel,run,['build',LABEL],**options)
    result[result.index('build')]='run'
    flags=['--symlink_prefix='+str(Path(run)/'bazel-'),'--repository_disable_download']
    if options.get('repository_cache') is not None:flags.append('--repo_contents_cache=')
    result[-1:-1]=flags
    return result+['--',*admission.argv()]
