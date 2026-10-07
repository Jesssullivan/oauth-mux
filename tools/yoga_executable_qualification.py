"""Finite executable qualification against separately trusted authenticated OS."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import time

SSH = '/nix/store/aq5s91svywqgs5l9zyhp1wcjqvnfa0ss-openssh-with-gssapi-10.2p1/bin/ssh'
BOOTSTRAP_SHA = 'c056b1b590c814bc662a7ef348ba4f5789e3534ed9ae8420fdc8614fefd9bc3a'
BOOTSTRAP_ROOT = '/nix/store/j5dnm7vp4w41x7rjia61c1hd6s7yszvd-omux-bazel-bootstrap-closure'
TRUST = 'authenticated-lab-yoga-host-OS:/bin/sh+/usr/bin/python3:-I:-S'
STORE_ROOT = re.compile(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}')
SHA = re.compile(r'[a-f0-9]{64}')
REMOTE_FIELDS = frozenset(('schemaVersion', 'hostAlias', 'system', 'bootstrapTrust',
    'machineIdSha256', 'bootIdSha256', 'uid', 'homeManagerGeneration',
    'labSourceRevision', 'labGenerationMarkerSha256', 'labDeploymentIdSha256',
    'remoteNixPath', 'remoteNixSha256', 'remoteNixBytes'))

def require(value, reason):
    if not value:
        raise ValueError(reason)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def budget(deadline_ns):
    require(type(deadline_ns) is int and deadline_ns > time.monotonic_ns(), 'qualification-deadline-exhausted')
    return (deadline_ns - time.monotonic_ns()) / 10**9

def release(descriptors):
    primary = sys.exc_info()[1]
    failed = False
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except BaseException:
            failed = True
    if failed:
        if primary is not None:
            primary.add_note('executable-custody-release-incomplete')
        else:
            failure = ValueError('executable-custody-release-incomplete')
            failure.add_note('executable-custody-release-incomplete')
            raise failure

def executable_hash(path, deadline_ns, expected=None):
    """Hash immutable bytes with stable descriptor and ancestor custody."""
    budget(deadline_ns)
    root, suffix = str(path).rsplit('/bin/', 1)
    require(STORE_ROOT.fullmatch(root) and suffix == 'ssh', 'fixed-ssh-path-required')
    require(path == SSH, 'fixed-controller-ssh-required')
    descriptors = [os.open('/nix/store', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    try:
        initial = os.fstat(descriptors[-1])
        require(initial.st_uid == 0 and stat.S_IMODE(initial.st_mode) in (0o755, 0o1775), 'ssh-store-custody')
        for component in (Path(root).name, 'bin'):
            budget(deadline_ns)
            descriptors.append(os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                       dir_fd=descriptors[-1]))
            info = os.fstat(descriptors[-1])
            require(info.st_uid == 0 and not info.st_mode & 0o222, 'ssh-ancestor-custody')
        directory = descriptors[-1]
        descriptor = os.open('ssh', os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        try:
            witness = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size,
                                   info.st_mtime_ns, info.st_ctime_ns)
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o222
                    and before.st_mode & 0o111 and 0 < before.st_size <= 64 * 1024**2, 'ssh-executable-custody')
            count, digest = 0, hashlib.sha256()
            while True:
                budget(deadline_ns)
                data = os.read(descriptor, 65536)
                if not data:
                    break
                count += len(data)
                require(count <= before.st_size, 'ssh-size-changed')
                digest.update(data)
            require(count == before.st_size and witness(before) == witness(os.fstat(descriptor))
                    == witness(os.stat('ssh', dir_fd=directory, follow_symlinks=False)), 'ssh-executable-changed')
            require(expected is None or digest.hexdigest() == expected, 'ssh-executable-digest')
            return digest.hexdigest()
        finally:
            release([descriptor])
    finally:
        release(reversed(descriptors))

def local_authority(bootstrap_data, rows, deadline_ns):
    require(hashlib.sha256(bootstrap_data).hexdigest() == BOOTSTRAP_SHA, 'fixed-bootstrap-manifest-required')
    manifest = json.loads(bootstrap_data)
    require(manifest['system'] == 'x86_64-linux'
            and manifest['packages']['openssh']['out'] + '/bin/ssh' == SSH,
            'fixed-bootstrap-ssh-mapping-required')
    roots = {row['path'] for row in rows}
    require(BOOTSTRAP_ROOT in roots and SSH.rsplit('/bin/', 1)[0] in roots,
            'ssh-outside-fixed-controller-inventory')
    return {'sshPath': SSH, 'sshSha256': executable_hash(SSH, deadline_ns)}

def remote_schema(value):
    require(type(value) is dict and set(value) == REMOTE_FIELDS and type(value['schemaVersion']) is int
            and value['schemaVersion'] == 1 and value['hostAlias'] == 'yoga'
            and value['system'] == 'x86_64-linux' and value['bootstrapTrust'] == TRUST,
            'remote-qualification-schema')
    require(type(value['uid']) is int and value['uid'] > 0
            and type(value['remoteNixBytes']) is int and 0 < value['remoteNixBytes'] <= 64 * 1024**2
            and type(value['homeManagerGeneration']) is str and STORE_ROOT.fullmatch(value['homeManagerGeneration'])
            and value['homeManagerGeneration'].endswith('-home-manager-generation')
            and type(value['remoteNixPath']) is str and value['remoteNixPath'].endswith('/bin/nix')
            and STORE_ROOT.fullmatch(value['remoteNixPath'][:-8])
            and all(type(value[key]) is str and SHA.fullmatch(value[key])
                    for key in ('machineIdSha256', 'bootIdSha256', 'remoteNixSha256',
                                'labGenerationMarkerSha256', 'labDeploymentIdSha256'))
            and type(value['labSourceRevision']) is str and re.fullmatch('[a-f0-9]{40}', value['labSourceRevision'])
            and value['labSourceRevision'] != '0' * 40,
            'remote-qualification-bindings')
    return value

# No Nix, shell hashing utility, profile activation, or write occurs in capture.
# The caller trusts the SSH-authenticated lab host OS to execute this exact code.
REMOTE_FAILURE_PREFIX = 'omux-yoga-bootstrap-failure-v1:'
REMOTE_FAILURE_STEPS = frozenset((
    'os-platform-uid', 'home-selection', 'hm-profile-link', 'hm-gcroot-link',
    'hm-profile-resolution', 'hm-gcroot-resolution', 'hm-generation-custody',
    'hm-marker-resolution', 'hm-marker-custody', 'hm-marker-readback', 'hm-marker-schema',
    'nix-resolution', 'nix-custody', 'nix-readback', 'hm-final-recheck',
    'machine-id-read', 'boot-id-read', 'expected-tuple', 'nix-isolated-exec'))
REMOTE_FAILURE_CATEGORIES = frozenset((
    'missing-input', 'access-refused', 'predicate-refused', 'custody-release-incomplete',
    'os-operation-refused', 'input-refused', 'unclassified'))

def remote_failure(stderr):
    """Decode one complete fixed marker; arbitrary stderr never supplies values."""
    prefix = REMOTE_FAILURE_PREFIX.encode()
    markers = [line for line in stderr.splitlines() if line.startswith(prefix)]
    if len(markers) != 1:
        return None
    fields = markers[0][len(prefix):].split(b':')
    if len(fields) != 2:
        return None
    allowed = {(step.encode(), category.encode()): {'step': step, 'category': category}
               for step in REMOTE_FAILURE_STEPS for category in REMOTE_FAILURE_CATEGORIES}
    return allowed.get(tuple(fields))

REMOTE_CODE = r'''
import hashlib,json,os,platform,pwd,re,signal,stat,sys
from pathlib import Path
step = 'os-platform-uid'
class PredicateRefused(ValueError): pass
class CustodyReleaseRefused(ValueError): pass
def failure_hook(kind,error,traceback):
    category = ('missing-input' if isinstance(error,FileNotFoundError) else
        'access-refused' if isinstance(error,PermissionError) else
        'predicate-refused' if isinstance(error,PredicateRefused) else
        'custody-release-incomplete' if isinstance(error,CustodyReleaseRefused) else
        'os-operation-refused' if isinstance(error,OSError) else
        'input-refused' if isinstance(error,(ValueError,TypeError,KeyError)) else 'unclassified')
    # All values are source-fixed categories. Suppress default traceback/text.
    sys.stderr.write('omux-yoga-bootstrap-failure-v1:'+step+':'+category+'\n')
    if isinstance(error,PredicateRefused):
        sys.stderr.write('remote-bootstrap-qualification-refused\n')
    if isinstance(error,CustodyReleaseRefused) or 'remote-custody-release-incomplete' in getattr(error,'__notes__',()):
        sys.stderr.write('remote-custody-release-incomplete\n')
sys.excepthook = failure_hook
def check(value):
    if not value: raise PredicateRefused('remote-bootstrap-qualification-refused')
def release(descriptors):
    primary = sys.exc_info()[1]
    failed = False
    for descriptor in descriptors:
        try: os.close(descriptor)
        except BaseException: failed = True
    if failed:
        if primary is not None: primary.add_note('remote-custody-release-incomplete')
        else: raise CustodyReleaseRefused('remote-custody-release-incomplete')
signal.alarm(int(sys.argv[1]))
check(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.getuid() > 0)
account = pwd.getpwuid(os.getuid())
check(account.pw_name == 'jsullivan2')
step = 'home-selection'
check(str(Path.home()) == account.pw_dir)
state = Path.home() / '.local/state'
profile = state / 'nix/profiles/home-manager'
current = state / 'home-manager/gcroots/current-home'
for link in (profile,current):
    step = 'hm-profile-link' if link == profile else 'hm-gcroot-link'
    info = link.lstat()
    check(stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid())
step = 'hm-profile-resolution'
generation = str(profile.resolve(strict=True))
step = 'hm-gcroot-resolution'
check(generation == str(current.resolve(strict=True)))
step = 'hm-generation-custody'
check(generation.startswith('/nix/store/') and len(Path(generation).parts) == 4
      and generation.endswith('-home-manager-generation'))
info = os.lstat(generation)
check(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o222)
step = 'hm-marker-resolution'
marker_path = str((Path(generation) / 'home-files/.config/tinyland/home-manager-control-revision').resolve(strict=True))
check(marker_path.startswith('/nix/store/'))
step = 'hm-marker-custody'
marker_fd = os.open(marker_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    marker_info = os.fstat(marker_fd)
    check(stat.S_ISREG(marker_info.st_mode) and marker_info.st_uid == 0 and not marker_info.st_mode & 0o222
          and 0 < marker_info.st_size <= 4096)
    step = 'hm-marker-readback'
    marker = os.read(marker_fd,4097)
    check(len(marker) == marker_info.st_size)
    identity = lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    check(identity(marker_info) == identity(os.fstat(marker_fd)) == identity(os.lstat(marker_path)))
finally: release([marker_fd])
step = 'hm-marker-schema'
parsed = re.fullmatch(rb'schema=2\nsource_rev=([0-9a-f]{40})\ndeployment_id=([A-Za-z0-9._+-]+@[A-Za-z0-9._-]+)\n',marker)
check(parsed is not None and parsed.group(1) != b'0'*40
      and parsed.group(2) == (account.pw_name+'@yoga').encode('ascii'))
# Fixed Lab installer selector, independently owned by root. This is not a
# fallback from Home Manager or PATH. OS byte custody is not Nix registration.
def system_nix_selector():
    selector = '/nix/var/nix/profiles/default/bin/nix'
    retained,pins = [],[]
    def identity(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
                info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    try:
        retained.append(os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW))
        root = retained[-1]
        info = os.fstat(root)
        check(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
        pins.append((root,None,'/',identity(info),None))
        pending = list(Path(selector).parts[1:])
        directory,current_path,links = root,'/',0
        while pending:
            check(len(retained) < 127 and len(pending) <= 32)
            component = pending.pop(0)
            check(component not in ('','.','..') and len(component) <= 255)
            named = os.path.join(current_path,component)
            retained.append(os.open(component,os.O_PATH|os.O_NOFOLLOW,dir_fd=directory))
            descriptor = retained[-1]
            info = os.fstat(descriptor)
            check(info.st_uid == 0)
            target = None
            if stat.S_ISLNK(info.st_mode):
                links += 1
                check(links <= 16 and 0 < info.st_size <= 4096)
                target = os.readlink(component,dir_fd=directory)
                check(isinstance(target,str) and 0 < len(target) <= 4096
                      and '..' not in Path(target).parts)
            elif stat.S_ISDIR(info.st_mode):
                check(not info.st_mode & 0o022 or named == '/nix/store'
                      and stat.S_IMODE(info.st_mode) == 0o1775)
            else:
                check(not pending and stat.S_ISREG(info.st_mode) and not info.st_mode & 0o222
                      and info.st_mode & 0o111 and 0 < info.st_size <= 64*1024**2)
            pins.append((descriptor,directory,component,identity(info),target))
            if target is not None:
                rewritten = os.path.normpath(os.path.join(
                    target if os.path.isabs(target) else os.path.join(current_path,target),*pending))
                check(rewritten.startswith('/nix/') and len(rewritten) <= 4096)
                pending = list(Path(rewritten).parts[1:])
                directory,current_path = root,'/'
            elif pending:
                check(stat.S_ISDIR(info.st_mode))
                directory,current_path = descriptor,named
            else:
                check(re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}/bin/nix',named))
                return named,directory,retained,pins
        check(False)
    except BaseException:
        release(reversed(retained))
        raise
def recheck_system_nix(pins):
    for descriptor,parent,name,before,target in pins:
        info = os.fstat(descriptor)
        identity = lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
            value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        named = os.lstat('/') if parent is None else os.stat(name,dir_fd=parent,follow_symlinks=False)
        check(before == identity(info) == identity(named))
        if target is not None:
            check(os.readlink(name,dir_fd=parent) == target)
    selected = os.stat('/nix/var/nix/profiles/default/bin/nix',follow_symlinks=True)
    check(identity(selected) == pins[-1][3])
step = 'nix-resolution'
nix,directory,selector_descriptors,selector_pins = system_nix_selector()
try:
    step = 'nix-custody'
    descriptor = os.open('nix',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    selector_descriptors.append(descriptor)
    witness = lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,
                       x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    before = os.fstat(descriptor)
    check(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o222
          and before.st_mode & 0o111 and 0 < before.st_size <= 64*1024**2)
    check(witness(before) == selector_pins[-1][3])
    recheck_system_nix(selector_pins)
    step = 'nix-readback'
    digest,count = hashlib.sha256(),0
    while True:
        data = os.read(descriptor,65536)
        if not data: break
        count += len(data); check(count <= before.st_size); digest.update(data)
    check(count == before.st_size and witness(before) == witness(os.fstat(descriptor))
          == witness(os.stat('nix',dir_fd=directory,follow_symlinks=False)))
    recheck_system_nix(selector_pins)

    step = 'hm-final-recheck'
    check(generation == str(profile.resolve(strict=True)) == str(current.resolve(strict=True)))
    def public_digest(path):
        global step
        step = 'machine-id-read' if path == '/etc/machine-id' else 'boot-id-read'
        with open(path,'rb') as source: data = source.read(4097)
        check(0 < len(data) <= 4096)
        return hashlib.sha256(data).hexdigest()
    result = dict(schemaVersion=1,hostAlias='yoga',system='x86_64-linux',
        bootstrapTrust='authenticated-lab-yoga-host-OS:/bin/sh+/usr/bin/python3:-I:-S',
        machineIdSha256=public_digest('/etc/machine-id'),bootIdSha256=public_digest('/proc/sys/kernel/random/boot_id'),
        uid=os.getuid(),homeManagerGeneration=generation,remoteNixPath=nix,
        labSourceRevision=parsed.group(1).decode('ascii'),labGenerationMarkerSha256=hashlib.sha256(marker).hexdigest(),
        labDeploymentIdSha256=hashlib.sha256(parsed.group(2)).hexdigest(),
        remoteNixSha256=digest.hexdigest(),remoteNixBytes=count)
    step = 'expected-tuple'
    expected = json.loads(sys.argv[2])
    check(expected is None or result == expected)
    arguments = json.loads(sys.argv[3])

    step = 'nix-custody'
    check(witness(before) == witness(os.fstat(descriptor)))
    recheck_system_nix(selector_pins)
finally: release(reversed(selector_descriptors))
if arguments is None:
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
else:
    check(expected is not None and isinstance(arguments,list) and all(isinstance(x,str) for x in arguments))
    # Nix runs only after independent OS custody/hash/generation/host comparison.
    step = 'nix-isolated-exec'
    absent = '/.omux-yoga-qualification-unavailable'
    check(not os.path.lexists(absent))
    # Nix configuration and plugin loading are executable input, independently
    # scoped from OS-bootstrap trust and the remote Nix byte witness.
    environment = {'HOME':absent,'NIX_CONF_DIR':absent,'NIX_USER_CONF_FILES':'',
                   'NIX_CONFIG':'','NIX_PATH':'','PATH':'','LANG':'C','LC_ALL':'C',
                   'XDG_CONFIG_HOME':absent,'XDG_DATA_HOME':absent,'XDG_STATE_HOME':absent,
                   'XDG_CACHE_HOME':absent,'XDG_RUNTIME_DIR':absent}
    os.execve(nix,[nix,'--option','plugin-files','']+arguments,environment)
'''

def remote_command(deadline_ns, expected=None, arguments=None):
    remaining = int(budget(deadline_ns) - 30)
    require(remaining > 5, 'remote-qualification-cleanup-reserve')
    require(arguments is None or expected is not None, 'remote-nix-requires-prior-qualification')
    if expected is not None:
        remote_schema(expected)
    return 'exec /usr/bin/python3 -I -S -c ' + shlex.quote(REMOTE_CODE) + ' ' + str(min(75, remaining)) + ' ' \
        + shlex.quote(canonical(expected).decode()) + ' ' + shlex.quote(canonical(arguments).decode())
