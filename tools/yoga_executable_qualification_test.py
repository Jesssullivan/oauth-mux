import copy
import hashlib
import json
import shlex
import unittest
from unittest.mock import patch
import yoga_executable_qualification as qualification

class QualificationTests(unittest.TestCase):
    def remote(self):
        return dict(schemaVersion=1,hostAlias='yoga',system='x86_64-linux',bootstrapTrust=qualification.TRUST,
            machineIdSha256='a'*64,bootIdSha256='b'*64,uid=1000,
            labSourceRevision='f'*40,labGenerationMarkerSha256='a'*64,labDeploymentIdSha256='b'*64,
            homeManagerGeneration='/nix/store/'+'c'*32+'-home-manager-generation',
            remoteNixPath='/nix/store/'+'d'*32+'-nix/bin/nix',remoteNixSha256='e'*64,remoteNixBytes=42)

    def test_qualify_contains_no_nix_invocation(self):
        with patch.object(qualification.time,'monotonic_ns',return_value=0):
            command = shlex.split(qualification.remote_command(1200*10**9))
        self.assertEqual(command[:5],['exec','/usr/bin/python3','-I','-S','-c'])
        self.assertEqual(command[6:],['75','null','null'])

    def test_prior_remote_qualification_required_before_nix(self):
        with patch.object(qualification.time,'monotonic_ns',return_value=0):
            with self.assertRaisesRegex(ValueError,'prior-qualification'):
                qualification.remote_command(1200*10**9,arguments=['store','info'])

    def test_host_generation_and_executable_tuple_travels_before_exec(self):
        remote = self.remote()
        with patch.object(qualification.time,'monotonic_ns',return_value=0):
            command = shlex.split(qualification.remote_command(1200*10**9,remote,['path-info','--offline']))
        self.assertEqual(json.loads(command[7]),remote)
        self.assertEqual(json.loads(command[8]),['path-info','--offline'])
        self.assertLess(command[5].index('check(expected is None or result == expected)'),command[5].index('os.execve'))
        self.assertIn("'NIX_USER_CONF_FILES':''",command[5])
        self.assertIn("'NIX_CONFIG':''",command[5])
        self.assertIn("'NIX_CONF_DIR':absent",command[5])
        self.assertIn("[nix,'--option','plugin-files','']",command[5])
        self.assertIn("check(not os.path.lexists(absent))",command[5])
        self.assertIn("home-files/.config/tinyland/home-manager-control-revision",command[5])
        self.assertIn("parsed.group(1) != b'0'*40",command[5])

    def test_trust_base_and_generation_are_exact(self):
        for key,value in (('bootstrapTrust','Nix-reported-self-hash'),('homeManagerGeneration','/tmp/generation'),
                          ('remoteNixPath','/nix/store/'+'d'*32+'-nix/bin/nix; touch /tmp/x'),
                          ('remoteNixBytes',True),('schemaVersion',True),('uid',0),
                          ('remoteNixPath',7),('homeManagerGeneration',False),('labSourceRevision','0'*40)):
            remote = self.remote(); remote[key] = value
            with self.assertRaises(ValueError): qualification.remote_schema(remote)

    def test_missing_or_extra_remote_field_refused(self):
        remote = self.remote(); remote['email'] = 'prohibited'
        with self.assertRaises(ValueError): qualification.remote_schema(remote)
        remote = self.remote(); del remote['bootIdSha256']
        with self.assertRaises(ValueError): qualification.remote_schema(remote)

    def test_remote_alarm_and_original_deadline_reserve(self):
        with patch.object(qualification.time,'monotonic_ns',return_value=0):
            command = shlex.split(qualification.remote_command(42*10**9))
            self.assertEqual(command[6],'12')
            with self.assertRaisesRegex(ValueError,'reserve'): qualification.remote_command(35*10**9)

    def test_elapsed_deadline_precedes_local_open(self):
        with patch.object(qualification.time,'monotonic_ns',return_value=10),patch.object(qualification.os,'open') as opened:
            with self.assertRaisesRegex(ValueError,'deadline'): qualification.executable_hash(qualification.SSH,10)
            opened.assert_not_called()

    def test_local_mapping_not_selected_by_caller(self):
        with self.assertRaisesRegex(ValueError,'bootstrap-manifest'):
            qualification.local_authority(b'{}',[],1200*10**9)

    def test_local_manifest_pin_and_inventory_both_required(self):
        manifest = {'system':'x86_64-linux','packages':{'openssh':{'out':qualification.SSH.rsplit('/bin/',1)[0]}}}
        data = qualification.canonical(manifest)
        with patch.object(qualification,'BOOTSTRAP_SHA',hashlib.sha256(data).hexdigest()), \
                patch.object(qualification,'executable_hash',return_value='a'*64) as hashed:
            with self.assertRaisesRegex(ValueError,'inventory'): qualification.local_authority(data,[],1200*10**9)
            hashed.assert_not_called()
            rows = [{'path':qualification.BOOTSTRAP_ROOT},{'path':manifest['packages']['openssh']['out']}]
            self.assertEqual(qualification.local_authority(data,rows,1200*10**9),
                             {'sshPath':qualification.SSH,'sshSha256':'a'*64})
            hashed.assert_called_once_with(qualification.SSH,1200*10**9)

    def remote_fixture(self,expected,arguments,fail_step=None,selector_case=None):
        import builtins
        import io
        import pathlib
        import platform
        import pwd
        import signal
        import sys
        from contextlib import ExitStack
        from types import SimpleNamespace
        generation = '/nix/store/'+'c'*32+'-home-manager-generation'
        nix = '/nix/store/'+'d'*32+'-nix/bin/nix'
        marker_path = '/nix/store/'+'f'*32+'-source-marker'
        system_profile = '/nix/store/'+'g'*32+'-profile'
        marker = b'schema=2\nsource_rev='+b'f'*40+b'\ndeployment_id=jsullivan2'+b'@'+b'yoga\n'
        if selector_case == 'wrong-marker-user':
            marker = marker.replace(b'jsullivan2',b'other-user')
        if selector_case == 'zero-marker-revision':
            marker = marker.replace(b'f'*40,b'0'*40)
        resolved = {'/fixture/.local/state/nix/profiles/home-manager':generation,
                    '/fixture/.local/state/home-manager/gcroots/current-home':generation,
                    generation+'/home-files/.config/tinyland/home-manager-control-revision':marker_path}
        class FakePath:
            def __init__(self,value): self.value = str(value)
            def __str__(self): return self.value
            def __truediv__(self,name): return FakePath(self.value+'/'+name)
            @classmethod
            def home(cls): return cls('/fixture')
            @property
            def parts(self): return pathlib.PurePosixPath(self.value).parts
            def resolve(self,**kwargs):
                if fail_step == 'hm-marker-resolution' and self.value.endswith('home-manager-control-revision'):
                    raise FileNotFoundError('private-fixture-path-must-not-escape')
                return FakePath(resolved.get(self.value,self.value))
            def lstat(self):
                if (fail_step == 'hm-profile-link' and self.value.endswith('nix/profiles/home-manager')
                        or fail_step == 'hm-gcroot-link' and self.value.endswith('gcroots/current-home')):
                    raise FileNotFoundError('private-fixture-path-must-not-escape')
                return SimpleNamespace(st_mode=qualification.stat.S_IFLNK|0o777,st_uid=1000)
        files = {marker_path:marker,nix:b'NIX'}
        symlinks = {'/nix/var/nix/profiles/default':'per-user/root/profile',
            '/nix/var/nix/profiles/per-user/root/profile':'profile-1-link',
            '/nix/var/nix/profiles/per-user/root/profile-1-link':system_profile,
            system_profile+'/bin':nix.rsplit('/nix',1)[0]}
        if selector_case == 'cycle':
            symlinks['/nix/var/nix/profiles/default'] = 'default'
        if selector_case == 'escape':
            symlinks['/nix/var/nix/profiles/default'] = '/outside-untrusted/profile'
        if selector_case == 'parent-traversal':
            symlinks['/nix/var/nix/profiles/default'] = 'per-user/root/other-link/../profile'
            symlinks['/nix/var/nix/profiles/per-user/root/other-link'] = '/nix/store/other/place'
        opened_descriptors,closed_descriptors = [],[]
        self.remote_opened,self.remote_closed = opened_descriptors,closed_descriptors
        descriptors,positions = {},{}
        nix_reads = [0]
        def information(path):
            regular,link = path in files,path in symlinks
            mode = ((qualification.stat.S_IFREG if regular else
                     qualification.stat.S_IFLNK if link else qualification.stat.S_IFDIR)
                    |(0o777 if link else 0o555))
            uid = 1000 if selector_case == 'nonroot-link' and path == '/nix/var/nix/profiles/default' else 0
            if selector_case == 'writable-parent' and path == '/nix/var/nix/profiles':
                mode = qualification.stat.S_IFDIR|0o777
            return SimpleNamespace(st_dev=1,st_ino=1 if path == nix else 2,
                st_mode=mode,st_uid=uid,st_gid=0,st_nlink=2 if path == nix else 1,
                st_size=len(files[path]) if regular else len(symlinks[path]) if link else 0,
                st_mtime_ns=1,st_ctime_ns=2 if selector_case == 'changed-byte-witness' and path == nix and nix_reads[0] else 1)
        def opened(path,flags,dir_fd=None):
            if dir_fd is not None:
                path = qualification.os.path.join(descriptors[dir_fd],path)
            if fail_step == 'nix-resolution' and path == '/nix/var/nix/profiles/default':
                raise FileNotFoundError('private-fixture-path-must-not-escape')
            descriptor = len(descriptors)+100
            descriptors[descriptor],positions[descriptor] = str(path),0
            opened_descriptors.append(descriptor)
            return descriptor
        def named(path,dir_fd=None,follow_symlinks=True):
            full_selector = path == '/nix/var/nix/profiles/default/bin/nix' and follow_symlinks
            if full_selector:
                path = nix
            if dir_fd is not None:
                path = qualification.os.path.join(descriptors[dir_fd],path)
            info = information(path)
            if (selector_case in ('rebound-link','rebound-link-cleanup') and path == '/nix/var/nix/profiles/default'
                    or selector_case == 'rebound-ancestor' and path == '/nix/var/nix/profiles'
                    or selector_case == 'rebound-leaf' and path == nix
                    or selector_case == 'full-selector-mismatch' and full_selector):
                info.st_ino = 99
            return info
        readlink_calls = {}
        def readlink(path,dir_fd=None):
            if dir_fd is not None:
                path = qualification.os.path.join(descriptors[dir_fd],path)
            readlink_calls[path] = readlink_calls.get(path,0)+1
            if (selector_case == 'changed-target' and path == '/nix/var/nix/profiles/default'
                    and readlink_calls[path] > 1):
                return '/nix/var/nix/profiles/replaced'
            return symlinks[path]
        def closed(descriptor):
            closed_descriptors.append(descriptor)
            if selector_case == 'rebound-link-cleanup' and descriptor == 101:
                raise OSError('private-cleanup-fixture-must-not-escape')
        def read(descriptor,size):
            if descriptors[descriptor] == nix:
                nix_reads[0] += 1
            data = files[descriptors[descriptor]]
            position = positions[descriptor]; positions[descriptor] += size
            return data[position:position+size]
        def public(path,*args,**kwargs):
            if (fail_step == 'machine-id-read' and path == '/etc/machine-id'
                    or fail_step == 'boot-id-read' and path == '/proc/sys/kernel/random/boot_id'):
                raise FileNotFoundError('private-fixture-path-must-not-escape')
            return io.BytesIO(b'MACHINE' if path == '/etc/machine-id' else b'BOOT')
        actual = self.remote()
        actual.update(remoteNixSha256=hashlib.sha256(b'NIX').hexdigest(),remoteNixBytes=3,
                      machineIdSha256=hashlib.sha256(b'MACHINE').hexdigest(),bootIdSha256=hashlib.sha256(b'BOOT').hexdigest(),
                      labGenerationMarkerSha256=hashlib.sha256(marker).hexdigest(),
                      labDeploymentIdSha256=hashlib.sha256(b'jsullivan2'+b'@'+b'yoga').hexdigest())
        selected = actual if expected is True else expected
        with ExitStack() as stack:
            stack.enter_context(patch.object(pathlib,'Path',FakePath))
            stack.enter_context(patch.object(platform,'system',return_value='Linux'))
            stack.enter_context(patch.object(platform,'machine',return_value='x86_64'))
            stack.enter_context(patch.object(signal,'alarm'))
            stack.enter_context(patch.object(sys,'excepthook'))
            stack.enter_context(patch.object(sys,'argv',['fixture','75',json.dumps(selected),json.dumps(arguments)]))
            stack.enter_context(patch.object(qualification.os,'getuid',return_value=1000))
            stack.enter_context(patch.object(pwd,'getpwuid',return_value=SimpleNamespace(
                pw_name='other-user' if selector_case == 'wrong-user' else 'jsullivan2',
                pw_dir='/other-home' if selector_case == 'wrong-home' else '/fixture')))
            stack.enter_context(patch.object(qualification.os,'open',side_effect=opened))
            stack.enter_context(patch.object(qualification.os,'read',side_effect=read))
            stack.enter_context(patch.object(qualification.os,'fstat',side_effect=lambda fd:information(descriptors[fd])))
            stack.enter_context(patch.object(qualification.os,'lstat',side_effect=information))
            stack.enter_context(patch.object(qualification.os,'stat',side_effect=named))
            stack.enter_context(patch.object(qualification.os,'readlink',side_effect=readlink))
            stack.enter_context(patch.object(qualification.os,'close',side_effect=closed))
            stack.enter_context(patch.object(qualification.os.path,'lexists',return_value=False))
            stack.enter_context(patch.object(builtins,'open',side_effect=public))
            execute = stack.enter_context(patch.object(qualification.os,'execve',side_effect=RuntimeError('remote-exec-observed')))
            self.remote_namespace = {}
            try:
                exec(qualification.REMOTE_CODE,self.remote_namespace)
            except (ValueError,RuntimeError,OSError) as error:
                return execute,error,actual
            raise AssertionError('fixture must terminate at refusal or mocked exec')

    def test_remote_os_fixture_checks_complete_tuple_before_isolated_nix_exec(self):
        execute,error,actual = self.remote_fixture(True,['store','info','--json','--store','daemon'])
        self.assertEqual(str(error),'remote-exec-observed')
        path,arguments,environment = execute.call_args.args
        self.assertEqual(path,actual['remoteNixPath']); self.assertEqual(arguments[1:4],['--option','plugin-files',''])
        self.assertEqual(environment['NIX_CONFIG'],''); self.assertEqual(environment['NIX_USER_CONF_FILES'],'')
        self.assertEqual(environment['HOME'],environment['NIX_CONF_DIR']); self.assertEqual(environment['PATH'],'')
        self.assertNotIn('LD_PRELOAD',environment); self.assertNotIn('SSH_AUTH_SOCK',environment)

    def test_remote_missing_input_fixtures_report_fixed_exact_step_without_exception_text(self):
        import io
        import sys
        for step in ('hm-profile-link','hm-gcroot-link','hm-marker-resolution',
                     'nix-resolution','machine-id-read','boot-id-read'):
            execute,error,actual = self.remote_fixture(None,None,fail_step=step)
            self.assertIsInstance(error,FileNotFoundError)
            execute.assert_not_called()
            capture = io.StringIO()
            with patch.object(sys,'stderr',capture):
                self.remote_namespace['failure_hook'](type(error),error,None)
            marker = capture.getvalue().encode()
            self.assertEqual(qualification.remote_failure(marker),{'step':step,'category':'missing-input'})
            self.assertEqual(len(marker.splitlines()),1)
            self.assertNotIn('private-fixture',capture.getvalue())
            self.assertNotIn('Traceback',capture.getvalue())

    def test_remote_failure_decoder_refuses_unknown_duplicate_or_noncanonical_markers(self):
        prefix = qualification.REMOTE_FAILURE_PREFIX.encode()
        valid = prefix+b'hm-profile-link:missing-input'
        self.assertEqual(qualification.remote_failure(valid),
                         {'step':'hm-profile-link','category':'missing-input'})
        for value in (b'no such file',prefix+b'private-path:missing-input',
                      prefix+b'hm-profile-link:private-exception',
                      valid+b':private-extra',valid+b' '+b'private-extra',
                      valid+b'\n'+valid,b'leading '+valid):
            self.assertIsNone(qualification.remote_failure(value))

    def test_fixed_system_nix_selector_rejects_changed_or_unowned_chain_before_exec(self):
        for case in ('nonroot-link','writable-parent','rebound-link','rebound-ancestor','rebound-leaf',
                     'changed-target','changed-byte-witness','cycle','escape','parent-traversal','full-selector-mismatch'):
            execute,error,actual = self.remote_fixture(True,['store','info'],selector_case=case)
            self.assertIsInstance(error,ValueError)
            execute.assert_not_called()
            self.assertCountEqual(self.remote_opened,self.remote_closed)

    def test_system_selector_primary_refusal_survives_all_attempted_cleanup_releases(self):
        execute,error,actual = self.remote_fixture(True,['store','info'],selector_case='rebound-link-cleanup')
        self.assertIsInstance(error,ValueError)
        self.assertEqual(str(error),'remote-bootstrap-qualification-refused')
        self.assertIn('remote-custody-release-incomplete',error.__notes__)
        execute.assert_not_called()
        self.assertCountEqual(self.remote_opened,self.remote_closed)

    def test_fixed_system_nix_selector_accepts_store_hardlinks_and_releases_all_custody(self):
        execute,error,actual = self.remote_fixture(True,['store','info'])
        self.assertEqual(str(error),'remote-exec-observed')
        self.assertCountEqual(self.remote_opened,self.remote_closed)
        execute.assert_called_once()
        self.assertIn("selector = '/nix/var/nix/profiles/default/bin/nix'",qualification.REMOTE_CODE)
        self.assertNotIn("generation) / 'home-path/bin/nix'",qualification.REMOTE_CODE)

    def test_authenticated_yoga_os_account_and_home_are_predicates_before_nix(self):
        for case in ('wrong-user','wrong-home','wrong-marker-user','zero-marker-revision'):
            execute,error,actual = self.remote_fixture(True,['store','info'],selector_case=case)
            self.assertIsInstance(error,ValueError)
            execute.assert_not_called()
            self.assertCountEqual(self.remote_opened,self.remote_closed)

    def test_remote_os_fixture_refuses_bad_hash_before_any_nix_exec(self):
        execute,error,actual = self.remote_fixture(self.remote(),['store','info'])
        self.assertIsInstance(error,ValueError); execute.assert_not_called()

if __name__ == '__main__': unittest.main()
