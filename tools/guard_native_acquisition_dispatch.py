"""Two exact acquisition actions; no resident effects or native proof admission."""
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time
# Only the declared logical delivery sibling; never resolve an ambient alias.
sys.path.insert(0,str(Path(__file__).parent.parent/'delivery'))
import guard_codex_live_profile as inputs
import guard_owner_runtime_input as retained

PROFILES = ('native-login-ui', 'codex-login')
FIELDS = ('codex_login_manifest', 'codex_login_manifest_sha256', 'native_login_directory',
    'native_login_sha256', 'native_login_source_receipt_sha256',
    'native_login_ui_qualification_sha256', 'ui_prepare_manifest', 'ui_prepare_output',
    'ui_prepare_manifest_sha256', 'ui_prepare_os_qualification_sha256', 'ui_prepare_control_sha256')
LOGIN_FIELDS, UI_FIELDS = FIELDS[:6], FIELDS[6:]
REPOSITORY_CACHE = Path('/srv/fast-local/jess/state/codex/omux-bazel9-owner-coordinator-20261004/cache/repos/v1')
NIXPKGS = Path('/nix/store/75bkaivfbwq3x8cs7155hag7hs1chjcx-source')
RESERVE_NS = 30 * 10**9
PROOF_MEMORY, PROOF_TASKS, PROOF_CPU_PERCENT = 4294967296, 512, 200

def require(value):
    if not value:
        raise ValueError('native-acquisition-refused')

def module(profile):
    require(profile in PROFILES)
    if profile == 'codex-login':
        import guard_codex_login_profile as selected
    else:
        import guard_native_login_ui_profile as selected
    return selected

def repositories(cache, nixpkgs):
    require((cache is None and nixpkgs is None) or (cache == REPOSITORY_CACHE and nixpkgs == NIXPKGS))

class Settings:
    acquisition_profile = True
    PROOF_MEMORY, PROOF_TASKS, PROOF_CPU_PERCENT = PROOF_MEMORY, PROOF_TASKS, PROOF_CPU_PERCENT
    def __init__(self, profile, selected, manifest):
        self.PROFILE, self.selected, self.manifest = profile, selected, manifest
    def finite(self, arguments, manager, manifest, reuse, unrelated=()):
        require(arguments == ['run', self.selected.LABEL] and manager == 'system'
            and manifest == self.manifest and not reuse and not any(unrelated))
        return {'PrivateNetwork': 'no'}
    def projection(self, actual, verified=False):
        # Always copy/redact both bind values before any failing verification.
        result = dict(actual)
        result['BindReadOnlyPaths'] = 'verified-acquisition-inputs' if verified else 'private-bind-redacted'
        result['BindPaths'] = 'verified-owned-acquisition-output' if verified else 'private-bind-redacted'
        return result
    def rejection(self, error):
        return 'native-acquisition-refused'

def select(args, arguments):
    values = tuple(getattr(args, field, None) for field in FIELDS)
    if args.profile not in PROFILES:
        require(all(value is None for value in values))
        return None
    selected = module(args.profile)
    wanted = LOGIN_FIELDS if args.profile == 'codex-login' else UI_FIELDS
    require(all(getattr(args, field, None) is not None for field in wanted)
        and all(getattr(args, field, None) is None for field in FIELDS if field not in wanted))
    allowed = set(FIELDS) | {'profile','manager','arguments','python','systemd_run','systemctl',
        'bazel','closure','bootstrap_closure','zig_sdk','java_home','source_commit','source_dirty',
        'state_dir','initialize_state_dir','coordination_dir','become_file','reuse_owned_cache',
        'repository_cache','nixpkgs_source'}
    manifest = args.codex_login_manifest if args.profile == 'codex-login' else args.ui_prepare_manifest
    settings = Settings(args.profile, selected, manifest)
    settings.finite(arguments, args.manager, manifest, args.reuse_owned_cache,
        tuple(value for key,value in vars(args).items() if key not in allowed))
    require(type(args.source_commit) is str and re.fullmatch(r'[0-9a-f]{40}', args.source_commit)
        and args.source_dirty == 'false')
    repositories(args.repository_cache, args.nixpkgs_source)
    for name in wanted:
        value = getattr(args,name)
        if name.endswith('sha256'):
            require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}',value))
        else:
            require(isinstance(value,Path) and value.is_absolute() and str(value) == os.path.normpath(value)
                and '..' not in value.parts)
            inputs.binding_selector(str(value))
    return settings

class Admission:
    acquisition_profile = True
    def __init__(self, settings, args, source, deadline):
        self.inner, self.run = None, None
        self.settings, self.original_deadline = settings, deadline
        require(type(deadline) is int and deadline > 0)
        self.work_deadline = deadline - RESERVE_NS
        self.collecting = False
        self.home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        self.repository_cache, self.nixpkgs_source = args.repository_cache, args.nixpkgs_source
        self.manifest = settings.manifest
        self.manifest_sha256 = (args.codex_login_manifest_sha256 if settings.PROFILE == 'codex-login'
            else args.ui_prepare_manifest_sha256)
        try:
            self.tick()
            if settings.PROFILE == 'codex-login':
                self.inner = settings.selected.Admission(args.codex_login_manifest,args.native_login_directory,
                    source,args.state_dir,self.work_deadline,(args.native_login_sha256,
                        args.native_login_source_receipt_sha256,args.native_login_ui_qualification_sha256))
                require(self.inner.value['schema_version'] == 2)
                # An exact fresh parent avoids enumerating other login sessions.
                with os.scandir(self.inner.parent_fd) as entries:
                    require(next(entries,None) is None)
                self.output_parent = self.inner.parent
                self.output_id = self.inner.parent_identity
            else:
                self.inner = settings.selected.Admission(args.ui_prepare_manifest,args.ui_prepare_output,
                    source,args.state_dir,self.work_deadline,(args.ui_prepare_manifest_sha256,
                        args.ui_prepare_os_qualification_sha256,args.ui_prepare_control_sha256))
                self.output_parent = self.inner.output
                self.output_id = self.inner.output_identity
            self.verify_manifest_pin()
            self.facts = {'scope':'native-account-acquisition-v2' if settings.PROFILE == 'codex-login'
                else 'provider-free-native-login-ui-readiness-v1','manifest_sha256':self.manifest_sha256,
                'credential_contents_read_by_guard':False,'resident_effects_authorized':False,
                'fresh_native_qualification':False,'continuity_qualified':False}
            self.recheck()
        except BaseException:
            self.close()
            raise

    def tick(self):
        require(time.monotonic_ns() < (self.original_deadline if self.collecting else self.work_deadline))

    def verify_manifest_pin(self):
        self.tick()
        raw = os.pread(self.inner.manifest_fd,65537,0)
        require(len(raw) == self.inner.manifest_identity[5]
            and hashlib.sha256(raw).hexdigest() == self.manifest_sha256)

    def bind_run(self, run):
        require(self.run is None and isinstance(run,Path))
        info = run.stat(follow_symlinks=False)
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid())
        self.run = run
        self.run_identity = (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))

    def recheck(self):
        self.tick()
        self.inner.recheck()
        if self.run is not None:
            info = self.run.stat(follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino,info.st_uid,
                info.st_gid,stat.S_IMODE(info.st_mode)) == self.run_identity)
        self.verify_manifest_pin()
        self.tick()
        return self.facts

    def environment(self):
        self.tick()
        selected = self.settings.selected
        identity = os.fstat(self.inner.namespace_fd)
        prefix = 'OMUX_NATIVE_LOGIN' if self.settings.PROFILE == 'codex-login' else 'OMUX_NATIVE_LOGIN_UI'
        result = {selected.VARIABLE:selected.DESTINATION,
            prefix+'_NAMESPACE_ID':str(identity.st_dev)+':'+str(identity.st_ino),
            prefix+'_ORIGINAL_DEADLINE_NS':str(self.original_deadline)}
        if self.settings.PROFILE == 'native-login-ui':
            identity = os.fstat(self.inner.output_fd)
            result[prefix+'_OUTPUT_ID'] = str(identity.st_dev)+':'+str(identity.st_ino)
        return result

    def bindings(self):
        return self.inner.bindings()

    def writable_bindings(self, run):
        require(run == self.run)
        output = (str(self.inner.parent)+':'+str(self.inner.parent) if self.settings.PROFILE == 'codex-login'
            else self.inner.writable_binding())
        return [output,str(run)+':'+str(run)]

    def verify_bindings(self, actual, run, repository_cache):
        require(run == self.run and repository_cache == self.repository_cache)
        selected = self.settings.selected
        wanted = self.writable_bindings(run)
        require(selected.normalized_bindings(actual.get('BindPaths',''),readback=True)
            == selected.normalized_bindings(' '.join(wanted)))
        projected = dict(actual)
        projected['BindPaths'] = (self.inner.writable_binding()+':rbind'
            if self.settings.PROFILE == 'native-login-ui' else '')
        if repository_cache is not None:
            token = str(repository_cache)+':'+str(repository_cache)+':rbind'
            rows = actual.get('BindReadOnlyPaths','').split()
            require(rows.count(token) == 1)
            rows.remove(token)
            projected['BindReadOnlyPaths'] = ' '.join(rows)
        self.inner.verify_bindings(projected)

    def runtime_seconds(self):
        self.tick()
        seconds = (self.work_deadline-time.monotonic_ns())//10**9
        require(1 <= seconds <= 1200)
        return seconds

    def completed(self,status,cleaned,epoch,producer_sha256,graph_sha256):
        require(type(status) is int and status == 0 and cleaned is True and self.run is not None and self.run.name == epoch
            and type(graph_sha256) is str and re.fullmatch(r'[0-9a-f]{64}',graph_sha256))
        # Only independently verified own cleanup permits spending the reserved
        # remainder on metadata collection. The original clock never renews.
        self.collecting = True
        self.inner.deadline = self.original_deadline
        self.recheck()
        if self.settings.PROFILE == 'native-login-ui':
            output = {'output_receipt_sha256':self.inner.completed(),'provider_request_performed':False,
                'selector_ready':False,'resident_enrollment_completed':False}
        else:
            from native_login_enrollment_selector import verify_generated
            output = verify_generated(self.inner.parent,self.inner.value['enrollment'],self.home,self.original_deadline)
            require(type(output) is dict and set(output) == {'selector_ready','identity_verified',
                'resident_enrollment_completed','renewal_owner','native_support'}
                and output == {'selector_ready':True,'identity_verified':False,
                    'resident_enrollment_completed':False,'renewal_owner':'native','native_support':False})
        self.recheck()
        return {'action_epoch':epoch,'controller_graph_sha256':graph_sha256,
            'manifest_sha256':self.manifest_sha256,'result':output}

    def close(self):
        if self.inner is not None:
            self.inner.close()
            self.inner = None

def admit(settings,args,source,deadline):
    require(type(settings) is Settings)
    return Admission(settings,args,source,deadline)

def command(builder,bazel,run,arguments,admission,*,source_commit,source_dirty,repository_cache=None,nixpkgs_source=None):
    require(type(admission) is Admission)
    admission.settings.finite(arguments,'system',admission.manifest,False)
    repositories(repository_cache,nixpkgs_source)
    require((repository_cache,nixpkgs_source) == (admission.repository_cache,admission.nixpkgs_source))
    result = builder(bazel,run,['build',arguments[1]],source_commit=source_commit,source_dirty=source_dirty,
        repository_cache=repository_cache,nixpkgs_source=nixpkgs_source)
    result[result.index('build')] = 'run'
    result[result.index('--spawn_strategy=sandboxed')] = '--spawn_strategy=linux-sandbox'
    position = result.index(arguments[1])
    additions = ['--disable_download','--repository_disable_download','--repo_env=OMUX_YOGA_DELIVERY_QUALIFICATION=']
    if repository_cache is not None:
        additions.append('--repo_contents_cache=')
    import guard_codex_login_profile as login
    additions.append('--repo_env='+login.DIRECTORY_VARIABLE+'='+
        (str(admission.inner.directory) if admission.settings.PROFILE == 'codex-login' else ''))
    additions += ['--run_env='+key+'='+value for key,value in admission.environment().items()]
    result[position:position] = additions
    return result

def unset_environment(values):
    return tuple(dict.fromkeys((*values,'SYSTEMD_HOST','SYSTEMD_MACHINE','SSH_AUTH_SOCK',
        'SSH_CONNECTION','SSH_CLIENT','SSH_TTY','LD_PRELOAD','LD_AUDIT','LD_LIBRARY_PATH',
        'PYTHONPATH','PYTHONHOME','GNOME_KEYRING_CONTROL','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY',
        'NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy','CODEX_HOME')))
