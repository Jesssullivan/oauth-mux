"""Only two explicit resident proof profiles; current guard retains execution."""
from pathlib import Path
import os
import pwd
import re
import uuid
import guard_resident_observation as resident

PROFILES=('resident-continuity','resident-namespace')
SETUP_PROFILE='resident-enrollment'
FIELDS=('resident_manifest','resident_epoch','resident_producer_sha256','resident_observer_sha256',
    'resident_runtime_selection','resident_runtime_sha256','resident_runtime_bytes','resident_native_version')
REPOSITORY_CACHE=Path('/srv/fast-local/jess/state/codex/omux-bazel9-owner-coordinator-20261004/cache/repos/v1')
NIXPKGS=Path('/nix/store/75bkaivfbwq3x8cs7155hag7hs1chjcx-source')

def module(profile):
    resident.require(profile in PROFILES)
    if profile=='resident-continuity':
        import guard_resident_continuity_profile as selected
    else:
        import guard_resident_namespace_profile as selected
    return selected

def select(args,arguments):
    import guard_codex_device_component_profile as component
    packaging=component.select(args,arguments)
    if packaging is not None:return packaging
    import guard_native_acquisition_dispatch as acquisition
    acquiring = acquisition.select(args,arguments)
    if acquiring is not None:
        return acquiring
    import guard_resident_setup_dispatch as setup
    installed = setup.select(args,arguments)
    if installed is not None:
        return installed
    values=tuple(getattr(args,key,None) for key in FIELDS)
    if args.profile not in PROFILES:
        resident.require(not any(value is not None for value in values))
        return None
    required=values if args.profile=='resident-continuity' else values[:4]
    resident.require(all(value is not None for value in required)
        and (args.profile=='resident-continuity' or all(value is None for value in values[4:])))
    allowed=set(FIELDS)|{'profile','manager','arguments','python','systemd_run','systemctl','bazel',
        'closure','bootstrap_closure','zig_sdk','java_home','source_commit','source_dirty','state_dir',
        'initialize_state_dir','coordination_dir','become_file','reuse_owned_cache','repository_cache','nixpkgs_source'}
    selected=module(args.profile)
    selected.finite(arguments,args.manager,args.resident_manifest,args.reuse_owned_cache,
        tuple(value for key,value in vars(args).items() if key not in allowed))
    resident.require(type(args.resident_epoch) is str and str(uuid.UUID(args.resident_epoch))==args.resident_epoch
        and all(type(getattr(args,key)) is str and re.fullmatch(r'[0-9a-f]{64}',getattr(args,key))
            for key in ('resident_producer_sha256','resident_observer_sha256'))
        and type(args.source_commit) is str and re.fullmatch(r'[0-9a-f]{40}',args.source_commit)
        and args.source_dirty=='false')
    resident.canonical(str(args.resident_manifest))
    resident.require(Path(args.resident_manifest).name=='input.json')
    cache,nixpkgs=getattr(args,'repository_cache',None),getattr(args,'nixpkgs_source',None)
    resident.require((cache is None and nixpkgs is None) or (cache==REPOSITORY_CACHE and nixpkgs==NIXPKGS))
    if args.profile=='resident-continuity':
        import guard_codex_fresh_live_profile as fresh
        # Its exact TEST selection validator is reused only for public selector
        # grammar; this fixed RUN is a separate explicitly admitted authority.
        import guard_codex_live_profile as live
        fresh.finite('codex-live',['test',live.LABEL],None,args.resident_runtime_selection,
            args.resident_runtime_sha256,args.resident_runtime_bytes)
        resident.require(type(args.resident_native_version) is str
            and selected.VERSION.fullmatch(args.resident_native_version))
    return selected

def admit(selected,args,source_root,systemctl,deadline):
    # Setup consumes the same original envelope and leaves its cleanup reserve.
    resident.require(type(deadline) is int)
    if getattr(selected,'component_profile',False):
        import guard_codex_device_component_profile as component
        return component.admit(selected,args,source_root,deadline)
    if getattr(selected,'acquisition_profile',False):
        import guard_native_acquisition_dispatch as acquisition
        return acquisition.admit(selected,args,source_root,deadline)
    if args.profile==SETUP_PROFILE:
        import guard_resident_setup_dispatch as setup
        arguments=args.arguments[1:] if args.arguments[:1]==['--'] else args.arguments
        return setup.admit(selected,args,Path(pwd.getpwuid(os.getuid()).pw_dir),systemctl,deadline,arguments)
    if args.profile=='resident-continuity':
        from guard_fresh_native_runtime_input import Admission as FreshAdmission
        fresh=None
        try:
            fresh=FreshAdmission(args.resident_runtime_selection,args.resident_runtime_sha256,args.resident_runtime_bytes,deadline-30*10**9)
            return selected.Admission(args.resident_manifest,Path(pwd.getpwuid(os.getuid()).pw_dir),
                deadline,args.resident_epoch,fresh,systemctl,args.resident_producer_sha256,
                args.resident_observer_sha256,args.resident_native_version,source_root)
        except (OSError,ValueError,KeyError,TypeError,AttributeError,IndexError):
            if fresh is not None: fresh.close()
            raise ValueError('resident-admission-refused') from None
        except BaseException:
            if fresh is not None: fresh.close()
            raise
    try:
        return selected.Admission(args.resident_manifest,Path(pwd.getpwuid(os.getuid()).pw_dir),deadline,
            args.resident_epoch,systemctl,args.resident_producer_sha256,args.resident_observer_sha256,source_root)
    except (OSError,ValueError,KeyError,TypeError,AttributeError,IndexError):
        raise ValueError('resident-admission-refused') from None

def command(builder,bazel,run,arguments,admission,*,source_commit,source_dirty,repository_cache=None,nixpkgs_source=None):
    if getattr(admission,'component_profile',False):
        import guard_codex_device_component_profile as component
        return component.command(builder,bazel,run,arguments,admission,source_commit=source_commit,
            source_dirty=source_dirty,repository_cache=repository_cache,nixpkgs_source=nixpkgs_source)
    if getattr(admission,'acquisition_profile',False):
        import guard_native_acquisition_dispatch as acquisition
        return acquisition.command(builder,bazel,run,arguments,admission,source_commit=source_commit,
            source_dirty=source_dirty,repository_cache=repository_cache,nixpkgs_source=nixpkgs_source)
    resident.require(admission.facts['scope'] in ('resident-continuity','provider_free_resident_namespace_qualification'))
    selected=module(admission.facts['scope'] if admission.facts['scope']=='resident-continuity' else 'resident-namespace')
    selected.finite(arguments,'system',admission.manifest,False)
    resident.require((repository_cache is None and nixpkgs_source is None) or
        (repository_cache==REPOSITORY_CACHE and nixpkgs_source==NIXPKGS))
    result=builder(bazel,run,['build',selected.LABEL],repository_cache=repository_cache,
        source_commit=source_commit,source_dirty=source_dirty,nixpkgs_source=nixpkgs_source)
    result[result.index('build')]='run'
    result[result.index('--spawn_strategy=sandboxed')]='--spawn_strategy=linux-sandbox'
    # Options precede the sole target; never caller-selected arbitrary labels.
    result.insert(result.index(selected.LABEL),'--repository_disable_download')
    if repository_cache is not None: result.insert(result.index(selected.LABEL),'--repo_contents_cache=')
    if selected.PROFILE=='resident-continuity':
        import guard_codex_fresh_live_profile as fresh
        for key in (fresh.VARIABLE,fresh.SHA_VARIABLE,fresh.BYTES_VARIABLE):
            result=[arg for arg in result if not arg.startswith('--repo_env='+key+'=')]
        result[result.index(selected.LABEL):result.index(selected.LABEL)]=[
            '--repo_env='+fresh.VARIABLE+'='+str(admission.fresh.selection_path),
            '--repo_env='+fresh.SHA_VARIABLE+'='+admission.fresh.selection_pin['sha256'],
            '--repo_env='+fresh.BYTES_VARIABLE+'='+str(admission.fresh.selection_pin['bytes'])]
    result[result.index(selected.LABEL):result.index(selected.LABEL)]=[
        '--run_env='+key+'='+value for key,value in admission.environment().items()]
    return result

def proof_properties(properties,settings=None):
    if getattr(settings,'component_profile',False):
        import guard_codex_device_component_profile as component
        return component.proof_properties(properties,settings.PROFILE)
    if getattr(settings,'acquisition_profile',False):
        return dict(properties)
    return {**properties,'MemoryMax':str(resident.PROOF_MEMORY),'TasksMax':str(resident.PROOF_TASKS),
        'CPUQuotaPerSecUSec':'1.9s'}

def writable_bindings(admission,run):
    if getattr(admission,'component_profile',False):return admission.writable_bindings(run)
    if getattr(admission,'acquisition_profile',False):
        return admission.writable_bindings(run)
    if getattr(admission,'setup_profile',False):
        return list(dict.fromkeys((*admission.writable_binding().split(),str(run)+':'+str(run))))
    return list(dict.fromkeys((admission.writable_binding(),str(run)+':'+str(run))))

def verify_bindings(admission,actual,run,repository_cache=None):
    if getattr(admission,'component_profile',False):return admission.verify_bindings(actual,run,repository_cache)
    if getattr(admission,'acquisition_profile',False):
        return admission.verify_bindings(actual,run,repository_cache)
    if getattr(admission,'setup_profile',False):
        return admission.verify_bindings(actual,run)
    projected=dict(actual)
    if repository_cache is not None:
        resident.require(repository_cache==REPOSITORY_CACHE)
        cache=str(repository_cache)+':'+str(repository_cache)+':rbind'
        values=actual.get('BindReadOnlyPaths','').split()
        resident.require(values.count(cache)==1)
        values.remove(cache)
        projected['BindReadOnlyPaths']=' '.join(values)
    admission.verify_bindings(projected,run)

def verify_cpu(value):
    from decimal import Decimal
    matched=re.fullmatch(r'([0-9]{1,7}(?:[.][0-9]{1,6})?)(us|ms|s)',value) if type(value) is str else None
    resident.require(matched is not None and Decimal(matched[1])*{'us':1,'ms':1000,'s':1000000}[matched[2]]==1900000)

def unset_environment(values):
    return tuple(key for key in values if key!='DBUS_SESSION_BUS_ADDRESS')+(
        'SYSTEMD_HOST','SYSTEMD_MACHINE','SSH_AUTH_SOCK','SSH_CONNECTION','SSH_CLIENT','SSH_TTY',
        'LD_PRELOAD','LD_AUDIT','LD_LIBRARY_PATH','PYTHONPATH','PYTHONHOME',
        'GNOME_KEYRING_CONTROL','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY',
        'http_proxy','https_proxy','all_proxy','no_proxy','CODEX_HOME')
