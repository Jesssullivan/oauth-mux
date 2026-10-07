"""Narrow operator-input predicates for controlled dependency acquisition.

Network is permitted only for one exact declared producer per invocation:
audited archives, a pinned dependency-object shard, or the pinned Home Manager
source acquisition. Source acquisition does not authorize evaluation/activation.
This does not authorize provider/application traffic or a general network build.
Disk sampling is an overshoot-prone monitor, not a hard aggregate quota.
"""
import hashlib
import json
import os
from pathlib import Path
import stat

FETCH_LABEL = '//tools:fetch_codex_archives_bundle'
BUNDLE_FETCH_LABEL = '//tools:codex_dependency_bundle_producer'
HOME_MANAGER_FETCH_LABEL = '//tools:home_manager_acquisition_producer'
GIT_FETCH_LABEL = '//tools:codex_git_input_producer_0'
PACK_DIRECTORY = Path('/srv/fast-local/jess/state/codex/omux-codex-native-recovery-development-20261004/git/objects/pack')
PACK_STEM = 'pack-c4c9ce7cd275c2c4f91c442087b9738342ae193a'
COORDINATION_DIRECTORY = Path('/home/jess/.local/state/omux-execution-20261005')
HOME_MANAGER_STATE = Path('/home/jess/.local/state/omux-home-manager-prefetch-20261006')
HOME_GIT_STATE = Path('/home/jess/.local/state/omux-codex-git-prefetch-20261006')
HOME_HTTP_STATE = Path('/home/jess/.local/state/omux-codex-http-prefetch-20261006')
RECOVERY_DIRECTORY = Path('/srv/fast-local/jess/state/codex/omux-codex-native-recovery-development-20261004/source')
PRISTINE_DIRECTORY = COORDINATION_DIRECTORY / '01c11682-8389-4519-9b1a-dc7403066431/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_pristine_source_producer/test.outputs/codex-pristine-source'
DELTA_DIRECTORY = COORDINATION_DIRECTORY / 'cache-v2-0263cddbc2fe72e072e344a70bf61fdc0e90702986c9738e791ef64375ac8aee/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_recovery_delta_producer/test.outputs/codex-recovery-delta'
FRESH_LABEL = '//tools:codex_fresh_source_producer'
FRESH_COMPANIONS = {FRESH_LABEL, '//tools:codex_fresh_source_test', '//tools:execution_guard_test', '//tools:guard_dependency_profile_test', '//:docs_check'}


def selected_fresh_inputs(profile, arguments, pristine, delta, validator):
    if pristine is None and delta is None:
        return {}
    if (profile != 'standard' or arguments[:1] != ['test'] or FRESH_LABEL not in arguments[1:]
            or not set(arguments[1:]) <= FRESH_COMPANIONS or
            pristine != PRISTINE_DIRECTORY or delta != DELTA_DIRECTORY):
        raise ValueError('fresh inputs require paired fixed directories and finite producer labels')
    result = {}
    for directory, files in ((pristine, {'pristine.tar.gz': 16113014, 'pristine-receipt.json': 1574870}),
                             (delta, {'recovery-delta.patch': 37136, 'recovery-delta-receipt.json': 24651})):
        validator(directory, owner_only=False)
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name, maximum in files.items():
                file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
                try:
                    info = os.fstat(file)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or not 0 < info.st_size <= maximum:
                        raise ValueError('fresh public input custody or size rejected')
                    result[str(directory / name)] = {'bytes': info.st_size, 'inode': info.st_ino,
                                                     'device': info.st_dev, 'mtime_ns': info.st_mtime_ns}
                finally:
                    os.close(file)
        finally:
            os.close(descriptor)
    return result


def selected_profile(profile, arguments, site_inputs=False, pack_input=False, recovery_input=False):
    if profile == 'codex-native':
        from codex_native_profile import MODES
        if site_inputs or pack_input or recovery_input or not any(arguments == [v[0], *v[1]] for v in MODES.values()):
            raise ValueError('native profile permits only finite selected mode')
        return {'PrivateNetwork': 'yes'}
    if profile == 'native-login-ui':
        from guard_native_login_ui_profile import selected
        if site_inputs or pack_input or recovery_input:
            raise ValueError('native-ui-unrelated-inputs')
        return selected(arguments)
    if profile == 'codex-login':
        from guard_codex_login_profile import selected
        if site_inputs or pack_input or recovery_input:
            raise ValueError('codex-login-unrelated-inputs')
        return selected(arguments)
    if profile == 'codex-live':
        from guard_codex_live_profile import selected
        if site_inputs or pack_input or recovery_input:
            raise ValueError('codex-live-unrelated-inputs')
        return selected(arguments)
    if profile == 'yoga-controller-delivery':
        from guard_yoga_delivery_profile import selected
        return selected(arguments, site=site_inputs, pack=pack_input,
                        recovery=recovery_input)
    if profile not in ('standard', 'dependency-prefetch', 'installed-browser', 'codex-sdk', 'yoga-toolbar'):
        raise ValueError('unknown execution profile')
    if recovery_input and profile != 'standard':
        raise ValueError('recovery source is exclusive to the standard producer profile')
    if profile == 'codex-sdk':
        from codex_sdk_profile import LANES
        if site_inputs or pack_input or len(arguments) != 2 or arguments[0] != 'test' or arguments[1] not in {value[0] for value in LANES.values()}:
            raise ValueError('SDK profile requires one fixed lane without unrelated inputs')
    if profile == 'dependency-prefetch':
        if (len(arguments) != 2 or arguments[0] != 'test'
                or arguments[1] not in (FETCH_LABEL, BUNDLE_FETCH_LABEL, HOME_MANAGER_FETCH_LABEL, GIT_FETCH_LABEL)
                or site_inputs or pack_input):
            raise ValueError('dependency profile permits one exact producer without extra/application/site inputs')
    if profile == 'installed-browser' and (arguments != ['test', '//delivery:installed_chromium_test'] or pack_input):
        raise ValueError('installed browser profile permits only its exact test without native pack inputs')
    if profile == 'yoga-toolbar' and (arguments != ['run', '//delivery:yoga_toolbar_consent_proof']
            or site_inputs or pack_input or recovery_input):
        raise ValueError('Yoga permits one exact local proof without acquisition/SDK/site inputs')
    return {'PrivateNetwork': 'no' if profile == 'dependency-prefetch' else 'yes'}


def recovery_source(path, validate_private):
    selected = Path(path)
    if selected != RECOVERY_DIRECTORY:
        raise ValueError('only the fixed public recovery source is accepted')
    validate_private(selected, owner_only=False)
    return selected


def validate_coordination(profile, selected, state_root, *, arguments=None):
    state_root = Path(state_root)
    if profile == 'yoga-controller-delivery':
        from guard_yoga_delivery_profile import coordination
        return coordination(selected, state_root, arguments)
    if not state_root.is_absolute() or '..' in state_root.parts:
        raise ValueError('absolute canonical state path required')
    if state_root == HOME_HTTP_STATE:
        if (profile != 'dependency-prefetch' or arguments != ['test', BUNDLE_FETCH_LABEL]
                or selected is None or Path(selected) != COORDINATION_DIRECTORY):
            raise ValueError('HTTP HOME state requires its exact bundle producer and fixed controller lock')
        return COORDINATION_DIRECTORY
    # One separately declared first-requirement producer shares the controller
    # lock. Neither other producers nor other HOME/FAST states inherit this lane.
    if (state_root == HOME_GIT_STATE
            or profile == 'dependency-prefetch' and arguments == ['test', GIT_FETCH_LABEL]):
        if (profile != 'dependency-prefetch' or arguments != ['test', GIT_FETCH_LABEL]
                or state_root != HOME_GIT_STATE or selected is None
                or Path(selected) != COORDINATION_DIRECTORY):
            raise ValueError('Git HOME state requires its exact first producer and fixed controller lock')
        return COORDINATION_DIRECTORY
    if state_root == HOME_MANAGER_STATE:
        if (profile != 'dependency-prefetch' or arguments != ['test', HOME_MANAGER_FETCH_LABEL]
                or selected is None or Path(selected) != COORDINATION_DIRECTORY):
            raise ValueError('Home Manager HOME state requires its exact producer and fixed controller lock')
        return COORDINATION_DIRECTORY
    if profile == 'yoga-toolbar':
        if (not str(state_root).startswith('/srv/') or
                selected is not None and Path(selected) != state_root):
            raise ValueError('Yoga requires one explicit local /srv state and coordination root')
    if profile in ('standard', 'installed-browser', 'codex-live', 'codex-login', 'native-login-ui') and selected is not None and Path(selected) != state_root:
        if (Path(selected) != COORDINATION_DIRECTORY or
                not str(state_root).startswith('/srv/fast-local/jess/state/')):
            raise ValueError('alternate standard coordination requires fixed home lock and fast state')
    if profile in ('dependency-prefetch', 'codex-sdk', 'codex-native'):
        if selected is None or Path(selected) != COORDINATION_DIRECTORY:
            raise ValueError('dependency producer requires the existing controller coordination directory')
        if state_root == COORDINATION_DIRECTORY:
            raise ValueError('dependency output must use its separate fast-storage state')
        if not str(state_root).startswith('/srv/fast-local/jess/state/'):
            raise ValueError('dependency state must use the explicit fast-storage operator root')
    return Path(selected) if selected is not None else Path(state_root)


def initialize_state(path, validate_private):
    """Only explicit caller-requested final-component creation; no parent mkdir."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path.name in ('', '.', '..'):
        raise ValueError('exact absolute final state component required')
    validate_private(path.parent, owner_only=False)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)
    validate_private(path)


def pack_metadata(path):
    selected = Path(path)
    if selected != PACK_DIRECTORY or not selected.is_absolute():
        raise ValueError('only the named public Codex pack directory is accepted')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    rows = {}
    try:
        for part in selected.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid not in (0, os.getuid()) or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError('public pack ancestor ownership rejected')
        for extension in ('pack', 'idx', 'rev'):
            name = PACK_STEM + '.' + extension
            file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            try:
                info = os.fstat(file)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
                    raise ValueError('public pack input custody rejected')
                metadata = {'bytes': info.st_size, 'device': info.st_dev, 'inode': info.st_ino,
                            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
                digest = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()
                rows[name] = {**metadata, 'metadata_sha256': digest,
                              'payload_verification': 'fixed producer SHA pins; launcher does not hash pack payload'}
            finally:
                os.close(file)
    finally:
        os.close(descriptor)
    return selected, rows
