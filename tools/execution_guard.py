"""Fail-closed Linux transient-service containment for pre-realized Bazel tools.

Bootstrap is deliberately source-only: no Nix evaluation/build or Bazelisk
resolution occurs here. The caller supplies tools from the locked, already
realized flake. Source/graph binding is a separate acceptance obligation.
"""
import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import json
import math
import os
import re
import pwd
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
import uuid
from guard_cache import CacheLease, stable_fingerprint, graph_digest
from guard_test_evidence import capture as capture_test_evidence
from system_mask_policy import setting as system_masks, verify_effective as verify_system_masks
from guard_dependency_profile import selected_profile, validate_coordination, initialize_state, pack_metadata, recovery_source, selected_fresh_inputs

PROPERTIES = {
    'MemoryMax': '4294967296', 'MemorySwapMax': '0', 'TasksMax': '512',
    'CPUQuotaPerSecUSec': '2s', 'RuntimeMaxUSec': '20min',
    'KillMode': 'control-group', 'SendSIGKILL': 'yes',
    'TimeoutStopUSec': '10s', 'OOMPolicy': 'kill',
}
CGROUP = {'memory.max': '4294967296', 'memory.swap.max': '0',
          'pids.max': '512', 'memory.oom.group': '1'}
LIMIT = 8 * 1024 * 1024
FREE_FLOOR = 2 * 1024 * 1024 * 1024
DIAGNOSTIC_STAGES = ('arguments/profile', 'privilege-metadata', 'tool/closure',
                     'state-custody', 'state-free-space', 'operatorinputs', 'lock', 'private-epoch')
DIAGNOSTIC_STAGE = 'arguments/profile'
CONTROLLER_TIMEOUT = 15
CLEANUP_SECONDS = 15
CLEANUP_READ_SECONDS = 2


def controller_thread_profile():
    """Bazel 9.0.1 standard graph policy, distinct from aggregate TasksMax.

    legacy_globbing_threads controls ForkJoin parallelism, not its maximum
    thread count. fsvc_threads controls the fixed filesystem-value pool.
    Explicit loading parallelism avoids the resource-derived auto option;
    ActiveProcessorCount=2 already makes its nominal default two in 9.0.1.
    Separate SDK and site constructors do not adopt this policy.
    """
    return {'legacy_globbing_threads': 2, 'fsvc_threads': 2, 'loading_phase_threads': 2}


def controller_diagnostic(error, operation, phase, timeout):
    """Finite categories only: transport data and exception text stay private."""
    return {'operation': operation if operation in ('launch', 'unit-readback', 'unit-stop') else 'unknown',
            'phase': phase if phase in ('launch', 'startup', 'qualification', 'monitor', 'cleanup') else 'unknown',
            'exception': ('TimeoutExpired' if isinstance(error, subprocess.TimeoutExpired) else
                          'CalledProcessError' if isinstance(error, subprocess.CalledProcessError) else
                          'OSError' if isinstance(error, OSError) else
                          'SubprocessError' if isinstance(error, subprocess.SubprocessError) else 'Exception'),
            'timeout_seconds': timeout if isinstance(timeout, (int, float)) and
                math.isfinite(timeout) and 0 <= timeout <= CONTROLLER_TIMEOUT else None}


def controller_run(parts, *, operation, phase, diagnose, stdin=subprocess.DEVNULL,
                   timeout=CONTROLLER_TIMEOUT, deadline=None, clock=time.monotonic, invoke=subprocess.run):
    budget = min(CONTROLLER_TIMEOUT, timeout)
    if deadline is not None:
        budget = max(0, min(budget, deadline - clock()))
    try:
        if budget <= 0:
            raise subprocess.TimeoutExpired(parts, budget)
        outcome = invoke(parts, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         timeout=budget, check=False)
        if outcome.returncode:
            raise subprocess.CalledProcessError(outcome.returncode, parts)
        return outcome.stdout.decode()
    except (OSError, subprocess.SubprocessError) as error:
        diagnose(controller_diagnostic(error, operation, phase, budget))
        raise


class CgroupPin:
    """Retain the admitted kernel object; a replacement path is never empty proof."""
    def __init__(self, path):
        self.path = path
        self.descriptor = os.open(path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            information = os.fstat(self.descriptor)
            self.identity = (information.st_dev, information.st_ino)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None

    def observe(self):
        try:
            information = self.path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return 'absent'
        if (information.st_dev, information.st_ino) != self.identity:
            return 'changed'
        descriptor = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            information = os.fstat(descriptor)
            if (information.st_dev, information.st_ino) != self.identity:
                return 'changed'
            events = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                data = os.read(events, 4097)
            finally:
                os.close(events)
            # Reobserve the name after the FD read as well as before it.
            information = self.path.stat(follow_symlinks=False)
            if (information.st_dev, information.st_ino) != self.identity:
                return 'changed'
            lines = data.decode('ascii').splitlines()
            populated = [line for line in lines if line.startswith('populated ')]
            if len(data) > 4096 or populated not in (['populated 0'], ['populated 1']):
                return 'unproved'
            return 'empty' if populated == ['populated 0'] else 'populated'
        finally:
            os.close(descriptor)


    def pids_snapshot(self):
        """Fixed metadata only, read through the held object; failures are unknown."""
        descriptor = None
        primary = None
        result = unknown_pids_snapshot()
        try:
            if self.descriptor is None:
                return result
            if _pids_identity(os.fstat(self.descriptor)) != self.identity:
                return unknown_pids_snapshot('changed')
            if _pids_identity(self.path.stat(follow_symlinks=False)) != self.identity:
                return unknown_pids_snapshot('changed')
            descriptor = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=self.descriptor)
            if _pids_identity(os.fstat(descriptor)) != self.identity:
                return unknown_pids_snapshot('changed')
            result = unknown_pids_snapshot('same')
            for name, key in (('pids.current', 'current'), ('pids.max', 'limit'),
                              ('pids.events', 'max_events')):
                try:
                    data = _pids_read(descriptor, name)
                    result[key] = parse_pids_metadata(data, name)
                except (OSError, ValueError, UnicodeError):
                    result[key] = None
            if _pids_identity(os.fstat(self.descriptor)) != self.identity or \
                    _pids_identity(os.fstat(descriptor)) != self.identity or \
                    _pids_identity(self.path.stat(follow_symlinks=False)) != self.identity:
                result = unknown_pids_snapshot('changed')
        except FileNotFoundError:
            result = unknown_pids_snapshot('absent')
        except (OSError, ValueError):
            result = unknown_pids_snapshot()
        except BaseException as error:
            primary = error
            raise
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException as error:
                    if primary is None:
                        if isinstance(error, Exception):
                            result = unknown_pids_snapshot()
                        else:
                            raise
        return result


def _pids_identity(information):
    if not stat.S_ISDIR(information.st_mode):
        raise ValueError('pids-directory-kind')
    return information.st_dev, information.st_ino


def unknown_pids_snapshot(custody='unavailable'):
    return {'custody': custody, 'current': None, 'limit': None, 'max_events': None}


def _pids_read(directory, name):
    # The call site supplies only these three fixed names, never an operator path.
    if name not in ('pids.current', 'pids.max', 'pids.events'):
        raise ValueError('pids-interface-name')
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=directory)
    primary = None
    try:
        information = os.fstat(descriptor)
        identity = information.st_dev, information.st_ino
        if not stat.S_ISREG(information.st_mode):
            raise ValueError('pids-interface-kind')
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != identity:
            raise ValueError('pids-interface-changed')
        chunks, size = [], 0
        while size < 4097:
            part = os.read(descriptor, 4097 - size)
            if not part:
                break
            chunks.append(part)
            size += len(part)
        data = b''.join(chunks)
        after = os.stat(name, dir_fd=directory, follow_symlinks=False)
        held = os.fstat(descriptor)
        if len(data) > 4096 or not stat.S_ISREG(after.st_mode) or \
                (after.st_dev, after.st_ino) != identity or \
                (held.st_dev, held.st_ino) != identity:
            raise ValueError('pids-interface-changed')
        return data
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            os.close(descriptor)
        except BaseException:
            if primary is None:
                raise


def parse_pids_metadata(data, name):
    if type(data) is not bytes or not data or len(data) > 4096:
        raise ValueError('pids-metadata-bound')
    text = data.decode('ascii')
    if name == 'pids.max' and text in ('max', 'max\n'):
        return 'max'
    if name not in ('pids.current', 'pids.max', 'pids.events'):
        raise ValueError('pids-interface-name')
    pattern = ('max ' if name == 'pids.events' else '') + r'(0|[1-9][0-9]{0,19})\n?'
    match = re.fullmatch(pattern, text)
    if match is None:
        raise ValueError('pids-metadata-shape')
    value = int(match.group(1))
    if value > 2**64 - 1:
        raise ValueError('pids-metadata-range')
    return value


class PidsObservation:
    """Bounded sampled workload metadata; never an admission or cleanup predicate."""
    def __init__(self, expected_limit=512):
        if expected_limit not in (480,512):
            raise ValueError('unknown finite workload task reservation')
        self.expected_limit = expected_limit
        self.baseline = self.classify(unknown_pids_snapshot(), 'baseline')
        self.last_monitor = self.classify(unknown_pids_snapshot(), 'monitor')
        self.pre_cleanup = self.classify(unknown_pids_snapshot(), 'pre-cleanup')
        self.unknown_pre_cleanup = self.pre_cleanup
        self.unknown_samples = {'baseline': self.baseline, 'monitor': self.last_monitor, 'pre-cleanup': self.pre_cleanup}
        self.monitor_samples = 0
        self.sample_count_saturated = False
        self.sampled_peak_current = None
        self.observed_at_or_over_verified_limit = False
        self.observed_max_event_increase = False
        self.observed_max_event_decrease = False
        self.observed_unknown = False
        self.finished = False
        self.pre_cleanup_control_flow_deferred = False

    def classify(self, snapshot, timing):
        current, limit, events = (snapshot[key] for key in ('current', 'limit', 'max_events'))
        baseline = getattr(self, 'baseline', {}).get('max_events')
        delta = events - baseline if type(events) is int and type(baseline) is int else None
        relation = ('unavailable' if type(current) is not int or type(limit) is not int else
                    'below' if current < limit else 'at' if current == limit else 'over')
        return {**snapshot, 'sample_timing': timing,
                'pids_limit': 'unavailable' if limit is None else 'verified'+str(self.expected_limit) if limit == self.expected_limit else 'changed',
                'pids_sample': relation, 'max_event_delta': delta,
                'pids_max_event_delta': 'unavailable' if delta is None else
                    'unchanged' if delta == 0 else 'increased' if delta > 0 else 'decreased'}

    def sample(self, pin, timing):
        try:
            snapshot = pin.pids_snapshot() if pin is not None else unknown_pids_snapshot()
            row = self.classify(snapshot, timing)
        except Exception:
            row = self.unknown_samples[timing]
        if timing == 'baseline':
            self.baseline = row
            if type(row['max_events']) is int:
                self.baseline['max_event_delta'] = 0
                self.baseline['pids_max_event_delta'] = 'unchanged'
        elif timing == 'monitor':
            self.last_monitor = row
            if self.monitor_samples < 4096:
                self.monitor_samples += 1
            else:
                self.sample_count_saturated = True
        elif timing == 'pre-cleanup':
            self.pre_cleanup = row
        else:
            raise ValueError('pids-sample-timing')
        if type(row['current']) is int:
            self.sampled_peak_current = max(self.sampled_peak_current or 0, row['current'])
        self.observed_at_or_over_verified_limit |= row['limit'] == self.expected_limit and row['pids_sample'] in ('at', 'over')
        self.observed_max_event_increase |= row['pids_max_event_delta'] == 'increased'
        self.observed_max_event_decrease |= row['pids_max_event_delta'] == 'decreased'
        self.observed_unknown |= row['custody'] != 'same' or any(row[key] is None for key in ('current', 'limit', 'max_events'))

    def finish(self, pin):
        if not self.finished:
            self.finished = True
            self.sample(pin, 'pre-cleanup')

    def receipt(self):
        return {'schema_version': 1, 'scope': 'whole-owned-workload-cgroup',
                'window': 'admitted-before-go-through-pre-cleanup', 'attribution': 'none',
                'counter_semantics': 'pids.events:max-as-exposed; mount-semantics-unqualified',
                'read_semantics': 'bounded-sequential-fields; sampled-not-continuous',
                'baseline': dict(self.baseline), 'last_monitor': dict(self.last_monitor),
                'pre_cleanup': dict(self.pre_cleanup), 'monitor_samples': self.monitor_samples,
                'sample_count_saturated': self.sample_count_saturated,
                'sampled_peak_current': self.sampled_peak_current,
                'observed_at_or_over_verified_limit': self.observed_at_or_over_verified_limit,
                'observed_max_event_increase': self.observed_max_event_increase,
                'observed_max_event_decrease': self.observed_max_event_decrease,
                'observed_unknown': self.observed_unknown,
                'pre_cleanup_control_flow_deferred': self.pre_cleanup_control_flow_deferred}


def workload_pids_observation(settings, profile):
    if profile in ('home-manager-reconstruction-reserved','home-manager-evaluation-reserved','home-manager-bundle-models-reserved'):
        return PidsObservation(480)
    if profile == 'native-peer-qualification-reserved':
        return PidsObservation(480)
    if profile in ('yoga-install-inputs','yoga-controller-qualify-reserved','yoga-controller-inspect-reserved','yoga-controller-verify-reserved','yoga-sealed-workspace-stage','yoga-sealed-workspace-models-reserved','native-seed-plan-reserved','native-seed-plan-reserved-models','default-archive-reserved','query-registration-reserved','resident-models-reserved','resident-owner-status-source-reserved','resident-owner-status-binding-reserved','resident-owner-status-persistence-source-reserved','resident-native-source-context-source-reserved','resident-native-source-context-refresh-source-reserved','resident-native-source-acquisition-source-reserved','native-acquisition-inputs-models-reserved','native-acquisition-binding-reserved','native-acquisition-metadata-reserved','native-acquisition-sdk-reserved','native-acquisition-plan-reserved','native-acquisition-query-reserved','native-acquisition-compilation-reserved','native-acquisition-runtime-qualification-reserved','native-acquisition-package-reserved','native-acquisition-bridge-material-reserved','native-acquisition-bridge-models-reserved','native-acquisition-ordinary-tui-reserved','native-acquisition-ordinary-models-reserved','native-acquisition-package-models-reserved','resident-native-source-context-metadata-reserved','resident-owner-status-persistence-binding-reserved','native-metadata-sdk-models-reserved','native-query-descriptor-reserved','native-persistence-metadata-reserved','native-persistence-sdk-reserved','native-persistence-package-models-reserved','resident-custody-runtime-models-reserved','resident-custody-runtime-reserved','resident-custody-runtime-linux-reserved','resident-custody-runtime-format-reserved','resident-installed-custody-models-reserved','resident-default-source-models-reserved','resident-native-acquisition-units-reserved','resident-native-deployment-wiring-units-reserved','resident-lifecycle-accounting-models-reserved','yoga-installed-selection-reserved','yoga-installed-workspace-reserved','yoga-installed-models-reserved','yoga-toolbar-reserved','yoga-toolbar-reserved-models'):
        return PidsObservation(480)
    return PidsObservation(settings.PROOF_TASKS
        if profile in ('resident-enrollment','resident-sources','codex-device-component-reserved') else 512)


def observe_pids_before_cleanup(observation, pin, primary=None, *, prior_failure=False):
    """Sampling never skips cleanup; only new control flow is deferred."""
    try:
        observation.finish(pin)
    except BaseException as error:
        # Preallocated unknown record: neither parsing nor allocation recurs here.
        observation.pre_cleanup = observation.unknown_pre_cleanup
        observation.observed_unknown = True
        if not isinstance(error, Exception) and primary is None and not prior_failure:
            observation.pre_cleanup_control_flow_deferred = True
            return error
    return None

def cleanup_owned(*, deadline, readback, authorize, stop, observe,
                  clock=time.monotonic, pause=time.sleep):
    """One absolute budget, read-only retries and at most one verified stop."""
    summary = {'state': 'unproved', 'stop': 'not-requested', 'ownership': 'unproved',
               'readback_attempts': 0}
    def observation():
        try:
            return observe()
        except (OSError, ValueError, UnicodeError):
            return 'unproved'
    def terminal(state):
        if clock() >= deadline:
            summary['state'] = 'deadline-exhausted'
            return True
        if state in ('empty', 'absent'):
            summary['state'] = 'empty'
            return True
        if state in ('changed', 'unproved'):
            summary['state'] = 'original-' + state
            return True
        return False
    while clock() < deadline and summary['readback_attempts'] < 8:
        if terminal(observation()):
            return summary
        remaining = deadline - clock()
        if remaining <= 0:
            break
        summary['readback_attempts'] += 1
        try:
            actual = readback(min(CLEANUP_READ_SECONDS, remaining), deadline)
        except (OSError, subprocess.SubprocessError):
            remaining = deadline - clock()
            if remaining > 0:
                pause(min(0.1, remaining))
            continue
        if clock() >= deadline:
            break
        try:
            # A first owned readback may capture a partially dispatched worker.
            # It must request another fresh readback before any stop.
            if authorize(actual) is False:
                continue
            summary['ownership'] = 'verified'
        except (OSError, ValueError):
            summary['ownership'] = 'refused'
            break
        if clock() >= deadline:
            break
        if terminal(observation()):
            return summary
        remaining = deadline - clock()
        # Leave room for an independent empty observation after an uncertain stop.
        if remaining <= 0.1:
            break
        summary['stop'] = 'unresolved'
        try:
            stop(min(CONTROLLER_TIMEOUT, remaining - 0.1), deadline)
            summary['stop'] = 'succeeded'
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        break
    while clock() < deadline:
        if terminal(observation()):
            return summary
        remaining = deadline - clock()
        if remaining > 0:
            pause(min(0.1, remaining))
    summary['state'] = 'deadline-exhausted'
    return summary


def monitor_workload(readback, deadline, on_iteration, *, clock=time.monotonic, pause=time.sleep):
    next_readback = clock()
    while clock() < deadline:
        on_iteration()
        now = clock()
        if now >= deadline:
            return 124
        if now >= next_readback:
            actual = readback()
            now = clock()
            if now >= deadline:
                return 124
            if actual.get('ActiveState') in ('inactive', 'failed'):
                result = int(actual.get('ExecMainStatus', '125'))
                return 125 if actual.get('Result') != 'success' and result == 0 else result
            next_readback = now + 2.0
        remaining = deadline - clock()
        if remaining <= 0:
            break
        pause(min(0.5, remaining))
    return 124


def process_start_ticks(pid):
    directory = Path('/proc') / str(pid)
    if pid <= 0 or directory.stat().st_uid != os.getuid():
        raise ValueError('owned workload process unavailable')
    text = (directory / 'stat').read_text()
    return text[text.rindex(')') + 2:].split()[19]


def unit_epoch_identity(actual, *, unit, manager, run, python, worker):
    if (actual.get('Id') != unit or
            (manager == 'system' and (actual.get('User') != str(os.getuid()) or
                                      actual.get('Group') != str(os.getgid()))) or
            'OMUX_EXECUTION_GUARD=' + str(run) not in actual.get('Environment', '').split()):
        raise ValueError('owned unit identity changed before cleanup')
    execution = actual.get('ExecStart', '')
    if 'path=' + python not in execution or worker + ' --worker ' + str(run) + ' --' not in execution:
        raise ValueError('owned unit executable changed before cleanup')


def capture_cleanup_pin(actual, *, unit, manager, run, python, worker):
    """Qualify an uncertain dispatch, then require a second readback before stop."""
    unit_epoch_identity(actual, unit=unit, manager=manager, run=run, python=python, worker=worker)
    name = actual.get('ControlGroup', '')
    if not name.startswith('/') or '..' in Path(name).parts or Path(name).name != unit:
        raise ValueError('uncertain dispatch has no exact owned cgroup')
    pid_text = actual.get('MainPID', '')
    if not re.fullmatch('[1-9][0-9]*', pid_text):
        raise ValueError('uncertain dispatch has no live owned worker')
    pid = int(pid_text)
    ticks = process_start_ticks(pid)
    if (Path('/proc') / pid_text / 'cgroup').read_text().splitlines() != ['0::' + name]:
        raise ValueError('uncertain dispatch worker belongs to another cgroup')
    pin = CgroupPin(Path('/sys/fs/cgroup') / name.lstrip('/'))
    try:
        if process_start_ticks(pid) != ticks or pin.observe() != 'populated':
            raise ValueError('uncertain dispatch changed during capture')
        return pin, pid, ticks
    except BaseException:
        pin.close()
        raise


def authorize_cleanup(actual, *, unit, manager, run, python, worker, cgroup,
                      original_pid, original_ticks, pid_ticks=process_start_ticks):
    unit_epoch_identity(actual, unit=unit, manager=manager, run=run, python=python, worker=worker)
    if (cgroup is None or actual.get('ControlGroup') != '/' + str(cgroup.relative_to('/sys/fs/cgroup'))):
        raise ValueError('owned unit cgroup changed before cleanup')
    pid = actual.get('MainPID')
    if pid != '0' and (pid != str(original_pid) or original_ticks is None or
                       pid_ticks(original_pid) != original_ticks):
        raise ValueError('owned workload process changed before cleanup')


def rejection_diagnostic(error, stage):
    selected = stage if stage in DIAGNOSTIC_STAGES else 'unknown'
    category = ('KeyboardInterrupt' if isinstance(error, KeyboardInterrupt) else
                'ValueError' if isinstance(error, ValueError) else
                'OSError' if isinstance(error, OSError) else
                'SubprocessError' if isinstance(error, subprocess.SubprocessError) else 'Exception')
    result = 'execution containment rejected; stage=' + selected + '; exception=' + category
    import guard_resident_enrollment_profile as resident
    diagnostic = resident.diagnostic_projection(error)
    if diagnostic is not None:
        result += '; resident_phase=' + diagnostic['phase'] + '; resident_errno=' + diagnostic['errno']
    if type(error).__module__ == 'guard_native_seed_plan_reserved':
        import guard_native_seed_plan_reserved as reservation
        diagnostic = reservation.diagnostic_projection(error)
        if diagnostic is not None:
            result += '; reserved_phase=' + diagnostic['phase'] + '; reserved_errno=' + diagnostic['errno']
            if 'proc_exit_confirmation' in diagnostic:
                result += '; proc_exit_confirmation=' + diagnostic['proc_exit_confirmation']
    return result


def sdk_owned_command(plan, run, output_base=None):
    command = list(plan['argv'])
    if sum(part.startswith('--output_base=') for part in command) != 1:
        raise ValueError('SDK command must have exactly one owned output base')
    command = [('--output_base=' + str(output_base or run / 'output-base'))
               if part.startswith('--output_base=') else part for part in command]
    command[2:2] = ['--host_jvm_args=-Xmx768m', '--host_jvm_args=-XX:ActiveProcessorCount=1']
    return command + ['--nocache_test_results', '--nozip_undeclared_test_outputs',
                      '--symlink_prefix=' + str(run / 'bazel-'), '--disk_cache=', '--spawn_strategy=sandboxed',
                      '--sandbox_default_allow_network=false']


def sdk_cache_provenance(plan, source_root, source_receipt, settings_root, settings_receipt, bundle_receipt, lanes, graph):
    if (plan.get('physical_mode_policy') != 'bazel-retained-export-all-regular-and-directories-0555-v1' or
            plan.get('git_mode_authority') != 'sha256-bound-source-receipt-Git-modes'):
        raise ValueError('SDK source physical/Git mode authority is missing or unsupported')
    return {'lanes': lanes, 'jvm_heap_mib': 768, 'active_processors': 1, 'jobs': 1,
            'local_test_jobs': 1, 'rust_test_threads': 1, 'graph': graph,
            'source_inventory_bound': True, 'source_root': str(source_root),
            'source_receipt_sha256': source_receipt, 'settings_root': str(settings_root),
            'settings_receipt_sha256': settings_receipt, 'bundle_receipt_sha256': bundle_receipt,
            'environment': dict(plan['environment']), 'physical_mode_policy': plan['physical_mode_policy'],
            'git_mode_authority': plan['git_mode_authority']}


def check_free_space(path):
    filesystem = os.statvfs(path)
    available = filesystem.f_bavail * filesystem.f_frsize
    if available < FREE_FLOOR:
        raise ValueError('state filesystem below sampled 2GiB free-space floor')
    return available


def prepare_state(state_root, profile, coordination_root, initialize=False, *, arguments=None):
    global DIAGNOSTIC_STAGE
    DIAGNOSTIC_STAGE = 'state-custody'
    if not state_root or not state_root.is_absolute():
        raise ValueError('absolute private state directory required')
    coordination = validate_coordination(profile, coordination_root, state_root, arguments=arguments)
    if coordination != state_root:
        private(coordination)
    if initialize:
        initialize_state(state_root, private)
    private(state_root)
    DIAGNOSTIC_STAGE = 'state-free-space'
    check_free_space(state_root)
    return coordination

SANDBOX = {'PrivateNetwork': 'yes', 'NoNewPrivileges': 'yes',
           'ProtectControlGroups': 'yes', 'RestrictSUIDSGID': 'yes'}
DELEGATION_ENV = ('DBUS_SESSION_BUS_ADDRESS', 'DBUS_SYSTEM_BUS_ADDRESS',
                  'SYSTEMD_BUS_ADDRESS', 'NIX_REMOTE', 'BAZEL_REMOTE_EXECUTOR',
                  'BAZEL_REMOTE_CACHE')


def blocked_paths(profile='standard'):
    if profile not in ('standard', 'dependency-prefetch', 'installed-browser', 'codex-sdk', 'codex-native', 'site', 'yoga-toolbar', 'yoga-controller-delivery'):
        raise ValueError('unknown mask profile')
    # Mask containing directories: mounting over individual host sockets can
    # be prohibited by the host's mandatory-access policy. The directory mask
    # also excludes alternative manager endpoints within the same namespace.
    return ['/run/user/' + str(os.getuid()), '/run/dbus',
            '/run/systemd', '/nix/var/nix/daemon-socket',
            str(Path(pwd.getpwuid(os.getuid()).pw_dir) / '.config/sops-nix/secrets/become')] + (['/etc/bluetooth', '/etc/environment'] if profile in ('installed-browser', 'site', 'yoga-toolbar','yoga-toolbar-reserved') else [])


def validate_become_metadata(metadata, uid):
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid
            or stat.S_IMODE(metadata.st_mode) not in (0o400, 0o600)
            or metadata.st_nlink != 1 or not 1 <= metadata.st_size <= 4096):
        raise ValueError('host-local become descriptor rejected')


def become_descriptor(path):
    expected = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.config/sops-nix/secrets/become/password'
    if Path(path) != expected:
        raise ValueError('only the fixed host-local SOPS become path is accepted')
    descriptor = os.open(expected, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        validate_become_metadata(os.fstat(descriptor), os.getuid())
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def validate_sudo():
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        metadata = os.fstat(directory)
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError('host sudo root ancestor ownership rejected')
        for name in ('usr', 'bin'):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
            metadata = os.fstat(directory)
            if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
                raise ValueError('host sudo ancestor ownership rejected')
        # Lab's execute-only SUID wrapper need not grant callers read access.
        # O_PATH verifies the object metadata without reading executable bytes.
        descriptor = os.open('sudo', os.O_PATH | os.O_NOFOLLOW, dir_fd=directory)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                    or not metadata.st_mode & stat.S_ISUID
                    or not metadata.st_mode & stat.S_IXUSR):
                raise ValueError('host sudo must be a root-owned immutable SUID executable')
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)
    return '/usr/bin/sudo'


def system_identity(actual, pid, proc=Path('/proc')):
    expected = {'User': str(os.getuid()), 'Group': str(os.getgid()),
                'PrivateUsers': 'no', 'CapabilityBoundingSet': '', 'AmbientCapabilities': '',
                'StandardInput': 'null'}
    if os.getuid() == 0 or pid <= 0:
        raise ValueError('system workload must use the unprivileged supervisor identity')
    if any(actual.get(key) != value for key, value in expected.items()):
        raise ValueError('effective system workload identity rejected')
    directory = proc / str(pid)
    status = properties((directory / 'status').read_text().replace(':\t', '='))
    if status.get('Uid', '').split() != [str(os.getuid())] * 4 or status.get('Gid', '').split() != [str(os.getgid())] * 4:
        raise ValueError('actual system workload UID/GID rejected')
    if any(int(status.get(name, '-1'), 16) != 0 for name in ('CapEff', 'CapPrm', 'CapAmb')):
        raise ValueError('system workload retained capabilities')
    maps = {name: (directory / name).read_text().strip() for name in ('uid_map', 'gid_map')}
    for name, text in maps.items():
        rows = [tuple(map(int, line.split())) for line in text.splitlines()]
        required = os.getuid() if name == 'uid_map' else os.getgid()
        if not any(inside == 0 and outside == 0 and count > required
                   for inside, outside, count in rows):
            raise ValueError('host root identity mapping required')
    return maps


def immutable(path):
    resolved = Path(path).resolve(strict=True)
    if not str(resolved).startswith('/nix/store/') or not resolved.is_file():
        raise ValueError('tool must be a pre-realized immutable store file')
    return str(resolved)


def store_object(path):
    resolved = Path(path).resolve(strict=True)
    if (not str(resolved).startswith('/nix/store/') or len(resolved.parts) != 4
            or not (resolved.is_dir() or resolved.is_file())):
        raise ValueError('pre-realized store root required')
    return resolved


def store_directory(path):
    resolved = store_object(path)
    if not resolved.is_dir():
        raise ValueError('pre-realized store directory required')
    return resolved


def closure_manifest(path):
    root = store_directory(path)
    manifest = root / 'native.json'
    paths = root / 'store-paths'
    registration = root / 'registration'
    for file in (manifest, paths, registration):
        immutable(file)
        if file.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('closure manifest exceeds bound')
    roots = {str(store_object(line)) for line in paths.read_text().splitlines() if line}
    payload = json.loads(manifest.read_text())
    if payload.get('system') not in ('x86_64-linux', 'aarch64-linux'):
        raise ValueError('Linux native closure required')
    def check(value):
        if isinstance(value, dict):
            for item in value.values():
                check(item)
        elif isinstance(value, list):
            for item in value:
                check(item)
        elif isinstance(value, str) and value.startswith('/nix/store/'):
            resolved = Path(value).resolve(strict=True)
            if str(Path(*resolved.parts[:4])) not in roots:
                raise ValueError('manifest path absent from pre-realized closure')
    check(payload)
    return root, payload, hashlib.sha256(manifest.read_bytes()).hexdigest()


def private(path, owner_only=True):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute trusted state path required')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            metadata = os.fstat(descriptor)
            if metadata.st_uid not in (0, os.getuid()) or stat.S_IMODE(metadata.st_mode) & 0o022:
                raise ValueError('state ancestor is not trusted')
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.getuid() or (owner_only and stat.S_IMODE(metadata.st_mode) != 0o700):
            raise ValueError('state directory must be owned and mode 0700')
    finally:
        os.close(descriptor)


def properties(text):
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)


def await_startup(read, timeout=10, clock=time.monotonic, pause=time.sleep):
    """A no-block submission can remain inactive while its start job is queued."""
    deadline = clock() + timeout
    actual = read()
    history = []
    while True:
        history.append({key: actual.get(key) for key in
                        ('ActiveState', 'SubState', 'Result', 'Job', 'MainPID',
                         'ExecMainPID', 'ControlGroup')})
        state = actual.get('ActiveState')
        if state in ('active', 'failed') or state not in ('inactive', 'activating'):
            return actual, history
        if clock() >= deadline:
            return actual, history
        pause(0.1)
        actual = read()


def selected_site_source(path, repository=None):
    repository = Path.cwd().resolve() if repository is None else Path(repository).resolve()
    expected = (repository.parent / 'omux.xoxd.ai').resolve(strict=True)
    selected = Path(path).resolve(strict=True)
    if selected != expected or any(char.isspace() for char in str(selected)):
        raise ValueError('site source must be the exact declared sibling repository')
    directory = os.open(selected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    digests = {}
    try:
        for relative in ('flake.nix', 'flake.lock', 'tools/offline-site-roots.json', 'tools/tool-selection.nix'):
            parent = os.dup(directory)
            try:
                parts = Path(relative).parts
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    os.close(parent)
                    parent = child
                descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
                with os.fdopen(descriptor, 'rb') as source:
                    info = os.fstat(source.fileno())
                    if (not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IROTH
                            or info.st_mode & 0o022 or info.st_size > 1024 * 1024):
                        raise ValueError('site input must be bounded public regular source')
                    content = source.read(1024 * 1024 + 1)
                    if len(content) > 1024 * 1024:
                        raise ValueError('site public input exceeds bound')
                digests[relative] = hashlib.sha256(content).hexdigest()
            finally:
                os.close(parent)
    finally:
        os.close(directory)
    return selected, digests


def selected_site_inventory(path, expected_sha256, state_root, coordination_root=None):
    if not isinstance(expected_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
        raise ValueError('exact site inventory SHA256 required')
    if state_root is None:
        raise ValueError('owned execution state is required for inventory selection')
    path, state_root = Path(path), Path(state_root)
    roots = [state_root]
    if coordination_root is not None:
        coordination_root = validate_coordination('standard', coordination_root, state_root)
        if coordination_root != state_root:
            roots.append(coordination_root)
    selected_root = None
    for root in roots:
        if path.is_relative_to(root):
            selected_root = root
            break
    if selected_root is None:
        raise ValueError('site inventory must remain inside owned state or selected fixed coordination state')
    state_root = selected_root
    try:
        relative = path.relative_to(state_root)
    except ValueError:
        raise ValueError('site inventory must remain inside the owned execution state')
    suffix = ('output-base', 'execroot', '_main', 'bazel-out', 'k8-fastbuild',
              'testlogs', 'tools', 'cached_site_inventory_probe', 'test.outputs', 'inventory.json')
    if (not path.is_absolute() or not relative.parts or
            not re.fullmatch(r'cache-(?:v2-)?[0-9a-f]{64}', relative.parts[0]) or relative.parts[1:] != suffix):
        raise ValueError('only the declared cached site inventory output is accepted')
    private(state_root)
    directory = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
            if os.fstat(directory).st_uid != os.getuid():
                raise ValueError('site inventory ancestor ownership rejected')
        descriptor = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, 'rb') as source:
            metadata = os.fstat(source.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or metadata.st_size > 8 * 1024 * 1024):
                raise ValueError('site inventory must be an owned bounded regular file')
            content = source.read(8 * 1024 * 1024 + 1)
            if len(content) > 8 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != expected_sha256:
                raise ValueError('selected site inventory digest rejected')
    finally:
        os.close(directory)
    return path


def selected_site_receipt(path, expected_sha256, state_root, coordination_root, kind):
    """Select only declared producer outputs with trusted, non-alias ancestors."""
    suffixes = {
        'qualification': ('output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/'
                          'site_coordinator_closure_qualification/test.outputs/'
                          'site-coordinator-closure-qualification/site-coordinator-closure-qualification.json'),
        'manifest': 'output-base/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/chromium_dev_metadata.json',
    }
    if kind not in suffixes:
        raise ValueError('unknown site receipt selection')
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or not re.fullmatch('[0-9a-f]{64}', expected_sha256 or ''):
        raise ValueError('canonical exact site receipt selection required')
    roots = (Path(state_root), Path(coordination_root))
    root = next((root for root in roots if path.is_relative_to(root)), None)
    if root is None:
        raise ValueError('site receipt must remain in selected owned execution state')
    relative = path.relative_to(root)
    if (not relative.parts or
            not (re.fullmatch('cache-(?:v2-)?[0-9a-f]{64}', relative.parts[0]) or
                 re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', relative.parts[0])) or
            relative.parts[1:] != Path(suffixes[kind]).parts):
        raise ValueError('site receipt is not the exact declared producer output')
    private(root)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise ValueError('site receipt ancestor ownership rejected')
        import guard_site_profile as site
        site.bounded_file(path, expected_sha256, 16384 if kind == 'manifest' else 65536)
    finally:
        os.close(descriptor)
    return path


def verify(actual, cgroup, manager='user', isolation=None, profile='standard', runtime_seconds=None, native_phase2=False):
    import guard_resident_dispatch as resident_dispatch
    import guard_native_acquisition_dispatch as acquisition
    import guard_codex_device_component_profile as component
    acquisition_proof = profile in (*acquisition.PROFILES,*component.PROFILES)
    resident_proof = profile in resident_dispatch.PROFILES or profile == resident_dispatch.SETUP_PROFILE
    component_reserved = profile == component.RESERVED_PROFILE
    install_stage = profile in ('yoga-install-inputs','yoga-sealed-workspace-stage')
    import guard_native_seed_plan_reserved as seed_reserved
    if profile == 'default-archive-reserved':
        import guard_default_archive_reserved as seed_reserved
    elif profile == 'query-registration-reserved':
        import guard_query_registration_reserved as seed_reserved
    elif profile == 'resident-models-reserved':
        import guard_resident_models_reserved as seed_reserved
    elif profile == 'resident-owner-status-source-reserved':
        import guard_resident_owner_status_source_reserved as seed_reserved
    elif profile == 'resident-owner-status-binding-reserved':
        import guard_resident_owner_status_binding_reserved as seed_reserved
    elif profile == 'resident-owner-status-persistence-source-reserved':
        import guard_resident_owner_status_persistence_source_reserved as seed_reserved
    elif profile == 'resident-native-source-context-source-reserved':
        import guard_resident_native_source_context_source_reserved as seed_reserved
    elif profile == 'resident-native-source-context-refresh-source-reserved':
        import guard_resident_native_source_context_refresh_source_reserved as seed_reserved
    elif profile == 'resident-native-source-acquisition-source-reserved':
        import guard_resident_native_source_acquisition_source_reserved as seed_reserved
    elif profile in ('native-acquisition-inputs-models-reserved','native-acquisition-binding-reserved','native-acquisition-metadata-reserved','native-acquisition-sdk-reserved','native-acquisition-plan-reserved','native-acquisition-query-reserved','native-acquisition-compilation-reserved','native-acquisition-runtime-qualification-reserved','native-acquisition-package-reserved','native-acquisition-bridge-material-reserved','native-acquisition-bridge-models-reserved','native-acquisition-ordinary-tui-reserved','native-acquisition-ordinary-models-reserved','native-acquisition-package-models-reserved'):
        import guard_native_acquisition_inputs_reserved as seed_reserved
    elif profile in ('home-manager-reconstruction-reserved','home-manager-evaluation-reserved','home-manager-bundle-models-reserved'):
        import guard_home_manager_bundle_reserved as seed_reserved
    elif profile == 'native-peer-qualification-reserved':
        import guard_native_peer_qualification_reserved as seed_reserved
    elif profile == 'resident-native-source-context-metadata-reserved':
        import guard_resident_native_source_context_metadata_reserved as seed_reserved
    elif profile == 'resident-owner-status-persistence-binding-reserved':
        import guard_resident_owner_status_persistence_binding_reserved as seed_reserved
    elif profile in ('native-metadata-sdk-models-reserved','native-query-descriptor-reserved','native-persistence-metadata-reserved','native-persistence-sdk-reserved','native-persistence-package-models-reserved'):
        import guard_native_metadata_sdk_reserved as seed_reserved
    elif profile in ('resident-custody-runtime-models-reserved','resident-custody-runtime-reserved','resident-custody-runtime-linux-reserved','resident-custody-runtime-format-reserved','resident-installed-custody-models-reserved','resident-default-source-models-reserved','resident-native-acquisition-units-reserved','resident-native-deployment-wiring-units-reserved','resident-lifecycle-accounting-models-reserved'):
        import guard_resident_custody_runtime_reserved as seed_reserved
    elif profile in ('yoga-installed-selection-reserved','yoga-installed-workspace-reserved','yoga-installed-models-reserved'):
        import guard_yoga_installed_reserved as seed_reserved
    elif profile in ('yoga-toolbar-reserved','yoga-toolbar-reserved-models'):
        import guard_yoga_toolbar_reserved as seed_reserved
    elif profile in ('yoga-controller-qualify-reserved','yoga-controller-inspect-reserved','yoga-controller-verify-reserved'):
        import guard_yoga_controller_qualify_reserved as seed_reserved
    elif profile == 'yoga-sealed-workspace-models-reserved':
        import guard_yoga_sealed_transfer_models_reserved as seed_reserved
    seed_proof = profile in seed_reserved.PROFILES
    expected = (component.proof_properties(PROPERTIES,profile) if component_reserved else
        resident_dispatch.proof_properties(PROPERTIES) if resident_proof else PROPERTIES)
    if install_stage:
        if profile == 'yoga-sealed-workspace-stage':
            import guard_yoga_sealed_transfer_profile as staging
        else:
            import guard_yoga_install_inputs_profile as staging
        expected = staging.proof_properties(PROPERTIES)
    if seed_proof:
        expected = seed_reserved.properties(PROPERTIES)
    for key, value in {**expected, **(isolation or SANDBOX)}.items():
        if key == 'RuntimeMaxUSec' and (profile in ('yoga-controller-delivery', 'yoga-install-inputs','yoga-sealed-workspace-stage', 'codex-native') or
                profile in ('standard', 'codex-live', *resident_dispatch.PROFILES, resident_dispatch.SETUP_PROFILE, *acquisition.PROFILES, *component.PROFILES, *seed_reserved.PROFILES) and runtime_seconds is not None):
            import yoga_delivery_settings as delivery_settings
            if profile == 'yoga-sealed-workspace-stage':
                staging.effective_runtime(actual.get(key),runtime_seconds)
            elif profile in ('yoga-toolbar-reserved','yoga-toolbar-reserved-models','yoga-sealed-workspace-models-reserved','yoga-controller-qualify-reserved','yoga-controller-inspect-reserved','yoga-controller-verify-reserved'):
                seed_reserved.verify_runtime(actual.get(key),runtime_seconds)
            elif profile == 'codex-native' and native_phase2 is True:
                from codex_native_profile import phase2_effective_runtime
                phase2_effective_runtime(actual.get(key), runtime_seconds)
            else:
                delivery_settings.effective_runtime(actual.get(key), runtime_seconds)
            continue
        if key == 'CPUQuotaPerSecUSec' and (resident_proof or component_reserved or install_stage or seed_proof):
            resident_dispatch.verify_cpu(actual.get(key))
            continue
        if actual.get(key) != value:
            raise ValueError('effective service property rejected: ' + key)
    if manager == 'system':
        if profile in ('yoga-toolbar','yoga-toolbar-reserved'):
            import guard_yoga_profile as yoga
            home = Path(pwd.getpwuid(os.getuid()).pw_dir)
            yoga.verify_masks(actual, home, actual.get('BindReadOnlyPaths', '').split())
        else:
            verify_system_masks(actual.get('TemporaryFileSystem', ''), profile='standard' if resident_proof or acquisition_proof or seed_proof or profile in ('codex-sdk', 'codex-native', 'yoga-controller-delivery', 'yoga-install-inputs','yoga-sealed-workspace-stage', 'codex-live') else profile)
        if profile in ('installed-browser', 'site', 'yoga-toolbar','yoga-toolbar-reserved') and '/etc/environment' not in {
                path.lstrip('-') for path in actual.get('InaccessiblePaths', '').split()}:
            raise ValueError('host environment file mask missing')
    else:
        hidden = {path.lstrip('-') for path in actual.get('InaccessiblePaths', '').split()}
        if not set(blocked_paths(profile)).issubset(hidden):
            raise ValueError('manager and Nix socket isolation rejected')
    if profile == 'site':
        from guard_site_profile import required_masks
        hidden = {path.lstrip('-') for path in actual.get('InaccessiblePaths', '').split()}
        if manager == 'system':
            hidden.update(entry.split(':', 1)[0] for entry in actual.get('TemporaryFileSystem', '').split())
        required_masks(hidden)
    delegated = acquisition.unset_environment(DELEGATION_ENV) if acquisition_proof else resident_dispatch.unset_environment(DELEGATION_ENV) if resident_proof else DELEGATION_ENV
    if not set(delegated).issubset(actual.get('UnsetEnvironment', '').split()):
        raise ValueError('delegation environment isolation rejected')
    expected_cgroup = {**CGROUP, 'memory.max':expected['MemoryMax'], 'pids.max':expected['TasksMax']} if resident_proof or component_reserved or install_stage or seed_proof else CGROUP
    for key, value in expected_cgroup.items():
        if (cgroup / key).read_text().strip() != value:
            raise ValueError('effective cgroup bound rejected: ' + key)
    quota, period = (cgroup / 'cpu.max').read_text().split()
    if quota == 'max' or int(quota) > 2 * int(period) or int(quota) <= 0 or (resident_proof and int(quota)*10 > 19*int(period)) or ((component_reserved or install_stage or seed_proof) and int(quota)*10 != 19*int(period)):
        raise ValueError('effective CPU quota rejected')


def resident_isolation(settings, args, arguments):
    import guard_resident_dispatch as resident_dispatch
    manifest = settings.manifest if args.profile == resident_dispatch.SETUP_PROFILE or getattr(settings,'acquisition_profile',False) else args.resident_manifest
    return {**SANDBOX, **settings.finite(arguments, args.manager, manifest, False)}


def resident_enrollment_command(bazel,run,arguments,admission,*,source_commit=None,source_dirty=None,repository_cache=None,nixpkgs_source=None):
    import guard_resident_enrollment_profile as repository
    repository.repository_inputs(repository_cache,nixpkgs_source)
    if arguments in (['run','//delivery:resident_vault_metadata'],['run','//delivery:resident_vault_unlock'],
                ['run','//delivery:resident_standard_vault_metadata'],['run','//delivery:resident_standard_vault_unlock']):
        import guard_resident_vault_profile as resident
    else:
        import guard_resident_enrollment_profile as resident
    resident.finite(arguments,'system',admission.manifest,False)
    command = bazel_command(bazel,run,['build',arguments[1]],source_commit=source_commit,source_dirty=source_dirty,
        repository_cache=repository_cache,nixpkgs_source=nixpkgs_source)
    command[command.index('build')] = 'run'
    if repository_cache is not None:
        # Bazel9 defaults the writable contents cache beneath repository_cache.
        # Keep hash-addressed inputs readonly and extract into this fresh output base.
        command[command.index('run')+1:command.index('run')+1] = [
            '--repository_disable_download', '--repo_contents_cache=']
    command[command.index('--spawn_strategy=sandboxed')] = '--spawn_strategy=linux-sandbox'
    command[-1:-1] = ['--run_env='+key+'='+value for key,value in admission.environment().items()]
    if arguments in (['run','//delivery:resident_vault_metadata'],['run','//delivery:resident_vault_unlock'],
                ['run','//delivery:resident_standard_vault_metadata'],['run','//delivery:resident_standard_vault_unlock']):
        command[-1:-1] = ['--run_env=OMUX_EXECUTION_GUARD='+str(run)]
    return command

DEV_STAGE_LABEL = '//delivery:dev_stage_complete_retained'
DEV_STAGE_SCOPE = 'guarded-development-four-component-byte-stage-v1'


def dev_stage_request(profile, manager, arguments, reuse, entry_ns, deadline_ns):
    if DEV_STAGE_LABEL not in arguments:
        return False
    if (profile != 'standard' or manager != 'system' or arguments != ['test',DEV_STAGE_LABEL]
            or reuse):
        raise ValueError('complete stage requires exact standard/system TEST without cache reuse')
    dev_stage_budget(entry_ns, deadline_ns)
    return True


def dev_stage_budget(entry_ns, deadline_ns, reserve_ns=30 * 10**9):
    if (type(entry_ns) is not int or type(deadline_ns) is not int or entry_ns <= 0
            or deadline_ns - entry_ns != 1200 * 10**9
            or type(reserve_ns) is not int or reserve_ns not in (0,30 * 10**9)):
        raise ValueError('complete stage exhausted original guardian deadline')
    now = time.monotonic_ns()
    if not entry_ns <= now < deadline_ns - reserve_ns:
        raise ValueError('complete stage exhausted original guardian deadline')
    return (deadline_ns - reserve_ns - now) / 10**9


def dev_stage_runtime(entry_ns, deadline_ns):
    seconds = int(dev_stage_budget(entry_ns, deadline_ns))
    if seconds <= 0:
        raise ValueError('complete stage exhausted original guardian deadline')
    return seconds


def dev_stage_source_after(entry_ns, deadline_ns, expected, readback):
    dev_stage_budget(entry_ns,deadline_ns,reserve_ns=0)
    observed = readback()
    dev_stage_budget(entry_ns,deadline_ns,reserve_ns=0)
    return observed == expected


def dev_stage_command(command, run, entry_ns, deadline_ns):
    dev_stage_budget(entry_ns, deadline_ns)
    if command[-1:] != [DEV_STAGE_LABEL] or 'test' not in command or 'run' in command:
        raise ValueError('complete stage command is not the fixed TEST')
    result = list(command)
    result[-1:-1] = ['--test_env=OMUX_EXECUTION_GUARD='+str(run),
        '--test_env=OMUX_DEV_STAGE_ENTRY_NS='+str(entry_ns),
        '--test_env=OMUX_DEV_STAGE_DEADLINE_NS='+str(deadline_ns)]
    return result


def dev_stage_admission(run, graph, entry_ns, deadline_ns):
    dev_stage_budget(entry_ns, deadline_ns)
    if type(graph) is not str or not re.fullmatch('[0-9a-f]{64}', graph):
        raise ValueError('complete stage requires measured guardian graph')
    value = {'schemaVersion':1,'scope':DEV_STAGE_SCOPE,'label':DEV_STAGE_LABEL,
        'epoch':run.name,'entryMonotonicNs':entry_ns,'deadlineMonotonicNs':deadline_ns,
        'graphSha256':graph}
    descriptor = os.open(run/'dev-stage-admission.json',
        os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as output:
        output.write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
        output.flush()
        os.fsync(output.fileno())


def bazel_command(bazel, run, arguments, repository_cache=None, source_commit=None, source_dirty=None, nixpkgs_source=None, output_base=None, site_source=None, site_inventory=None, site_inventory_sha256=None, site_nixpkgs_source=None, codex_pack_directory=None, profile='standard', codex_recovery_source=None, codex_pristine_directory=None, codex_recovery_delta_directory=None, codex_owner_runtime_directory=None, codex_fresh_runtime_selection=None, codex_fresh_runtime_sha256=None, codex_fresh_runtime_bytes=None):
    format_base = ['run', '//:format', '--', 'src/main.zig', 'src/setup_collector.zig', 'src/setup_collector_tests.zig']
    sdk_export_run = profile=='standard' and arguments==['run','//tools:codex_retained_sdk_export_run']
    formatter = profile == 'standard' and (arguments == format_base or
                                           arguments == format_base + ['src/engine.zig'] or
                                           arguments == ['run', '//:format', '--', 'src'] or
                                           arguments == ['run', '//delivery:linux_launcher_format', '--',
                                                         'delivery/linux_launcher.zig'])
    if not arguments or (arguments[0] not in ('build', 'test') and not formatter and not sdk_export_run):
        raise ValueError('explicit Bazel verb required')
    # Do not accept startup flags/output-base overrides before the verb.
    # Strict local graph: no caller flags/config/remote execution/delegation.
    if not formatter and (len(arguments) < 2 or any(not arg.startswith('//') or any(char.isspace() for char in arg)
           for arg in arguments[1:])):
        raise ValueError('only explicit local Bazel labels are accepted')
    provenance = []
    if source_commit is not None or source_dirty is not None:
        if (not isinstance(source_commit, str) or not re.fullmatch(r'[0-9a-f]{40}', source_commit)
                or source_dirty not in ('true', 'false')):
            raise ValueError('complete explicit source provenance required')
        provenance = ['--define=OMUX_SOURCE_COMMIT=' + source_commit,
                      '--define=OMUX_SOURCE_DIRTY=' + source_dirty]
    cache_args = ['--repository_cache=' + str(repository_cache)] if repository_cache else []
    evaluation_args = ['--repo_env=OMUX_NIXPKGS_EVALUATION_SOURCE=' + str(nixpkgs_source)] if nixpkgs_source else []
    site_args = ['--repo_env=OMUX_SITE_SOURCE=' + str(site_source)] if site_source else []
    from guard_owner_runtime_input import VARIABLE as retained_variable, finite as retained_finite
    if codex_owner_runtime_directory is not None:
        retained_finite(profile, arguments, (nixpkgs_source, site_source, site_inventory,
            site_inventory_sha256, site_nixpkgs_source, codex_pack_directory,
            codex_recovery_source, codex_pristine_directory, codex_recovery_delta_directory))
    retained_args = ['--repo_env=' + retained_variable + '=' +
                     (str(codex_owner_runtime_directory) if codex_owner_runtime_directory is not None else '')]
    import guard_codex_fresh_live_profile as fresh_live
    fresh_selected = fresh_live.finite(profile,arguments,codex_owner_runtime_directory,
        codex_fresh_runtime_selection,codex_fresh_runtime_sha256,codex_fresh_runtime_bytes)
    retained_args += ['--repo_env='+fresh_live.VARIABLE+'='+
        (str(codex_fresh_runtime_selection) if fresh_selected else ''),
        '--repo_env='+fresh_live.SHA_VARIABLE+'='+(codex_fresh_runtime_sha256 if fresh_selected else ''),
        '--repo_env='+fresh_live.BYTES_VARIABLE+'='+(str(codex_fresh_runtime_bytes) if fresh_selected else '')]
    if fresh_selected:
        retained_args.append(fresh_live.DEFINE)
    pack_args = ['--repo_env=OMUX_CODEX_PACK_DIRECTORY=' + str(codex_pack_directory)] if codex_pack_directory else []
    if codex_pristine_directory is not None:
        pack_args += ['--repo_env=OMUX_CODEX_PRISTINE_DIRECTORY=' + str(codex_pristine_directory),
                      '--repo_env=OMUX_CODEX_RECOVERY_DELTA_DIRECTORY=' + str(codex_recovery_delta_directory)]
    if codex_recovery_source is not None:
        selected_profile(profile, arguments, recovery_input=True)
        # Custody is checked by main; command construction still checks exact selection.
        codex_recovery_source = recovery_source(codex_recovery_source, lambda path, **kwargs: None)
        pack_args += ['--repo_env=OMUX_CODEX_RECOVERY_SOURCE=' + str(codex_recovery_source)]
    if site_nixpkgs_source is not None:
        if site_source is None:
            raise ValueError('site Nixpkgs input requires explicit sibling source')
        site_nixpkgs_source = store_directory(site_nixpkgs_source)
        site_args += ['--repo_env=OMUX_SITE_NIXPKGS_EVALUATION_SOURCE=' + str(site_nixpkgs_source)]
    if site_inventory is not None or site_inventory_sha256 is not None:
        if site_inventory is None or not isinstance(site_inventory_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', site_inventory_sha256):
            raise ValueError('complete exact site inventory selection required')
        site_args += ['--repo_env=OMUX_SITE_INVENTORY=' + str(site_inventory),
                      '--repo_env=OMUX_SITE_INVENTORY_SHA256=' + site_inventory_sha256]
    test_args = ['--keep_going', '--test_output=errors', '--test_summary=detailed', '--test_env=TZ=UTC', '--nocache_test_results', '--nozip_undeclared_test_outputs',
                 '--strategy=TestRunner=processwrapper-sandbox'] if arguments[0] == 'test' else []
    if arguments == ['test', '//tools:execution_probe_output']:
        test_args += ['--experimental_ui_max_stdouterr_bytes=10485760']
    if profile == 'installed-browser':
        selected_profile(profile, arguments, pack_input=codex_pack_directory is not None)
        test_args += ['--test_env=OMUX_BROWSER_HOST_CONFIGURATION=host-configurations-unavailable']
    if profile == 'codex-live':
        import guard_codex_live_profile as live
        live.selected(arguments)
        test_args += ['--test_env=' + live.VARIABLE + '=' + live.DESTINATION]
    threads = controller_thread_profile()
    run_args = ['--run_env=OMUX_SDK_EXPORT_EPOCH='+str(run),
                '--run_env=OMUX_EXECUTION_GUARD='+str(run)] if sdk_export_run else []
    # Exactly one finite writer; no caller argv or other RUN labels admitted.
    return [bazel, '--batch', '--nosystem_rc', '--nohome_rc',
            '--host_jvm_args=-Xmx1536m', '--host_jvm_args=-XX:ActiveProcessorCount=2',
            '--noworkspace_rc', '--output_base=' + str(output_base or run / 'output-base')] + arguments[:1] + [
            '--jobs=2', '--legacy_globbing_threads=' + str(threads['legacy_globbing_threads']),
            '--experimental_fsvc_threads=' + str(threads['fsvc_threads']),
            '--loading_phase_threads=' + str(threads['loading_phase_threads']),
            '--spawn_strategy=' + ('linux-sandbox' if profile == 'codex-live' else 'sandboxed'), '--remote_executor=',
            '--remote_cache=', '--disk_cache=', '--sandbox_default_allow_network=false',
            '--enable_bzlmod', '--noenable_workspace', '--incompatible_strict_action_env',
            '--@rules_zig//zig/settings:use_standalone_translate_c', '--lockfile_mode=error'] + cache_args + evaluation_args + site_args + pack_args + retained_args + test_args + run_args + provenance + arguments[1:]


def yoga_command(bazel, run, arguments, admission, *, manager, source_commit=None, source_dirty=None):
    """Route the fixed proof only; offline dependencies remain a separate gate."""
    import guard_yoga_profile as yoga
    yoga.finite('yoga-toolbar', manager, arguments)
    if bazel != admission['receipt']['controllerTools']['bazel']:
        raise ValueError('Yoga command requires the qualified Bazel selector')
    installed = admission['receipt'].get('scope') == yoga.INSTALLED_SCOPE or admission.get('reservedToolbar') is True
    if installed:
        import guard_yoga_installed_workspace as inventory
        if inventory.verified(admission) is not True or source_commit is not None or source_dirty is not None:
            raise ValueError('Yoga installed graph requires independent origin without source stamp overrides')
    bindings = yoga.repository_bindings(admission, run)
    # Reuse the fixed local build options, then select this single run label.
    # The generic constructor continues refusing all non-formatter run calls.
    command = bazel_command(bazel, run, ['build', yoga.LABEL],
                            source_commit=source_commit, source_dirty=source_dirty)
    command[command.index('build')] = 'run'
    if installed:
        command.remove('--@rules_zig//zig/settings:use_standalone_translate_c')
        command[command.index('run')+1:command.index('run')+1] = [
            '--repository_disable_download', '--repo_contents_cache=']
    command[-1:-1] = ['--symlink_prefix=' + str(Path(run) / 'bazel-')] + [
        '--repo_env=' + key + '=' + value for key, value in sorted(bindings.items())]
    return command


def delivery_monitor_deadline(deadline_ns, settings):
    return (deadline_ns - settings.CLEANUP_RESERVE_NS) / 10**9


def yoga_controller_readonly_go(settings, profile, run, source_root, source_commit, prior,
                                expected_graph, expected_lock, lockfd, entry_ns, deadline_ns):
    """Final exact readonly fence after readiness, before publishing worker Go.

    Raw authority is reopened with the existing bounded nofollow/value-identity
    policy; this is not continuous raw-file FD custody. The existing HTTP and
    resident witnesses have just rechecked independently in guard main.
    """
    import guard_yoga_controller_qualify_reserved as reserved
    if settings is not reserved or profile not in reserved.READONLY_PROFILES:
        raise ValueError('exact-reserved-yoga-readonly-go-required')
    reserved.remaining(entry_ns, deadline_ns)
    current_graph = graph_digest(source_root)[0]
    if current_graph != expected_graph:
        raise ValueError('yoga-readonly-current-graph-changed-before-go')
    if reserved.lock_witness(lockfd, deadline_ns) != expected_lock:
        raise ValueError('original-home-lock-changed-before-go')
    reserved.recheck(prior, current_graph, PROPERTIES, deadline_ns, expected_lock,
                     source_commit=source_commit)
    reserved.remaining(entry_ns, deadline_ns)
    (run / 'go').touch(mode=0o600, exist_ok=False)


def yoga_delivery_command(bazel, run, arguments, deadline_ns, prior=None, *, source_commit=None, source_dirty=None, repository_cache=None, nixpkgs_source=None):
    if arguments == ['run','//tools:yoga_sealed_transfer_stage']:
        import guard_yoga_sealed_transfer_profile as delivery_profile
    elif arguments == ['run', '//tools:yoga_install_inputs_stage']:
        import guard_yoga_install_inputs_profile as delivery_profile
    else:
        import guard_yoga_delivery_profile as delivery_profile
    delivery_profile.selected(arguments)
    # The standard constructor keeps rejecting general run verbs. Its fixed
    # local build options are reused, then one exact reviewed run replaces build.
    command = bazel_command(bazel, run, ['build', arguments[1]],
                            source_commit=source_commit, source_dirty=source_dirty,
                            repository_cache=repository_cache, nixpkgs_source=nixpkgs_source)
    command[command.index('build')] = 'run'
    values = delivery_profile.envelope(deadline_ns, arguments, prior['sha256'] if prior else None)
    options = delivery_profile.run_options(values)
    if prior is None:
        options += ['--run_env=OMUX_YOGA_DELIVERY_AUTHORITY_SHA256=']
    # Empty repo_env clears an inherited qualification selection for qualify.
    options += ['--repo_env=OMUX_YOGA_DELIVERY_QUALIFICATION=' + (prior['path'] if prior else ''),
                '--symlink_prefix=' + str(Path(run) / 'bazel-')]
    if arguments in (['run','//tools:yoga_sealed_transfer_stage'],['run', '//tools:yoga_install_inputs_stage']):
        options += ['--repository_disable_download']
        if repository_cache is not None:
            options += ['--repo_contents_cache=']
    command[-1:-1] = options
    return command, values

def worker(run, command):
    if os.environ.get('OMUX_EXECUTION_GUARD') != str(run):
        raise ValueError('worker ownership marker missing')
    deadline = time.monotonic() + 30
    while not (run / 'go').exists():
        if time.monotonic() >= deadline:
            return 125
        time.sleep(0.05)
    descriptor = os.open(run / 'workload.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        total = 0
        while True:
            data = process.stdout.read1(65536)
            if not data:
                break
            total += len(data)
            if total > LIMIT:
                process.kill()
                return 125
            output.write(data)
            output.flush()
        return process.wait()


def record_resident_lifecycle(receipt,admission,*,clock=time.monotonic_ns):
    """Append only after the actual final outer verdict; no effect authority."""
    if admission is None or receipt.get('profile') != 'resident-continuity':
        return
    try:
        observation = admission.lifecycle_attempt(receipt,clock())
    except (AttributeError,OSError,ValueError,KeyError,TypeError,IndexError):
        # Measurement loss never changes an effect, cached result or original
        # guard verdict, and cannot become an optimistic successful sample.
        observation = {'schema_version':1,'state':'unavailable','cause':'projection_refused',
            'native_proof_admitted':False,'safe_refusal_proven':False,
            'complete_supported_demand_coverage':False,'achieved_slo':False}
    receipt['resident_continuity']['lifecycle_attempt'] = observation

def main(argv=None):
    with ExitStack() as admission_resources:
        return _main(argv, admission_resources)


def _main(argv, admission_resources):
    # Delivery's one deadline begins before parsing/tool validation/bootstrap.
    # Other profiles keep their existing deadlines and execution behavior.
    delivery_entry_monotonic_ns = time.monotonic_ns()
    delivery_entry_deadline_ns = delivery_entry_monotonic_ns + 1200 * 10**9
    global DIAGNOSTIC_STAGE
    DIAGNOSTIC_STAGE = 'arguments/profile'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path)
    parser.add_argument('--python')
    parser.add_argument('--systemd-run')
    parser.add_argument('--systemctl')
    parser.add_argument('--bazel')
    parser.add_argument('--closure')
    parser.add_argument('--bootstrap-closure')
    parser.add_argument('--zig-sdk')
    parser.add_argument('--java-home')
    parser.add_argument('--repository-cache', type=Path)
    parser.add_argument('--nixpkgs-source', type=Path)
    parser.add_argument('--site-source', type=Path)
    parser.add_argument('--site-nixpkgs-source', type=Path)
    parser.add_argument('--site-inventory', type=Path)
    parser.add_argument('--site-inventory-sha256')
    parser.add_argument('--site-phase', choices=('qualification', 'checks', 'build', 'archive', 'import', 'lock', 'fetch'))
    parser.add_argument('--site-qualification', type=Path)
    parser.add_argument('--site-qualification-sha256')
    parser.add_argument('--site-delivery-manifest', type=Path)
    parser.add_argument('--site-delivery-manifest-sha256')
    parser.add_argument('--source-commit')
    parser.add_argument('--source-dirty', choices=('true', 'false'))
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('--initialize-state-dir', action='store_true')
    parser.add_argument('--coordination-dir', type=Path)
    parser.add_argument('--profile', choices=('home-manager-reconstruction-reserved','home-manager-evaluation-reserved','home-manager-bundle-models-reserved','standard', 'dependency-prefetch', 'installed-browser', 'codex-sdk', 'codex-native', 'site', 'yoga-toolbar', 'yoga-controller-delivery', 'yoga-install-inputs','yoga-controller-qualify-reserved','yoga-controller-inspect-reserved','yoga-controller-verify-reserved','yoga-sealed-workspace-stage','yoga-sealed-workspace-models-reserved', 'codex-live', 'resident-continuity', 'resident-namespace', 'resident-sources', 'resident-enrollment', 'native-login-ui', 'codex-login', 'codex-device-component', 'codex-device-component-reserved', 'native-seed-plan-reserved', 'native-seed-plan-reserved-models', 'default-archive-reserved', 'query-registration-reserved', 'resident-models-reserved', 'resident-owner-status-source-reserved', 'resident-owner-status-binding-reserved', 'resident-owner-status-persistence-source-reserved','resident-native-source-context-source-reserved','resident-native-source-context-refresh-source-reserved','resident-native-source-acquisition-source-reserved','native-acquisition-inputs-models-reserved','native-acquisition-binding-reserved','native-acquisition-metadata-reserved','native-acquisition-sdk-reserved','native-acquisition-plan-reserved','native-acquisition-query-reserved','native-acquisition-compilation-reserved','native-acquisition-runtime-qualification-reserved','native-acquisition-package-reserved','native-acquisition-bridge-material-reserved','native-acquisition-bridge-models-reserved','native-acquisition-ordinary-tui-reserved','native-acquisition-ordinary-models-reserved','native-acquisition-package-models-reserved','resident-native-source-context-metadata-reserved','native-peer-qualification-reserved', 'resident-owner-status-persistence-binding-reserved','native-metadata-sdk-models-reserved','native-query-descriptor-reserved','native-persistence-metadata-reserved','native-persistence-sdk-reserved','native-persistence-package-models-reserved','resident-custody-runtime-models-reserved','resident-custody-runtime-reserved','resident-custody-runtime-linux-reserved','resident-custody-runtime-format-reserved','resident-installed-custody-models-reserved','resident-default-source-models-reserved','resident-native-acquisition-units-reserved','resident-native-deployment-wiring-units-reserved','resident-lifecycle-accounting-models-reserved', 'yoga-installed-selection-reserved', 'yoga-installed-workspace-reserved', 'yoga-installed-models-reserved', 'yoga-toolbar-reserved', 'yoga-toolbar-reserved-models'), default='standard')
    parser.add_argument('--yoga-installed-producer-selection-sha256')
    parser.add_argument('--native-mode')
    parser.add_argument('--native-source-root', type=Path)
    parser.add_argument('--native-source-sha256')
    parser.add_argument('--native-export-root', type=Path)
    parser.add_argument('--native-export-sha256')
    parser.add_argument('--native-patch-sha256', action='append')
    parser.add_argument('--native-owned-candidate-cache', action='store_true')
    parser.add_argument('--native-cache-attempt', type=int)
    parser.add_argument('--native-cache-transition', type=Path)
    parser.add_argument('--native-cache-transition-sha256')
    parser.add_argument('--native-cache-phase2', type=Path)
    parser.add_argument('--native-cache-phase2-sha256')
    parser.add_argument('--native-fresh-completion', type=Path)
    parser.add_argument('--native-fresh-completion-sha256')
    parser.add_argument('--native-global-attempt', type=int)
    parser.add_argument('--native-staged-compilation', type=Path)
    parser.add_argument('--native-staged-compilation-sha256')
    parser.add_argument('--native-stage', type=int)
    parser.add_argument('--native-protocol-history', type=Path)
    parser.add_argument('--native-protocol-history-sha256')
    parser.add_argument('--native-protocol-stage', type=int)
    parser.add_argument('--native-protocol-cli', type=Path)
    parser.add_argument('--native-protocol-cli-sha256')
    parser.add_argument('--yoga-delivery-epoch')
    parser.add_argument('--yoga-sealed-transfer-input')
    parser.add_argument('--yoga-sealed-transfer-input-sha256')
    parser.add_argument('--yoga-qualification', type=Path)
    parser.add_argument('--yoga-qualification-sha256')
    parser.add_argument('--yoga-deadline-monotonic-ns', type=int)
    parser.add_argument('--sdk-lane', choices=('core', 'app-server', 'protocol'))
    parser.add_argument('--sdk-source-root', type=Path)
    parser.add_argument('--sdk-source-receipt-sha256')
    parser.add_argument('--sdk-settings-root', type=Path)
    parser.add_argument('--sdk-settings-receipt-sha256')
    parser.add_argument('--sdk-bundle', type=Path)
    parser.add_argument('--sdk-bundle-receipt-sha256')
    parser.add_argument('--codex-pack-directory', type=Path)
    parser.add_argument('--codex-recovery-source', type=Path)
    parser.add_argument('--codex-pristine-directory', type=Path)
    parser.add_argument('--codex-recovery-delta-directory', type=Path)
    parser.add_argument('--codex-owner-runtime-directory', type=Path)
    parser.add_argument('--codex-live-manifest', type=Path)
    parser.add_argument('--codex-login-manifest', type=Path)
    parser.add_argument('--codex-component-manifest', type=Path)
    parser.add_argument('--codex-component-manifest-sha256')
    parser.add_argument('--codex-login-manifest-sha256')
    parser.add_argument('--native-login-directory', type=Path)
    parser.add_argument('--native-login-sha256')
    parser.add_argument('--native-login-source-receipt-sha256')
    parser.add_argument('--native-login-ui-qualification-sha256')
    parser.add_argument('--ui-prepare-manifest', type=Path)
    parser.add_argument('--ui-prepare-output', type=Path)
    parser.add_argument('--ui-prepare-manifest-sha256')
    parser.add_argument('--ui-prepare-os-qualification-sha256')
    parser.add_argument('--ui-prepare-control-sha256')
    parser.add_argument('--resident-enrollment-manifest', type=Path)
    parser.add_argument('--resident-vault-manifest', type=Path)
    parser.add_argument('--resident-manifest', type=Path)
    parser.add_argument('--resident-epoch')
    parser.add_argument('--resident-producer-sha256')
    parser.add_argument('--resident-observer-sha256')
    parser.add_argument('--resident-runtime-selection', type=Path)
    parser.add_argument('--resident-runtime-sha256')
    parser.add_argument('--resident-runtime-bytes', type=int)
    parser.add_argument('--resident-native-version')
    parser.add_argument('--codex-fresh-runtime-selection')
    parser.add_argument('--codex-fresh-runtime-sha256')
    parser.add_argument('--codex-fresh-runtime-bytes',type=int)
    parser.add_argument('--manager', choices=('user', 'system'), default='user')
    parser.add_argument('--become-file', type=Path)
    parser.add_argument('--reuse-owned-cache', action='store_true')
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
    import guard_resident_dispatch as resident_dispatch
    resident_settings = resident_dispatch.select(args, arguments)
    import guard_native_seed_plan_reserved as seed_reserved
    if args.profile == 'default-archive-reserved':
        import guard_default_archive_reserved as seed_reserved
    elif args.profile == 'query-registration-reserved':
        import guard_query_registration_reserved as seed_reserved
    elif args.profile == 'resident-models-reserved':
        import guard_resident_models_reserved as seed_reserved
    elif args.profile == 'resident-owner-status-source-reserved':
        import guard_resident_owner_status_source_reserved as seed_reserved
    elif args.profile == 'resident-owner-status-binding-reserved':
        import guard_resident_owner_status_binding_reserved as seed_reserved
    elif args.profile == 'resident-owner-status-persistence-source-reserved':
        import guard_resident_owner_status_persistence_source_reserved as seed_reserved
    elif args.profile == 'resident-native-source-context-source-reserved':
        import guard_resident_native_source_context_source_reserved as seed_reserved
    elif args.profile == 'resident-native-source-context-refresh-source-reserved':
        import guard_resident_native_source_context_refresh_source_reserved as seed_reserved
    elif args.profile == 'resident-native-source-acquisition-source-reserved':
        import guard_resident_native_source_acquisition_source_reserved as seed_reserved
    elif args.profile in ('native-acquisition-inputs-models-reserved','native-acquisition-binding-reserved','native-acquisition-metadata-reserved','native-acquisition-sdk-reserved','native-acquisition-plan-reserved','native-acquisition-query-reserved','native-acquisition-compilation-reserved','native-acquisition-runtime-qualification-reserved','native-acquisition-package-reserved','native-acquisition-bridge-material-reserved','native-acquisition-bridge-models-reserved','native-acquisition-ordinary-tui-reserved','native-acquisition-ordinary-models-reserved','native-acquisition-package-models-reserved'):
        import guard_native_acquisition_inputs_reserved as seed_reserved
    elif args.profile in ('home-manager-reconstruction-reserved','home-manager-evaluation-reserved','home-manager-bundle-models-reserved'):
        import guard_home_manager_bundle_reserved as seed_reserved
    elif args.profile == 'native-peer-qualification-reserved':
        import guard_native_peer_qualification_reserved as seed_reserved
    elif args.profile == 'resident-native-source-context-metadata-reserved':
        import guard_resident_native_source_context_metadata_reserved as seed_reserved
    elif args.profile == 'resident-owner-status-persistence-binding-reserved':
        import guard_resident_owner_status_persistence_binding_reserved as seed_reserved
    elif args.profile in ('native-metadata-sdk-models-reserved','native-query-descriptor-reserved','native-persistence-metadata-reserved','native-persistence-sdk-reserved','native-persistence-package-models-reserved'):
        import guard_native_metadata_sdk_reserved as seed_reserved
    elif args.profile in ('resident-custody-runtime-models-reserved','resident-custody-runtime-reserved','resident-custody-runtime-linux-reserved','resident-custody-runtime-format-reserved','resident-installed-custody-models-reserved','resident-default-source-models-reserved','resident-native-acquisition-units-reserved','resident-native-deployment-wiring-units-reserved','resident-lifecycle-accounting-models-reserved'):
        import guard_resident_custody_runtime_reserved as seed_reserved
    elif args.profile in ('yoga-installed-selection-reserved','yoga-installed-workspace-reserved','yoga-installed-models-reserved'):
        import guard_yoga_installed_reserved as seed_reserved
    elif args.profile == 'yoga-toolbar-reserved-models':
        import guard_yoga_toolbar_reserved as seed_reserved
    elif args.profile in ('yoga-controller-qualify-reserved','yoga-controller-inspect-reserved','yoga-controller-verify-reserved'):
        import guard_yoga_controller_qualify_reserved as seed_reserved
    elif args.profile == 'yoga-sealed-workspace-models-reserved':
        import guard_yoga_sealed_transfer_models_reserved as seed_reserved
    import guard_yoga_toolbar_reserved as toolbar_reserved
    yoga_toolbar_reserved = args.profile == toolbar_reserved.PROFILE
    if yoga_toolbar_reserved:
        toolbar_reserved.request(args,arguments)
    seed_selected = seed_reserved.request(args,arguments)
    reservation_selected = seed_selected or yoga_toolbar_reserved
    reservation_helper = toolbar_reserved if yoga_toolbar_reserved else seed_reserved
    yoga_reserved = args.profile in ('yoga-installed-selection-reserved','yoga-installed-workspace-reserved','yoga-installed-models-reserved')
    if args.yoga_installed_producer_selection_sha256 is not None and args.profile != 'yoga-installed-workspace-reserved':
        raise ValueError('installed Yoga input is exclusive to the reserved workspace profile')
    yoga_installed_input,yoga_installed_before,yoga_installed_after = None,None,None
    yoga_installed_verified_after = None
    seed_reservation,seed_verified_after,seed_after = None,None,None
    seed_failure = None
    resident_input = None
    resident_verified_after = None
    resident_output = None
    if args.worker:
        return worker(args.worker, arguments)
    dev_stage_proof = dev_stage_request(args.profile,args.manager,arguments,args.reuse_owned_cache,
        delivery_entry_monotonic_ns,delivery_entry_deadline_ns)
    dev_stage_verified_after = None
    sdk = None
    sdk_plan = None
    sdk_source_verified_after = None
    native_sdk = None
    native_plan = None
    native_verified_after = None
    native_controller_graph = None
    native_cache = None
    native_fresh = None
    native_staged = None
    native_history = None
    native_cli = None
    native_inputs = (args.native_mode, args.native_source_root, args.native_source_sha256,
                     args.native_export_root, args.native_export_sha256, args.native_patch_sha256)
    if args.profile == 'codex-native':
        cli_selected = any(value is not None for value in (args.native_protocol_cli, args.native_protocol_cli_sha256))
        if cli_selected:
            import codex_protocol_history_cli as cli_profile
            cli_selected = cli_profile.selected(args)
        history_selected = any(value is not None for value in (args.native_protocol_history,
            args.native_protocol_history_sha256, args.native_protocol_stage))
        if history_selected:
            import codex_protocol_history_native as history_profile
            history_selected = history_profile.selected(args)
        import codex_native_fresh_completion as fresh_completion
        import codex_native_staged_compilation as staged_compilation
        fresh_completion_selected = fresh_completion.selected(args)
        staged_compilation_selected = staged_compilation.selected(args)
        if args.native_mode == 'staged-libraries' and not staged_compilation_selected:
            raise ValueError('fixed libraries require independently selected staged compilation')
        if args.native_owned_candidate_cache != (args.native_cache_attempt is not None):
            raise ValueError('native continuation requires explicit finite attempt')
        if (args.native_cache_transition is None) != (args.native_cache_transition_sha256 is None):
            raise ValueError('native transition requires one exact reviewed amendment pin')
        if args.native_cache_transition is not None and (not args.native_owned_candidate_cache
            or args.manager != 'system' or args.native_cache_attempt not in (5, 6)
            or args.native_mode not in ('qualification-cli', 'schema')):
            raise ValueError('native transition restricted to final C26 combined and schema invocations')
        if (args.native_cache_phase2 is None) != (args.native_cache_phase2_sha256 is None):
            raise ValueError('native phase2 requires one exact reviewed amendment pin')
        phase2_selected = args.native_cache_phase2 is not None
        if phase2_selected and (args.native_cache_transition is not None
            or args.native_cache_transition_sha256 is not None
            or not args.native_owned_candidate_cache or args.manager != 'system'
            or (args.native_mode, args.native_cache_attempt) not in (('qualification-cli', 6), ('schema', 7))):
            raise ValueError('native phase2 restricted to exact completion retry and independent schema')
        if args.native_cache_attempt is not None and not 1 <= args.native_cache_attempt <= (7 if phase2_selected else 6):
            raise ValueError('native continuation exceeds explicitly selected finite phase')
        args.native_aggregate_seconds = 3600 if phase2_selected or fresh_completion_selected or staged_compilation_selected or history_selected or cli_selected else 1200
        if cli_selected:
            native_sdk = cli_profile
        elif history_selected:
            native_sdk = history_profile
        else:
            import codex_native_profile as native_sdk
        args.native_deadline = delivery_entry_deadline_ns / 10**9
        if arguments or args.native_mode not in native_sdk.MODES or any(v is None for v in native_inputs):
            raise ValueError('native profile requires finite mode and independent receipts')
        if args.reuse_owned_cache or any(v is not None for v in (
            getattr(args, 'codex_live_manifest', None),
            args.repository_cache, args.nixpkgs_source, args.site_source, args.site_inventory,
            args.site_inventory_sha256, args.site_nixpkgs_source, args.site_phase, args.site_qualification,
            args.site_qualification_sha256, args.site_delivery_manifest, args.site_delivery_manifest_sha256,
            args.codex_pack_directory, args.codex_recovery_source, args.codex_pristine_directory,
            args.codex_recovery_delta_directory, args.codex_owner_runtime_directory,
            args.sdk_lane, args.sdk_source_root, args.sdk_source_receipt_sha256, args.sdk_settings_root,
            args.sdk_settings_receipt_sha256, args.sdk_bundle, args.sdk_bundle_receipt_sha256,
            args.yoga_delivery_epoch, args.yoga_qualification, args.yoga_qualification_sha256,
            args.yoga_deadline_monotonic_ns)):
            raise ValueError('native profile refuses unrelated profile inputs and cache reuse')
        if args.state_dir != native_sdk.STATE:
            raise ValueError('native profile requires fixed fresh fast state')
        arguments = [native_sdk.MODES[args.native_mode][0], *native_sdk.MODES[args.native_mode][1]]
    elif any(v is not None for v in native_inputs) or args.native_owned_candidate_cache or args.native_cache_attempt is not None or args.native_cache_transition is not None or args.native_cache_transition_sha256 is not None or args.native_cache_phase2 is not None or args.native_cache_phase2_sha256 is not None or args.native_fresh_completion is not None or args.native_fresh_completion_sha256 is not None or args.native_global_attempt is not None or args.native_staged_compilation is not None or args.native_staged_compilation_sha256 is not None or args.native_stage is not None or args.native_protocol_history is not None or args.native_protocol_history_sha256 is not None or args.native_protocol_stage is not None or args.native_protocol_cli is not None or args.native_protocol_cli_sha256 is not None:
        raise ValueError('native inputs are exclusive to native profile')
    site = None
    site_qualification = None
    site_bindings = {}
    site_snapshot = None
    site_source_verified_after = None
    site_source_changes = []
    site_controller_graph = None
    site_controller_graph_after = None
    site_snapshot_after = None
    site_lock_evidence = {}
    yoga = None
    yoga_admission = None
    yoga_support = None
    yoga_summary = None
    yoga_verified_after = None
    yoga_operator_writer = None
    yoga_worker_identity = None
    if args.profile == 'yoga-sealed-workspace-stage':
        import guard_yoga_sealed_transfer_profile as sealed_transfer
        sealed_transfer.request(args,arguments,delivery_entry_deadline_ns)
        admission_resources.callback(sealed_transfer.close)
    elif args.yoga_sealed_transfer_input is not None or args.yoga_sealed_transfer_input_sha256 is not None:
        raise ValueError('sealed-transfer-input-exclusive-to-exact-stage-profile')
    delivery_settings = None
    delivery_http = None
    delivery_prior = None
    delivery_summary = None
    delivery_verified_after = None
    delivery_runtime_seconds = None
    owner_input = None
    owner_input_verified_after = None
    owner_input_after = None
    live_input = None
    live_input_verified_after = None
    live_binding_readback = None
    fresh_input = None
    fresh_input_verified_after = None
    fresh_input_after = None
    fresh_input_before = None
    import guard_codex_fresh_live_profile as fresh_live
    fresh_selected = fresh_live.finite(args.profile,arguments,args.codex_owner_runtime_directory,
        args.codex_fresh_runtime_selection,args.codex_fresh_runtime_sha256,args.codex_fresh_runtime_bytes)
    if args.profile == 'codex-live':
        import guard_codex_live_profile as live
        live.finite(arguments, args.manager, args.codex_live_manifest,
                    args.codex_owner_runtime_directory, args.reuse_owned_cache,
                    (args.repository_cache, args.nixpkgs_source, args.site_source,
                     args.codex_pack_directory, args.codex_recovery_source,
                     args.site_inventory, args.site_inventory_sha256, args.site_nixpkgs_source,
                     args.site_phase, args.site_qualification, args.site_qualification_sha256,
                     args.site_delivery_manifest, args.site_delivery_manifest_sha256,
                     args.codex_pristine_directory, args.codex_recovery_delta_directory,
                     args.sdk_lane, args.sdk_source_root, args.sdk_source_receipt_sha256,
                     args.sdk_settings_root, args.sdk_settings_receipt_sha256, args.sdk_bundle,
                     args.sdk_bundle_receipt_sha256, args.yoga_delivery_epoch,
                     args.yoga_qualification, args.yoga_qualification_sha256, args.yoga_deadline_monotonic_ns),
                    fresh_runtime=fresh_selected)
    elif args.codex_live_manifest is not None:
        raise ValueError('codex-live-input-exclusive-to-live-profile')
    delivery_lock = None
    delivery_lock_verified_before_cleanup = None
    if args.codex_owner_runtime_directory is not None:
        from guard_owner_runtime_input import finite as retained_finite
        retained_finite(args.profile, arguments, (
            args.nixpkgs_source, args.site_source, args.site_inventory, args.site_inventory_sha256,
            args.site_nixpkgs_source, args.site_phase, args.site_qualification,
            args.site_qualification_sha256, args.site_delivery_manifest,
            args.site_delivery_manifest_sha256, args.codex_pack_directory, args.codex_recovery_source,
            args.codex_pristine_directory, args.codex_recovery_delta_directory,
            args.sdk_lane, args.sdk_source_root, args.sdk_source_receipt_sha256,
            args.sdk_settings_root, args.sdk_settings_receipt_sha256,
            args.sdk_bundle, args.sdk_bundle_receipt_sha256, args.yoga_delivery_epoch,
            args.yoga_qualification, args.yoga_qualification_sha256, args.yoga_deadline_monotonic_ns))
    if args.profile in ('yoga-controller-delivery','yoga-controller-qualify-reserved','yoga-controller-inspect-reserved','yoga-controller-verify-reserved','yoga-install-inputs','yoga-sealed-workspace-stage'):
        if args.profile in ('yoga-controller-qualify-reserved','yoga-controller-inspect-reserved','yoga-controller-verify-reserved'):
            import guard_yoga_controller_qualify_reserved as delivery_settings
        elif args.profile == 'yoga-sealed-workspace-stage':
            import guard_yoga_sealed_transfer_profile as delivery_settings
        elif args.profile == 'yoga-install-inputs':
            import guard_yoga_install_inputs_profile as delivery_settings
        else:
            import yoga_delivery_settings as delivery_settings
        delivery_settings.finite(arguments, args.manager, args.yoga_delivery_epoch,
            (args.reuse_owned_cache,
             args.repository_cache if args.profile not in ('yoga-install-inputs','yoga-sealed-workspace-stage') else False,
             args.nixpkgs_source if args.profile not in ('yoga-install-inputs','yoga-sealed-workspace-stage') else False, args.site_source,
             args.site_nixpkgs_source, args.site_inventory, args.site_inventory_sha256, args.site_phase,
             args.site_qualification, args.site_qualification_sha256, args.site_delivery_manifest,
             args.site_delivery_manifest_sha256, args.codex_pack_directory, args.codex_recovery_source,
             args.codex_pristine_directory, args.codex_recovery_delta_directory, args.yoga_qualification,
             args.yoga_qualification_sha256, args.yoga_deadline_monotonic_ns, args.sdk_lane, args.sdk_source_root,
             args.sdk_source_receipt_sha256, args.sdk_settings_root, args.sdk_settings_receipt_sha256,
             args.sdk_bundle, args.sdk_bundle_receipt_sha256))
        delivery_settings.budget(delivery_entry_deadline_ns, 30 * 10**9)
        if args.profile in ('yoga-install-inputs','yoga-sealed-workspace-stage'):
            import guard_resident_enrollment_profile as repository_policy
            repository_policy.repository_inputs(args.repository_cache,args.nixpkgs_source)
    elif args.yoga_delivery_epoch is not None:
        raise ValueError('prior Yoga delivery epoch is exclusive to its fixed read-only profile')
    if args.profile in ('yoga-toolbar','yoga-toolbar-reserved'):
        import guard_yoga_profile as yoga
        if yoga_toolbar_reserved:
            toolbar_reserved.finite(args.manager,arguments)
        else:
            yoga.finite(args.profile, args.manager, arguments)
        if (any(value is None for value in (args.yoga_qualification, args.yoga_qualification_sha256,
                args.yoga_deadline_monotonic_ns)) or args.reuse_owned_cache or
                any(value is not None for value in (args.repository_cache, args.site_source, args.site_phase,
                args.site_inventory, args.site_inventory_sha256, args.site_nixpkgs_source, args.nixpkgs_source,
                args.codex_pack_directory, args.codex_recovery_source, args.codex_pristine_directory,
                args.codex_recovery_delta_directory))):
            raise ValueError('Yoga requires qualified local seat inputs without cache/site/acquisition/SDK lanes')
        yoga.display.budget(args.yoga_deadline_monotonic_ns)
        yoga.selectors(args.yoga_qualification, args.state_dir, Path.cwd(), Path(pwd.getpwuid(os.getuid()).pw_dir))
        if not isinstance(args.yoga_qualification_sha256, str) or not yoga.SHA.fullmatch(args.yoga_qualification_sha256):
            raise ValueError('Yoga requires an independently selected qualification SHA256')
    elif any(value is not None for value in (args.yoga_qualification, args.yoga_qualification_sha256,
                                            args.yoga_deadline_monotonic_ns)):
        raise ValueError('Yoga seat inputs are exclusive to its local profile')
    if args.profile == 'site':
        import guard_site_profile as site
        if (any(value is None for value in (args.site_phase, args.site_source, args.site_inventory,
                args.site_inventory_sha256, args.site_qualification, args.site_qualification_sha256)) or
                any(value is not None for value in (args.zig_sdk, args.nixpkgs_source, args.site_nixpkgs_source,
                args.codex_pack_directory, args.codex_recovery_source, args.codex_pristine_directory,
                args.codex_recovery_delta_directory, args.sdk_lane, args.sdk_source_root, args.sdk_source_receipt_sha256,
                args.sdk_settings_root, args.sdk_settings_receipt_sha256, args.sdk_bundle, args.sdk_bundle_receipt_sha256))):
            raise ValueError('site requires independent complete qualification and inventory without runtime/SDK inputs')
        if args.site_phase == 'import':
            if (args.site_delivery_manifest is None or args.site_delivery_manifest_sha256 is None or
                    arguments != ['run', '//:import_extension_delivery', '--', '--manifest',
                                  str(args.site_delivery_manifest), '--sha256', args.site_delivery_manifest_sha256]):
                raise ValueError('site import requires the exact admitted runtime metadata path and digest')
        else:
            site.finite_phase(args.site_phase, arguments)
            if args.site_delivery_manifest is not None or args.site_delivery_manifest_sha256 is not None:
                raise ValueError('delivery metadata selection is exclusive to site import')
        site_controller_graph = graph_digest(Path.cwd())
    elif any(value is not None for value in (args.site_phase, args.site_qualification,
            args.site_qualification_sha256, args.site_delivery_manifest, args.site_delivery_manifest_sha256)):
        raise ValueError('finite site inputs are exclusive to the site profile')
    if args.profile == 'codex-sdk':
        import codex_sdk_profile as sdk
        if arguments or args.sdk_lane is None or any(value is None for value in
                (args.sdk_source_root, args.sdk_source_receipt_sha256, args.sdk_settings_root,
                 args.sdk_settings_receipt_sha256, args.sdk_bundle, args.sdk_bundle_receipt_sha256)):
            raise ValueError('SDK requires one explicit lane and all retained receipts without caller arguments')
        arguments = ['test', sdk.LANES[args.sdk_lane][0]]
    elif any(value is not None for value in (args.sdk_lane, args.sdk_source_root, args.sdk_source_receipt_sha256,
            args.sdk_settings_root, args.sdk_settings_receipt_sha256, args.sdk_bundle, args.sdk_bundle_receipt_sha256)):
        raise ValueError('SDK inputs are exclusive to the SDK profile')
    if os.environ.get('OMUX_EXECUTION_GUARD'):
        raise ValueError('recursive launcher reentry rejected')
    isolation = {**SANDBOX,**selected_profile('yoga-toolbar',arguments)} if yoga_toolbar_reserved else {**SANDBOX,**seed_reserved.selected(args.profile,arguments)} if seed_selected else resident_isolation(resident_settings, args, arguments) if resident_settings else {**SANDBOX, **site.phase_isolation(args.site_phase, arguments)} if site else {**SANDBOX, **selected_profile(args.profile, arguments,
        site_inputs=any((args.site_source, args.site_nixpkgs_source, args.site_inventory,
                         args.site_inventory_sha256, args.nixpkgs_source if args.profile not in ('yoga-install-inputs','yoga-sealed-workspace-stage') else False)),
        pack_input=args.codex_pack_directory is not None,
        recovery_input=args.codex_recovery_source is not None)}
    if args.profile == 'dependency-prefetch' and args.reuse_owned_cache:
        raise ValueError('dependency producer requires a unique retained output base')
    if sdk and (args.repository_cache or args.codex_pristine_directory or args.codex_recovery_delta_directory):
        raise ValueError('SDK refuses unrelated producer/cache inputs')
    if sdk and (args.sdk_bundle != Path('/srv/fast-local/jess/state/codex/omux-dependency-prefetch-20261005/052fde9c-7e07-490f-a940-fb11820f1d31/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/fetch_codex_archives_bundle/test.outputs/bundle') or
               args.sdk_bundle_receipt_sha256 != '1d3d34323a3e19fd7e640146bf0eba006881a9bdd2d376a0493153f4cd8d30a0'):
        raise ValueError('SDK requires the exact retained archive producer receipt')
    mask_profile = 'installed-browser' if yoga else 'standard' if seed_selected or resident_settings or sdk or native_sdk or delivery_settings or args.profile == 'codex-live' else args.profile
    DIAGNOSTIC_STAGE = 'privilege-metadata'
    sudo = None
    if args.manager == 'system':
        if os.getuid() == 0 or args.become_file is None:
            raise ValueError('system manager requires an unprivileged user and explicit become file')
        sudo = validate_sudo()
        descriptor = become_descriptor(args.become_file)
        os.close(descriptor)  # Metadata validation only; never read payload.
    elif args.become_file is not None:
        raise ValueError('become input is exclusive to the system manager')
    DIAGNOSTIC_STAGE = 'tool/closure'
    python, runner, control, bazel = map(immutable, (args.python, args.systemd_run, args.systemctl, args.bazel))
    closure, native, closure_digest = closure_manifest(args.closure)
    bootstrap, host, bootstrap_digest = closure_manifest(args.bootstrap_closure)
    java = store_directory(args.java_home)
    zig = None if site or native_sdk else store_directory(args.zig_sdk)
    if zig is not None:
        immutable(zig / 'zig')
    immutable(java / 'bin/java')
    if str(java) != native['packages']['bazel_jdk']['out']:
        raise ValueError('Java home must match native closure')
    if python != immutable(Path(host['packages']['python']['out']) / 'bin/python3'):
        raise ValueError('Python must match bootstrap closure')
    if control != immutable(native['tools']['systemctl']):
        raise ValueError('systemctl must match native closure')
    if runner != immutable(Path(native['packages']['systemctl']['out']) / 'bin/systemd-run'):
        raise ValueError('systemd-run must match native closure')
    environment = {'OMUX_BAZEL_BOOTSTRAP_CLOSURE': str(bootstrap), 'JAVA_HOME': str(java)}
    if seed_selected:
        seed_reservation = seed_reserved.Witness(delivery_entry_monotonic_ns,delivery_entry_deadline_ns)
        admission_resources.callback(seed_reservation.close)
    if resident_settings:
        resident_input = resident_dispatch.admit(resident_settings,args,Path.cwd(),control,delivery_entry_deadline_ns)
        admission_resources.callback(resident_input.close)
        environment['HOME'] = pwd.getpwuid(os.getuid()).pw_dir
    if not site and not native_sdk:
        environment.update(OMUX_BAZEL_CLOSURE=str(closure), OMUX_ZIG_SDK=str(zig))
    if delivery_settings:
        delivery_settings.budget(delivery_entry_deadline_ns, 30 * 10**9)
        delivery_settings.tools({'python': python, 'systemd_run': runner, 'systemctl': control, 'bazel': bazel,
            'closure': str(closure), 'bootstrap_closure': str(bootstrap), 'zig_sdk': str(zig), 'java_home': str(java)},
            closure_digest, bootstrap_digest)
        # HOME is the same inspected user's native SSH configuration boundary.
        environment['HOME'] = pwd.getpwuid(os.getuid()).pw_dir
        if args.profile in ('yoga-install-inputs','yoga-sealed-workspace-stage'):
            delivery_settings.admit(delivery_entry_deadline_ns)
            if args.profile == 'yoga-install-inputs':
                admission_resources.callback(delivery_settings.AGENT.close)
    if yoga:
        # All live seat/input/closure checks precede state initialization, lock,
        # epoch, cache or unit creation. The selected deadline never restarts.
        preallocate = toolbar_reserved.preallocate if yoga_toolbar_reserved else yoga.preallocate
        yoga_admission = preallocate(args.yoga_qualification, args.yoga_qualification_sha256,
            args.yoga_deadline_monotonic_ns, manager=args.manager, arguments=arguments,
            state_root=args.state_dir, source_root=Path.cwd(), home=Path(pwd.getpwuid(os.getuid()).pw_dir),
            tools={'python': python, 'systemd_run': runner, 'systemctl': control, 'bazel': bazel,
                   'closure': str(closure), 'bootstrap_closure': str(bootstrap), 'zig_sdk': str(zig), 'java_home': str(java)},
            graph_sha256=graph_digest(Path.cwd())[0], uid=os.getuid(), operator_descriptor=sys.stdin.fileno())
        admission_resources.callback(yoga_admission['pin'].close)
        if 'installedCapture' in yoga_admission:
            admission_resources.callback(yoga_admission['installedCapture'].close)
        if yoga_toolbar_reserved:
            delivery_entry_monotonic_ns,delivery_entry_deadline_ns = toolbar_reserved.clock(
                yoga_admission['receipt'],args.yoga_deadline_monotonic_ns)
            seed_reservation = toolbar_reserved.Witness(delivery_entry_monotonic_ns,delivery_entry_deadline_ns)
            admission_resources.callback(seed_reservation.close)
        environment['OMUX_BROWSER_HOST_CONFIGURATION'] = 'host-configurations-unavailable'
    if args.profile == 'yoga-installed-workspace-reserved':
        yoga_installed_input = seed_reserved.admit(args.yoga_installed_producer_selection_sha256,
            Path.cwd(),delivery_entry_deadline_ns)
        admission_resources.callback(yoga_installed_input.close)
        yoga_installed_before = yoga_installed_input.facts()
    coordination = prepare_state(args.state_dir, 'yoga-toolbar' if yoga_toolbar_reserved else seed_reserved.STATE_PROFILE if args.profile in ('yoga-controller-qualify-reserved','yoga-controller-inspect-reserved','yoga-controller-verify-reserved') else 'standard' if seed_selected or resident_settings else 'codex-sdk' if site else args.profile,
                                 args.coordination_dir, args.initialize_state_dir, arguments=arguments)
    DIAGNOSTIC_STAGE = 'operatorinputs'
    if args.codex_owner_runtime_directory is not None:
        from guard_owner_runtime_input import Admission as RetainedAdmission
        owner_input = RetainedAdmission(args.codex_owner_runtime_directory,
            Path.cwd() / 'integrations/codex-owner-runtime/runtime-manifest.json',
            Path.cwd() / 'integrations/codex-owner-runtime/runtime-receipt.json',
            Path.cwd(), delivery_entry_deadline_ns)
        admission_resources.callback(owner_input.close)
    if fresh_selected:
        from guard_fresh_native_runtime_input import Admission as FreshAdmission
        fresh_input = FreshAdmission(args.codex_fresh_runtime_selection,args.codex_fresh_runtime_sha256,
            args.codex_fresh_runtime_bytes,delivery_entry_deadline_ns)
        fresh_input_before = dict(fresh_input.facts)
        admission_resources.callback(fresh_input.close)
    if args.profile == 'codex-live':
        live_input = live.Admission(args.codex_live_manifest, Path.cwd(), delivery_entry_deadline_ns, arguments)
        admission_resources.callback(live_input.close)
    fresh_metadata = selected_fresh_inputs(args.profile, arguments, args.codex_pristine_directory,
                                           args.codex_recovery_delta_directory, private)
    if args.codex_recovery_source is not None:
        args.codex_recovery_source = recovery_source(args.codex_recovery_source, private)
    pack_digests = {}
    if args.codex_pack_directory is not None:
        args.codex_pack_directory, pack_digests = pack_metadata(args.codex_pack_directory)
    if args.repository_cache is not None:
        private(args.repository_cache, owner_only=False)
    if args.nixpkgs_source is not None:
        args.nixpkgs_source = store_directory(args.nixpkgs_source)
    site_digests = {}
    if args.site_source is not None:
        args.site_source, site_digests = selected_site_source(args.site_source)
    if args.site_nixpkgs_source is not None:
        if args.site_source is None:
            raise ValueError('site Nixpkgs input requires explicit sibling source')
        args.site_nixpkgs_source = store_directory(args.site_nixpkgs_source)
    if args.site_inventory is not None or args.site_inventory_sha256 is not None:
        if args.site_inventory is None or args.site_source is None:
            raise ValueError('site inventory requires explicit sibling source and complete selection')
        args.site_inventory = selected_site_inventory(args.site_inventory, args.site_inventory_sha256,
                                                     args.state_dir, coordination)
    if site:
        if bazel != str(site.BAZEL_NATIVE) or java != site.JDK:
            raise ValueError('site dispatch requires the fixed native ELF and JDK')
        args.site_qualification = selected_site_receipt(args.site_qualification,
            args.site_qualification_sha256, args.state_dir, coordination, 'qualification')
        site_qualification = site.read_qualification(args.site_qualification, args.site_qualification_sha256)
        site.source_binding(args.site_source, site_qualification['site_bazelversion_sha256'])
        site_bindings = site.proof_bindings(args.site_inventory, args.site_inventory_sha256,
            selected_site_inventory, args.state_dir, coordination)
        site_bindings['OMUX_BAZEL_BOOTSTRAP_CLOSURE'] = str(bootstrap)
        if args.site_phase == 'import':
            args.site_delivery_manifest = selected_site_receipt(args.site_delivery_manifest,
                args.site_delivery_manifest_sha256, args.state_dir, coordination, 'manifest')
            site_qualification['delivery_manifest'] = str(args.site_delivery_manifest)
            site.importer_arguments(args.site_delivery_manifest, args.site_delivery_manifest_sha256,
                                    site_qualification['delivery_manifest'])
        site_snapshot = site.source_snapshot(args.site_source)
    DIAGNOSTIC_STAGE = 'lock'
    lockfd = os.open(coordination / 'execution.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lockfd, 'w') as lock, ExitStack() as resources:
        metadata = os.fstat(lock.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise ValueError('private lock ownership rejected')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if delivery_settings:
            delivery_settings.budget(delivery_entry_deadline_ns, 30 * 10**9)
            delivery_lock = delivery_settings.lock_witness(lock.fileno(), delivery_entry_deadline_ns)
            delivery_initial_graph = graph_digest(Path.cwd())[0]
            if args.profile == 'yoga-sealed-workspace-stage':
                delivery_settings.schema.require(delivery_settings.VALUE['producerGraphSha256']==delivery_initial_graph)
            delivery_prior = delivery_settings.select_prior(args.yoga_delivery_epoch, delivery_initial_graph,
                PROPERTIES, delivery_entry_deadline_ns, delivery_lock,
                **({'source_commit':args.source_commit} if args.profile in
                    ('yoga-controller-inspect-reserved','yoga-controller-verify-reserved') else {})) if args.yoga_delivery_epoch else None
        identifier = args.resident_epoch if args.profile in resident_dispatch.PROFILES else yoga_admission['receipt']['proofId'] if yoga else str(uuid.uuid4())
        run = args.state_dir / identifier
        run.mkdir(mode=0o700)
        if yoga_installed_input is not None:
            (run / 'home').mkdir(mode=0o700)
            (run / 'tmp').mkdir(mode=0o700)
            environment.update(HOME=str(run / 'home'),TMPDIR=str(run / 'tmp'))
        if resident_input is not None:
            resident_input.bind_run(run)
            environment.update(resident_input.environment())
        if yoga:
            import yoga_operator_launch as yoga_launch
            (run / 'home').mkdir(mode=0o700)
            environment['HOME'] = str(run / 'home')
            resources.callback(yoga_admission['pin'].close)
            yoga_support = yoga.coordinator.Coordinator(profile=args.profile, manager=args.manager, arguments=arguments,
                proof_id=identifier, proof_root=str(run), source_socket=yoga_admission['witness']['source'], uid=os.getuid(),
                deadline_ns=args.yoga_deadline_monotonic_ns, input_digests=yoga_admission['receipt']['inputSha256'],
                vault_wrapper_authority=yoga_admission['receipt']['vaultWrapperAuthority'],
                source_root=yoga_admission['receipt']['sourceRoot'], source_files_sha256=yoga_admission['receipt']['sourceFilesSha256'],
                **({'original_entry_ns':delivery_entry_monotonic_ns} if yoga_toolbar_reserved else {}))
            resources.callback(yoga_support.close)
            yoga_support.witness = yoga_admission['witness']
            operator_read, yoga_operator_writer = os.pipe()
            resources.callback(os.close, yoga_operator_writer)
            try:
                yoga_support.retain_operator_channel(operator_read)
            finally:
                os.close(operator_read)
        DIAGNOSTIC_STAGE = 'private-epoch'
        if args.profile in ('yoga-controller-qualify-reserved','yoga-controller-inspect-reserved','yoga-controller-verify-reserved'):
            delivery_http = delivery_settings.http_snapshot(run,delivery_entry_monotonic_ns,delivery_entry_deadline_ns)
            resources.callback(delivery_http.close)
        if args.profile == resident_dispatch.SETUP_PROFILE:
            command = resident_enrollment_command(bazel,run,arguments,resident_input.inner,
                source_commit=args.source_commit,source_dirty=args.source_dirty,
                repository_cache=args.repository_cache,nixpkgs_source=args.nixpkgs_source)
        elif resident_input is not None:
            command = resident_dispatch.command(bazel_command,bazel,run,arguments,resident_input,
                source_commit=args.source_commit,source_dirty=args.source_dirty,
                repository_cache=args.repository_cache,nixpkgs_source=args.nixpkgs_source)
        elif seed_selected:
            seed_command_options = ({'admission':yoga_installed_input} if yoga_reserved else
                {'prior':delivery_prior} if args.profile in
                    ('yoga-controller-qualify-reserved','yoga-controller-inspect-reserved','yoga-controller-verify-reserved') else {})
            command = seed_reserved.command(bazel_command,bazel,run,arguments,args.profile,
                delivery_entry_monotonic_ns,delivery_entry_deadline_ns,
                repository_cache=args.repository_cache,nixpkgs_source=args.nixpkgs_source,
                source_commit=args.source_commit,source_dirty=args.source_dirty,**seed_command_options)
        elif delivery_settings:
            command, delivery_envelope = yoga_delivery_command(bazel, run, arguments, delivery_entry_deadline_ns,
                delivery_prior, source_commit=args.source_commit, source_dirty=args.source_dirty,
                repository_cache=args.repository_cache,nixpkgs_source=args.nixpkgs_source)
            environment.update(delivery_envelope)
        elif yoga:
            yoga.publish_repository_inventory(yoga_admission, run)
            command = yoga_command(bazel, run, arguments, yoga_admission, manager=args.manager,
                                   source_commit=args.source_commit, source_dirty=args.source_dirty)
        elif native_sdk:
            if bazel != native_sdk.BAZEL:
                raise ValueError('native profile requires locked Bazel9')
            command = []
        else:
            command = site.command(bazel, java, site_qualification, run / 'output-base',
                               args.site_phase, arguments, site_bindings, run) if site else bazel_command(bazel, run, arguments, args.repository_cache,
                                args.source_commit, args.source_dirty, args.nixpkgs_source,
                                site_source=args.site_source, site_inventory=args.site_inventory,
                                site_inventory_sha256=args.site_inventory_sha256,
                                site_nixpkgs_source=args.site_nixpkgs_source,
                                codex_pack_directory=args.codex_pack_directory, profile=args.profile,
                                codex_recovery_source=args.codex_recovery_source,
                                codex_pristine_directory=args.codex_pristine_directory,
                                codex_recovery_delta_directory=args.codex_recovery_delta_directory,
                                codex_owner_runtime_directory=args.codex_owner_runtime_directory,
                                codex_fresh_runtime_selection=args.codex_fresh_runtime_selection,
                                codex_fresh_runtime_sha256=args.codex_fresh_runtime_sha256,
                                codex_fresh_runtime_bytes=args.codex_fresh_runtime_bytes)
        workload_cwd = args.site_source if site else Path.cwd()
        if dev_stage_proof:
            command = dev_stage_command(command,run,delivery_entry_monotonic_ns,delivery_entry_deadline_ns)
        if native_sdk:
            # PATH and Bash are explicit immutable bootstrap closure inputs.
            locked_path = ':'.join(host['packages'][name]['out'] + '/bin' for name in ('bash', 'coreutils', 'python', 'git'))
            bash = immutable(Path(host['packages']['bash']['out']) / 'bin/bash')
            native_controller_graph = graph_digest(Path.cwd())
            if args.native_owned_candidate_cache or fresh_completion_selected or staged_compilation_selected or history_selected or cli_selected:
                from codex_native_candidate_cache import Candidate
                def previous_empty(previous):
                    if previous['manager'] != args.manager:
                        return False
                    unit_name = previous['unit']
                    if not re.fullmatch(r'omux-execution-[0-9a-f-]{36}\.service', unit_name):
                        return False
                    def query(parts):
                        return controller_run(parts, operation='unit-readback', phase='qualification',
                            diagnose=lambda row: None, deadline=args.native_deadline)
                    listing = query([control, '--' + args.manager, 'list-units', '--all', '--plain', '--no-legend', unit_name])
                    if listing.strip():
                        actual_previous = properties(query([control, '--' + args.manager, 'show', '--all', unit_name]))
                        if actual_previous.get('ActiveState') not in ('inactive', 'failed') or actual_previous.get('MainPID') != '0':
                            return False
                    group = previous['observed_properties'].get('ControlGroup')
                    if not isinstance(group, str) or not group.startswith('/') or '..' in Path(group).parts:
                        return False
                    path = Path('/sys/fs/cgroup') / group.lstrip('/')
                    try:
                        pin = CgroupPin(path)
                    except FileNotFoundError:
                        return True
                    try:
                        identity = previous['original_cgroup_identity']
                        return pin.identity == (identity['device'], identity['inode']) and pin.observe() == 'empty'
                    finally:
                        pin.close()
                tools = {'bazel': bazel, 'python': python, 'systemd_run': runner, 'systemctl': control,
                    'bootstrap': str(bootstrap), 'closure': str(closure), 'java': str(java), 'bash': bash}
                if cli_selected:
                    native_cli = cli_profile.Admission(args, run, tools, native_controller_graph,
                        locked_path, args.manager, previous_empty, delivery_entry_monotonic_ns)
                    resources.callback(native_cli.close)
                elif history_selected:
                    native_history = history_profile.Admission(args, run, tools, native_controller_graph,
                        locked_path, args.manager, previous_empty, delivery_entry_monotonic_ns)
                    resources.callback(native_history.close)
                elif staged_compilation_selected:
                    native_staged = staged_compilation.Admission(args, run, tools, native_controller_graph,
                        locked_path, args.manager, previous_empty)
                    resources.callback(native_staged.close)
                elif fresh_completion_selected:
                    native_fresh = fresh_completion.Admission(args, run, tools, native_controller_graph,
                        locked_path, args.manager, previous_empty)
                    resources.callback(native_fresh.close)
                else:
                    native_cache = Candidate(args, run, tools, native_controller_graph, locked_path,
                        args.manager, previous_empty)
                    resources.callback(native_cache.close)
            args.native_deadline = native_sdk.completion_deadline(args,
                delivery_entry_monotonic_ns, native_cli or native_history or native_staged or native_fresh or native_cache)
            args.native_original_deadline_ns = (native_cli.original_deadline_ns if native_cli else native_history.original_deadline_ns if native_history
                else delivery_entry_monotonic_ns + args.native_aggregate_seconds * 10**9)
            native_plan = native_sdk.command(args, run, locked_path, bash, native_cli or native_history or native_staged or native_fresh or native_cache)
            command = native_plan['argv']
            workload_cwd = Path(native_plan['cwd'])
            environment.update(native_plan['environment'])
        if site and args.repository_cache:
            command.insert(command.index(arguments[0]) + 1, '--repository_cache=' + str(args.repository_cache))
        if sdk:
            if args.state_dir != sdk.FAST_STATE or bazel != sdk.BAZEL:
                raise ValueError('SDK requires exact fast state and pinned SDK Bazel')
            _, bash, _ = sdk.validate_settings(args.sdk_settings_root, args.sdk_settings_receipt_sha256, str(args.sdk_bundle))
            sdk.prepare_workspace_status(run, bash)
            sdk_plan = sdk.command_plan(args.sdk_source_root, args.sdk_source_receipt_sha256,
                args.sdk_bundle, args.sdk_bundle_receipt_sha256, sdk.ARCHIVE_MANIFEST_SHA,
                args.sdk_settings_root, args.sdk_settings_receipt_sha256, run, args.sdk_lane)
            sdk_cache_provenance(sdk_plan, args.sdk_source_root, args.sdk_source_receipt_sha256,
                                 args.sdk_settings_root, args.sdk_settings_receipt_sha256,
                                 args.sdk_bundle_receipt_sha256, sdk.LANES, sdk.GRAPH)
            command = sdk_owned_command(sdk_plan, run)
            workload_cwd = Path(sdk_plan['cwd'])
            environment.update(sdk_plan['environment'])
        unit = 'omux-execution-' + identifier + '.service'
        cgroup = None
        cgroup_pin = None
        original_pid = None
        original_ticks = None
        started = False
        proof_worker = None
        result = 125
        cleanup = False
        controller_failure = None
        pids_observation = workload_pids_observation(resident_settings, args.profile)
        pids_cancellation = None
        controller_diagnostics = []
        cleanup_summary = {'state': 'not-started', 'stop': 'not-requested',
                           'ownership': 'unproved', 'readback_attempts': 0, 'pre_stop': None}
        rejection = None
        observed_properties = {}
        identity_maps = {}
        epoch_start_ns = None
        startup_history = []
        evidence = {'state': 'not-admitted' if arguments[0] == 'test' else 'not-applicable'}
        evidence_ok = arguments[0] != 'test'
        lease = native_cache.lease if native_cache is not None else None
        cache_key = native_cache.key if native_cache is not None else None
        cache_profile = native_cache.facts() if native_cache is not None else None
        graph_sha256 = None
        graph_inputs = []
        supervisor_pid = os.getpid()
        supervisor_stat = Path('/proc/self/stat').read_text()
        supervisor_start_ticks = supervisor_stat[supervisor_stat.rindex(')') + 2:].split()[19]
        yoga_launch_nonce = str(uuid.uuid4()) if yoga else None
        manager_flag = '--' + args.manager
        def diagnose(row):
            nonlocal controller_failure
            if controller_failure is None:
                controller_failure = row
            if len(controller_diagnostics) < 16:
                controller_diagnostics.append(row)
        def call(parts, *, operation, phase, authenticate=False,
                 timeout=CONTROLLER_TIMEOUT, deadline=None):
            descriptor = None
            try:
                if authenticate:
                    if args.manager != 'system' or parts[0] not in (runner, control):
                        raise ValueError('privileged transport is limited to declared controllers')
                    if parts[0] == control and parts != [control, '--system', 'stop', unit]:
                        raise ValueError('privileged controller operation rejected')
                    descriptor = become_descriptor(args.become_file)
                    parts = [sudo, '-S', '-p', '', '--'] + parts
                if reservation_selected or dev_stage_proof or resident_input is not None or delivery_settings or owner_input is not None or live_input is not None:
                    bound = delivery_entry_deadline_ns - (30*10**9 if (getattr(resident_input,'acquisition_profile',False) or getattr(resident_input,'sources_profile',False) or args.profile in ('yoga-install-inputs','yoga-sealed-workspace-stage') or reservation_selected) and phase != 'cleanup' else 0)
                    deadline = min(deadline, bound / 10**9) if deadline is not None else bound / 10**9
                if native_sdk and (phase != 'cleanup' or native_history is not None or native_cli is not None):
                    deadline = min(deadline, args.native_deadline) if deadline is not None else args.native_deadline
                return controller_run(parts, operation=operation, phase=phase, diagnose=diagnose,
                    stdin=descriptor if descriptor is not None else subprocess.DEVNULL,
                    timeout=timeout, deadline=deadline)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        def interrupted(signum, frame):
            raise KeyboardInterrupt
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, interrupted)
        try:
            graph_sha256, graph_inputs = graph_digest(Path.cwd())
            if native_sdk and (graph_sha256, graph_inputs) != native_controller_graph:
                raise ValueError('native controller graph changed before dispatch')
            if seed_reservation is not None:
                seed_reservation.observe()
            if fresh_input is not None:
                fresh_input.recheck()
            if owner_input is not None:
                owner_input.recheck()
            if yoga_installed_input is not None:
                yoga_installed_input.recheck()
            if live_input is not None:
                live_input.recheck()
            if delivery_settings:
                if args.profile in ('yoga-install-inputs','yoga-sealed-workspace-stage'):
                    delivery_settings.observe(delivery_entry_deadline_ns)
                delivery_settings.budget(delivery_entry_deadline_ns, 30 * 10**9)
                require_delivery_graph = graph_sha256 == delivery_initial_graph
                if not require_delivery_graph: raise ValueError('delivery graph changed before dispatch')
                if delivery_settings.lock_witness(lock.fileno(), delivery_entry_deadline_ns) != delivery_lock:
                    raise ValueError('original-home-lock-changed-before-launch')
                if delivery_http is not None:
                    delivery_http.recheck()
                if delivery_prior:
                    delivery_settings.recheck(delivery_prior, graph_sha256, PROPERTIES, delivery_entry_deadline_ns, delivery_lock,
                        **({'source_commit':args.source_commit} if args.profile in
                            ('yoga-controller-inspect-reserved','yoga-controller-verify-reserved') else {}))
            if yoga:
                yoga.refresh(yoga_admission, Path(pwd.getpwuid(os.getuid()).pw_dir), graph_sha256)
                environment['OMUX_YOGA_WORKER_PLAN_SHA256'] = yoga_launch.prepare_worker(yoga_support, command,
                    yoga_admission['receipt']['inputPaths'], host_home=str(Path(pwd.getpwuid(os.getuid()).pw_dir)), gid=os.getgid())
                environment['OMUX_YOGA_LAUNCH_NONCE'] = yoga_launch_nonce
                yoga.require_unit_absent(control, identifier, args.yoga_deadline_monotonic_ns)
            if site and (graph_sha256, graph_inputs) != site_controller_graph:
                raise ValueError('site controller source changed before dispatch')
            if args.reuse_owned_cache:
                if args.state_dir.resolve().is_relative_to(Path.cwd().resolve()):
                    raise ValueError('owned output cache must remain outside the source repository')
                cache_inputs = {key: environment[key] for key in
                                ('OMUX_BAZEL_BOOTSTRAP_CLOSURE', 'JAVA_HOME') if key in environment}
                if not site:
                    cache_inputs.update({key: environment[key] for key in ('OMUX_BAZEL_CLOSURE', 'OMUX_ZIG_SDK')})
                cache_inputs.update({'bazel': bazel, 'python': python,
                                     'systemd_run': runner, 'systemctl': control})
                if args.nixpkgs_source is not None:
                    cache_inputs['nixpkgs_source'] = str(args.nixpkgs_source)
                if args.site_nixpkgs_source is not None:
                    cache_inputs['site_nixpkgs_source'] = str(args.site_nixpkgs_source)
                cache_profile = {'limits': PROPERTIES, 'isolation': isolation,
                                 'inaccessible_paths': blocked_paths(args.profile) if args.manager == 'user' else
                                     (['/etc/environment'] if args.profile in ('installed-browser', 'site') else []),
                                 'temporary_filesystem_masks': system_masks(profile=mask_profile) if args.manager == 'system' else None,
                                 'system_identity': {'PrivateUsers': 'no', 'CapabilityBoundingSet': '',
                                                     'AmbientCapabilities': '', 'StandardInput': 'null'} if args.manager == 'system' else None,
                                 'execution': {'batch': True, 'jvm_heap_mib': 1536, 'active_processors': 2,
                                               'jobs': 2, 'spawn_strategy': 'sandboxed',
                                               'test_strategy': 'processwrapper-sandbox',
                                               'cache_test_results': False, 'remote_executor': '',
                                               'remote_cache': '', 'sandbox_allow_network': False,
                                               'system_home_workspace_rc': False}}
                if not sdk and not site:
                    cache_profile['execution'].update(controller_thread_profile())
                if owner_input is not None:
                    cache_profile['codex_owner_runtime_input'] = owner_input.facts()
                if sdk:
                    cache_profile['sdk'] = sdk_cache_provenance(sdk_plan, args.sdk_source_root,
                        args.sdk_source_receipt_sha256, args.sdk_settings_root,
                        args.sdk_settings_receipt_sha256, args.sdk_bundle_receipt_sha256, sdk.LANES, sdk.GRAPH)
                    cache_profile['execution'].update(jvm_heap_mib=768, active_processors=1,
                                                      jobs=1, test_strategy='SDK owner-local-test-toolchain')
                if site:
                    cache_profile['site'] = {'qualification_sha256': args.site_qualification_sha256,
                        'inventory_sha256': args.site_inventory_sha256, 'proof_bindings': site_bindings,
                        'native_dispatch': bazel, 'registry_revision': '5b85ae10730928abece3bb57994adcfb59c9a6ee',
                        'lockfile_mode': 'update' if args.site_phase == 'lock' else 'error'}
                    if args.site_phase == 'lock':
                        cache_profile['execution'].update(jobs=None, loading_phase_threads=2,
                            spawn_strategy='not-applicable-dependency-metadata', test_strategy=None)
                    elif args.site_phase == 'fetch':
                        cache_profile['execution'].update(build_actions=False, loading_phase_threads=2,
                                                          test_strategy=None)
                    else:
                        cache_profile['execution']['strategy_exceptions'] = {'CopyFile': 'local'}
                cache_key = stable_fingerprint(workload_cwd if site else Path.cwd(), cache_inputs, os.getuid(), os.getgid(),
                                               args.manager, cache_profile)
                lease = CacheLease(args.state_dir, cache_key, identifier, policy_version=2)
                resources.callback(lease.close)
                lease.__enter__()
                if sdk:
                    command = sdk_owned_command(sdk_plan, run, lease.output_base)
                elif site:
                    command = site.command(bazel, java, site_qualification, lease.output_base,
                                           args.site_phase, arguments, site_bindings, run)
                    if args.repository_cache:
                        command.insert(command.index(arguments[0]) + 1, '--repository_cache=' + str(args.repository_cache))
                else:
                    command = bazel_command(bazel, run, arguments, args.repository_cache,
                                        args.source_commit, args.source_dirty, args.nixpkgs_source,
                                        output_base=lease.output_base, site_source=args.site_source,
                                        site_inventory=args.site_inventory,
                                        site_inventory_sha256=args.site_inventory_sha256,
                                        site_nixpkgs_source=args.site_nixpkgs_source,
                                        codex_pack_directory=args.codex_pack_directory, profile=args.profile,
                                        codex_recovery_source=args.codex_recovery_source,
                                        codex_pristine_directory=args.codex_pristine_directory,
                                        codex_recovery_delta_directory=args.codex_recovery_delta_directory,
                                codex_owner_runtime_directory=args.codex_owner_runtime_directory,
                                codex_fresh_runtime_selection=args.codex_fresh_runtime_selection,
                                codex_fresh_runtime_sha256=args.codex_fresh_runtime_sha256,
                                codex_fresh_runtime_bytes=args.codex_fresh_runtime_bytes)
            if site and args.site_phase == 'lock':
                site_lock_evidence['before'] = site.retain_lockfile(args.site_source, run,
                    site_snapshot['MODULE.bazel.lock'], 'before')
            descriptor = os.open(run / 'supervisor.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w') as output:
                output.write(json.dumps({'id': identifier, 'pid': supervisor_pid,
                                         'start_ticks': supervisor_start_ticks}) + '\n')
            if dev_stage_proof:
                dev_stage_admission(run,graph_sha256,delivery_entry_monotonic_ns,delivery_entry_deadline_ns)
            launch = [runner, manager_flag, '--no-block', '--unit=' + unit,
                      '--property=Type=exec',
                      '--property=StandardOutput=null', '--property=StandardError=null',
                      '--property=WorkingDirectory=' + str(workload_cwd),
                      '--setenv=OMUX_EXECUTION_GUARD=' + str(run)]
            launch += (['--property=TemporaryFileSystem=' + (yoga.mask_setting(Path(pwd.getpwuid(os.getuid()).pw_dir))
                        if yoga else system_masks(profile=mask_profile))] if args.manager == 'system'
                       else ['--property=InaccessiblePaths=' + ' '.join('-' + path for path in blocked_paths(args.profile))])
            if args.manager == 'system' and args.profile in ('installed-browser', 'site', 'yoga-toolbar','yoga-toolbar-reserved'):
                launch += ['--property=InaccessiblePaths=-/etc/environment']
            if yoga:
                launch += ['--property=BindReadOnlyPaths=' + yoga.display.readonly_setting(yoga_admission['witness'])]
            if args.profile in ('yoga-install-inputs','yoga-sealed-workspace-stage'):
                launch += ['--property=BindReadOnlyPaths='+' '.join(delivery_settings.AGENT.bindings())]
            if delivery_http is not None:
                launch += ['--property=BindReadOnlyPaths='+delivery_http.binding()]
            if native_sdk:
                launch += ['--property=BindReadOnlyPaths=' + ' '.join(native_sdk.readonly_paths(args, native_plan))]
                if native_cache is not None or native_fresh is not None or native_staged is not None or native_history is not None or native_cli is not None:
                    launch += ['--property=BindPaths=' + str((native_cli or native_history or native_staged or native_fresh or native_cache).lease.output_base)]
            if live_input is not None:
                live_binds = fresh_live.readonly_bindings(fresh_input,live_input.binding()) if fresh_input else [live_input.binding()]
                launch += ['--property=BindReadOnlyPaths=' + ' '.join(live_binds)]
            if yoga_installed_input is not None:
                import guard_yoga_installed_producer as installed_producer
                readonly,writable = yoga_installed_input.bindings()
                launch += ['--property=BindReadOnlyPaths='+readonly,'--property=BindPaths='+writable,
                    '--property=ProtectSystem=strict',
                    '--property=ReadWritePaths='+str(run)+' '+str(installed_producer.OUTPUT_PARENT)]
            if resident_input is not None:
                extra_binds = ([str(args.repository_cache)+':'+str(args.repository_cache)]
                    if args.repository_cache and args.profile != resident_dispatch.SETUP_PROFILE else [])
                launch += ['--property=BindReadOnlyPaths='+' '.join(resident_input.bindings()+extra_binds),
                    '--property=BindPaths='+' '.join(resident_dispatch.writable_bindings(resident_input,run))]
            unset = DELEGATION_ENV + (('OMUX_ZIG_SDK', 'OMUX_BAZEL_CLOSURE', 'OMUX_SITE_BAZEL_CLOSURE') if site else ())
            if resident_input is not None:
                if getattr(resident_input,'acquisition_profile',False):
                    import guard_native_acquisition_dispatch as acquisition
                    unset = acquisition.unset_environment(unset)
                else:
                    unset = resident_dispatch.unset_environment(unset)
            if yoga or yoga_reserved or args.profile in ('yoga-install-inputs','yoga-sealed-workspace-stage'):
                unset += ('DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR', 'DBUS_STARTER_ADDRESS', 'DBUS_STARTER_BUS_TYPE',
                          'SSH_AUTH_SOCK', 'SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY', 'NODE_OPTIONS', 'NODE_PATH',
                          'LD_PRELOAD', 'LD_AUDIT', 'LD_LIBRARY_PATH', 'PYTHONPATH', 'PYTHONHOME', 'XAUTHORITY',
                          'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_DIRS',
                          'GNOME_KEYRING_CONTROL', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                          'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')
            launch += ['--property=UnsetEnvironment=' + ' '.join(unset)]
            launch += ['--setenv=' + key + '=' + value for key, value in environment.items()]
            settings = dict(PROPERTIES)
            settings.update(isolation)
            settings.pop('CPUQuotaPerSecUSec')
            settings.pop('RuntimeMaxUSec')
            settings.pop('TimeoutStopUSec')
            settings.update(CPUQuota='200%', RuntimeMaxSec='1200', TimeoutStopSec='10')
            if reservation_selected:
                delivery_runtime_seconds = (yoga_support.reserved_runtime if yoga_toolbar_reserved else
                    int(reservation_helper.remaining(delivery_entry_monotonic_ns,delivery_entry_deadline_ns)))
                if delivery_runtime_seconds < 1: raise ValueError('native-seed-reservation-expired')
                settings.update(MemoryMax=str(reservation_helper.MEMORY),TasksMax=str(reservation_helper.TASKS),
                    CPUQuota='190%',RuntimeMaxSec=str(delivery_runtime_seconds),RemainAfterExit='yes')
            if dev_stage_proof:
                delivery_runtime_seconds = dev_stage_runtime(delivery_entry_monotonic_ns,delivery_entry_deadline_ns)
                settings['RuntimeMaxSec'] = str(delivery_runtime_seconds)
            if resident_input is not None:
                delivery_runtime_seconds = resident_input.runtime_seconds()
                settings.update(MemoryMax=str(resident_settings.PROOF_MEMORY),TasksMax=str(resident_settings.PROOF_TASKS),
                    CPUQuota=str(getattr(resident_settings,'PROOF_CPU_PERCENT',190))+'%',RuntimeMaxSec=str(delivery_runtime_seconds))
            if native_sdk:
                delivery_runtime_seconds = native_sdk.runtime(args)
                settings['RuntimeMaxSec'] = str(delivery_runtime_seconds)
            if delivery_settings:
                delivery_runtime_seconds = delivery_settings.runtime_seconds(delivery_entry_deadline_ns)
                settings['RuntimeMaxSec'] = str(delivery_runtime_seconds)
                if args.profile in ('yoga-install-inputs','yoga-sealed-workspace-stage'):
                    settings.update(MemoryMax=str(delivery_settings.PROOF_MEMORY),
                        TasksMax=str(delivery_settings.PROOF_TASKS),CPUQuota='190%')
            elif owner_input is not None:
                delivery_runtime_seconds = owner_input.runtime_seconds()
                settings['RuntimeMaxSec'] = str(delivery_runtime_seconds)
            elif live_input is not None:
                delivery_runtime_seconds = live_input.runtime_seconds()
                settings['RuntimeMaxSec'] = str(delivery_runtime_seconds)
            if args.manager == 'system':
                settings.update(User=str(os.getuid()), Group=str(os.getgid()), PrivateUsers='no',
                                CapabilityBoundingSet='', AmbientCapabilities='', StandardInput='null')
            launch += ['--property=' + key + '=' + value for key, value in settings.items()]
            launch += [python, str(Path(yoga_launch.__file__).resolve()) if yoga else str(Path(__file__).resolve()), '--worker', str(run), '--'] + command
            # Mark before dispatch: a failed client can still leave an owned unit.
            started = True
            call(launch, operation='launch', phase='launch', authenticate=args.manager == 'system')
            actual, startup_history = await_startup(
                lambda: properties(call([control, manager_flag, 'show', '--all', unit],
                                        operation='unit-readback', phase='startup')))
            if actual.get('ActiveState') != 'active':
                raise ValueError('workload did not reach active startup before admission')
            observed_properties = {key: actual.get(key) for key in
                                   (*PROPERTIES, *SANDBOX, 'ActiveState', 'Result', 'ControlGroup',
                                    'User', 'Group', 'PrivateUsers', 'CapabilityBoundingSet',
                                    'AmbientCapabilities', 'StandardInput', 'MainPID',
                                    'TemporaryFileSystem', 'InaccessiblePaths', 'BindReadOnlyPaths', 'BindPaths')}
            if reservation_selected:
                observed_properties['RemainAfterExit'] = actual.get('RemainAfterExit')
            if yoga_installed_input is not None:
                observed_properties.update(ProtectSystem=actual.get('ProtectSystem'),
                    ReadWritePaths=actual.get('ReadWritePaths'))
            if live_input is not None:
                observed_properties = live.receipt_properties(observed_properties)
                live_binding_readback = fresh_live.binding_facts(actual,live_binds) if fresh_input else live.binding_facts(actual,live_input.binding())
            if resident_input is not None:
                observed_properties = resident_settings.projection(observed_properties)
            name = actual.get('ControlGroup', '')
            if (not name.startswith('/') or '..' in Path(name).parts
                    or Path(name).name != unit or actual.get('Id') != unit):
                raise ValueError('dedicated cgroup path unavailable')
            supervisor = Path('/proc/self/cgroup').read_text().strip().splitlines()
            if any(line == '0::' + name or line.startswith('0::' + name + '/')
                   for line in supervisor):
                raise ValueError('supervisor must remain outside workload cgroup')
            cgroup = Path('/sys/fs/cgroup') / name.lstrip('/')
            cgroup_pin = CgroupPin(cgroup)
            resources.callback(cgroup_pin.close)
            original_pid = int(actual.get('MainPID', '0'))
            original_ticks = process_start_ticks(original_pid)
            verify(actual, cgroup, args.manager, isolation, args.profile,
                   runtime_seconds=delivery_runtime_seconds,
                   native_phase2=(native_cache is not None and native_cache.phase2_verified_before_launch is True)
                       or (native_fresh is not None and native_fresh.fresh_verified_before_launch is True)
                       or (native_staged is not None and native_staged.staged_verified_before_launch is True)
                       or (native_history is not None and native_history.verified_before_launch is True)
                       or (native_cli is not None and native_cli.verified_before_launch is True))
            if delivery_http is not None:
                delivery_http.verify_binding(actual)
            if native_sdk:
                native_sdk.verify_readonly(actual, args, native_plan)
            if resident_input is not None:
                resident_dispatch.verify_bindings(resident_input,actual,run,args.repository_cache)
                resident_input.recheck()
                observed_properties = resident_settings.projection(observed_properties,True)
            if live_input is not None:
                if fresh_input is not None:
                    fresh_live.verify_readonly(actual,live_binds)
                    fresh_input.recheck()
                else:
                    live.verify_binding(actual,live_input.binding())
                observed_properties = live.receipt_properties(observed_properties, verified=True)
                live_input.recheck()
            if yoga_installed_input is not None:
                yoga_installed_input.verify(actual,run)
                yoga_installed_input.recheck()
            exported = set(actual.get('Environment', '').split())
            if not {key + '=' + value for key, value in environment.items()}.issubset(exported):
                raise ValueError('effective pinned tool environment rejected')
            if actual.get('ActiveState') != 'active':
                raise ValueError('service is not active before admission')
            if args.manager == 'system':
                identity_maps = system_identity(actual, int(actual.get('MainPID', '0')))
            check_free_space(args.state_dir)
            if site:
                if graph_digest(Path.cwd()) != site_controller_graph:
                    raise ValueError('site controller source changed before admission')
                site.verify_source_snapshot(site_snapshot, site.source_snapshot(args.site_source), 'qualification')
                site.read_qualification(args.site_qualification, args.site_qualification_sha256)
                site.proof_bindings(args.site_inventory, args.site_inventory_sha256,
                                    selected_site_inventory, args.state_dir, coordination)
                if args.site_phase == 'import':
                    site.importer_arguments(args.site_delivery_manifest, args.site_delivery_manifest_sha256,
                                            site_qualification['delivery_manifest'])
            if yoga:
                expected_binds = [yoga_admission['witness']['source'] + ':' + yoga_admission['witness']['destination']]
                yoga.verify_masks(actual, Path(pwd.getpwuid(os.getuid()).pw_dir), expected_binds)
                ready_deadline = args.yoga_deadline_monotonic_ns - yoga.CLEANUP_RESERVE_NS
                while not (run / 'worker-ready.json').exists():
                    yoga.display.budget(args.yoga_deadline_monotonic_ns)
                    if time.monotonic_ns() >= ready_deadline:
                        raise ValueError('Yoga worker qualification exhausted original preparation budget')
                    state = properties(call([control, manager_flag, 'show', '--all', unit],
                                            operation='unit-readback', phase='qualification'))
                    if state.get('ActiveState') != 'active':
                        raise ValueError('Yoga held worker exited before live namespace qualification')
                    time.sleep(0.05)
                ready, ready_sha = yoga_launch.read_worker_ready(yoga_support, expected_pid=int(actual['MainPID']))
                yoga_worker_identity = ready
                actual = properties(call([control, manager_flag, 'show', '--all', unit],
                                         operation='unit-readback', phase='qualification'))
                verify(actual, cgroup, args.manager, isolation, args.profile,
                    runtime_seconds=delivery_runtime_seconds if yoga_toolbar_reserved else None)
                system_identity(actual, int(actual['MainPID']))
                yoga.verify_masks(actual, Path(pwd.getpwuid(os.getuid()).pw_dir), expected_binds)
                source_snapshot = yoga.refresh(yoga_admission, Path(pwd.getpwuid(os.getuid()).pw_dir), graph_digest(Path.cwd())[0])
                pids_observation.sample(cgroup_pin, 'baseline')
                if yoga_toolbar_reserved:
                    yoga.owns_unit(actual,unit=unit,run=run,nonce=yoga_launch_nonce,
                        plan_sha256=environment['OMUX_YOGA_WORKER_PLAN_SHA256'],
                        worker=str(Path(yoga_launch.__file__).resolve()),python=python,cgroup=cgroup,
                        worker_identity=yoga_worker_identity)
                    unit_epoch_identity(actual,unit=unit,manager=args.manager,run=run,
                        python=python,worker=str(Path(yoga_launch.__file__).resolve()))
                    proof_worker = reservation_helper.WorkloadWitness(args.profile,delivery_entry_monotonic_ns,
                        delivery_entry_deadline_ns,cgroup_pin,actual,original_pid,original_ticks)
                    resources.callback(proof_worker.close)
                    seed_reservation.observe()
                yoga_launch.admit_worker(yoga_support, ready, properties=actual, source_snapshot=source_snapshot,
                    effective_readonly_binds=actual.get('BindReadOnlyPaths', '').split(),
                    effective_writable_binds=actual.get('BindPaths', '').split())
            if seed_selected:
                unit_epoch_identity(actual,unit=unit,manager=args.manager,run=run,
                    python=python,worker=str(Path(__file__).resolve()))
                proof_worker = reservation_helper.WorkloadWitness(args.profile,delivery_entry_monotonic_ns,
                    delivery_entry_deadline_ns,cgroup_pin,actual,original_pid,original_ticks)
                resources.callback(proof_worker.close)
            epoch_start_ns = time.time_ns()
            if not yoga:
                pids_observation.sample(cgroup_pin, 'baseline')
                if dev_stage_proof:
                    dev_stage_budget(delivery_entry_monotonic_ns,delivery_entry_deadline_ns)
                if resident_input is not None:
                    resident_input.recheck()
                    resident_input.runtime_seconds()
                if args.profile in ('yoga-install-inputs','yoga-sealed-workspace-stage'):
                    delivery_settings.observe(delivery_entry_deadline_ns)
                    delivery_settings.AGENT.verify_bindings(actual)
                if seed_reservation is not None:
                    seed_reservation.observe()
                if yoga_installed_input is not None:
                    yoga_installed_input.recheck()
                if delivery_http is not None:
                    delivery_http.recheck()
                if args.profile in ('yoga-controller-inspect-reserved','yoga-controller-verify-reserved'):
                    yoga_controller_readonly_go(delivery_settings,args.profile,run,Path.cwd(),args.source_commit,
                        delivery_prior,delivery_initial_graph,delivery_lock,lock.fileno(),
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns)
                else:
                    (run / 'go').touch(mode=0o600, exist_ok=False)
            deadline = ((args.yoga_deadline_monotonic_ns - yoga.CLEANUP_RESERVE_NS) / 10**9
                        if yoga else time.monotonic() + 1200)
            if delivery_settings:
                deadline = delivery_monitor_deadline(delivery_entry_deadline_ns, delivery_settings)
            elif native_sdk:
                deadline = args.native_deadline - 120
            elif reservation_selected or dev_stage_proof or resident_input is not None or owner_input is not None or live_input is not None:
                deadline = (delivery_entry_deadline_ns - 30 * 10**9) / 10**9
            def iteration():
                if delivery_http is not None:
                    delivery_http.recheck()
                if yoga_installed_input is not None:
                    yoga_installed_input.recheck()
                if seed_reservation is not None:
                    seed_reservation.observe()
                pids_observation.sample(cgroup_pin, 'monitor')
                check_free_space(args.state_dir)
                if args.profile in ('yoga-install-inputs','yoga-sealed-workspace-stage'):
                    delivery_settings.observe(delivery_entry_deadline_ns)
                if yoga:
                    for progress in yoga_launch.read_progress(yoga_support):
                        print(json.dumps(progress, sort_keys=True), flush=True)
                    yoga.pump_event(yoga_admission, yoga_support, yoga_operator_writer)
            if reservation_selected:
                result = reservation_helper.monitor(args.profile,proof_worker,
                    lambda: properties(call([control,manager_flag,'show',
                        '--property=Id,InvocationID,ExecMainPID,MainPID,RemainAfterExit,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus',unit],
                        operation='unit-readback',phase='monitor')),deadline,iteration)
            else:
                result = monitor_workload(lambda: properties(call([control, manager_flag, 'show', '--property=ActiveState,Result,ExecMainStatus', unit],
                    operation='unit-readback', phase='monitor')), deadline, iteration)
        except (ValueError, OSError) as error:
            if reservation_selected:
                import guard_native_seed_plan_reserved as reservation_diagnostic
                seed_failure = reservation_diagnostic.diagnostic_projection(error)
            rejection = (resident_settings.rejection(error) if resident_settings else live.rejection_category(error) if args.profile == 'codex-live'
                         else str(error) if isinstance(error, ValueError) else None)
            raise
        finally:
            if started:
                if delivery_settings:
                    try:
                        delivery_lock_verified_before_cleanup = delivery_settings.lock_witness(lock.fileno(),
                            delivery_entry_deadline_ns) == delivery_lock
                    except (OSError, ValueError):
                        delivery_lock_verified_before_cleanup = False
                cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
                if native_cli is not None:
                    cleanup_deadline = min(cleanup_deadline, native_cli.original_deadline_ns / 10**9)
                if native_history is not None:
                    cleanup_deadline = min(cleanup_deadline, native_history.original_deadline_ns / 10**9)
                if reservation_selected or dev_stage_proof or resident_input is not None or delivery_settings or owner_input is not None or live_input is not None:
                    cleanup_deadline = min(cleanup_deadline, delivery_entry_deadline_ns / 10**9)
                if yoga:
                    cleanup_deadline = min(cleanup_deadline, args.yoga_deadline_monotonic_ns / 10**9)
                pids_cancellation = observe_pids_before_cleanup(pids_observation, cgroup_pin,
                    sys.exc_info()[1], prior_failure=controller_failure is not None)
                def authorize(owned):
                    nonlocal cgroup_pin, cgroup, original_pid, original_ticks
                    selected_worker = str(Path(yoga_launch.__file__).resolve()) if yoga else str(Path(__file__).resolve())
                    if cgroup_pin is None:
                        if yoga:
                            # Yoga's random nonce/plan ownership precedes late capture too.
                            yoga.owns_unit(owned, unit=unit, run=run, nonce=yoga_launch_nonce,
                                plan_sha256=environment['OMUX_YOGA_WORKER_PLAN_SHA256'],
                                worker=selected_worker, python=python, cgroup=cgroup,
                                worker_identity=yoga_worker_identity)
                        cgroup_pin, original_pid, original_ticks = capture_cleanup_pin(owned,
                            unit=unit, manager=args.manager, run=run, python=python, worker=selected_worker)
                        cgroup = cgroup_pin.path
                        resources.callback(cgroup_pin.close)
                        return False
                    if reservation_selected and proof_worker is not None:
                        unit_epoch_identity(owned,unit=unit,manager=args.manager,run=run,
                            python=python,worker=selected_worker)
                        proof_worker.authorize_cleanup(owned)
                    else:
                        authorize_cleanup(owned, unit=unit, manager=args.manager, run=run,
                            python=python, worker=selected_worker,
                            cgroup=cgroup, original_pid=original_pid, original_ticks=original_ticks)
                    if yoga:
                        yoga.owns_unit(owned, unit=unit, run=run, nonce=yoga_launch_nonce,
                            plan_sha256=environment['OMUX_YOGA_WORKER_PLAN_SHA256'],
                            worker=str(Path(yoga_launch.__file__).resolve()), python=python, cgroup=cgroup,
                            worker_identity=yoga_worker_identity)
                cleanup_method = reservation_helper.cleanup_retained if reservation_selected else cleanup_owned
                cleanup_summary = cleanup_method(deadline=cleanup_deadline,
                    readback=lambda timeout, absolute: properties(call([control, manager_flag, 'show', '--all', unit],
                        operation='unit-readback', phase='cleanup', timeout=timeout, deadline=absolute)),
                    authorize=authorize,
                    stop=lambda timeout, absolute: call([control, manager_flag, 'stop', unit],
                        operation='unit-stop', phase='cleanup', authenticate=args.manager == 'system',
                        timeout=timeout, deadline=absolute),
                    observe=lambda: cgroup_pin.observe() if cgroup_pin is not None else 'uncaptured')
                cleanup = cleanup_summary['state'] == 'empty'
            if reservation_selected and not reservation_helper.release_worker(proof_worker):
                cleanup = False
                result = 125
            if delivery_settings:
                try:
                    delivery_settings.budget(delivery_entry_deadline_ns)
                    delivery_verified_after = graph_digest(Path.cwd())[0] == delivery_initial_graph
                    delivery_verified_after = delivery_verified_after and delivery_lock_verified_before_cleanup is not False
                    delivery_settings.budget(delivery_entry_deadline_ns)
                    if delivery_settings.lock_witness(lock.fileno(), delivery_entry_deadline_ns) != delivery_lock:
                        raise ValueError('original-home-lock-changed-after-cleanup')
                    if delivery_http is not None:
                        delivery_http.recheck(content=True,cleanup=True)
                        delivery_http.close()
                        delivery_http.verified_after_cleanup = cleanup is True
                    delivery_summary = delivery_settings.finish(run, arguments, result, cleanup,
                        delivery_verified_after, delivery_entry_deadline_ns, delivery_lock)
                except (OSError, ValueError, KeyError, TypeError, UnicodeError):
                    delivery_verified_after = False
                    if delivery_http is not None:
                        result = 125
                        delivery_http.verified_after_cleanup = False
                    delivery_summary = {'mode': 'unproved', 'source_verified_after_cleanup': False,
                                        'qualification': None, 'copy_performed': False,
                                        'remote_owned_containment_verified': False, 'remote_cleanup': 'unknown'}
            if sdk:
                try:
                    sdk.validate_source(args.sdk_source_root, args.sdk_source_receipt_sha256)
                    sdk_source_verified_after = True
                except (OSError, ValueError):
                    sdk_source_verified_after = False
            if native_sdk:
                try:
                    if graph_digest(Path.cwd()) != native_controller_graph:
                        raise ValueError('native controller graph changed')
                    verified_native_inputs = native_sdk.verify_inputs(args)
                    fd = native_sdk.trusted_parent(Path(native_plan['cwd']))
                    try:
                        receipt = native_sdk.validate_source(args.native_source_root, args.native_source_sha256, args.native_patch_sha256, args.native_deadline)
                        native_sdk.verify_inventory(fd, receipt['source_inventory'], native_sdk.EXPORT_MODE_POLICY, on_read=lambda count: native_sdk.tick(args.native_deadline))
                    finally:
                        os.close(fd)
                    if native_cache is not None:
                        native_cache.verify_transition_after_cleanup()
                    if native_fresh is not None:
                        native_fresh.verify_after_cleanup(verified_native_inputs)
                    if native_staged is not None:
                        native_staged.verify_after_cleanup(verified_native_inputs)
                    if native_history is not None:
                        native_history.verify_after_cleanup(verified_native_inputs)
                    if native_cli is not None:
                        native_cli.verify_after_cleanup(verified_native_inputs)
                    native_verified_after = True
                except (OSError, ValueError, KeyError, TypeError):
                    native_verified_after = False
            if yoga:
                try:
                    yoga.refresh(yoga_admission, Path(pwd.getpwuid(os.getuid()).pw_dir), graph_digest(Path.cwd())[0],
                        **({'cleanup':True} if yoga_toolbar_reserved else {}))
                    yoga_verified_after = True
                except (OSError, ValueError, KeyError, TypeError):
                    yoga_verified_after = False
                try:
                    yoga_summary = yoga_launch.finish_proof(yoga_support, workload_exit=result, aggregate_empty=cleanup,
                        cancellation_requested=result == 124 or sys.exc_info()[0] is KeyboardInterrupt)
                except (OSError, ValueError, KeyError, TypeError):
                    yoga_verified_after = False
                    yoga_summary = {'scope': 'yoga-final-join', 'executionPassed': False,
                                    'toolbarConsentProved': False, 'descendantsEmpty': cleanup}
                    yoga_support.close()
                if len(yoga_support.events) != 3:
                    yoga_verified_after = False
            if site:
                try:
                    # Preserve final lock bytes even if another source input
                    # later makes the full source inventory fail closed.
                    if args.site_phase == 'lock':
                        if cleanup:
                            site_lock_evidence['after'] = dict(
                                site.retain_lockfile(args.site_source, run, None, 'after'),
                                state='preserved-after-verified-cleanup')
                        else:
                            site_lock_evidence['after'] = {'state': 'terminal-unproved'}
                    site_controller_graph_after = graph_digest(Path.cwd())
                    site_snapshot_after = site.source_snapshot(args.site_source)
                    if args.site_phase == 'lock' and cleanup and site_snapshot_after['MODULE.bazel.lock'] != site_lock_evidence['after']['sha256']:
                        raise ValueError('site final lock changed during evidence preservation')
                    if site_controller_graph_after != site_controller_graph:
                        raise ValueError('site controller source changed during execution')
                    site_source_changes = site.verify_source_snapshot(site_snapshot,
                        site_snapshot_after, args.site_phase)
                    site.read_qualification(args.site_qualification, args.site_qualification_sha256)
                    site.proof_bindings(args.site_inventory, args.site_inventory_sha256,
                                        selected_site_inventory, args.state_dir, coordination)
                    if args.site_phase == 'import':
                        site.importer_arguments(args.site_delivery_manifest, args.site_delivery_manifest_sha256,
                                                site_qualification['delivery_manifest'])
                    site_source_verified_after = True
                except (OSError, ValueError, KeyError, TypeError):
                    site_source_verified_after = False
            if dev_stage_proof:
                try:
                    dev_stage_verified_after = dev_stage_source_after(delivery_entry_monotonic_ns,
                        delivery_entry_deadline_ns,(graph_sha256,graph_inputs),lambda:graph_digest(Path.cwd()))
                except (OSError,ValueError):
                    dev_stage_verified_after = False
            if arguments[0] == 'test' and epoch_start_ns is not None and cleanup:
                try:
                    manifest = capture_test_evidence(native_cli.lease.output_base if native_cli
                        else native_history.lease.output_base if native_history
                        else native_staged.lease.output_base if native_staged
                        else native_fresh.lease.output_base if native_fresh
                        else lease.output_base if lease else run / 'output-base',
                                                     run, arguments[1:], result, epoch_start_ns)
                    if native_sdk:
                        qualification_context = None
                        if args.native_mode == 'qualification-cli':
                            selected_native = native_cli or native_history or native_staged or native_fresh or native_cache
                            if selected_native is None or native_plan['candidate_output_base'] is None:
                                raise ValueError('combined qualification requires exact owned output base')
                            qualification_context = {
                                'invocation_id': run.name,
                                'output_base': native_plan['candidate_output_base'],
                                'source_receipt_sha256': args.native_source_sha256,
                                'export_receipt_sha256': args.native_export_sha256,
                                'source_inventory_sha256': native_plan['source_inventory_sha256'],
                                'export_inventory_sha256': native_plan['export_inventory_sha256'],
                                'candidate_cache_key': selected_native.facts()['key'],
                                'candidate_provenance_sha256': selected_native.facts()['provenance_sha256'],
                                'controller_graph_sha256': native_controller_graph[0],
                                'bazel': native_sdk.BAZEL, 'workload_exit': result,
                                'descendants_empty': cleanup,
                                'source_and_export_verified_after_cleanup': native_verified_after,
                            }
                        native_sdk.meaningful_tests(run, manifest, args.native_mode, qualification_context)
                    refused = {'copy-refused', 'directory-refused', 'over-budget', 'unsupported-label',
                               'file-budget-exhausted', 'changed-during-copy'}
                    evidence_ok = not any(row.get('state') in refused or
                                          any(entry.get('state') in refused for entry in row['files'])
                                          for row in manifest['results'])
                    evidence = {'state': 'preserved' if evidence_ok else 'preservation-incomplete',
                                'manifest': 'test-evidence.json',
                                'sha256': hashlib.sha256((run / 'test-evidence.json').read_bytes()).hexdigest(),
                                'bytes': manifest['bytes'], 'files': manifest['copied_files']}
                except (OSError, ValueError):
                    evidence_ok = False
                    evidence = {'state': 'preservation-failed'}
            if owner_input is not None:
                try:
                    owner_input_after = owner_input.recheck()
                    owner_input_verified_after = graph_digest(Path.cwd()) == (graph_sha256, graph_inputs)
                except (OSError, ValueError):
                    owner_input_verified_after = False
                finally:
                    try:
                        owner_input.close()
                    except OSError:
                        owner_input_verified_after = False
            if yoga_installed_input is not None:
                try:
                    yoga_installed_after = yoga_installed_input.recheck()
                    yoga_installed_verified_after = graph_digest(Path.cwd()) == (graph_sha256,graph_inputs)
                except (OSError,ValueError):
                    yoga_installed_verified_after = False
                finally:
                    try: yoga_installed_input.close()
                    except OSError: yoga_installed_verified_after = False
            if live_input is not None:
                try:
                    live_input.recheck()
                    live_input_verified_after = graph_digest(Path.cwd()) == (graph_sha256, graph_inputs)
                except (OSError, ValueError):
                    live_input_verified_after = False
            if fresh_input is not None:
                try:
                    fresh_input_after = fresh_input.recheck()
                    fresh_input_verified_after = graph_digest(Path.cwd()) == (graph_sha256,graph_inputs)
                except (OSError,ValueError):
                    fresh_input_verified_after = False
            if resident_input is not None:
                try:
                    if graph_digest(Path.cwd()) != (graph_sha256,graph_inputs):
                        raise ValueError('resident-source-changed')
                    resident_output = resident_input.completed(result,
                        cleanup is True and cleanup_summary.get('state')=='empty' and pids_cancellation is None,
                        identifier,args.resident_producer_sha256,graph_sha256)
                    resident_verified_after = graph_digest(Path.cwd()) == (graph_sha256,graph_inputs)
                except (OSError,ValueError,KeyError,TypeError,IndexError):
                    resident_verified_after = False
            if seed_reservation is not None:
                try:
                    seed_after = seed_reservation.complete(result,
                        cleanup is True and cleanup_summary.get('state')=='empty' and pids_cancellation is None,
                        evidence_ok,graph_digest(Path.cwd())==(graph_sha256,graph_inputs))
                    seed_verified_after = True
                except (OSError,ValueError,KeyError,TypeError) as error:
                    seed_verified_after = False
                    if seed_failure is None:
                        import guard_native_seed_plan_reserved as reservation_diagnostic
                        seed_failure = reservation_diagnostic.diagnostic_projection(error)
                finally:
                    try: seed_reservation.close()
                    except OSError: seed_verified_after = False
            final_status = result if fresh_input_verified_after is not False and cleanup and evidence_ok and live_input_verified_after is not False and sdk_source_verified_after is not False and site_source_verified_after is not False and yoga_verified_after is not False and delivery_verified_after is not False and owner_input_verified_after is not False and yoga_installed_verified_after is not False and (not yoga or yoga_summary['executionPassed']) else 125
            if dev_stage_proof:
                try:
                    dev_stage_budget(delivery_entry_monotonic_ns,delivery_entry_deadline_ns,reserve_ns=0)
                except ValueError:
                    dev_stage_verified_after = False
                if dev_stage_verified_after is not True:
                    final_status = 125
            if native_verified_after is False:
                final_status = 125
            if resident_verified_after is False or seed_verified_after is False:
                final_status = 125
            if pids_cancellation is not None:
                final_status = 125
            receipt = {'id': identifier, 'unit': unit, 'exit': final_status,
                       'workload_exit': result, 'epoch_start_ns': epoch_start_ns,
                       'test_evidence': evidence,
                       'targets': arguments[1:], 'verb': arguments[0],
                       'source_commit': args.source_commit, 'source_dirty': args.source_dirty,
                       'manager': args.manager, 'host_identity_maps': identity_maps,
                       'profile': args.profile, 'coordination_directory': str(coordination),
                       'native_sdk': {'mode': args.native_mode, 'plan': native_plan,
                           'aggregate_seconds': args.native_aggregate_seconds,
                           'original_entry_monotonic_ns': native_cli.original_entry_ns if native_cli else native_history.original_entry_ns if native_history else delivery_entry_monotonic_ns,
                           'original_deadline_monotonic_ns': args.native_original_deadline_ns,
                           'source_receipt_sha256': args.native_source_sha256,
                           'export_receipt_sha256': args.native_export_sha256,
                           'source_and_export_verified_after_cleanup': native_verified_after} if native_sdk else None,
                       'native_candidate_cache': native_cache.facts() if native_cache is not None else None,
                       'resident_enrollment': {'budget':resident_input.facts,
                           'service_disposition':resident_output,'verified_after_cleanup':resident_verified_after,
                           'native_support':False,'same_process_handoff_proven':False
                       } if resident_input is not None and args.profile=='resident-enrollment' and not resident_input.vault else None,
                       'resident_vault': {'budget':resident_input.facts,
                           'verified_after_cleanup':resident_verified_after,
                           'factor_contents_read_by_guard':False,'provider_invocation':False,
                           'omux_wrapping_key_regeneration':False,'atomic_existing_collection_only':False,
                           'native_support':False
                       } if resident_input is not None and args.profile=='resident-enrollment' and resident_input.vault else None,
                       'resident_continuity': {'budget':resident_input.facts,'output':resident_output,
                           'verified_after_cleanup':resident_verified_after,'success_requires_matching_outer_receipt':True,
                           'original_entry_monotonic_ns':delivery_entry_monotonic_ns,
                           'original_deadline_monotonic_ns':delivery_entry_deadline_ns
                       } if resident_input is not None and args.profile=='resident-continuity' else None,
                       'resident_namespace': {'budget':resident_input.facts,'output':resident_output,
                           'verified_after_cleanup':resident_verified_after,'success_requires_matching_outer_receipt':True,
                           'original_entry_monotonic_ns':delivery_entry_monotonic_ns,
                           'original_deadline_monotonic_ns':delivery_entry_deadline_ns
                       } if resident_input is not None and args.profile=='resident-namespace' else None,
                       'resident_sources': {'budget':resident_input.facts,'output':resident_output,
                           'verified_after_cleanup':resident_verified_after,'success_requires_matching_outer_receipt':True,
                           'original_entry_monotonic_ns':delivery_entry_monotonic_ns,
                           'original_deadline_monotonic_ns':delivery_entry_deadline_ns,
                           'enrollment_verified':False,'same_process_handoff_proven':False
                       } if resident_input is not None and args.profile=='resident-sources' else None,
                       'native_acquisition': {'input':resident_input.facts,'output':resident_output,
                           'verified_after_cleanup':resident_verified_after,'success_requires_matching_outer_receipt':True,
                           'original_entry_monotonic_ns':delivery_entry_monotonic_ns,
                           'original_deadline_monotonic_ns':delivery_entry_deadline_ns
                       } if resident_input is not None and getattr(resident_input,'acquisition_profile',False)
                           and not getattr(resident_input,'component_profile',False) else None,
                       'codex_device_component': {'input':resident_input.facts,'output':resident_output,
                           'verified_after_cleanup':resident_verified_after,
                           'original_entry_monotonic_ns':delivery_entry_monotonic_ns,
                           'original_deadline_monotonic_ns':delivery_entry_deadline_ns
                       } if resident_input is not None and getattr(resident_input,'component_profile',False) else None,
                       'native_fresh_completion': native_fresh.facts() if native_fresh is not None else None,
                       'native_staged_compilation': native_staged.facts() if native_staged is not None else None,
                       'native_protocol_history': native_history.facts() if native_history is not None else None,
                       'native_protocol_history_cli': native_cli.facts() if native_cli is not None else None,
                       'codex_live_input': {'verified_after_cleanup': live_input_verified_after,
                           'selected_sources': live_input.count, 'source_content_read_by_guard': False} if live_input else None,
                       'codex_live_binding_readback': live_binding_readback,
                       'yoga_delivery': dict(delivery_summary, prior_qualification=delivery_prior,
                           original_deadline_monotonic_ns=delivery_entry_deadline_ns,
                           runtime_seconds=delivery_runtime_seconds) if delivery_settings else None,
                       'yoga': {'qualification_sha256': args.yoga_qualification_sha256,
                                'source_verified_after_cleanup': yoga_verified_after,
                                'installed_workspace': yoga_admission['installedCapture'].projection(yoga_verified_after is True)
                                    if 'installedCapture' in yoga_admission else None,
                                'summary': yoga_summary, 'toolbarConsentProved': final_status == 0 and yoga_summary.get('toolbarConsentProved', False)} if yoga else None,
                       'coordination_lock': str(coordination / 'execution.lock'),
                       'codex_pack_directory': str(args.codex_pack_directory) if args.codex_pack_directory else None,
                       'codex_pack_metadata': pack_digests,
                       'codex_recovery_source': str(args.codex_recovery_source) if args.codex_recovery_source else None,
                       'codex_fresh_public_inputs': fresh_metadata,
                       'codex_fresh_runtime_input': {
                           'before':fresh_input_before,'after':fresh_input_after,
                           'verified_after_cleanup':fresh_input_verified_after,
                           'original_deadline_monotonic_ns':delivery_entry_deadline_ns,
                           'native_support':False,'provider_evaluation':False
                       } if fresh_input else None,
                       'codex_owner_runtime_input': {'before': owner_input.facts(), 'after': owner_input_after,
                           'verified_after_cleanup': owner_input_verified_after,
                           'original_deadline_monotonic_ns': delivery_entry_deadline_ns,
                           'runtime_seconds': delivery_runtime_seconds} if owner_input else None,
                       'pids_observation': pids_observation.receipt(),
                       'disk_monitor': {'free_floor_bytes': FREE_FLOOR, 'filesystem': str(args.state_dir),
                                        'enforcement': 'sampled free space; not a hard disk quota'},
                       'sdk': {'lane': args.sdk_lane, 'plan': sdk_plan,
                               'physical_mode_policy': sdk_plan['physical_mode_policy'],
                               'git_mode_authority': sdk_plan['git_mode_authority'],
                               'source_verified_after_cleanup': sdk_source_verified_after,
                               'graph': sdk.GRAPH} if sdk else None,
                       'site': {'phase': args.site_phase, 'qualification': str(args.site_qualification),
                                'fetch_no_build': args.site_phase == 'fetch',
                                'action_strategy_exceptions': {} if args.site_phase in ('lock', 'fetch') else {'CopyFile': 'local'},
                                'qualification_sha256': args.site_qualification_sha256,
                                'native_bazel': bazel, 'java_home': str(java), 'bindings': site_bindings,
                                'source_verified_after_cleanup': site_source_verified_after,
                                'source_changes': site_source_changes,
                                'lockfile_evidence': site_lock_evidence,
                                'controller_graph_before': site_controller_graph,
                                'controller_graph_after': site_controller_graph_after,
                                'source_inputs': sorted(site_snapshot),
                                'source_snapshot_before_sha256': hashlib.sha256(json.dumps(site_snapshot, sort_keys=True).encode()).hexdigest(),
                                'source_snapshot_after_sha256': hashlib.sha256(json.dumps(site_snapshot_after, sort_keys=True).encode()).hexdigest() if site_snapshot_after is not None else None,
                                'delivery_manifest': str(args.site_delivery_manifest) if args.site_delivery_manifest else None,
                                'delivery_manifest_sha256': args.site_delivery_manifest_sha256} if site else None,
                       'supervisor': {'pid': supervisor_pid, 'start_ticks': supervisor_start_ticks},
                       'cache_reuse_requested': args.reuse_owned_cache,
                       'cache_key': cache_key, 'graph_sha256': graph_sha256,
                       'cache_policy': 2 if args.reuse_owned_cache else None,
                       'cache_profile': cache_profile,
                       'graph_inputs': graph_inputs,
                       'output_base': str(native_cli.lease.output_base if native_cli else native_history.lease.output_base if native_history
                           else native_staged.lease.output_base if native_staged
                           else native_fresh.lease.output_base if native_fresh
                           else lease.output_base if lease else run / 'output-base'),
                       'artifact_epoch': identifier,
                       'privilege_transport': 'fixed host-local SOPS stdin; exact UUID controller only' if sudo else None,
                       'controller_failure': controller_failure,
                       'controller_diagnostics': controller_diagnostics,
                       'cleanup': cleanup_summary,
                       'original_cgroup_identity': {'device': cgroup_pin.identity[0], 'inode': cgroup_pin.identity[1]} if cgroup_pin else None,
                       'rejection': rejection, 'observed_properties': observed_properties,
                       'startup_history': startup_history,
                       'descendants_empty': cleanup, 'limits': reservation_helper.properties(PROPERTIES) if reservation_selected else resident_dispatch.proof_properties(PROPERTIES,resident_settings) if resident_settings else PROPERTIES,
                       'isolation': isolation,
                       'inaccessible_paths': blocked_paths(args.profile) if args.manager == 'user' else
                           (['/etc/environment'] if args.profile in ('installed-browser', 'site', 'yoga-toolbar','yoga-toolbar-reserved') else []),
                       'temporary_filesystem_masks': (yoga.mask_setting(Path(pwd.getpwuid(os.getuid()).pw_dir)) if yoga else system_masks(profile=mask_profile)) if args.manager == 'system' else None,
                       'nixpkgs_evaluation_source': str(args.nixpkgs_source) if args.nixpkgs_source else None,
                       'site_source': str(args.site_source) if args.site_source else None,
                       'site_nixpkgs_evaluation_source': str(args.site_nixpkgs_source) if args.site_nixpkgs_source else None,
                       'site_public_inputs_sha256': site_digests,
                       'site_inventory': str(args.site_inventory) if args.site_inventory else None,
                       'site_inventory_sha256': args.site_inventory_sha256,
                       'tool_environment': environment,
                       'closure_manifest_sha256': closure_digest,
                       'bootstrap_manifest_sha256': bootstrap_digest,
                       'graph_binding': 'caller must verify locked-flake and exact local action graph',
                       'bootstrap': 'pre-realized immutable tools; no Nix build',
                       'authority': 'AGENTS.md; R-N11; R-N13'}
            if delivery_http is not None:
                receipt['yoga_controller_http_inputs'] = delivery_http.facts()
            if reservation_selected:
                receipt['reserved_failure'] = seed_failure
                if yoga_installed_input is not None:
                    receipt['yoga_installed_producer_input'] = {'before':yoga_installed_before,
                        'after':yoga_installed_after,'verified_after_cleanup':yoga_installed_verified_after}
                outcome = getattr(proof_worker, 'proc_exit_confirmation', 'not-requested')
                import guard_native_seed_plan_reserved as reservation_diagnostic
                receipt['reserved_proc_exit_confirmation'] = (outcome if type(outcome) is str
                    and outcome in reservation_diagnostic.PROC_EXIT_OUTCOMES else 'unknown')
                try:
                    reservation_helper.remaining(delivery_entry_monotonic_ns,delivery_entry_deadline_ns,cleanup=True)
                except ValueError:
                    seed_verified_after=False
                    final_status=receipt['exit']=125
                if yoga_toolbar_reserved:
                    toolbar_reserved.finalize(receipt,delivery_entry_monotonic_ns,
                        delivery_entry_deadline_ns,seed_verified_after is True,seed_after)
                    final_status = receipt['exit']
                elif args.profile == toolbar_reserved.MODEL_PROFILE:
                    receipt['yoga_toolbar_model_reservation'] = toolbar_reserved.model_projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif yoga_reserved:
                    receipt['yoga_installed_reservation'] = seed_reserved.projection(args.profile,
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'default-archive-reserved':
                    receipt['default_archive_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'yoga-controller-qualify-reserved':
                    receipt['yoga_controller_qualify_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile in ('yoga-controller-inspect-reserved','yoga-controller-verify-reserved'):
                    receipt['yoga_controller_readonly_reservation'] = seed_reserved.readonly_projection(args.profile,
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'yoga-sealed-workspace-models-reserved':
                    receipt['yoga_sealed_transfer_models_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'query-registration-reserved':
                    receipt['query_registration_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'resident-models-reserved':
                    receipt['resident_models_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'resident-owner-status-source-reserved':
                    receipt['resident_owner_status_source_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'resident-owner-status-binding-reserved':
                    receipt['resident_owner_status_binding_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'resident-owner-status-persistence-source-reserved':
                    receipt['resident_owner_status_persistence_source_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'resident-native-source-context-source-reserved':
                    receipt['resident_native_source_context_source_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'resident-native-source-context-refresh-source-reserved':
                    receipt['resident_native_source_context_refresh_source_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'resident-native-source-acquisition-source-reserved':
                    receipt['resident_native_source_acquisition_source_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile in ('native-acquisition-inputs-models-reserved','native-acquisition-binding-reserved','native-acquisition-metadata-reserved','native-acquisition-sdk-reserved','native-acquisition-plan-reserved','native-acquisition-query-reserved','native-acquisition-compilation-reserved','native-acquisition-runtime-qualification-reserved','native-acquisition-package-reserved','native-acquisition-bridge-material-reserved','native-acquisition-bridge-models-reserved','native-acquisition-ordinary-tui-reserved','native-acquisition-ordinary-models-reserved','native-acquisition-package-models-reserved'):
                    receipt['native_acquisition_inputs_reservation'] = seed_reserved.projection(
                        args.profile,delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile in ('home-manager-reconstruction-reserved','home-manager-evaluation-reserved','home-manager-bundle-models-reserved'):
                    receipt['home_manager_bundle_reservation'] = seed_reserved.projection(args.profile,
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'native-peer-qualification-reserved':
                    receipt['native_peer_qualification_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'resident-native-source-context-metadata-reserved':
                    receipt['resident_native_source_context_metadata_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile == 'resident-owner-status-persistence-binding-reserved':
                    receipt['resident_owner_status_persistence_binding_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile in ('native-metadata-sdk-models-reserved','native-query-descriptor-reserved','native-persistence-metadata-reserved','native-persistence-sdk-reserved','native-persistence-package-models-reserved'):
                    receipt['native_metadata_sdk_reservation'] = seed_reserved.projection(args.profile,
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after)
                elif args.profile in ('resident-custody-runtime-models-reserved','resident-custody-runtime-reserved','resident-custody-runtime-linux-reserved','resident-custody-runtime-format-reserved','resident-installed-custody-models-reserved','resident-default-source-models-reserved','resident-native-acquisition-units-reserved','resident-native-deployment-wiring-units-reserved','resident-lifecycle-accounting-models-reserved'):
                    receipt['resident_custody_runtime_reservation'] = seed_reserved.projection(
                        delivery_entry_monotonic_ns,delivery_entry_deadline_ns,seed_verified_after,seed_after,args.profile)
                else:
                    receipt['native_seed_plan_reservation'] = {
                        'scope':'native-seed-plan-reserved-v1','mode':'qualification' if args.profile==seed_reserved.PROFILE else 'models',
                        'original_entry_monotonic_ns':delivery_entry_monotonic_ns,
                        'original_deadline_monotonic_ns':delivery_entry_deadline_ns,
                        'verified_after_cleanup':seed_verified_after,'resident':seed_after,
                        'seed_qualification':False,'seed_qualification_requires_matching_outer_success':True,
                        'native_runtime_qualified':False,'complete_build_seed_qualified':False}
            record_resident_lifecycle(receipt,resident_input)
            if dev_stage_proof:
                receipt['development_stage'] = {'scope':DEV_STAGE_SCOPE,'stage_child':'dev-stage-complete',
                    'original_entry_monotonic_ns':delivery_entry_monotonic_ns,
                    'original_deadline_monotonic_ns':delivery_entry_deadline_ns,
                    'source_verified_after_cleanup':dev_stage_verified_after}
            receipt_raw = json.dumps(receipt, sort_keys=True) + '\n'
            if native_fresh is not None:
                receipt_raw = fresh_completion.terminal_receipt(native_fresh, receipt)
                final_status = receipt['exit']
            if native_staged is not None:
                receipt_raw = staged_compilation.terminal_receipt(native_staged, receipt)
                final_status = receipt['exit']
            if native_history is not None:
                receipt_raw = history_profile.terminal_receipt(native_history, receipt)
                final_status = receipt['exit']
            if native_cli is not None:
                receipt_raw = cli_profile.terminal_receipt(native_cli, receipt)
                final_status = receipt['exit']
            descriptor = os.open(run / 'receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w') as output:
                output.write(receipt_raw)
                output.flush()
                os.fsync(output.fileno())
            directory = os.open(run, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            if lease is not None:
                try:
                    if cleanup and (evidence_ok or native_cache is not None) and (native_cache is None or native_cache.may_complete(cleanup, native_verified_after)) and native_verified_after is not False and sdk_source_verified_after is not False and site_source_verified_after is not False and owner_input_verified_after is not False:
                        lease.complete(True, hashlib.sha256((run / 'receipt.json').read_bytes()).hexdigest())
                finally:
                    lease.close()
            print(json.dumps({'id': identifier, 'exit': final_status, 'workload_exit': result,
                              'descendants_empty': cleanup, 'test_evidence': evidence['state'],
                              'controller_failure': controller_failure, 'cleanup': cleanup_summary}))
            if pids_cancellation is not None:
                raise pids_cancellation
        return final_status


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt as error:
        print(rejection_diagnostic(error, DIAGNOSTIC_STAGE), file=sys.stderr)
        sys.exit(125)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(rejection_diagnostic(error, DIAGNOSTIC_STAGE))
