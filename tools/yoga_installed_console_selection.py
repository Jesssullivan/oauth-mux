"""Private installed selection construction from public pins and local witnesses.

Only the console-envelope owner supplies the original clock. This module does
not grant execution, create an envelope, realize tools, or open browser data.
"""
import hashlib
import os
from pathlib import Path
import pwd
import re
import time
import uuid

import guard_yoga_installed_workspace as installed
import guard_yoga_profile as guard
import guard_yoga_toolbar_reserved as reserved
import yoga_display_binding as display
import yoga_local_console_scope as console
import yoga_session_qualification as qualification

REQUEST_SCOPE = 'yoga-installed-console-public-input-v1'
REQUEST_FIELDS = frozenset(('schemaVersion', 'scope', 'installedWorkspace',
    'machineIdSha256', 'seatSessionId', 'stateRoot', 'sourceSocket', 'inputPaths',
    'controllerTools', 'controllerInventory', 'controllerNarProof', 'vaultWrapperAuthority'))


def require(value):
    if value is not True:
        raise ValueError('installed-console-selection-refused')


def request(raw):
    value = guard.decode(raw)
    require(type(value) is dict and set(value) == REQUEST_FIELDS
        and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
        and value['scope'] == REQUEST_SCOPE)
    pin = value['installedWorkspace']
    require(type(pin) is dict and set(pin) == {'path', 'sha256'}
        and type(pin['path']) is str and pin['path'].endswith('/installed-workspace.json')
        and type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}', pin['sha256']) is not None)
    require(type(value['machineIdSha256']) is str
        and re.fullmatch('[0-9a-f]{64}', value['machineIdSha256']) is not None
        and type(value['seatSessionId']) is str
        and re.fullmatch('[A-Za-z0-9_-]{1,32}', value['seatSessionId']) is not None)
    # Paths are explicit public evidence, never discovery or browser-profile input.
    installed.workspace_root(str(Path(pin['path']).parent))
    return value


def local_facts(value, deadline, terminal_descriptor):
    uid = os.getuid()
    terminal = console.terminal_identity(terminal_descriptor)
    machine = hashlib.sha256(guard.file_bytes('/etc/machine-id', 128, deadline)).hexdigest()
    require(machine == value['machineIdSha256'])
    session = value['seatSessionId']
    raw = guard.file_bytes('/run/systemd/sessions/' + session, 16384, deadline, owner=0)
    pairs = [line.split('=', 1) for line in raw.decode('ascii').splitlines()
        if line and not line.startswith('#')]
    require(all(len(row) == 2 for row in pairs) and len(pairs) == len({row[0] for row in pairs}))
    seat = dict(pairs).get('SEAT')
    require(type(seat) is str and re.fullmatch('seat[0-9]{1,3}', seat) is not None)
    host = {'machineIdSha256': machine, 'uid': uid}
    selected = {'host': host, 'seat': {'sessionId': session, 'seatId': seat, 'uid': uid},
        'operatorTerminal': os.ttyname(terminal_descriptor)}
    qualification.identity_capture(selected, deadline, uid, terminal_descriptor)
    console.recheck_terminal(terminal_descriptor, terminal)
    return selected, terminal


def build(value, record, facts, entry, deadline, proof_id):
    reserved.clock({reserved.CLOCK: entry, 'deadlineMonotonicNs': deadline})
    root = str(Path(value['installedWorkspace']['path']).parent)
    selected = {name: value[name] for name in ('stateRoot', 'sourceSocket', 'inputPaths',
        'controllerTools', 'controllerInventory', 'controllerNarProof', 'vaultWrapperAuthority',
        'installedWorkspace')}
    selected.update(facts)
    selected.update(schemaVersion=1, scope=reserved.SELECTION_SCOPE, proofId=proof_id,
        sourceRoot=root, sourceGraphSha256=record['workspaceGraphSha256'],
        sourceFilesSha256=record['sourceFilesSha256'], inputSha256=record['inputSha256'],
        deadlineMonotonicNs=deadline)
    selected[reserved.CLOCK] = entry
    reserved.selection(selected, deadline, os.getuid(), Path(pwd.getpwuid(os.getuid()).pw_dir))
    return selected


class PreparedSelection:
    """Retained local observations; parent and its forked child recheck before Go.

    This is an internal constructor, not a caller-supplied authority object.
    The public CLI owns the sole clock; terminal and endpoint data stay private.
    """
    def __init__(self, request_path, request_sha256, selection_path, qualification_path,
                 entry, deadline, *, terminal_descriptor=0):
        self.capture, self.pin, self.closed, self.published = None, None, False, False
        self.request_path, self.request_sha256 = request_path, request_sha256
        self.selection_path, self.qualification_path = selection_path, qualification_path
        self.entry, self.deadline, self.terminal_descriptor = entry, deadline, terminal_descriptor
        try:
            reserved.clock({reserved.CLOCK: entry, 'deadlineMonotonicNs': deadline})
            qualification.selectors(selection_path, qualification_path, deadline)
            qualification.selectors(request_path, selection_path, deadline)
            require(request_path not in (selection_path, qualification_path))
            self.raw = guard.file_bytes(request_path, qualification.MAX_SELECTION, deadline,
                private=True, expected=request_sha256)
            self.value = request(self.raw)
            self.root = str(Path(self.value['installedWorkspace']['path']).parent)
            # Construction executes the controller copied into this workspace.
            require(Path(__file__).resolve() == Path(self.root)/'tools/yoga_installed_console_selection.py')
            self.capture = installed.Capture(self.root, self.value['installedWorkspace'], deadline, guard.file_bytes)
            require(self.capture.record['schemaVersion'] == 2 and
                'yoga_installed_console_selection.py' in self.capture.record['controllerPackageSha256'])
            self.facts, self.terminal = local_facts(self.value, deadline, terminal_descriptor)
            self.selection = build(self.value, self.capture.record, self.facts, entry, deadline, str(uuid.uuid4()))
            proof_root = self.selection['stateRoot']+'/'+self.selection['proofId']
            for path in (request_path, selection_path, qualification_path):
                require(not Path(path).is_relative_to(self.root) and not Path(path).is_relative_to(proof_root))
            self.witness, self.pin = display.capture_pinned(self.selection['sourceSocket'],
                proof_root+'/wayland.sock', proof_root, os.getuid(), deadline)
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        require(not self.closed)
        reserved.clock(self.selection, self.deadline)
        require(guard.file_bytes(self.request_path, qualification.MAX_SELECTION, self.deadline,
            private=True, expected=self.request_sha256) == self.raw)
        self.capture.qualify(self.selection, self.selection['sourceGraphSha256'])
        require(qualification.graph_capture(self.root, self.deadline) == self.selection['sourceGraphSha256'])
        current, terminal = local_facts(self.value, self.deadline, self.terminal_descriptor)
        require(current == self.facts and terminal == self.terminal)
        guard.runtime_qualification(self.selection, self.deadline)
        self.pin.check(self.witness)

    def publish(self):
        require(not self.published)
        digest = qualification.publish(self.selection_path, qualification.canonical(self.selection),
            self.deadline, self.verify)
        self.published = True
        return {'selection': self.selection_path, 'selectionSha256': digest,
            'qualification': self.qualification_path, 'deadlineMonotonicNs': self.deadline,
            reserved.CLOCK: self.entry, 'executionAuthority': False, 'toolbarConsentProved': False}

    def close(self):
        if not self.closed:
            self.closed = True
            try:
                if self.pin is not None:
                    self.pin.close()
            finally:
                if self.capture is not None:
                    self.capture.close()
