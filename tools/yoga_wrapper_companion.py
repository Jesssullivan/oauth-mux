"""One declared public registry/wrapper companion TEST producer.

No realization, tool subprocess, network, installation, browser, provider,
private profile or credential access. Genuine producer receipts and original
coordinator clocks are mandatory; metadata never grants execution authority.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import time

# Exact declared sibling modules are in this target's runfiles closure.
sys.path.insert(0, str(Path(__file__).parent.parent/'delivery'))
import yoga_installed_workspace as workspace
import yoga_wrapper_authority as authority
import yoga_wrapper_custody as custody
import yoga_installed_controller_support as support
import yoga_wrapper_companion_inputs as inputs
import yoga_python_role_alias as alias
import yoga_delivery_settings as settings
import guard_yoga_controller_qualify_reserved as qualification
import guard_native_seed_plan_reserved as kernel
import execution_guard as guard

SELECTOR = '//delivery:yoga_installed_selection'
BYTE_PROOF = '//tools:yoga_controller_byte_verification'
REASON = 'yoga-wrapper-companion-refused'


def require(value):
    if value is not True:
        raise ValueError(REASON)


def canonical(value):
    return custody.canonical(value)


def emitted(log, predicate):
    require(type(log) is bytes and 0 < len(log) <= 8*1024**2)
    rows = []
    for line in log.splitlines():
        if line.startswith(b'{'):
            value = inputs.decode(line)
            if predicate(value):
                rows.append(value)
    require(len(rows) == 1)
    return rows[0]


def receipt(value, pin, label, *, source=None, graph=None):
    require(type(value) is dict and value.get('id') == pin['epoch']
        and type(value.get('exit')) is int and value['exit'] == 0
        and type(value.get('workload_exit')) is int and value['workload_exit'] == 0
        and value.get('verb') == 'test' and value.get('targets') == [label]
        and value.get('manager') == 'system' and value.get('source_dirty') == 'false'
        and value.get('cache_reuse_requested') is False
        and value.get('descendants_empty') is True and value.get('controller_failure') is None
        and value.get('rejection') is None and value.get('artifact_epoch') == pin['epoch'])
    cleanup = value.get('cleanup')
    require(type(cleanup) is dict and cleanup.get('state') == 'empty'
        and cleanup.get('ownership') == 'verified'
        and type(cleanup.get('readback_attempts')) is int and cleanup['readback_attempts'] >= 2)
    if source is not None:
        require(value.get('source_commit') == source and value.get('graph_sha256') == graph
            and value.get('profile') == 'yoga-installed-selection-reserved'
            and value.get('reserved_failure') is None and value.get('limits') == kernel.properties(guard.PROPERTIES))
        reserved = value.get('yoga_installed_reservation')
        require(type(reserved) is dict and reserved.get('verified_after_cleanup') is True
            and reserved.get('mode') == 'selection'
            and reserved.get('scope') == 'fixed-yoga-installed-reservation-v1')
        kernel.envelope(reserved.get('original_entry_monotonic_ns'), reserved.get('original_deadline_monotonic_ns'))
        resident = reserved.get('resident')
        require(type(resident) is dict and resident.get('scope') == 'sampled-fixed-default-cgroup-kernel-reservation-v1'
            and resident.get('initial_direct_processes_retained') is True
            and resident.get('outer_pid_namespace_matched') is True and resident.get('hierarchical_caps') is True
            and resident.get('resident_signalled') is False)
        kernel.kernel_bounds(resident.get('kernel_bounds'))
    else:
        # The old fixed immutable NAR generation may have an earlier source.
        require(value.get('profile') == 'standard'
            and type(value.get('source_commit')) is str and re.fullmatch('[a-f0-9]{40}', value['source_commit']) is not None
            and value.get('limits') == guard.PROPERTIES)
    evidence = value.get('test_evidence')
    require(type(evidence) is dict and evidence.get('state') == 'preserved'
        and evidence.get('manifest') == 'test-evidence.json'
        and type(evidence.get('sha256')) is str and inputs.SHA.fullmatch(evidence['sha256']) is not None)
    return evidence


def log_pin(manifest, label, parent):
    require(type(manifest) is dict and manifest.get('schema') == 1
        and type(manifest.get('bazel_exit')) is int and manifest['bazel_exit'] == 0
        and manifest.get('targets') == [label] and type(manifest.get('results')) is list
        and 0 < len(manifest['results']) <= 32)
    rows = [row for row in manifest['results'] if row.get('target') == label]
    require(len(rows) == 1 and rows[0].get('state') == 'observed')
    files = rows[0].get('files')
    require(type(files) is list and len(files) <= 8)
    logs = [row for row in files if row.get('source') == 'test.log']
    require(len(logs) == 1 and logs[0].get('state') == 'copied'
        and type(logs[0].get('file')) is str and re.fullmatch(r'[a-f0-9]{64}\.evidence', logs[0]['file']) is not None)
    return {'path': str(parent/'test-evidence'/logs[0]['file']),
        'sha256': logs[0]['sha256'], 'bytes': logs[0]['bytes']}


def proof(value, inventory, inventory_sha):
    require(type(value) is dict and set(value) == custody.NAR_FIELDS
        and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
        and value['passed'] is True and value['contentRehashed'] is True
        and value['inventorySha256'] == inventory_sha
        and type(value['descriptorSha256']) is str and inputs.SHA.fullmatch(value['descriptorSha256']) is not None
        and type(value['verifiedPaths']) is int and value['verifiedPaths'] == len(inventory['paths'])
        and type(value['verifiedRegularInputs']) is int and value['verifiedRegularInputs'] > 0
        and type(value['verifiedNarBytes']) is int
        and value['verifiedNarBytes'] == sum(row['narSize'] for row in inventory['paths'])
        and all(value[name] is False for name in ('linkTargetsFollowed','executionAuthority','flakeMappingVerified','realized')))


class Producer:
    def __init__(self, request_path, request_sha, entry, deadline, prior, source, graph, lock):
        self.resources, self.aliases, self.resolved_inputs = [], [], []
        self.entry, self.deadline, self.prior = entry, deadline, prior
        self.source, self.graph, self.lock = source, graph, lock
        try:
            kernel.envelope(entry, deadline)
            require(type(source) is str and re.fullmatch('[a-f0-9]{40}', source) is not None
                and type(graph) is str and inputs.SHA.fullmatch(graph) is not None)
            self.request = inputs.HeldRequest(request_path, request_sha, deadline)
            self.resources.append(self.request)
            self.qcheck()
            request = self.request.value
            selected_logs = {}
            for name, label in (('selector', SELECTOR), ('controllerNarProducer', BYTE_PROOF)):
                selected = request[name]
                captured = self.public({key: selected[key] for key in ('path','sha256','bytes')})
                value = inputs.decode(captured.raw)
                evidence = receipt(value, selected, label,
                    **({'source': source, 'graph': graph} if name == 'selector' else {}))
                parent = Path(selected['path']).parent
                metadata_path = parent/evidence['manifest']
                metadata = self.public({'path': str(metadata_path), 'sha256': evidence['sha256'],
                    'bytes': metadata_path.stat(follow_symlinks=False).st_size})
                selected_logs[name] = self.public(log_pin(inputs.decode(metadata.raw), label, parent)).raw
            selection = self.public(request['selectedData'])
            digest = hashlib.sha256(selection.raw).hexdigest()
            result = emitted(selected_logs['selector'], lambda row: type(row) is dict
                and row.get('scope') == 'yoga-installed-selection-assembly-v1')
            require(result == {'schemaVersion': 1, 'scope': 'yoga-installed-selection-assembly-v1',
                'selectionSha256': digest, 'executionAuthority': False, 'toolbarConsentProved': False})
            self.selected = workspace.selected(inputs.decode(selection.raw))
            require(self.selected['schemaVersion'] == support.SCHEMA)
            inventory = self.capture(self.selected['controllerInventory']['path'], settings.INVENTORY, 8*1024**2)
            self.inventory = custody.decode(inventory.data)
            self.rows, total, provenance = authority.inventory(self.inventory, deadline, time.monotonic_ns)
            nar = self.public(request['controllerNarProof'])
            nar_value = inputs.decode(nar.raw)
            proof(nar_value, self.inventory, settings.INVENTORY)
            observed = emitted(selected_logs['controllerNarProducer'], lambda row: type(row) is dict
                and set(row) == custody.NAR_FIELDS)
            require(observed == nar_value)
            custody.registered_rows(list(self.rows.values()), deadline)
            self.native = self.capture(self.selected['nativeManifest'], self.selected['nativeManifestSha256'], 1024**2)
            native = custody.decode(self.native.data)
            self.role = alias.RoleIdentity(settings.TOOLS['python'], native, deadline)
            self.resources.append(self.role)
            logical = self.role.logical_tools(settings.TOOLS)
            native_object = self.registered_object(logical['closure'], 'native.json')
            bootstrap_object = self.registered_object(logical['bootstrap_closure'], 'native.json')
            registered = self.capture(native_object, None, 1024**2)
            bootstrap = self.capture(bootstrap_object, provenance['bootstrap_manifest'], 1024**2)
            require(custody.decode(registered.data) == native)
            wrappers, wrapper_bytes, wrapper_paths, wrapper_shas = {}, {}, {}, {}
            bash = native['packages']['bash']['out']+'/bin/bash'
            for name, (tool, basename) in authority.ROLES.items():
                logical_path = self.selected['inputPaths'][name]
                target = workspace.safe_resolve(logical_path, frozenset(self.rows))
                item = self.capture(str(target), self.selected['inputSha256'][name], 8192, executable=True)
                # Actual wrapper leaf path is the immutable historical action role.
                require(str(target) == str(Path(self.native.path).parent/'tool_wrappers'/tool))
                backend = native['tools'][tool]
                root = authority.store_root(backend)
                require(backend == root+'/bin/'+basename and root in self.rows)
                self.resources.append(custody.Captured(backend, None, 512*1024**2,
                    deadline, time.monotonic_ns, executable=True, read=False))
                wrappers[name] = {'sha256': item.digest, 'backend': backend, 'backendRoot': root,
                    'interpreter': bash, 'abi': 'omux-native-capability-wrapper-v1'}
                wrapper_bytes[name], wrapper_paths[name], wrapper_shas[name] = item.data, str(target), item.digest
            self.resources.append(custody.Captured(bash, None, 512*1024**2,
                deadline, time.monotonic_ns, executable=True, read=False))
            # The closed eleven delivery roles are all actual byte readbacks,
            # including the prebuilt bundle and extension. No browser state.
            for name, logical_path in self.selected['inputPaths'].items():
                target = workspace.safe_resolve(logical_path, frozenset(self.rows))
                item = self.capture(str(target), self.selected['inputSha256'][name], workspace.payload.MAX_FILE)
                self.resolved_inputs.append((logical_path, str(target)))
                if name in workspace.ARTIFACTS:
                    require(len(item.data) == workspace.ARTIFACTS[name][1])
            # Current package bytes join the genuine current-source selector.
            require(support.TOOLS == Path(inputs.__file__).resolve().parent)
            self.source_pins = dict(self.selected['controllerPackage']['files'])
            self.source_check()
            self.companion = dict(schemaVersion=1, scope='yoga-controller-registry-and-wrapper-v1',
                selectionSha256=provenance['selection'], inventorySha256=settings.INVENTORY,
                controllerTools=logical,
                nativeManifest={'sha256': self.selected['nativeManifestSha256'], 'registeredObject': native_object,
                    'registeredManifestSha256': registered.digest},
                bootstrapManifest={'sha256': provenance['bootstrap_manifest'], 'registeredObject': bootstrap_object,
                    'registeredManifestSha256': bootstrap.digest}, wrappers=wrappers,
                rootCount=len(self.inventory['roots']), registeredPaths=len(self.rows), registeredNarBytes=total,
                deadlineMonotonicNs=deadline, registrySnapshotVerified=True, selectedInputBytesVerified=True,
                **{name: False for name in authority.FALSE_FIELDS})
            self.content = canonical(self.companion)+b'\n'
            authority.validate(self.content, companion_sha256=hashlib.sha256(self.content).hexdigest(),
                native_manifest_bytes=self.native.data, native_manifest_sha256=self.native.digest,
                registered_native_manifest_bytes=registered.data, inventory_bytes=inventory.data,
                inventory_sha256=settings.INVENTORY, native_manifest_path=self.native.path,
                wrapper_paths=wrapper_paths, wrapper_bytes=wrapper_bytes, wrapper_sha256=wrapper_shas,
                controller_tools=logical, deadline_ns=deadline)
            self.metadata = {'schemaVersion': 1, 'scope': 'yoga-wrapper-companion-production-v1',
                'requestSha256': request_sha, 'sourceCommit': source, 'sourceGraphSha256': graph,
                'qualificationProducerEpoch': prior['producer_epoch'],
                'selectorEpoch': request['selector']['epoch'], 'controllerNarProducerEpoch': request['controllerNarProducer']['epoch'],
                'controllerTools': settings.TOOLS, 'pythonRole': {'logical': self.role.logical,
                    'physical': self.role.physical, 'sha256': self.role.digest,
                    'device': self.role.saved[0], 'inode': self.role.saved[1]},
                'companionSha256': hashlib.sha256(self.content).hexdigest(),
                'executionAuthority': False, 'installationQualified': False, 'toolbarConsentProved': False}
            self.check()
        except BaseException:
            self.close()
            raise

    def public(self, selected):
        item = inputs.HeldPublic(selected, self.deadline)
        self.resources.append(item)
        return item

    def capture(self, path, sha, maximum, **kwargs):
        item = custody.Captured(path, sha, maximum, self.deadline, time.monotonic_ns, **kwargs)
        self.resources.append(item)
        return item

    def registered_object(self, closure, leaf):
        require(closure in self.rows)
        directory = os.open(closure, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info = os.fstat(directory)
            require(info.st_uid == 0 and not info.st_mode & 0o222)
            saved = inputs.directory_identity(info)
            link = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
            target = os.readlink(leaf, dir_fd=directory)
            require(stat.S_ISLNK(link.st_mode) and link.st_uid == 0
                and authority.STORE.fullmatch(target) is not None
                and target in self.rows[closure]['references'])
            self.aliases.append((closure, directory, saved, leaf, inputs.identity(link), target))
            return target
        except BaseException:
            os.close(directory)
            raise

    def source_check(self):
        # Sequential named/held full readbacks plus final current graph fence;
        # no assertion of continuous custody of every controller descriptor.
        for name, pin in self.source_pins.items():
            item = inputs.HeldSource(name, pin['sha256'], pin['bytes'], self.deadline)
            try:
                item.recheck()
            finally:
                item.close()

    def qcheck(self):
        kernel.remaining(self.entry, self.deadline)
        qualification.recheck(self.prior, self.graph, guard.PROPERTIES, self.deadline,
            self.lock, source_commit=self.source)
        require(guard.graph_digest(support.ROOT)[0] == self.graph)

    def check(self):
        self.qcheck()
        self.source_check()
        for resource in self.resources:
            if isinstance(resource, (inputs.HeldPublic, inputs.HeldRequest, inputs.HeldSource)):
                resource.recheck()
            else:
                resource.check()
        for logical_path, target in self.resolved_inputs:
            require(str(workspace.safe_resolve(logical_path, frozenset(self.rows))) == target)
        for closure, fd, saved, leaf, link, target in self.aliases:
            require(saved == inputs.directory_identity(os.fstat(fd))
                == inputs.directory_identity(os.stat(closure, follow_symlinks=False))
                and link == inputs.identity(os.stat(leaf, dir_fd=fd, follow_symlinks=False))
                and target == os.readlink(leaf, dir_fd=fd))
        custody.registered_rows(list(self.rows.values()), self.deadline)
        self.qcheck()

    def publish(self, output):
        self.check()
        output = inputs.output_path(str(output))
        chain, created = [], []
        try:
            current = Path('/')
            fd = os.open(current, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            chain.append((current, fd, inputs.directory_identity(os.fstat(fd))))
            for part in output.parts[1:]:
                kernel.remaining(self.entry, self.deadline)
                current /= part
                fd = os.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=fd)
                chain.append((current, fd, inputs.directory_identity(os.fstat(fd))))
            require(all(row[2][2] in (0, os.getuid()) and not row[2][4] & 0o022 for row in chain)
                and chain[-1][2][2] == os.getuid())
            def joined():
                for index, (path, held, saved) in enumerate(chain):
                    named = path.stat(follow_symlinks=False) if index == 0 else os.stat(path.name,
                        dir_fd=chain[index-1][1], follow_symlinks=False)
                    require(saved == inputs.directory_identity(os.fstat(held)) == inputs.directory_identity(named))
            for name, data in (('wrapper-companion.json', self.content),
                               ('wrapper-companion-production.json', canonical(self.metadata)+b'\n')):
                self.check(); joined()
                child = os.open(name, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600, dir_fd=fd)
                created.append((name, child, None, data))
                view = memoryview(data)
                while view:
                    kernel.remaining(self.entry, self.deadline)
                    count = os.write(child, view); require(count > 0); view = view[count:]
                os.fsync(child)
                saved = inputs.identity(os.fstat(child))
                created[-1] = (name, child, saved, data)
                require(stat.S_ISREG(saved[4]) and saved[2] == os.getuid() and saved[5] == 1
                    and stat.S_IMODE(saved[4]) == 0o600)
            os.fsync(fd)
            for name, child, saved, data in created:
                joined(); self.check()
                require(saved == inputs.identity(os.fstat(child))
                    == inputs.identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
                    and os.pread(child, len(data)+1, 0) == data)
            joined(); self.check()
            return self.metadata
        except BaseException:
            failed = False
            for name, child, saved, _ in reversed(created):
                try:
                    held = inputs.identity(os.fstat(child))
                    require(held == inputs.identity(os.stat(name, dir_fd=chain[-1][1], follow_symlinks=False))
                        and (saved is None or held == saved))
                    os.unlink(name, dir_fd=chain[-1][1])
                except (OSError, ValueError):
                    failed = True
            if failed:
                raise ValueError('wrapper-companion-partial-publication-cleanup-refused') from None
            raise
        finally:
            failed = False
            for descriptor in [row[1] for row in reversed(created)] + [row[1] for row in reversed(chain)]:
                try:
                    os.close(descriptor)
                except OSError:
                    failed = True
            if failed:
                raise ValueError('wrapper-companion-publication-release-refused') from None

    def close(self):
        resources, self.resources = self.resources, []
        aliases, self.aliases = self.aliases, []
        failed = False
        for resource in reversed(resources):
            try:
                resource.close()
            except (OSError, ValueError):
                failed = True
        for _, fd, *_ in reversed(aliases):
            try:
                os.close(fd)
            except OSError:
                failed = True
        require(not failed)


def main():
    producer = None
    try:
        require(len(sys.argv) == 1)
        entry = int(os.environ[kernel.ENTRY]); deadline = int(os.environ[kernel.DEADLINE])
        producer = Producer(os.environ['OMUX_YOGA_WRAPPER_REQUEST'],
            os.environ['OMUX_YOGA_WRAPPER_REQUEST_SHA256'], entry, deadline,
            inputs.decode(os.environ['OMUX_YOGA_WRAPPER_PRIOR']),
            os.environ['OMUX_YOGA_WRAPPER_SOURCE_COMMIT'], os.environ['OMUX_YOGA_WRAPPER_GRAPH_SHA256'],
            inputs.decode(os.environ['OMUX_YOGA_WRAPPER_LOCK_WITNESS']))
        result = producer.publish(os.environ['TEST_UNDECLARED_OUTPUTS_DIR'])
        producer.close(); producer = None
        print(canonical(result).decode('ascii'))
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        print(REASON, file=sys.stderr)
        raise SystemExit(125) from None
    finally:
        if producer is not None:
            try:
                producer.close()
            except (OSError, ValueError):
                print('yoga-wrapper-companion-custody-release-refused', file=sys.stderr)
                raise SystemExit(125) from None


if __name__ == '__main__':
    main()
