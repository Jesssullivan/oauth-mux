"""Declared finite coordinator byte/version qualification; no build or Nix call.

This does not verify the complete closure or grant site execution authority.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time

CANDIDATE = Path('/home/jess/.local/state/omux-execution-20261005/cache-v2-0263cddbc2fe72e072e344a70bf61fdc0e90702986c9738e791ef64375ac8aee/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/site_coordinator_settings_producer/test.outputs/site-coordinator-settings/site-coordinator-settings.json')
CANDIDATE_SHA256 = '48253bf1b32bc341baadbe77e9fc983ad898c338166009e92e9e2f0047e7e55c'
BAZEL = Path('/nix/store/ia8gp7v2h790lwdx7a7p5clh063v0qy1-bazel-9.0.1/bin/bazel')
BAZEL_PACKAGE_WRAPPER = BAZEL.parent / 'bazel-9.0.1-linux-x86_64'
BAZEL_NATIVE = BAZEL.parent / '.bazel-9.0.1-linux-x86_64-wrapped'
JDK = Path('/nix/store/siln89j8b6k5wdzw4asl69bma0k96nns-openjdk-headless-21.0.10+7')
SITE_VERSION = Path('/srv/fast-local/jess/git/omux.xoxd.ai/.bazelversion')
NIX_BAZEL_VERSION = b'bazel 9.0.1- (@non-git)\n'
NIX_BAZEL_VERSION_SHA256 = 'a48452b91b946cf12c2e9bd73072286709bcf2c810c06e10389f17cb1421d3ee'


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_ancestor(path, info, immutable):
    path = Path(path)
    mode = stat.S_IMODE(info.st_mode)
    if immutable and path == Path('/nix/store'):
        require(info.st_uid == 0 and mode == 0o1775, 'immutable store parent is not the exact sticky root-owned directory')
    elif immutable and path.is_relative_to('/nix/store'):
        require(info.st_uid == 0 and not mode & 0o222, 'immutable package directory is writable or foreign')
    else:
        require(info.st_uid in (0, os.getuid()) and not mode & 0o022, 'untrusted input ancestor')


def file_bytes(path, maximum, immutable=False):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'noncanonical input')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    ancestor = Path('/')
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            ancestor /= part
            validate_ancestor(ancestor, info, immutable)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum and
                    before.st_uid == (0 if immutable else os.getuid()) and
                    not before.st_mode & (0o222 if immutable else 0o022), 'input custody mismatch')
            digest, payload, count = hashlib.sha256(), [], 0
            while chunk := os.read(fd, 1024 * 1024):
                count += len(chunk)
                require(count <= maximum, 'input exceeds bound')
                digest.update(chunk)
                payload.append(chunk)
            after = os.fstat(fd)
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed')
            return b''.join(payload), {'sha256': digest.hexdigest(), 'bytes': count,
                                      'mode': oct(stat.S_IMODE(before.st_mode))}
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def version_command(kind):
    if kind == 'bazel':
        require(BAZEL_NATIVE.resolve(strict=True) == BAZEL_NATIVE, 'native Bazel alias rejected')
        return [str(BAZEL_NATIVE), '--version']
    if kind == 'java':
        resolved = (JDK / 'bin/java').resolve(strict=True)
        require(resolved in (JDK / 'bin/java', JDK / 'lib/openjdk/bin/java'), 'Java alias escaped fixed JDK')
        return [str(resolved), '-version']
    raise ValueError('unknown version command')


def bounded_version(argv, scratch):
    require(argv in (version_command('bazel'), version_command('java')), 'version command is not fixed')
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, env={'PATH': '', 'HOME': str(scratch), 'JAVA_HOME': str(JDK),
                                    'XDG_CONFIG_HOME': str(scratch), 'XDG_CACHE_HOME': str(scratch),
                                    'LANG': 'C', 'LC_ALL': 'C'})
    output = bytearray()
    deadline = time.monotonic() + 10
    handlers = {}
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        handlers[signum] = signal.signal(signum, interrupted)
    try:
        with selectors.DefaultSelector() as selected:
            for stream in (process.stdout, process.stderr):
                selected.register(stream, selectors.EVENT_READ)
            while selected.get_map():
                require(time.monotonic() < deadline, 'version deadline')
                for key, _ in selected.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selected.unregister(key.fileobj)
                    output.extend(chunk)
                    require(len(output) <= 4096, 'version output bound')
        while (result := os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)) is None:
            require(time.monotonic() < deadline, 'version exit deadline')
            time.sleep(0.01)
        require(result.si_code == os.CLD_EXITED and result.si_status == 0, 'version command failed')
        return bytes(output)
    finally:
        # Retain direct-child leader until its original process group is killed.
        try:
            require(process.returncode is None, 'version leader reaped early')
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            require(os.getpgid(process.pid) == process.pid, 'version group identity changed')
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        finally:
            process.stdout.close()
            process.stderr.close()
            for signum, handler in handlers.items():
                signal.signal(signum, handler)


def validate_versions(bazel, java):
    stamped = bazel == NIX_BAZEL_VERSION and hashlib.sha256(bazel).hexdigest() == NIX_BAZEL_VERSION_SHA256
    if bazel.strip() != b'bazel 9.0.1' and not stamped:
        raise ValueError('Bazel version differs; ' + version_diagnostic(bazel))
    require(b'openjdk version "21.0.10"' in java and b'21.0.10+7' in java, 'Java version differs')
    return {'bazel_version_output': bazel.decode('ascii').strip(),
            'packaging_stamp': 'Nix exact non-git build stamp' if stamped else 'plain release version'}


def version_diagnostic(value):
    """Only a version-shaped token and byte facts; never arbitrary stderr text."""
    lines = value.splitlines()
    tokens = [line.decode('ascii') for line in lines
              if re.fullmatch(rb'(?:bazel|\.?bazel-9\.0\.1-linux-x86_64(?:-wrapped)?) '
                              rb'(?:no_version|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
                              rb'(?:[-+][0-9A-Za-z.]{1,24})?(?:- \(@non-git\))?)', line)]
    observed = tokens[0] if len(tokens) == 1 else 'unrecognized'
    return ('reported=' + observed + '; bytes=' + str(len(value)) + '; lines=' + str(len(lines)) +
            '; sha256=' + hashlib.sha256(value).hexdigest())


def qualify(candidate_sha256, native_manifest, bootstrap_manifest, output, scratch):
    require(candidate_sha256 == CANDIDATE_SHA256, 'candidate selection is not the fixed retained producer')
    payload, candidate_meta = file_bytes(CANDIDATE, 65536)
    require(candidate_meta['sha256'] == candidate_sha256, 'candidate receipt digest differs')
    candidate = json.loads(payload)
    require(candidate.get('status') == 'candidate-settings-only' and candidate.get('runtime_outputs_match') is True
            and candidate.get('bazel') == str(BAZEL) and candidate.get('java_home') == str(JDK)
            and candidate.get('execution_authority') is False, 'candidate authority differs')
    version, version_meta = file_bytes(SITE_VERSION, 64)
    require(version.strip() == b'9.0.1', 'site Bazel version differs')
    manifests = {}
    native_bazel_binding = 'native manifest has no packages.bazel entry; candidate and exact immutable package bind Bazel'
    for name, selected in (('native', native_manifest), ('bootstrap', bootstrap_manifest)):
        resolved = Path(selected).resolve(strict=True)
        require(resolved.parts[:3] == ('/', 'nix', 'store'), 'manifest outside immutable store')
        value, facts = file_bytes(resolved, 1024 * 1024, immutable=True)
        manifests[name] = facts
        if name == 'native':
            native = json.loads(value)
            require(native['packages']['bazel_jdk']['out'] == str(JDK), 'native closure JDK differs')
            if 'bazel' in native['packages']:
                require(native['packages']['bazel']['out'] == str(BAZEL.parent.parent), 'native closure Bazel differs')
                native_bazel_binding = 'native packages.bazel exact output matched'
    binaries = {}
    wrapper, wrapper_metadata = file_bytes(BAZEL, 1024 * 1024, immutable=True)
    require(BAZEL.resolve(strict=True) == BAZEL and wrapper.startswith(b'#!'), 'fixed Bazel wrapper differs')
    wrapper_metadata['path'] = str(BAZEL)
    package_wrapper, package_wrapper_metadata = file_bytes(BAZEL_PACKAGE_WRAPPER, 16384, immutable=True)
    require(BAZEL_PACKAGE_WRAPPER.resolve(strict=True) == BAZEL_PACKAGE_WRAPPER and
            package_wrapper.startswith(b'#!') and
            ('exec -a "$0" "' + str(BAZEL_NATIVE) + '"  "$@"').encode() in package_wrapper,
            'package wrapper native delegation differs')
    package_wrapper_metadata['path'] = str(BAZEL_PACKAGE_WRAPPER)
    for kind in ('bazel', 'java'):
        command = version_command(kind)
        value, binaries[kind] = file_bytes(command[0], 256 * 1024 * 1024, immutable=True)
        require(value.startswith(b'\x7fELF'), 'version command is not native ELF')
        require(int(binaries[kind]['mode'], 8) & 0o111, 'coordinator binary not executable')
        binaries[kind]['path'] = command[0]
    versions = validate_versions(bounded_version(version_command('bazel'), scratch), bounded_version(version_command('java'), scratch))
    report = {'schema_version': 1, 'status': 'version-and-byte-qualified-site-coordinator',
              'candidate': str(CANDIDATE), 'candidate_sha256': candidate_sha256,
              'bazel': str(BAZEL), 'java_home': str(JDK), 'bazel_version': '9.0.1', 'java_version': '21.0.10+7',
              'binary_versions_verified': True, 'binaries': binaries, 'manifest_metadata': manifests,
              'bazel_wrapper': wrapper_metadata,
              'bazel_package_wrapper': package_wrapper_metadata,
              'bazel_version_binding': 'fixed native ELF in the same pinned package; wrapper recorded but not executed',
              'native_manifest_bazel_binding': native_bazel_binding, **versions,
              'site_bazelversion': version_meta, 'closure_verified': False, 'execution_authority': False}
    output.mkdir(mode=0o700)
    content = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    with (output / 'site-coordinator-qualification.json').open('xb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'status': report['status'], 'receipt_sha256': hashlib.sha256(content).hexdigest(),
                      'execution_authority': False}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--native-manifest', required=True)
    parser.add_argument('--bootstrap-manifest', required=True)
    args = parser.parse_args()
    qualify(args.candidate_sha256, args.native_manifest, args.bootstrap_manifest,
            Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True) / 'site-coordinator-qualification',
            Path(os.environ['TEST_TMPDIR']).resolve(strict=True))


if __name__ == '__main__':
    main()
