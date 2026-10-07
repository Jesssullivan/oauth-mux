"""Bounded public SSH policy compatibility; never reads key material."""
import contextlib
import glob
import os
from pathlib import Path
import shlex
import stat
import tempfile

SUBSET = ("mlkem768x25519-sha256", "curve25519-sha256")
UNSUPPORTED = {"mlkem768nistp256-sha256", "mlkem1024nistp384-sha384"}


def rewrite_kex(line):
    words = shlex.split(line, comments=True)
    if not words or words[0].lower() != "kexalgorithms":
        return line
    if len(words) != 2:
        raise ValueError("malformed public KEX policy")
    algorithms = words[1].split(",")
    if any(unsupported in words[1] for unsupported in UNSUPPORTED) and words[1].startswith(("+", "-", "^")):
        raise ValueError("relative KEX policy cannot be narrowed safely")
    if not UNSUPPORTED.intersection(algorithms):
        return line
    if not set(SUBSET).issubset(algorithms):
        raise ValueError("approved subset is not permitted by actual policy")
    return "KexAlgorithms " + ",".join(SUBSET) + "\n"


@contextlib.contextmanager
def operator_config():
    """Clone public config includes; original user config is included by path."""
    with tempfile.TemporaryDirectory(prefix="omux-ssh-policy-") as directory:
        written = {}
        active = set()
        total = 0
        changed = False

        def clone(source, depth=0):
            nonlocal total, changed
            if depth > 8 or len(written) >= 32:
                raise ValueError("public SSH include graph exceeds bound")
            path = Path(source)
            name = str(path)
            if not (name.startswith("/etc/ssh/") or name.startswith("/etc/crypto-policies/")):
                raise ValueError("SSH include is outside public policy roots")
            if name in active:
                raise ValueError("cyclic SSH policy include")
            if name in written:
                return written[name]
            if path.is_symlink():
                if name != "/etc/crypto-policies/back-ends/openssh.config" or str(path.resolve()) != "/usr/share/crypto-policies/DEFAULT/openssh.txt":
                    raise ValueError("unexpected public SSH config symlink")
            canonical = str(path.resolve())
            if not (canonical.startswith(("/etc/ssh/", "/etc/crypto-policies/", "/private/etc/ssh/", "/private/etc/crypto-policies/"))
                    or (name == "/etc/crypto-policies/back-ends/openssh.config"
                        and canonical == "/usr/share/crypto-policies/DEFAULT/openssh.txt")):
                raise ValueError("public SSH include resolves outside public policy roots")
            info = path.stat()
            if (info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o004
                    or not stat.S_ISREG(info.st_mode)):
                raise ValueError("public SSH config ownership or mode rejected")
            total += info.st_size
            if total > 1024 * 1024:
                raise ValueError("public SSH config exceeds byte bound")
            destination = Path(directory) / (str(len(written)) + ".conf")
            written[name] = str(destination)
            active.add(name)
            output = []
            for line in path.read_text().splitlines(keepends=True):
                words = shlex.split(line, comments=True)
                if words and words[0].lower() == "include":
                    includes = []
                    for pattern in words[1:]:
                        if not pattern.startswith("/"):
                            pattern = str(path.parent / pattern)
                        includes.extend(clone(match, depth + 1) for match in sorted(glob.glob(pattern)))
                    if includes:
                        output.append("Include " + " ".join('"' + item + '"' for item in includes) + "\n")
                else:
                    rewritten = rewrite_kex(line)
                    changed = changed or rewritten != line
                    output.append(rewritten)
            active.remove(name)
            destination.write_text("".join(output))
            destination.chmod(0o600)
            return str(destination)

        system = clone("/etc/ssh/ssh_config")
        if not changed:
            yield []
            return
        user = Path.home() / ".ssh/config"
        if any(character in str(user) for character in ['"', "\n", "\r"]):
            raise ValueError("user SSH config path cannot be represented safely")
        entry = Path(directory) / "operator.conf"
        entry.write_text('Include "' + str(user) + '"\nHost *\nInclude "' + system + '"\n')
        entry.chmod(0o600)
        yield ["-F", str(entry)]
