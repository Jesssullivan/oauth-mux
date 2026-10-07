"""Local-only cancellation of one recorded operator-owned SSH custodian."""
import argparse
import json
import os
from pathlib import Path
import signal
import re
import time
import stat

PROOF = "2acf30f9-a1df-4a57-9231-ad2ee195299e"
MAX_PROCESSES = 65536

def declared_ssh(path):
    resolved = Path(path).resolve(strict=True)
    store = r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._-]+/bin/ssh"
    if re.fullmatch(store, str(resolved)):
        return str(resolved)
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid not in {0, os.getuid()} or before.st_mode & 0o022:
            raise ValueError("declared wrapper custody rejected")
        wrapper = stream.read(2049)
        after = os.fstat(stream.fileno())
        current = resolved.stat(follow_symlinks=False)
        key = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if key(before) != key(after) or key(before) != key(current):
            raise ValueError("declared wrapper changed")
    match = re.fullmatch(rb"#!/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._-]+/bin/bash\nset -eu\nexec '(/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._-]+/bin/ssh)' \"\$@\"\n", wrapper)
    if match is None:
        raise ValueError("declared pinned SSH wrapper rejected")
    executable = str(Path(match.group(1).decode("ascii")).resolve(strict=True))
    if not re.fullmatch(store, executable):
        raise ValueError("declared SSH store custody rejected")
    return executable

def bounded(fd, name, limit):
    opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(opened, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("bounded process metadata rejected")
    return data

def identity(root, pid, ssh):
    path = root / str(pid)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return opened_identity(fd, path, pid, ssh)
    finally:
        os.close(fd)

def opened_identity(fd, path, pid, ssh):
    before = os.fstat(fd)
    if before.st_uid != os.getuid():
        return None
    if bounded(fd, "comm", 32) != b"ssh\n":
        return None
    raw = bounded(fd, "cmdline", 32768)
    if len(raw) > 32768:
        return None
    args = raw.rstrip(b"\0").split(b"\0")
    if len(args) < 3 or args[-2] != b"neo" or not re.search(rb"(?<![A-Za-z0-9-])" + PROOF.encode() + rb"(?![A-Za-z0-9-])", args[-1]):
        return None
    if os.readlink("exe", dir_fd=fd) != ssh:
        return None
    raw_stat = bounded(fd, "stat", 4096).decode("ascii")
    fields = raw_stat[raw_stat.rfind(")") + 2:].split()
    if len(fields) < 20 or int(fields[2]) != pid or int(fields[3]) != pid:
        return None
    after = os.fstat(fd)
    current = path.stat(follow_symlinks=False)
    if (before.st_dev, before.st_ino, before.st_uid) != (after.st_dev, after.st_ino, after.st_uid) or (current.st_dev, current.st_ino, current.st_uid) != (before.st_dev, before.st_ino, before.st_uid):
        return None
    return (before.st_dev, before.st_ino, fields[19])

def cancel(root, ssh, send=os.killpg, wait=time.sleep):
    matches = []
    for index, path in enumerate(root.iterdir()):
        if index >= MAX_PROCESSES:
            return {"outcome": "process-bound", "proof_id": PROOF}
        if not path.name.isdecimal():
            continue
        try:
            found = identity(root, int(path.name), ssh)
            if found:
                matches.append((int(path.name), found))
        except (OSError, ValueError):
            continue
    if len(matches) != 1:
        return {"outcome": "absent" if not matches else "ambiguous", "proof_id": PROOF, "match_count": len(matches)}
    pid, admitted = matches[0]
    if identity(root, pid, ssh) != admitted:
        return {"outcome": "identity-changed", "proof_id": PROOF}
    send(pid, signal.SIGTERM)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            if identity(root, pid, ssh) != admitted:
                return {"outcome": "identity-changed", "proof_id": PROOF}
        except FileNotFoundError:
            return {"outcome": "terminated", "proof_id": PROOF}
        wait(0.05)
    if identity(root, pid, ssh) == admitted:
        send(pid, signal.SIGKILL)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                if identity(root, pid, ssh) != admitted:
                    return {"outcome": "identity-changed", "proof_id": PROOF}
            except FileNotFoundError:
                return {"outcome": "terminated", "proof_id": PROOF}
            wait(0.05)
        return {"outcome": "termination-unconfirmed", "proof_id": PROOF}
    return {"outcome": "identity-changed", "proof_id": PROOF}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh", required=True)
    args = parser.parse_args()
    ssh = declared_ssh(args.ssh)
    if not ssh.startswith("/nix/store/") or Path(ssh).name != "ssh":
        parser.error("declared pinned SSH required")
    result = cancel(Path("/proc"), ssh)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] in {"terminated", "absent"} else 2

if __name__ == "__main__":
    raise SystemExit(main())
