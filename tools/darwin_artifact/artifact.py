"""Bound final Darwin app bytes. No compilation, signing, activation or trust grant.

Seal only AFTER the operator's last signing/stapling mutation. NAR and manifest
are outside the signed app. A later app mutation requires a fresh seal and pin.
The developer-id receipt is reported evidence, never Apple trust verification.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import posixpath
import re
import stat
import struct
import time

MAX_NODES = 1024
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_METADATA = 1024 * 1024
MAX_SECONDS = 300
MANIFEST = "darwin-artifact.json"
RECEIPT = "operator-signing-receipt.json"
ROLES = {"omux": "omux-runtime", "omuxd": "omux-daemon-runtime",
         "omux-native-host": "omux-runtime", "Omux": "OmuxControls"}
BINARIES = set(ROLES) | set(ROLES.values())
SIGNING_FIELDS = {"schemaVersion", "kind", "teamIdentifier", "signingIdentifier",
                  "designatedRequirementSha256", "entitlementsSha256", "unsignedInputSha256",
                  "signedAppInventorySha256", "signatureVerificationReceiptSha256",
                  "notarizationReceiptSha256", "staplingReceiptSha256", "gatekeeperReceiptSha256"}


def require(condition, reason):
    if not condition:
        raise ValueError("Darwin artifact: " + reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def decode(raw):
    require(type(raw) is bytes and len(raw) <= MAX_METADATA, "metadata bound")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate field")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("Darwin artifact: nonfinite JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def fields(value, expected):
    require(type(value) is dict and set(value) == set(expected), "closed fields")


def snapshot(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def check_deadline(deadline):
    require(time.monotonic() <= deadline, "deadline")


def safe_path(value):
    require(isinstance(value, str) and len(value.encode()) <= 4096 and
            re.fullmatch(r"[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*", value) is not None and
            all(part not in (".", "..") for part in value.split("/")), "relative path")


class Directory:
    """Pin actual protected ancestors. No link traversal or ambient store search."""
    def __init__(self, path):
        path = os.fspath(path)
        require(path.startswith("/") and not path.endswith("/") and
                all(p not in ("", ".", "..") for p in path.split("/")[1:]), "absolute root")
        self.chain = []
        try:
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            self.chain.append((None, "", fd, snapshot(os.fstat(fd))))
            for part in path.split("/")[1:]:
                parent = fd
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
                self.chain.append((parent, part, fd, snapshot(os.fstat(fd))))
            self.fd = fd
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for parent, name, fd, expected in self.chain:
            info = os.fstat(fd)
            # Ancestor content can change independently; identity and protection
            # matter here. Complete tree snapshots are separately held below.
            require((info.st_dev, info.st_ino, info.st_uid) == expected[:3] and
                    stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid()) and
                    (not info.st_mode & 0o022 or
                     (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)), "ancestor custody")
            if parent is not None:
                live = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require((live.st_dev, live.st_ino, live.st_uid) == expected[:3] and
                        stat.S_ISDIR(live.st_mode), "ancestor replacement")

    def close(self):
        for _, _, fd, _ in reversed(self.chain):
            os.close(fd)
        self.chain = []

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


def read_selected(path, limit, deadline):
    """Read only the selected metadata leaf, never its siblings."""
    path = Path(path).absolute()
    safe_path(path.name)
    with Directory(path.parent) as parent:
        check_deadline(deadline)
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent.fd)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid()) and
                    not info.st_mode & 0o7022 and info.st_size <= limit, "selected metadata custody")
            chunks, size = [], 0
            while True:
                parent.check()
                check_deadline(deadline)
                chunk = os.read(fd, min(65536, info.st_size + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                require(size <= info.st_size, "selected metadata growth")
                chunks.append(chunk)
            require(size == info.st_size and snapshot(os.fstat(fd)) == snapshot(info) ==
                    snapshot(os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)),
                    "selected metadata changed")
            return b"".join(chunks)
        finally:
            os.close(fd)


def scan(root, deadline):
    """Closed regular tree, normalized NAR modes and descriptor-stable bytes."""
    nodes, payloads, total = [], {}, 0
    with Directory(root) as held:
        def walk(fd, prefix):
            nonlocal total
            check_deadline(deadline)
            held.check()
            before = snapshot(os.fstat(fd))
            require(not before[3] & 0o7022, "directory permissions")
            names = sorted(os.listdir(fd), key=os.fsencode)
            require(len(nodes) + len(names) < MAX_NODES, "node bound")
            for name in names:
                check_deadline(deadline)
                path = prefix + "/" + name if prefix else name
                safe_path(path)
                require(path.count("/") <= 32, "depth bound")
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o7022,
                        "node permissions/owner")
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=fd)
                    try:
                        require(snapshot(os.fstat(child)) == snapshot(info), "directory replaced")
                        nodes.append({"path": path, "type": "directory", "mode": "0755"})
                        walk(child, path)
                        require(snapshot(os.stat(name, dir_fd=fd, follow_symlinks=False)) == snapshot(info),
                                "directory changed")
                    finally:
                        os.close(child)
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE,
                            "regular file required")
                    total += info.st_size
                    require(total <= MAX_TOTAL, "total byte bound")
                    leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                   dir_fd=fd)
                    try:
                        require(snapshot(os.fstat(leaf)) == snapshot(info), "file replaced")
                        chunks, size = [], 0
                        while True:
                            check_deadline(deadline)
                            chunk = os.read(leaf, min(65536, info.st_size + 1 - size))
                            if not chunk:
                                break
                            size += len(chunk)
                            require(size <= info.st_size, "file grew")
                            chunks.append(chunk)
                        require(size == info.st_size and snapshot(os.fstat(leaf)) == snapshot(info) ==
                                snapshot(os.stat(name, dir_fd=fd, follow_symlinks=False)), "file changed")
                    finally:
                        os.close(leaf)
                    raw = b"".join(chunks)
                    payloads[path] = raw
                    # Canonical NAR records owner-execute only. Other/group
                    # execute bits must never promote owner executability.
                    nodes.append({"path": path, "type": "regular", "mode": "0755" if info.st_mode & stat.S_IXUSR else "0644",
                                  "size": len(raw), "sha256": sha(raw)})
            require(snapshot(os.fstat(fd)) == before and sorted(os.listdir(fd), key=os.fsencode) == names,
                    "tree changed")
        walk(held.fd, "")
        held.check()
    return sorted(nodes, key=lambda node: os.fsencode(node["path"])), payloads


def nar_hash(nodes, payloads):
    """Canonical NAR stream: modes preserve only executable status, as Nix does."""
    by_path = {node["path"]: node for node in nodes}
    children = {"": []}
    for node in nodes:
        parent, _, name = node["path"].rpartition("/")
        children.setdefault(parent, []).append((name, node["path"]))
        if node["type"] == "directory":
            children.setdefault(node["path"], [])
    h, count = hashlib.sha256(), 0
    def word(raw):
        nonlocal count
        raw = raw.encode() if isinstance(raw, str) else raw
        for piece in (struct.pack("<Q", len(raw)), raw, b"\0" * (-len(raw) % 8)):
            h.update(piece)
            count += len(piece)
    def node(path):
        word("(")
        word("type")
        if not path or by_path[path]["type"] == "directory":
            word("directory")
            for name, child in sorted(children[path], key=lambda item: os.fsencode(item[0])):
                word("entry"); word("("); word("name"); word(name); word("node")
                node(child)
                word(")")
        else:
            word("regular")
            if by_path[path]["mode"] == "0755":
                word("executable"); word("")
            word("contents"); word(payloads[path])
        word(")")
    word("nix-archive-1")
    node("")
    return "sha256-" + base64.b64encode(h.digest()).decode(), count


def app_contract(nodes, payloads, channel, parse_macho):
    instance = "dev" if channel == "development" else "default"
    require(channel in ("development", "release"), "channel")
    prefix = "Omux.app/Contents/MacOS/"
    by_path = {node["path"]: node for node in nodes}
    binding = decode(payloads["Omux.app/Contents/Resources/channel-binding.json"])
    fields(binding, ("kind", "instance", "roles", "sourceSha256"))
    require(binding["kind"] == "compiled-entrypoints-v1" and binding["instance"] == instance and
            binding["roles"] == ROLES and digest(binding["sourceSha256"]), "channel binding metadata")
    require({path[len(prefix):] for path in payloads if path.startswith(prefix)} == BINARIES,
            "exact executable/backend set")
    for role, backend in ROLES.items():
        marker = ("OMUX_CHANNEL_BINDING_V1:" + instance + ":" + role + ":" + backend).encode()
        raw = payloads[prefix + role]
        require(raw.count(marker) == 1 and raw.count(b"OMUX_CHANNEL_BINDING_V1:") == 1,
                "compiled channel entrypoint marker")
    for path in payloads:
        executable = path.startswith(prefix) or path.startswith("Omux.app/Contents/Frameworks/")
        if not executable:
            require(by_path[path]["mode"] == "0644", "non-code objects must be data-only")
            require(payloads[path][:4] not in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe",
                b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"),
                "unclassified Mach-O object")
        if executable:
            require(by_path[path]["mode"] == "0755", "Mach-O executable mode")
            slices = parse_macho(payloads[path])
            require(len(slices) == 1 and slices[0].architecture == "arm64", "arm64 only")
            item = slices[0]
            require(item.minimum_os is not None and item.minimum_os <= (14, 0, 0) and
                    item.code_signature is not None and not item.rpaths, "deployment/signature structure/rpath")
            require(item.filetype == (2 if path.startswith(prefix) else 6), "Mach-O role")
            if path.startswith("Omux.app/Contents/Frameworks/"):
                require(item.install_id == "@rpath/" + posixpath.basename(path), "relocated dylib install ID")
            for dependency in item.dependencies:
                if dependency.startswith("@loader_path/"):
                    resolved = posixpath.normpath(posixpath.dirname(path) + "/" + dependency[13:])
                    require(resolved.startswith("Omux.app/Contents/Frameworks/") and resolved in payloads,
                            "relocated dependency closure")
                else:
                    normalized = posixpath.normpath(dependency)
                    require(dependency == normalized and normalized.startswith(("/System/Library/", "/usr/lib/")),
                            "external non-system dependency")
    info = plistlib.loads(payloads["Omux.app/Contents/Info.plist"])
    identifier = "ai.xoxd.omux.dev.controls" if channel == "development" else "ai.xoxd.omux.controls"
    require(info.get("CFBundleIdentifier") == identifier and info.get("CFBundleExecutable") == "Omux" and
            info.get("LSMinimumSystemVersion") == "14.0", "app metadata binding")
    label = "ai.xoxd.omux.dev.daemon" if channel == "development" else "ai.xoxd.omux.daemon"
    helper_path = "Omux.app/Contents/Library/LaunchAgents/" + label + ".plist"
    require({path for path in payloads if path.startswith("Omux.app/Contents/Library/LaunchAgents/")} ==
            {helper_path}, "bundled helper set")
    helper = plistlib.loads(payloads[helper_path])
    require(helper.get("Label") == label and helper.get("BundleProgram") == "Contents/MacOS/omux" and
            helper.get("ProgramArguments") == ["omux", "daemon"] and
            helper.get("AssociatedBundleIdentifiers") == [identifier] and
            helper.get("RunAtLoad") is True and helper.get("KeepAlive") == {"SuccessfulExit": False} and
            helper.get("ThrottleInterval") == 3 and helper.get("Umask") == 63, "bundled helper binding")
    custody = decode(payloads["Omux.app/Contents/Resources/apple-toolchain-custody.json"])
    require(custody.get("available") is True and custody.get("system") == "aarch64-darwin" and
            custody.get("apple", {}).get("sdk_version") == "14.4" and
            custody.get("apple", {}).get("swift_version") == "5.10.1", "declared Apple inputs")
    require("Omux.app/Contents/_CodeSignature/CodeResources" in payloads, "resource seal")
    require(type(plistlib.loads(payloads["Omux.app/Contents/_CodeSignature/CodeResources"])) is dict,
            "resource seal structure")
    # The marker and Mach-O metadata are source/byte predicates only. They do
    # not authenticate the compiler or validate Apple signatures/requirements.


def validate_manifest(raw, nodes, payloads, revision, channel, parse_macho):
    manifest = decode(raw)
    fields(manifest, ("schemaVersion", "distribution", "target", "channel", "product", "source",
                      "stage", "signing", "channelBinding", "inventory", "capabilityLimits"))
    require(manifest["schemaVersion"] == 1 and type(manifest["schemaVersion"]) is int and
            manifest["distribution"] == "experimental-darwin-app" and manifest["target"] == "aarch64-darwin" and
            manifest["channel"] == channel and manifest["stage"] == "final-post-sign-inventory", "manifest identity")
    fields(manifest["source"], ("revision", "dirty"))
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision) is not None and
            manifest["source"]["revision"] == revision and type(manifest["source"]["dirty"]) is bool and
            (channel == "development" or manifest["source"]["dirty"] is False), "source binding")
    fields(manifest["product"], ("name", "version", "status"))
    require(manifest["product"]["name"] == "Omux" and manifest["product"]["status"] == "experimental" and
            isinstance(manifest["product"]["version"], str) and
            re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?", manifest["product"]["version"]), "product")
    require(manifest["capabilityLimits"] == {"appleAcceptance": "unproved", "installedPlatform": "unproved",
            "nativePeer": "unsupported", "serviceObservation": "unsupported", "liveHandoff": "unproved"},
            "capability limits")
    expected = [node for node in nodes if node["path"] != MANIFEST]
    require(encoded(manifest["inventory"]) == encoded(expected) and encoded(manifest) == raw,
            "complete typed canonical inventory")
    fields(manifest["signing"], ("kind", "receiptSha256", "verification"))
    signing = manifest["signing"]
    require(signing["verification"] == "embedded-structure-only", "no Apple trust promotion")
    if signing["kind"] == "ad-hoc-development":
        require(signing["receiptSha256"] is None and RECEIPT not in payloads, "ad-hoc receipt")
    else:
        require(signing["kind"] == "developer-id-reported" and digest(signing["receiptSha256"]) and
                RECEIPT in payloads and sha(payloads[RECEIPT]) == signing["receiptSha256"], "reported signing receipt")
        receipt = decode(payloads[RECEIPT])
        fields(receipt, SIGNING_FIELDS)
        require(type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1 and
                receipt["kind"] == "developer-id" and isinstance(receipt["teamIdentifier"], str) and
                re.fullmatch(r"[A-Z0-9]{10}", receipt["teamIdentifier"]) and
                isinstance(receipt["signingIdentifier"], str) and
                re.fullmatch(r"[A-Za-z0-9.-]{1,128}", receipt["signingIdentifier"]), "reported signer shape")
        for key in SIGNING_FIELDS - {"schemaVersion", "kind", "teamIdentifier", "signingIdentifier"}:
            require(digest(receipt[key]) or (receipt[key] is None and key in
                    {"notarizationReceiptSha256", "staplingReceiptSha256", "gatekeeperReceiptSha256"}),
                    "reported proof digest")
        app_nodes = [node for node in expected if node["path"].startswith("Omux.app/") or node["path"] == "Omux.app"]
        require(receipt["signedAppInventorySha256"] == sha(encoded(app_nodes)), "post-sign receipt app binding")
        info = plistlib.loads(payloads["Omux.app/Contents/Info.plist"])
        require(receipt["signingIdentifier"] == info.get("CFBundleIdentifier"), "reported signing identifier")
    require(all(node["path"] == RECEIPT or node["path"] == "Omux.app" or
                node["path"].startswith("Omux.app/") for node in expected), "closed root namespace")
    app_contract(nodes, payloads, channel, parse_macho)
    require(manifest["channelBinding"] == decode(payloads["Omux.app/Contents/Resources/channel-binding.json"]),
            "manifest channel binding")
    info = plistlib.loads(payloads["Omux.app/Contents/Info.plist"])
    require(info.get("OmuxProductVersion") == manifest["product"]["version"] and
            info.get("CFBundleShortVersionString") == manifest["product"]["version"].split("-")[0].split("+")[0],
            "app product version")
    return manifest


def verify(root, nar, revision, channel, parse_macho, seconds=MAX_SECONDS):
    require(type(seconds) is int and 1 <= seconds <= MAX_SECONDS, "finite seconds")
    nodes, payloads = scan(root, time.monotonic() + seconds)
    require(MANIFEST in payloads, "manifest missing")
    manifest = validate_manifest(payloads[MANIFEST], nodes, payloads, revision, channel, parse_macho)
    actual, size = nar_hash(nodes, payloads)
    require(actual == nar, "full NAR binding")
    return {"schemaVersion": 1, "narHash": actual, "narSize": size,
            "manifestSha256": sha(payloads[MANIFEST]), "channel": channel, "sourceRevision": revision,
            "scope": "artifact-bytes-only-not-platform-proof", "signing": manifest["signing"]}


def seal(app, output, revision, dirty, channel, version, parse_macho, signing_receipt=None):
    """Create a new final envelope; never rewrite/import/sign the selected app."""
    deadline = time.monotonic() + MAX_SECONDS
    app_nodes, app_payloads = scan(app, deadline)
    nodes = [{"path": "Omux.app", "type": "directory", "mode": "0755"}] + [
        dict(node, path="Omux.app/" + node["path"]) for node in app_nodes]
    payloads = {"Omux.app/" + path: raw for path, raw in app_payloads.items()}
    signing = {"kind": "ad-hoc-development", "receiptSha256": None, "verification": "embedded-structure-only"}
    if signing_receipt is not None:
        require(type(signing_receipt) is bytes and len(signing_receipt) <= MAX_METADATA, "signing receipt bound")
        payloads[RECEIPT] = signing_receipt
        nodes.append({"path": RECEIPT, "type": "regular", "mode": "0644",
                      "size": len(signing_receipt), "sha256": sha(signing_receipt)})
        signing.update(kind="developer-id-reported", receiptSha256=sha(signing_receipt))
    nodes.sort(key=lambda node: os.fsencode(node["path"]))
    manifest = {"schemaVersion": 1, "distribution": "experimental-darwin-app", "target": "aarch64-darwin",
                "channel": channel, "product": {"name": "Omux", "version": version, "status": "experimental"},
                "source": {"revision": revision, "dirty": dirty}, "stage": "final-post-sign-inventory",
                "channelBinding": decode(payloads["Omux.app/Contents/Resources/channel-binding.json"]),
                "signing": signing, "inventory": nodes,
                "capabilityLimits": {"appleAcceptance": "unproved", "installedPlatform": "unproved",
                    "nativePeer": "unsupported", "serviceObservation": "unsupported", "liveHandoff": "unproved"}}
    raw = encoded(manifest)
    payloads[MANIFEST] = raw
    nodes = nodes + [{"path": MANIFEST, "type": "regular", "mode": "0644", "size": len(raw), "sha256": sha(raw)}]
    nodes.sort(key=lambda node: os.fsencode(node["path"]))
    validate_manifest(raw, nodes, payloads, revision, channel, parse_macho)
    expected_nar, _ = nar_hash(nodes, payloads)
    target = Path(output).absolute()
    safe_path(target.name)
    with Directory(target.parent) as parent:
        parent.check()
        # Exclusive creation. A failed private output remains diagnostic evidence;
        # this adapter never recursively removes a path or overwrites a seal.
        os.mkdir(target.name, 0o700, dir_fd=parent.fd)
        root_fd = os.open(target.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=parent.fd)
        directories = {"": (root_fd, parent.fd, target.name, snapshot(os.fstat(root_fd))[:3])}
        def check_output():
            check_deadline(deadline)
            parent.check()
            for fd, ancestor, leaf, witness in directories.values():
                live = os.stat(leaf, dir_fd=ancestor, follow_symlinks=False)
                require(snapshot(os.fstat(fd))[:3] == witness == snapshot(live)[:3] and
                        stat.S_ISDIR(live.st_mode) and not live.st_mode & 0o7022,
                        "output directory replaced")
        try:
            for node in sorted(nodes, key=lambda n: (n["path"].count("/"), os.fsencode(n["path"]))):
                check_output()
                parent_path, _, leaf = node["path"].rpartition("/")
                ancestor = directories[parent_path][0]
                if node["type"] == "directory":
                    os.mkdir(leaf, 0o755, dir_fd=ancestor)
                    expected = os.stat(leaf, dir_fd=ancestor, follow_symlinks=False)
                    fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=ancestor)
                    directories[node["path"]] = (fd, ancestor, leaf, snapshot(expected)[:3])
                    check_output()
                else:
                    fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=ancestor)
                    try:
                        view = memoryview(payloads[node["path"]])
                        while view:
                            check_deadline(deadline)
                            count = os.write(fd, view[:65536])
                            require(count > 0, "short output write")
                            view = view[count:]
                        os.fchmod(fd, int(node["mode"], 8))
                        os.fsync(fd)
                        require(snapshot(os.fstat(fd)) == snapshot(os.stat(leaf, dir_fd=ancestor,
                                follow_symlinks=False)), "output file replaced")
                        check_output()
                    finally:
                        os.close(fd)
            os.fchmod(root_fd, 0o755)
            os.fsync(root_fd)
            check_output()
        finally:
            for fd, _, _, _ in reversed(list(directories.values())):
                os.close(fd)
    return verify(str(target), expected_nar, revision, channel, parse_macho)


def load_macho(path):
    spec = importlib.util.spec_from_file_location("declared_macho", path)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.parse_macho


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--macho", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--nar-hash", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--channel", required=True, choices=("development", "release"))
    args = parser.parse_args()
    print(encoded(verify(args.root, args.nar_hash, args.source_revision, args.channel,
                         load_macho(args.macho))).decode(), end="")


if __name__ == "__main__":
    main()
