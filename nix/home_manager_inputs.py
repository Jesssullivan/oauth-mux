"""Pure exact paired-source bindings; these predicates do not verify NAR bytes."""
import re

PINS = {
    "home-manager": ("65258d5c65a250189fde2e35f490d15e064c4c62", "sha256-Sxu1NLTD/Ern6hFGLlZmtKCSct3YQXZI/lls8RE1XeM="),
    "nixpkgs": ("a9e6d84f9c2f9012f5fe7d964a7851352300e61a", "sha256-WncT27+3BOkgTaJZLnCsf3LcYf9RXMuR9ONSN4rzQ7s="),
}


def paired_lock(lock):
    """Return only the exact inspected Lab pair and root-follow relationship."""
    nodes = lock["nodes"]
    root = nodes[lock["root"]]["inputs"]
    hm = nodes[root["home-manager"]]
    if hm["inputs"]["nixpkgs"] != ["nixpkgs"]:
        raise ValueError("home-manager-nixpkgs-follow-invalid")
    selected = {}
    for name, (revision, nar_hash) in PINS.items():
        locked = nodes[root[name]]["locked"]
        if locked.get("rev") != revision or locked.get("narHash") != nar_hash:
            raise ValueError("paired-lock-binding-invalid")
        selected[name] = locked
    return selected


def paired_sources(lock, inputs):
    """Select exactly root HM and its root-followed nixpkgs; return pending hashes."""
    paired_lock(lock)
    results = {}
    for name, (revision, nar_hash) in PINS.items():
        supplied = inputs[name]
        if (supplied.get("revision") != revision or supplied.get("narHash") != nar_hash
                or supplied.get("schemaVersion") != 1):
            raise ValueError("paired-source-binding-invalid")
        source = supplied.get("source", "")
        if not isinstance(source, str) or not re.fullmatch(r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9._+-]+", source):
            raise ValueError("paired-source-path-invalid")
        results[name] = {"source": source, "narHash": nar_hash, "verification": "pending-byte-hash"}
    return results
