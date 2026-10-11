"""Fixed offline Nix 2.34.6 missing-plan primitive; no seed/admission claim.

Only a declared owner with a qualified private store, held Nix executable and
actual evaluated derivation graph may call query(). No standalone entrypoint.
"""
from dataclasses import dataclass
import re

import nix_private_store_qualification as proof
import nix_private_store_seed as seed

MAX_PATHS = 4096
MAX_LINE = 4096
# Pinned Nix StorePath name grammar, including the final .drv within 211 characters.
DRV = r"/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-(?![.]($|-)|[.][.]($|-))[A-Za-z0-9+._?=-]{0,207}[.]drv"
ADVISORY = ("warning: you did not specify '--add-root'; the result might be "
            "removed by the garbage collector")
UNKNOWN = frozenset({
    "don't know how to build these paths:",
    "don't know how to build these paths (may be caused by read-only store access):",
})


@dataclass(frozen=True)
class MissingPlan:
    willBuild: frozenset[str]
    willSubstitute: frozenset[str]
    unknown: frozenset[str]
    diagnostics: tuple[str, ...]


def allowed_paths(paths):
    seed.require(type(paths) is frozenset and len(paths) <= MAX_PATHS)
    seed.require(all(type(path) is str and len(path) <= MAX_LINE
                     and re.fullmatch(DRV, path) is not None for path in paths))
    return paths


def parse(stderr, *, allowed_drvs):
    """Recognize only the pinned plain logger grammar under offline policy.

    Unknown/substitution sections always refuse, including on a zero child
    exit. Empty output describes an empty missing set, not ready-output proof.
    """
    allowed = allowed_paths(allowed_drvs)
    seed.require(type(stderr) is bytes and len(stderr) <= proof.MAX_OUTPUT)
    if not stderr:
        return MissingPlan(frozenset(), frozenset(), frozenset(), ())
    seed.require(stderr.endswith(b"\n"))
    seed.require(all(byte == 10 or 32 <= byte <= 126 for byte in stderr))
    lines = stderr.decode("ascii").split("\n")[:-1]
    seed.require(len(lines) <= MAX_PATHS + 2)
    seed.require(all(0 < len(line) <= MAX_LINE for line in lines))
    built = set()
    diagnostics = []
    seen_section = False
    index = 0
    while index < len(lines):
        line = lines[index]
        if line == ADVISORY:
            seed.require(not diagnostics)
            diagnostics.append("unrooted-output-advisory")
            index += 1
            continue
        # No online mode: neither fetched sizes nor unknown path bodies may
        # turn a forbidden section into an accepted partial plan.
        seed.require(line not in UNKNOWN)
        seed.require(not line.startswith("this path will be fetched ("))
        seed.require(re.match(r"these [0-9]+ paths will be fetched [(]", line) is None)
        if line == "this derivation will be built:":
            count = 1
        else:
            match = re.fullmatch(r"these ([1-9][0-9]{0,3}) derivations will be built:", line)
            seed.require(match is not None)
            count = int(match.group(1))
            seed.require(2 <= count <= MAX_PATHS)
        seed.require(not seen_section and index + count < len(lines))
        seen_section = True
        for row in lines[index + 1:index + count + 1]:
            seed.require(row.startswith("  ") and not row.startswith("   "))
            path = row[2:]
            seed.require(re.fullmatch(DRV, path) is not None)
            seed.require(path in allowed and path not in built)
            built.add(path)
        index += count + 1
    return MissingPlan(frozenset(built), frozenset(), frozenset(), tuple(diagnostics))


def command(tools, private, target_drv):
    seed.require(type(target_drv) is str and len(target_drv) <= MAX_LINE
                 and re.fullmatch(DRV, target_drv) is not None)
    # Exact out output of the evaluated native closure. No ignore-unknown,
    # repair, real build, or caller-supplied option sequence is admitted.
    return proof.common(tools["nix_store"], private) + [
        "--log-format", "raw", "--option", "print-missing", "true",
        "--realise", "--dry-run", target_drv + "!out"]


def query(tools, private, work, target_drv, allowed_drvs, deadline, *, tool_fd):
    """Transient stderr only; return typed sets after complete owned child IO."""
    allowed = allowed_paths(allowed_drvs)
    seed.require(type(target_drv) is str and target_drv in allowed)
    proof.tick(deadline)
    result = proof.run(command(tools, private, target_drv), proof.environment(work),
        work, deadline, tool_fd=tool_fd, output_limit=proof.MAX_OUTPUT, capture_stderr=True)
    seed.require(type(result) is tuple and len(result) == 2
                 and all(type(part) is bytes for part in result))
    stdout, stderr = result
    seed.require(stdout == b"")
    value = parse(stderr, allowed_drvs=allowed)
    proof.tick(deadline)
    return value
