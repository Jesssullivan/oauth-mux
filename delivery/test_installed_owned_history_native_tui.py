"""Dedicated history13 ordinary-first native launch/resume; no Omux launcher."""
from pathlib import Path
import os
import re
import sys
import time

sys.path.insert(0,str(Path(__file__).parent.parent/"tools"))
sys.path.insert(0,str(Path(__file__).parent.parent/"integrations/codex-owner-runtime"))
import owned_history_runtime as proof
import owned_history_native_tui_runtime as qualified
import test_installed_native_tui as tui


def original_deadlines(environment,clock_ns=time.monotonic_ns):
    proof.need(environment.get("OMUX_NATIVE_ORDINARY_MODE") == "native-acquisition-ordinary-tui-reserved")
    values = []
    for name in ("OMUX_NATIVE_ORDINARY_ENTRY_NS","OMUX_NATIVE_ORDINARY_DEADLINE_NS"):
        value = environment.get(name)
        proof.need(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,18}",value) is not None)
        values.append(int(value))
    entry,until = values
    proof.need(until-entry == 1200*10**9 and until<2**63 and entry<=clock_ns()<until-30*10**9)
    return entry,until,(until-30*10**9)/10**9


def child_environment(environment):
    names = ("OMUX_NATIVE_ORDINARY_MODE","OMUX_NATIVE_ORDINARY_ENTRY_NS","OMUX_NATIVE_ORDINARY_DEADLINE_NS")
    result = {name:environment[name] for name in names}
    roots = [Path(environment[name]).resolve(strict=True) for name in ("TEST_SRCDIR","RUNFILES_DIR") if name in environment]
    proof.need(bool(roots) and all(root.is_absolute() and root.is_dir() and root==roots[0] for root in roots))
    result["TEST_SRCDIR"] = str(roots[0])
    return result


def main():
    proof.need(len(sys.argv)>=4 and sys.argv[1].startswith("--history-pin=")
        and sys.argv[2].startswith("--history-pin-sha=") and sys.argv[3].startswith("--history-aliases=")
        and not any(value.startswith("--history-") for value in sys.argv[4:]))
    entry,until,deadline = original_deadlines(os.environ)
    pin,sha_file,aliases = (Path(row.split("=",1)[1]) for row in sys.argv[1:4])
    # This small pre-reader owner is enrolled before acquisition and spans all
    # child work; no stat/read/resolved control is taken as stable by itself.
    with proof.Held(deadline,until-30*10**9) as control:
        raw = control.add(sha_file,65,modes=(0o444,0o555,0o644))
        proof.need(len(raw)==65 and raw[-1:] == b"\n")
        digest = proof.pin(raw[:-1].decode("ascii"))
        reader = qualified.Reader(pin,digest,aliases,deadline,until-30*10**9)
        try:
            flags = tuple(sys.argv[1:4]); sys.argv[1:] = sys.argv[4:]
            result = tui.main(runtime_reader=reader,entrypoint=Path(__file__).absolute(),entrypoint_args=flags,
                original_deadline=until/10**9,child_environment=child_environment(os.environ),ordinary_first=True)
            reader.finish(); control.full(); reader.owner.fence()
            if reader.installed is not None: reader.installed.fence()
        except BaseException as primary:
            try: reader.close()
            except BaseException as cleanup: proof.preserve_primary(primary,cleanup)
            raise
        else:
            reader.close()
    # All success owners have retired, including the control owner closed last.
    # Observe their original names after close effects; no new bulk read or pin.
    control.named_fence(); reader.terminal()
    original_deadlines(os.environ)
    return result


if __name__ == "__main__":
    try:
        result = main()
        original_deadlines(os.environ)
        sys.exit(result)
    except Exception:
        print("installed native terminal proof failed at "+tui.PHASE,file=sys.stderr)
        sys.exit(1)
