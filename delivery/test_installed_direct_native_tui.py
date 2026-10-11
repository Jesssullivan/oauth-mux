"""Provider-free ordinary direct-main TUI; existing fixture owns cold resume."""
from pathlib import Path
import os
import sys
sys.path.insert(0,str(Path(__file__).parent.parent/'tools'))
import direct_native_tui_runtime as direct
import test_installed_native_tui as tui

def declared_child_environment(environment):
    """Transport only the original clock and explicit declared runfiles root."""
    names=('OMUX_NATIVE_ORDINARY_MODE','OMUX_NATIVE_ORDINARY_ENTRY_NS','OMUX_NATIVE_ORDINARY_DEADLINE_NS')
    roots=[]
    for name in ('TEST_SRCDIR','RUNFILES_DIR'):
        if name in environment:
            value=environment[name]
            direct.require(type(value) is str and Path(value).is_absolute())
            root=Path(value).resolve(strict=True)
            direct.require(root.is_dir())
            roots.append(root)
    direct.require(bool(roots) and all(root==roots[0] for root in roots))
    mapping=roots[0]/'_repo_mapping'
    direct.require(mapping.is_file() and 0<mapping.stat().st_size<=1024*1024)
    result={name:environment[name] for name in names}
    result['TEST_SRCDIR']=str(roots[0])
    return result

def main():
    direct.require(len(sys.argv)>=3 and sys.argv[1].startswith('--direct-pin=')
        and sys.argv[2].startswith('--direct-pin-sha-file=')
        and not any(value.startswith('--direct-') for value in sys.argv[3:]))
    work,until=direct.original_deadlines(os.environ)
    pin=Path(sys.argv[1].split('=',1)[1]).resolve(strict=True)
    sha_file=Path(sys.argv[2].split('=',1)[1]).resolve(strict=True)
    sha=direct.retained.public_runtime_file(sha_file,65).decode('ascii')
    direct.require(sha.endswith('\n') and len(sha)==65)
    reader=direct.DirectReader(pin,sha[:-1],work)
    flags=('--direct-pin='+str(pin),'--direct-pin-sha-file='+str(sha_file))
    sys.argv[1:]=sys.argv[3:]
    return tui.main(runtime_reader=reader,entrypoint=Path(__file__).absolute(),entrypoint_args=flags,
        original_deadline=until,child_environment=declared_child_environment(os.environ))

if __name__=='__main__':
    try:sys.exit(main())
    except Exception:
        print('installed native terminal proof failed at '+tui.PHASE,file=sys.stderr)
        sys.exit(1)
