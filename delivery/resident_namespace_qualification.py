"""Exact provider-free health/namespace carrier; no continuity controller."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parent.parent/'tools'))
from guard_resident_namespace_profile import NamespaceContext
def main():
    if len(sys.argv)!=1: raise ValueError('resident-namespace-qualification-refused')
    with NamespaceContext.open() as context: context.publish(context.run())
    return 0
if __name__=='__main__':
    try: sys.exit(main())
    except Exception:
        print('resident-namespace-qualification-refused',file=sys.stderr)
        sys.exit(125)
