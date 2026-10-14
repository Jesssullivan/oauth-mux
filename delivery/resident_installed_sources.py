"""One ordinary installed Sources window; real operator consent is never automated."""
import hashlib
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parent.parent/"tools"))
from guard_resident_sources_profile import SourcesContext, launch, require

def main():
    require(len(sys.argv)==1)
    with SourcesContext.open() as context:
        require(context.context["producer_source_sha256"]==hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        context.publish(launch(context))
    return 0

if __name__=="__main__":
    try:sys.exit(main())
    except Exception:
        print("resident-sources-refused",file=sys.stderr)
        sys.exit(125)

