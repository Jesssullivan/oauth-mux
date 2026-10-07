"""Finite destination-readonly admission; does not admit copy or store mutation."""
from pathlib import Path

PROFILE = 'yoga-controller-delivery'
STATE = Path('/home/jess/.local/state/omux-yoga-delivery-20261006')
COORDINATION = Path('/home/jess/.local/state/omux-execution-20261005')
MODES = {'//tools:yoga_controller_qualify': 'qualify',
         '//tools:yoga_controller_inspect': 'inspect',
         '//tools:yoga_controller_verify': 'verify'}
LABELS = frozenset(MODES)
SSH = '/nix/store/aq5s91svywqgs5l9zyhp1wcjqvnfa0ss-openssh-with-gssapi-10.2p1/bin/ssh'

def selected(arguments, *, site=False, pack=False, recovery=False):
    if (len(arguments) != 2 or arguments[0] != 'run' or arguments[1] not in LABELS
            or site or pack or recovery):
        raise ValueError('exact provider-free Yoga inspect/verify target required')
    return {'PrivateNetwork': 'no'}

def coordination(selected_root, state_root, arguments):
    selected(arguments)
    if Path(state_root) != STATE or selected_root is None or Path(selected_root) != COORDINATION:
        raise ValueError('fixed Yoga delivery state and existing HOME lock required')
    return COORDINATION

def envelope(deadline_ns, arguments, approved_sha256=None):
    selected(arguments)
    import time
    import re
    mode = MODES[arguments[1]]
    if type(deadline_ns) is not int or not 30 * 10**9 < deadline_ns - time.monotonic_ns() <= 1200 * 10**9:
        raise ValueError('original enclosing deadline required')
    if mode == 'qualify' and approved_sha256 is not None or mode != 'qualify' and (
            type(approved_sha256) is not str or not re.fullmatch('[a-f0-9]{64}', approved_sha256)):
        raise ValueError('prior authenticated OS qualification required; no selfapproval')
    result = {'OMUX_YOGA_DELIVERY_DEADLINE_NS': str(deadline_ns), 'OMUX_YOGA_DELIVERY_MODE': mode}
    if approved_sha256 is not None:
        result['OMUX_YOGA_DELIVERY_AUTHORITY_SHA256'] = approved_sha256
    return result

def run_options(values):
    require_keys = {'OMUX_YOGA_DELIVERY_DEADLINE_NS', 'OMUX_YOGA_DELIVERY_MODE'}
    if not require_keys <= set(values) or not set(values) <= require_keys | {'OMUX_YOGA_DELIVERY_AUTHORITY_SHA256'}:
        raise ValueError('fixed delivery envelope keys required')
    return ['--run_env=' + key + '=' + values[key] for key in sorted(values)]
