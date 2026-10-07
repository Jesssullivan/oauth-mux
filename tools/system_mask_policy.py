"""Diagnostic tmpfs isolation policy for the privileged system-manager profile.

This avoids systemd's inaccessible bind source; it is not a proved host fix.
A successful property readback must still be paired with a live denial probe
and verified resource, identity and descendant cleanup evidence.
"""
from pathlib import Path
import os
import pwd

OPTIONS = 'ro,mode=000,size=1M'


def paths(home=None, profile='standard'):
    if profile not in ('standard', 'dependency-prefetch', 'installed-browser', 'site'):
        raise ValueError('unknown mask profile')
    home = Path(pwd.getpwuid(os.getuid()).pw_dir if home is None else home)
    if not home.is_absolute() or '..' in home.parts or any(char.isspace() for char in str(home)):
        raise ValueError('exact absolute host home required')
    return ('/run', '/nix/var/nix/daemon-socket',
            str(home / '.config/sops-nix/secrets/become')) + (('/etc/bluetooth',) if profile in ('installed-browser', 'site') else ())


def setting(home=None, profile='standard'):
    return ' '.join(path + ':' + OPTIONS for path in paths(home, profile))


def verify_effective(value, home=None, profile='standard'):
    if not isinstance(value, str) or not value:
        raise ValueError('effective tmpfs masks missing')
    expected = set(paths(home, profile))
    observed = set()
    for entry in value.split():
        if ':' not in entry:
            raise ValueError('effective tmpfs options missing')
        path, options = entry.split(':', 1)
        if path not in expected or path in observed:
            raise ValueError('unexpected or duplicate tmpfs mask')
        fields = options.split(',')
        if len(fields) != 3 or len(set(fields)) != 3:
            raise ValueError('unexpected mutable tmpfs options')
        names = {field.split('=', 1)[0] for field in fields}
        if names != {'ro', 'mode', 'size'}:
            raise ValueError('tmpfs mask must remain read-only and bounded')
        mode = next(field[5:] for field in fields if field.startswith('mode='))
        size = next(field[5:] for field in fields if field.startswith('size='))
        # systemctl may retain input spelling or normalize units. Accept only
        # semantically identical spellings, never permission/budget expansion.
        if mode not in ('0', '00', '000', '0000', '0o000') or size not in ('1M', '1Mib', '1MiB', '1048576'):
            raise ValueError('tmpfs mask permissions or size changed')
        observed.add(path)
    if observed != expected:
        raise ValueError('effective tmpfs mask coverage incomplete')
