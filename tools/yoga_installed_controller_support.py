"""Fixed root-successor controller support, distinct from c106 application origin."""
from pathlib import Path
import re

# Physical declared controller module binds this checkout; historical c106 stays separate.
ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / 'tools'
DELIVERY = ROOT / 'delivery'
FILES = frozenset({'codex_device_acquisition_component.py'})
SCHEMA = 2
SELECTION_SCOPE = 'yoga-installed-toolbar-selection-v2'
WORKSPACE_SCOPE = 'yoga-installed-toolbar-workspace-v2'
SHA = re.compile(r'[0-9a-f]{64}')


def require(value):
    if value is not True:
        raise ValueError('installed-controller-support-refused')


def support(value):
    require(type(value) is dict and set(value) == {'root', 'files'}
        and value['root'] == str(DELIVERY) and type(value['files']) is dict
        and set(value['files']) == FILES)
    for name, pin in value['files'].items():
        require(type(pin) is dict and set(pin) == {'sha256', 'bytes'}
            and type(pin['sha256']) is str and SHA.fullmatch(pin['sha256']) is not None
            and type(pin['bytes']) is int and 0 < pin['bytes'] <= 1024 * 1024)
    return value


def controller(value, source_root):
    require(Path(source_root) == ROOT and type(value) is dict
        and value.get('root') == str(TOOLS))


def declared(alias, output_base):
    path = Path(alias)
    require(str(path) == str(alias) and path.is_absolute()
        and not {'.', '..'}.intersection(path.parts))
    expected = DELIVERY / 'codex_device_acquisition_component.py'
    if path != expected:
        require(str(path).endswith('.runfiles/_main/delivery/codex_device_acquisition_component.py'))
        output_base(path)
    return path, expected


def record_shape(value, workspace_files):
    require(type(value) is dict and set(value) == FILES and type(workspace_files) is dict)
    for name, sha in value.items():
        require(type(sha) is str and SHA.fullmatch(sha) is not None
            and workspace_files.get('delivery/' + name, {}).get('sha256') == sha)


def loaded_modules(root, hashes, modules):
    record_shape(hashes, {'delivery/' + name: {'sha256': sha} for name, sha in hashes.items()})
    for module in modules:
        filename = getattr(module, '__file__', None)
        if filename and Path(filename).name in FILES:
            require(Path(filename).resolve() == Path(root) / 'delivery' / Path(filename).name)


def reindex(mapping, copied, store, extra, until, budget):
    """Reindex the one new delivery alias without changing historical targets."""
    require(type(mapping) is dict and type(copied) is dict and type(store) is dict
        and extra == {'_main/delivery/codex_device_acquisition_component.py':
                      'delivery/codex_device_acquisition_component.py'}
        and set(extra).issubset(mapping))
    old = {key: 'f%06d' % index for index, key in enumerate(sorted(set(mapping) - set(extra)))}
    require(set(copied).isdisjoint(store) and set(copied) | set(store) == set(old.values()))
    new_copied, new_store = {}, {}
    for index, key in enumerate(sorted(mapping)):
        budget(until)
        alias = 'f%06d' % index
        if key in extra:
            new_copied[alias] = extra[key]
        elif old[key] in copied:
            new_copied[alias] = copied[old[key]]
        else:
            new_store[alias] = store[old[key]]
    return new_copied, new_store
