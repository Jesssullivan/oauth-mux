"""Enumerate immutable tool inputs without recursing through directory cycles."""
import json
import os
import re
from pathlib import Path
import sys

SITE_BLUEZ_ROOT = Path('/nix/store/zb0vr338s1sq0c7a3ca5i4zx89kjzd4n-bluez-5.86')
SITE_INERT_POLICY = 'cached-site-bluez-5.86'


def inert_site_alias(path, parent, allowed, policy):
    if policy != SITE_INERT_POLICY:
        return False
    if (parent != SITE_BLUEZ_ROOT / 'etc/bluetooth' or SITE_BLUEZ_ROOT not in allowed or
            path.name not in ('input.conf', 'main.conf', 'network.conf')):
        return False
    return path.is_symlink() and os.readlink(path) == '/etc/bluetooth/' + path.name

def public_source_alias(candidate, allowed):
    """Translate only a known immutable source into a bounded public alias."""
    for root in sorted(allowed):
        if candidate == root or root in candidate.parents:
            if not re.fullmatch(r'[0-9a-z]{32}-[A-Za-z0-9+._?=-]+', root.name):
                return '[unavailable]'
            suffix = candidate.relative_to(root).as_posix()
            if suffix == '.':
                suffix = ''
            if len(suffix) > 1024 or not re.fullmatch(r'[A-Za-z0-9_./+@=-]*', suffix):
                return 'closure/' + root.name + '/[redacted-component]'
            return 'closure/' + root.name + ('/' + suffix if suffix else '')
    return '[unavailable]'


def alias_failure(candidate, allowed, reason):
    return ValueError(reason + ' public_source_alias=' + public_source_alias(candidate, allowed) +
                      ' target_class=outside-declared-closure')


def resolution_policy(repository, allowed):
    structural = {repository / prefix for prefix in ["closure", "packages", "runtime_closure", "qt_runtime_closure"]}
    ancestors = {repository, *repository.parents}
    for store_root in allowed:
        ancestors.update(store_root.parents)
    return structural, ancestors


def declared_resolve(path, repository, allowed, policy=None, directory_cache=None, parent_cache=None, hop_result=None):
    """Validate each link target before consulting its metadata."""
    pending = list(path.absolute().parts[1:])
    current = Path("/")
    hops = 0
    if parent_cache is not None and path.parent in parent_cache:
        current, hops = parent_cache[path.parent]
        pending = [path.name]
    elif path == repository or repository in path.parents:
        relative = path.relative_to(repository).parts
        if ".." not in relative:
            # Only the trusted canonical generated repository bootstrap is
            # skipped. Closure aliases still traverse every guarded hop.
            current = repository
            pending = list(relative)
    structural, ancestors = policy if policy is not None else resolution_policy(repository, allowed)
    while pending:
        component = pending.pop(0)
        if component == ".":
            continue
        if component == "..":
            current = current.parent
            continue
        candidate = current / component
        candidate_parents = {candidate, *candidate.parents}
        if candidate not in ancestors and not (candidate_parents & allowed) and not (candidate_parents & structural):
            raise alias_failure(current, allowed, "Nix input traversal consults an undeclared directory")
        if directory_cache is not None and candidate in directory_cache:
            # Cache only canonical physical directories, never alias mappings:
            # no symlink hop budget or .. semantics can disappear on a hit.
            current = directory_cache[candidate]
            continue
        if candidate.is_symlink():
            hops += 1
            if hops > 64:
                raise RuntimeError("cyclic input alias")
            raw_target = os.readlink(candidate)
            raw_target = raw_target if os.path.isabs(raw_target) else str(candidate.parent / raw_target)
            target = Path(os.path.normpath(raw_target))
            structural_alias = any(target == repository / prefix or repository / prefix in target.parents
                                   for prefix in ["closure", "packages", "runtime_closure", "qt_runtime_closure"])
            permitted = structural_alias or bool({target, *target.parents} & allowed)
            if not permitted:
                raise alias_failure(candidate, allowed, "Nix input alias has an undeclared intermediate target")
            # Keep .. components until their preceding directory aliases have
            # resolved; lexical normalization would change filesystem meaning.
            pending = raw_target.split("/")[1:] + pending
            current = Path("/")
        else:
            current = candidate
    if hop_result is not None:
        hop_result.append(hops)
    return current


def inventory(root, prefixes, allowed_roots=None, exclusions=None, inert_alias_policy=None):
    # The generated private repository itself is the trusted bootstrap root.
    # Canonicalize its OS directory alias once (Darwin /tmp -> /private/tmp).
    root = root.resolve(strict=True)
    files = []
    allowed_set = set(allowed_roots) if allowed_roots is not None else None
    policy = resolution_policy(root, allowed_set) if allowed_set is not None else None
    directory_cache = {}
    parent_cache = {root: (root, 0)}
    if inert_alias_policy not in (None, SITE_INERT_POLICY):
        raise ValueError('unsupported inert alias policy')
    def visit(path, ancestors):
        if (inert_alias_policy == SITE_INERT_POLICY and allowed_set is not None and
                path.name in ('input.conf', 'main.conf', 'network.conf')):
            parent = declared_resolve(path.parent, root, allowed_set, policy, directory_cache, parent_cache)
            if inert_site_alias(path, parent, allowed_set, inert_alias_policy):
                if exclusions is not None:
                    exclusions.append({'alias': path.relative_to(root).as_posix(),
                                       'policy': SITE_INERT_POLICY,
                                       'reason': 'inert host configuration link; excluded from execution inputs',
                                       'target_class': 'host-configuration', 'target_followed': False})
                return
        # This exact immutable systemd alias is operator configuration, never
        # a build input. Inspect its own link metadata only, not its target.
        if allowed_roots is not None and path.name == "99-environment.conf":
            parent = declared_resolve(path.parent, root, allowed_set, policy, directory_cache, parent_cache)
            source_root = parent.parent.parent
            if (source_root in allowed_roots and re.fullmatch(r"[a-z0-9]{32}-(?:systemd-minimal|systemd)-260\.1", source_root.name)
                    and parent.relative_to(source_root).as_posix() == "lib/environment.d"
                    and path.is_symlink()
                    and os.readlink(path) == "../../../../../etc/environment"):
                if exclusions is not None:
                    exclusions.append({"alias": path.relative_to(root).as_posix(), "reason": "operator runtime environment configuration; not an action input"})
                return
        try:
            hop_result = []
            unresolved = declared_resolve(path, root, allowed_set, policy, directory_cache, parent_cache, hop_result) if allowed_set is not None else path.resolve(strict=False)
            structural = not path.is_symlink() and path.is_dir() and (unresolved == root or root in unresolved.parents)
            if allowed_roots is not None and not structural:
                if not ({unresolved, *unresolved.parents} & allowed_set):
                    raise alias_failure(unresolved, allowed_set, "Nix input symlink escapes the declared immutable closure")
            if not path.exists():
                return
            real = unresolved
        except (FileNotFoundError, RuntimeError):
            # A dangling or self-cyclic alias is not a readable action input.
            return
        if path.is_dir():
            if real in ancestors:
                return
            if allowed_set is not None and ({real, *real.parents} & allowed_set):
                directory_cache[real] = real
            parent_cache[path] = (real, hop_result[0] if hop_result else 0)
            for child in sorted(path.iterdir()):
                visit(child, ancestors | {real})
        elif path.is_file():
            name = path.relative_to(root).as_posix()
            if not any(character in name for character in "\\:\n\r"):
                files.append(name)
        else:
            raise ValueError("unsupported declared Nix input type")
    for prefix in prefixes:
        path = root / prefix
        if path.exists():
            visit(path, set())
    return sorted(files)


if __name__ == "__main__":
    root = Path(sys.argv[1])
    allowed = [Path(line) for line in (root / "store-paths").read_text().splitlines() if line]
    exclusions = []
    arguments = sys.argv[2:]
    selected_policy = None
    policy_argument = '--inert-policy=' + SITE_INERT_POLICY
    policy_arguments = [argument for argument in arguments if argument.startswith('--inert-policy=')]
    if policy_arguments and policy_arguments != [policy_argument]:
        raise ValueError('unsupported or duplicate inert alias policy')
    if policy_argument in arguments:
        arguments = [argument for argument in arguments if argument != policy_argument]
        selected_policy = SITE_INERT_POLICY
    print(json.dumps({"files": inventory(root, arguments, allowed, exclusions, selected_policy), "excluded_non_inputs": exclusions}))
