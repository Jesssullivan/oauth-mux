"""Pure HM definition predicates; filesystem ownership and activation are separate.

The native collector verifies immutable files and rechecks descriptors. This
helper is a bounded fixture oracle, never an installation or service command.
"""
import hashlib
import re


def verify_definition(record, *, channel, manifest_sha256, config_home,
                      unit_bytes, unit_link, login_link):
    """Return modeled definition compatibility, never activation authority."""
    unknown = {"definition": "unknown", "activation": "unknown"}
    if not isinstance(record, dict) or channel not in ("development", "release"):
        return unknown
    name = "ai.xoxd.omux" + (".dev" if channel == "development" else "") + ".service"
    instance = "dev" if channel == "development" else "default"
    if (not isinstance(config_home, str) or not config_home.startswith("/")
            or any(p in ("", ".", "..") for p in config_home[1:].split("/"))):
        return unknown
    if not isinstance(manifest_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
        return unknown
    if (record.get("schemaVersion") != 1 or record.get("owner") != "home-manager"
            or record.get("channel") != channel or record.get("instance") != instance
            or record.get("artifactManifestSha256") != manifest_sha256
            or record.get("scope") != "definition-only-not-activation"):
        return unknown
    unit, login = record.get("unit"), record.get("login")
    if not isinstance(unit, dict) or not isinstance(login, dict):
        return unknown
    source = unit.get("sourcePath")
    if not isinstance(source, str) or not re.fullmatch(
            r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9._+-]+/" + re.escape(name), source):
        return unknown
    installed = config_home + "/systemd/user/" + name
    if (unit.get("name") != name or unit.get("mode") != 420
            or unit.get("installedPath") != installed or unit_link != source
            or login.get("sourcePath") != source
            or login.get("installedPath") != config_home + "/systemd/user/default.target.wants/" + name
            or login_link not in (source, "../" + name)):
        return unknown
    if not isinstance(unit_bytes, bytes) or len(unit_bytes) > 65536:
        return unknown
    if unit.get("sha256") != hashlib.sha256(unit_bytes).hexdigest():
        return unknown
    return {"definition": "modeled-compatible", "activation": "unknown"}
