"""Explicit, bounded operator-host probe; never part of an automatic test."""
import argparse
import json
import os
import re
import subprocess
import sys
from ssh_policy import operator_config

HOSTS = {"neo": "Darwin", "pzm": "Darwin", "sting": "Linux", "yoga": "Linux"}


def ssh_command(ssh, host, command, timeout=30, config_options=()):
    # Known-host enrollment and credentials remain operator configuration.
    return subprocess.run(
        [ssh, *config_options, "-oBatchMode=yes", "-oConnectTimeout=10", "-oConnectionAttempts=1",
         "-oStrictHostKeyChecking=yes", "-oForwardAgent=no", "-oClearAllForwardings=yes",
         host, command], capture_output=True, text=True, timeout=timeout,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh", required=True)
    parser.add_argument("--host", choices=HOSTS, required=True)
    args = parser.parse_args()
    if not os.path.isfile(args.ssh) or not os.access(args.ssh, os.X_OK):
        parser.error("SSH executable must be supplied by the declared Bazel tool target")
    try:
        with operator_config() as config_options:
            return probe(args, config_options)
    except (OSError, ValueError):
        print(json.dumps({"host_alias": args.host, "ready": False, "gate": "public operator SSH policy custody rejected"}, sort_keys=True))
        return 2


def probe(args, config_options):
    result = {"host_alias": args.host, "expected_os": HOSTS[args.host], "ready": False}
    if config_options:
        result["policy_compatibility"] = "existing-policy subset mlkem768x25519-sha256,curve25519-sha256; all other policy unchanged"
    try:
        # ssh -G is read-only; its potentially identifying output is never emitted.
        config = subprocess.run([args.ssh, *config_options, "-G", args.host], capture_output=True,
                                text=True, timeout=10)
        values = dict(line.split(" ", 1) for line in config.stdout.splitlines() if " " in line)
        if config.returncode:
            result["gate"] = "operator SSH configuration unavailable"
            diagnostic = config.stderr.lower()
            result["configuration_exit_code"] = config.returncode
            for needle, reason in [
                ("bad configuration option", "unsupported operator SSH option"),
                ("unsupported kex", "operator SSH key-exchange policy unsupported by locked SSH"),
                ("bad ssh2 kexalgorithms", "operator SSH key-exchange policy unsupported by locked SSH"),
                ("bad ssh2 cipher", "operator SSH cipher policy unsupported by locked SSH"),
                ("bad ssh2 mac", "operator SSH MAC policy unsupported by locked SSH"),
                ("bad owner or permissions", "operator SSH configuration permissions rejected"),
                ("no such file", "declared SSH support input unavailable"),
                ("error while loading shared libraries", "declared SSH runtime input unavailable"),
                ("undefined symbol", "declared SSH runtime ABI mismatch"),
            ]:
                if needle in diagnostic:
                    result["gate"] = reason
                    break
            option = re.search(r"bad configuration option:\s*['\"]?([a-z][a-z0-9_-]{0,63})", diagnostic)
            if option:
                result["unsupported_option"] = option.group(1)
            algorithm = re.search(r"unsupported kex algorithm\s*['\"]?([a-z0-9@_.+-]{1,100})", diagnostic)
            if algorithm:
                result["gate"] = "operator SSH key-exchange policy unsupported by locked SSH"
                result["unsupported_kex_algorithm"] = algorithm.group(1)
            result["configuration_error_categories"] = [term for term in [
                "gssapi", "kex", "cipher", "macs", "hostkey", "pubkey", "unsupported", "invalid", "missing argument",
            ] if term in diagnostic]
        else:
            result["configured_alias"] = values.get("hostname") != args.host
            command = """set -eu
printf 'os='; uname -s
printf 'arch='; uname -m
if command -v nix >/dev/null 2>&1; then printf 'nix=present\\n'; else printf 'nix=missing\\n'; fi
if test -d /nix/store; then printf 'store=present\\n'; else printf 'store=missing\\n'; fi
"""
            remote = ssh_command(args.ssh, args.host, command, config_options=config_options)
            if remote.returncode:
                diagnostic = remote.stderr.lower()
                if "could not resolve hostname" in diagnostic:
                    result["gate"] = "hostname resolution failed"
                elif "host key verification failed" in diagnostic:
                    result["gate"] = "existing host key trust missing or rejected"
                elif "permission denied" in diagnostic:
                    result["gate"] = "existing operator SSH authentication rejected"
                elif "timed out" in diagnostic or "connection refused" in diagnostic or "no route to host" in diagnostic:
                    result["gate"] = "host SSH endpoint unreachable"
                else:
                    result["gate"] = "SSH connection or read-only host probe failed"
            else:
                fields = dict(line.split("=", 1) for line in remote.stdout.splitlines() if "=" in line)
                # Emit only bounded enumerated capability values, no hostnames or paths.
                result.update({key: value for key, value in fields.items()
                               if key in {"os", "arch", "nix", "store"}
                               and value in {"Darwin", "Linux", "arm64", "aarch64", "x86_64", "present", "missing"}})
                result["ready"] = (fields.get("os") == HOSTS[args.host]
                                   and fields.get("nix") == "present"
                                   and fields.get("store") == "present")
                result["gate"] = "ready for declared host build" if result["ready"] else "platform or Nix capability missing"
    except (OSError, subprocess.TimeoutExpired):
        result["gate"] = "bounded SSH probe unavailable or timed out"
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ready"] else 2


if __name__ == "__main__":
    sys.exit(main())
