"""One-time public SPKI output; private key exists only in an anonymous pipe.

Run solely as an explicit local, noncached Bazel action using its pinned OpenSSL.
The output is a public development identity pin, never a signing key.
"""
import argparse
import base64
from pathlib import Path
import resource
import subprocess


def generate(openssl, output):
    executable = Path(openssl).resolve(strict=True)
    if not executable.is_file():
        raise ValueError("declared OpenSSL executable must be a file")
    # Disable core files before either child can hold private key material.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = {"PATH": str(executable.parent), "LC_ALL": "C"}
    private = subprocess.Popen(
        [str(executable), "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=environment, close_fds=True)
    public = None
    try:
        public = subprocess.Popen(
            [str(executable), "pkey", "-pubout", "-outform", "DER"],
            stdin=private.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=environment, close_fds=True)
        private.stdout.close()
        der, _ = public.communicate(timeout=60)
        if private.wait(timeout=5) != 0 or public.returncode != 0:
            raise RuntimeError("public development identity generation failed")
        if not 128 <= len(der) <= 1024 or der[0] != 0x30:
            raise RuntimeError("public identity output is invalid")
        # Exclusive output prevents accidental replacement of an accepted pin.
        with Path(output).open("xb") as destination:
            destination.write(base64.b64encode(der) + b"\n")
    finally:
        for child in (public, private):
            if child is not None and child.poll() is None:
                child.kill()
                child.wait()
        if private.stdout is not None:
            private.stdout.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    generate(args.openssl, args.out)


if __name__ == "__main__":
    main()
