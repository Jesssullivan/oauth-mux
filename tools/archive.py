"""Produce reproducible archives from Bazel's explicit source inputs."""

import argparse
import gzip
import io
from pathlib import Path, PurePosixPath
import tarfile
import zipfile


def safe_name(value):
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(part in (".", "..") for part in value.split("/")):
        raise ValueError(f"unsafe archive path: {value!r}")
    return str(path)


def entries(files, prefix):
    result = {}
    prefix = safe_name(prefix) if prefix else ""
    for specification in files:
        destination, separator, source = specification.partition("=")
        if not separator or not source:
            raise ValueError("archive inputs must be destination=source")
        destination = safe_name(destination)
        name = f"{prefix}/{destination}" if prefix else destination
        if name in result:
            raise ValueError(f"duplicate archive input: {name}")
        path = Path(source)
        if not path.is_file():
            raise ValueError(f"archive input is not a regular file: {source}")
        mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
        result[name] = (path.read_bytes(), mode)
    return sorted(result.items())


def write_zip(output, contents):
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, (payload, mode) in contents:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100000 | mode) << 16
            archive.writestr(info, payload)


def write_tar(output, contents):
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, (payload, mode) in contents:
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    info.mode = mode
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(payload))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("zip", "tar.gz"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prefix", default="")
    parser.add_argument("--file", action="append", default=[])
    options = parser.parse_args()
    try:
        contents = entries(options.file, options.prefix)
        if options.format == "zip":
            write_zip(options.output, contents)
        else:
            write_tar(options.output, contents)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, f"archive: {error}\n")


if __name__ == "__main__":
    main()
