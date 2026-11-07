#!/usr/bin/env python3
"""Validate and safely smoke-test a SideEffect Linux release tar.gz archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import zlib
from pathlib import Path

MAX_ARCHIVE_BYTES = 160 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 160 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 8
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 15
COPY_CHUNK_BYTES = 64 * 1024

FILE_LIMITS = {
    "sideeffect": 128 * 1024 * 1024,
    "README.md": 4 * 1024 * 1024,
    "LICENSE": 1 * 1024 * 1024,
    "THIRD_PARTY_NOTICES.txt": 8 * 1024 * 1024,
    "INSTALL.md": 4 * 1024 * 1024,
    "AGENT_SKILL.md": 4 * 1024 * 1024,
    "RELEASE_NOTES.md": 4 * 1024 * 1024,
}
EXPECTED_FILES = frozenset(FILE_LIMITS)


class ArchiveError(ValueError):
    """Raised when a release archive violates the bounded archive contract."""


class _BoundedReader:
    def __init__(self, source, limit: int):
        self.source = source
        self.limit = limit
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.limit - self.total
        request = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self.source.read(request)
        if len(data) > remaining:
            raise ArchiveError("uncompressed tar data exceeds the size limit")
        self.total += len(data)
        return data


def _archive_fd(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ArchiveError(f"could not open archive safely: {error}") from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ArchiveError("archive must be a regular file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_ARCHIVE_BYTES:
        os.close(descriptor)
        raise ArchiveError(f"compressed archive exceeds the {MAX_ARCHIVE_BYTES}-byte limit")
    return descriptor


def _hash_archive(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, COPY_CHUNK_BYTES):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _member_relative_name(name: str, top_directory: str, is_directory: bool) -> str | None:
    if not name or "\\" in name or name.startswith("/") or "\x00" in name:
        raise ArchiveError(f"unsafe archive path: {name!r}")
    if name == top_directory + "/" and is_directory:
        return None
    if name.startswith("/") or ":" in name:
        raise ArchiveError(f"absolute archive path is not allowed: {name!r}")
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ArchiveError(f"non-canonical archive path: {name!r}")
    if len(parts) != 2 or parts[0] != top_directory:
        raise ArchiveError(f"unexpected archive member: {name!r}")
    return parts[1]


def _copy_member(member: tarfile.TarInfo, source, output=None) -> str:
    if member.size < 0:
        raise ArchiveError(f"negative member size: {member.name!r}")
    digest = hashlib.sha256()
    remaining = member.size
    while remaining:
        chunk = source.read(min(COPY_CHUNK_BYTES, remaining))
        if not chunk:
            raise ArchiveError(f"truncated archive member: {member.name!r}")
        remaining -= len(chunk)
        digest.update(chunk)
        if output is not None:
            output.write(chunk)
    if source.read(1):
        raise ArchiveError(f"archive member exceeded its declared size: {member.name!r}")
    return digest.hexdigest()


def _walk_archive(descriptor: int, top_directory: str, extract_directory: Path | None = None):
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), "rb") as archive_stream:
        with gzip.GzipFile(fileobj=archive_stream, mode="rb") as gzip_stream:
            bounded = _BoundedReader(gzip_stream, MAX_UNCOMPRESSED_BYTES)
            manifest: dict[str, tuple[int, str]] = {}
            saw_root_directory = False
            total_size = 0
            with tarfile.open(fileobj=bounded, mode="r|") as archive:
                for member in archive:
                    if member.pax_headers:
                        raise ArchiveError("PAX metadata is not allowed in the release archive")
                    if member.type == tarfile.DIRTYPE:
                        if member.name not in (top_directory, top_directory + "/") or member.size != 0 or saw_root_directory:
                            raise ArchiveError(f"unexpected archive directory: {member.name!r}")
                        if len(manifest) + 1 > MAX_ARCHIVE_MEMBERS:
                            raise ArchiveError("archive has too many members")
                        saw_root_directory = True
                        continue
                    if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                        raise ArchiveError(f"links and special files are not allowed: {member.name!r}")
                    relative_name = _member_relative_name(member.name, top_directory, False)
                    assert relative_name is not None
                    if relative_name not in EXPECTED_FILES:
                        raise ArchiveError(f"unexpected archive file: {member.name!r}")
                    if relative_name in manifest:
                        raise ArchiveError(f"duplicate archive member: {member.name!r}")
                    if len(manifest) + int(saw_root_directory) + 1 > MAX_ARCHIVE_MEMBERS:
                        raise ArchiveError("archive has too many members")
                    limit = FILE_LIMITS[relative_name]
                    if member.size > limit:
                        raise ArchiveError(
                            f"archive member {relative_name!r} exceeds its {limit}-byte limit"
                        )
                    total_size += member.size
                    if total_size > MAX_UNCOMPRESSED_BYTES:
                        raise ArchiveError("archive files exceed the total uncompressed size limit")
                    source = archive.extractfile(member)
                    if source is None:
                        raise ArchiveError(f"could not read archive member: {member.name!r}")
                    if extract_directory is None:
                        digest = _copy_member(member, source)
                    else:
                        mode = 0o755 if relative_name == "sideeffect" else 0o644
                        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                        target = extract_directory / relative_name
                        try:
                            target_fd = os.open(target, flags, mode)
                        except OSError as error:
                            raise ArchiveError(f"could not create extracted file safely: {relative_name}") from error
                        with os.fdopen(target_fd, "wb") as output:
                            digest = _copy_member(member, source, output)
                    manifest[relative_name] = (member.size, digest)

                if not saw_root_directory:
                    raise ArchiveError("archive is missing its exact top-level directory")
                if frozenset(manifest) != EXPECTED_FILES:
                    missing = sorted(EXPECTED_FILES - manifest.keys())
                    raise ArchiveError(f"archive file set is incomplete; missing: {', '.join(missing)}")
                tar_stream = archive.fileobj
                while trailing := tar_stream.read(COPY_CHUNK_BYTES):
                    if any(trailing):
                        raise ArchiveError("non-zero data follows the tar end markers")
    return manifest


def _kill_process(process: subprocess.Popen) -> None:
    try:
        # The leader may have exited while a descendant still holds our pipes.
        # On POSIX, signal its process group even when poll() reports completion.
        os.killpg(process.pid, signal.SIGKILL)
    except (AttributeError, ProcessLookupError, PermissionError):
        if process.poll() is None:
            process.kill()
    if process.poll() is None:
        process.wait()


def _run_cli(executable: Path, arguments: list[str]) -> str:
    environment = {"PATH": os.environ.get("PATH", ""), "LANG": "C", "LC_ALL": "C"}
    process = subprocess.Popen(
        [str(executable), *arguments],
        cwd=executable.parent,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=(os.name != "nt"),
        creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
    )
    selector = selectors.DefaultSelector()
    output: dict[int, bytearray] = {}
    total = 0
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        assert process.stdout is not None and process.stderr is not None
        descriptors = {stream: stream.fileno() for stream in (process.stdout, process.stderr)}
        for stream, descriptor in descriptors.items():
            if hasattr(os, "set_blocking"):
                os.set_blocking(descriptor, False)
            output[descriptor] = bytearray()
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ArchiveError(f"CLI command timed out: {' '.join(arguments)}")
            for key, _ in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fd, min(8192, MAX_COMMAND_OUTPUT_BYTES + 1 - total))
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                total += len(chunk)
                if total > MAX_COMMAND_OUTPUT_BYTES:
                    raise ArchiveError("extracted CLI exceeded its command output limit")
                output[key.fd].extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ArchiveError(f"CLI command timed out: {' '.join(arguments)}")
        return_code = process.wait(timeout=remaining)
        stdout = bytes(output[descriptors[process.stdout]]).decode("utf-8", errors="replace")
        stderr = bytes(output[descriptors[process.stderr]]).decode("utf-8", errors="replace")
        if return_code != 0:
            raise ArchiveError(
                f"extracted CLI command {' '.join(arguments)!r} exited {return_code}: {stderr[:2000]}"
            )
        return stdout
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ArchiveError(f"could not run extracted CLI: {error}") from error
    finally:
        selector.close()
        _kill_process(process)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def smoke_archive(archive_path: Path, version: str, temp_directory: Path) -> None:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ArchiveError("release version must use the numeric MAJOR.MINOR.PATCH form")
    top_directory = f"sideeffect-v{version}-linux-x86_64"
    descriptor = _archive_fd(archive_path)
    try:
        initial_hash = _hash_archive(descriptor)
        expected = _walk_archive(descriptor, top_directory)
        with tempfile.TemporaryDirectory(
            prefix="sideeffect-linux-release-smoke-", dir=temp_directory
        ) as temporary_root:
            package_directory = Path(temporary_root) / top_directory
            os.mkdir(package_directory, 0o700)
            extracted = _walk_archive(descriptor, top_directory, package_directory)
            if extracted != expected or _hash_archive(descriptor) != initial_hash:
                raise ArchiveError("release archive changed during inspection or extraction")
            executable = package_directory / "sideeffect"
            help_output = _run_cli(executable, ["--help"])
            if not help_output.strip():
                raise ArchiveError("extracted CLI --help returned no output")
            version_output = _run_cli(executable, ["version"]).strip()
            expected_version = f"sideeffect {version}"
            if version_output != expected_version:
                raise ArchiveError(
                    f"extracted CLI reported {version_output!r}; expected {expected_version!r}"
                )
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--temp-dir", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        smoke_archive(arguments.archive, arguments.version, arguments.temp_dir)
    except (ArchiveError, OSError, EOFError, tarfile.TarError, gzip.BadGzipFile, zlib.error) as error:
        parser.exit(1, f"release archive smoke failed: {error}\n")
    print(f"validated and smoke-tested SideEffect Linux archive v{arguments.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
