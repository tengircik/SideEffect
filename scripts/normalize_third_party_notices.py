#!/usr/bin/env python3
"""Normalize generated third-party license text without changing its wording."""

from __future__ import annotations

import argparse
from pathlib import Path


MAX_NOTICE_BYTES = 2 * 1024 * 1024


def normalize(source: Path, destination: Path) -> None:
    raw = source.read_bytes()
    if not raw or len(raw) > MAX_NOTICE_BYTES:
        raise ValueError("generated notices are empty or exceed the 2 MiB limit")
    text = raw.decode("utf-8", errors="strict")
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    normalized = "\n".join(line.rstrip(" \t") for line in lines).rstrip("\n") + "\n"
    encoded = normalized.encode("utf-8")
    if len(encoded) > MAX_NOTICE_BYTES:
        raise ValueError("normalized notices exceed the 2 MiB limit")
    destination.write_bytes(encoded)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="raw generated notice file")
    parser.add_argument("destination", type=Path, help="normalized output file")
    args = parser.parse_args()
    try:
        normalize(args.source, args.destination)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
