#!/usr/bin/env python3
"""Verify the complete vendored Libhydrogen snapshot against its manifest."""

from __future__ import annotations

import hashlib
import pathlib
import sys


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} SNAPSHOT MANIFEST")

    root = pathlib.Path(sys.argv[1])
    manifest = pathlib.Path(sys.argv[2])
    expected: dict[str, str] = {}
    for line in manifest.read_text(encoding="ascii").splitlines():
        digest, name = line.split("  ", 1)
        if not name.startswith("./") or name in expected:
            raise SystemExit(f"invalid manifest entry: {line}")
        expected[name] = digest

    actual = {
        f"./{path.relative_to(root).as_posix()}": hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }
    if actual == expected:
        return 0

    for name in sorted(expected.keys() | actual.keys()):
        if name not in actual:
            print(f"missing: {name}", file=sys.stderr)
        elif name not in expected:
            print(f"unexpected: {name}", file=sys.stderr)
        elif actual[name] != expected[name]:
            print(f"changed: {name}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
