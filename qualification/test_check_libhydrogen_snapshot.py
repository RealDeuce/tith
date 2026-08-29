"""Negative and positive tests for the Libhydrogen snapshot verifier."""

from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys
import tempfile
import unittest


CHECKER = pathlib.Path(__file__).with_name("check_libhydrogen_snapshot.py")


class SnapshotVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name) / "snapshot"
        self.root.mkdir()
        self.manifest = pathlib.Path(self.temporary.name) / "SHA256SUMS"
        self.write_file("hydrogen.c", b"pinned source\n")
        self.write_manifest(["hydrogen.c"])

    def write_file(self, name: str, contents: bytes) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)

    def write_manifest(self, names: list[str]) -> None:
        lines = []
        for name in names:
            digest = hashlib.sha256((self.root / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  ./{name}\n")
        self.manifest.write_text("".join(lines), encoding="ascii")

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), str(self.root), str(self.manifest)],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_accepts_an_exact_complete_snapshot(self) -> None:
        self.assertEqual(self.run_checker().returncode, 0)

    def test_rejects_changed_missing_and_unexpected_files(self) -> None:
        self.write_file("hydrogen.c", b"changed source\n")
        changed = self.run_checker()
        self.assertEqual(changed.returncode, 1)
        self.assertIn("changed: ./hydrogen.c", changed.stderr)

        (self.root / "hydrogen.c").unlink()
        missing = self.run_checker()
        self.assertEqual(missing.returncode, 1)
        self.assertIn("missing: ./hydrogen.c", missing.stderr)

        self.write_file("hydrogen.c", b"pinned source\n")
        self.write_file("extra.h", b"unexpected\n")
        unexpected = self.run_checker()
        self.assertEqual(unexpected.returncode, 1)
        self.assertIn("unexpected: ./extra.h", unexpected.stderr)

    def test_rejects_malformed_and_duplicate_entries(self) -> None:
        digest = hashlib.sha256(b"pinned source\n").hexdigest()
        for text in (
            "malformed\n",
            f"{digest}  hydrogen.c\n",
            f"{digest}  ./hydrogen.c\n{digest}  ./hydrogen.c\n",
        ):
            with self.subTest(text=text):
                self.manifest.write_text(text, encoding="ascii")
                self.assertNotEqual(self.run_checker().returncode, 0)


if __name__ == "__main__":
    unittest.main()
