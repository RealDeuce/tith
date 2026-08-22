#!/usr/bin/env python3
"""Build the static TITH standards archive without third-party dependencies."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
STANDARDS = ROOT / "standards"
STATIC_FILES = (
    "index.html",
    "document.html",
    "styles.css",
    "app.js",
    "document.js",
)
HEADER_PATTERN = re.compile(r"^(Publication|Revision|Title|Date):\s*(.+?)\s*$")
DISPLAY_HYPHENS = str.maketrans({"‑": "-", "‐": "-", "–": "-"})


def git_value(*arguments: str) -> str:
    return subprocess.check_output(
        ("git", *arguments), cwd=ROOT, text=True
    ).strip()


def document_metadata(path: Path) -> dict[str, str]:
    metadata: dict[str, str] = {}
    with path.open(encoding="utf-8") as document:
        for line_number, line in enumerate(document):
            if line_number > 30:
                break
            match = HEADER_PATTERN.match(line)
            if match:
                metadata[match.group(1).lower()] = match.group(2)

    missing = {"publication", "revision", "title", "date"} - metadata.keys()
    if missing:
        raise ValueError(f"{path}: missing header fields: {', '.join(sorted(missing))}")

    publication = metadata["publication"].translate(DISPLAY_HYPHENS)
    document_type = path.name.split("-", 1)[0]
    if document_type not in {"TTS", "TSP", "TPS", "TRD"}:
        raise ValueError(f"{path}: unsupported document type {document_type!r}")

    return {
        "filename": path.name,
        "type": document_type,
        "publication": publication,
        "revision": metadata["revision"],
        "title": metadata["title"],
        "date": metadata["date"].translate(DISPLAY_HYPHENS),
    }


def build(output: Path) -> None:
    output = output.resolve()
    if output in {ROOT, SITE, STANDARDS}:
        raise ValueError(f"refusing to replace source directory {output}")
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    source_commit = os.environ.get("GITHUB_SHA") or git_value("rev-parse", "HEAD")
    for filename in STATIC_FILES:
        source = SITE / filename
        destination = output / filename
        if source.suffix == ".html":
            rendered = source.read_text(encoding="utf-8").replace(
                "{{SOURCE_COMMIT}}", source_commit
            )
            destination.write_text(rendered, encoding="utf-8")
        else:
            shutil.copy2(source, destination)

    output_standards = output / "standards"
    output_standards.mkdir()
    documents = []
    for source in sorted(STANDARDS.glob("*.txt")):
        documents.append(document_metadata(source))
        shutil.copy2(source, output_standards / source.name)

    standards_updated_at = git_value("log", "-1", "--format=%cI", "--", "standards")
    archive = {
        "sourceCommit": source_commit,
        "standardsUpdatedAt": standards_updated_at,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "documents": documents,
    }
    with (output_standards / "index.json").open("w", encoding="utf-8") as manifest:
        json.dump(archive, manifest, ensure_ascii=False, indent=2)
        manifest.write("\n")

    (output / ".nojekyll").touch()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "_site")
    arguments = parser.parse_args()
    build(arguments.output)


if __name__ == "__main__":
    main()
