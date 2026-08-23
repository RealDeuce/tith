#!/usr/bin/env python3
"""Require complete LLVM function, line, and branch coverage for sources."""

import json
import pathlib
import sys


def uncovered_lines(entry: dict) -> list[int]:
	"""Reconstruct uncovered source lines from LLVM's ordered segments."""
	executable: set[int] = set()
	covered: set[int] = set()
	segments = entry.get("segments", [])
	for index, segment in enumerate(segments[:-1]):
		line, _, count, has_count, _, is_gap = segment
		if not has_count or is_gap:
			continue
		next_line = segments[index + 1][0]
		for source_line in range(line, next_line + 1):
			executable.add(source_line)
			if count:
				covered.add(source_line)
	return sorted(executable - covered)


def main() -> int:
	if len(sys.argv) < 3:
		raise SystemExit("usage: check_source_line_coverage.py REPORT SOURCE...")
	report = pathlib.Path(sys.argv[1])
	wanted = [pathlib.Path(value).as_posix() for value in sys.argv[2:]]
	data = json.loads(report.read_text(encoding="utf-8"))["data"]
	if len(data) != 1:
		raise SystemExit(f"expected one LLVM coverage data set, found {len(data)}")
	files = data[0]["files"]
	failed = False
	for source in wanted:
		matches = [
			entry
			for entry in files
			if pathlib.Path(entry["filename"]).as_posix().endswith(f"/{source}")
			or pathlib.Path(entry["filename"]).as_posix() == source
		]
		if len(matches) != 1:
			print(f"{source}: expected one report entry, found {len(matches)}")
			failed = True
			continue
		summary = matches[0]["summary"]
		parts = []
		for kind in ("functions", "lines", "branches"):
			counts = summary[kind]
			parts.append(f"{kind} {counts['covered']}/{counts['count']}")
			if counts["covered"] != counts["count"]:
				failed = True
		print(f"{source}: " + ", ".join(parts))
		if summary["lines"]["covered"] != summary["lines"]["count"]:
			print(f"{source}: reconstructed uncovered lines {uncovered_lines(matches[0])}")
		if summary["branches"]["covered"] != summary["branches"]["count"]:
			for branch in matches[0].get("branches", []):
				if branch[4] == 0 or branch[5] == 0:
					print(f"{source}: uncovered branch {branch}")
	return int(failed)


if __name__ == "__main__":
	raise SystemExit(main())
