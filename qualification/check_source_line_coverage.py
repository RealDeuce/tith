#!/usr/bin/env python3
"""Require complete LLVM function, line, and branch coverage for sources."""

import json
import pathlib
import sys


def uncovered_lines(entry: dict) -> list[int]:
	"""Return lines whose first mapped source region has a zero count."""
	primary: dict[int, tuple[int, int]] = {}
	for line, column, count, has_count, is_region, is_gap in entry.get("segments", []):
		if not has_count or not is_region or is_gap:
			continue
		current = primary.get(line)
		if current is None or column < current[0]:
			primary[line] = (column, count)
	return sorted(line for line, (_, count) in primary.items() if count == 0)


def main() -> int:
	if len(sys.argv) < 3:
		raise SystemExit("usage: check_source_line_coverage.py REPORT SOURCE...")
	report = pathlib.Path(sys.argv[1])
	wanted = [pathlib.Path(value).as_posix() for value in sys.argv[2:]]
	data = json.loads(report.read_text(encoding="utf-8"))["data"]
	if len(data) != 1:
		raise SystemExit(f"expected one LLVM coverage data set, found {len(data)}")
	files = data[0]["files"]
	functions = data[0].get("functions", [])
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
			if kind != "lines" and counts["covered"] != counts["count"]:
				failed = True
		print(f"{source}: " + ", ".join(parts))
		if summary["functions"]["covered"] != summary["functions"]["count"]:
			uncovered = sorted(
				function["name"]
				for function in functions
				if function.get("count", 0) == 0
				and any(
					pathlib.Path(filename).as_posix().endswith(f"/{source}")
					or pathlib.Path(filename).as_posix() == source
					for filename in function.get("filenames", [])
				)
			)
			print(f"{source}: uncovered functions {uncovered}")
		if summary["lines"]["covered"] != summary["lines"]["count"]:
			uncovered = uncovered_lines(matches[0])
			print(f"{source}: uncovered primary source lines {uncovered}")
			if uncovered:
				failed = True
		if summary["branches"]["covered"] != summary["branches"]["count"]:
			for branch in matches[0].get("branches", []):
				if branch[4] == 0 or branch[5] == 0:
					print(f"{source}: uncovered branch {branch}")
	return int(failed)


if __name__ == "__main__":
	raise SystemExit(main())
