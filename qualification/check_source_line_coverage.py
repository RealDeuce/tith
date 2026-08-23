#!/usr/bin/env python3
"""Require complete LLVM function, line, and branch coverage for sources."""

import json
import pathlib
import sys


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
			for segment in matches[0].get("segments", []):
				if segment[3] and segment[2] == 0 and not segment[5]:
					print(f"{source}: zero-count segment {segment}")
		if summary["branches"]["covered"] != summary["branches"]["count"]:
			for branch in matches[0].get("branches", []):
				if branch[4] == 0 or branch[5] == 0:
					print(f"{source}: uncovered branch {branch}")
	return int(failed)


if __name__ == "__main__":
	raise SystemExit(main())
