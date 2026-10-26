#!/usr/bin/env python3
"""Report production line coverage from a GCC MTDD_COVERAGE build."""

import argparse
import gzip
import json
import subprocess
import tempfile
from pathlib import Path


def report(build, project):
    covered = {}
    objects = sorted(build.rglob("*.gcda"))
    if not objects:
        raise SystemExit("no coverage data; configure MTDD_COVERAGE=ON, build and run tests first")
    with tempfile.TemporaryDirectory(prefix="gcov-", dir=build) as directory:
        destination = Path(directory)
        for data in objects:
            result = subprocess.run(
                ["gcov", "--json-format", str(data)], cwd=destination,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            if result.returncode:
                raise SystemExit(f"gcov failed for {data.name}: {result.stderr.strip()}")
            for output in destination.glob("*.gcov.json.gz"):
                with gzip.open(output, "rt") as stream:
                    document = json.load(stream)
                for item in document["files"]:
                    source = Path(item["file"])
                    if not source.is_absolute():
                        source = Path(document["current_working_directory"]) / source
                    try:
                        relative = source.resolve().relative_to(project)
                    except ValueError:
                        continue
                    if relative.parts[0] not in ("src", "include"):
                        continue
                    if not item["lines"]:
                        continue
                    counts = covered.setdefault(str(relative), {})
                    for line in item["lines"]:
                        number = line["line_number"]
                        counts[number] = max(counts.get(number, 0), line["count"])
                output.unlink()
    total = hits = 0
    for name, lines in sorted(covered.items()):
        visited = sum(count > 0 for count in lines.values())
        print(f"{100 * visited / len(lines):6.2f}% {visited:5}/{len(lines):5} {name}")
        total += len(lines)
        hits += visited
    if not total:
        raise SystemExit("no mtdd production source lines found")
    print(f"TOTAL {100 * hits / total:.2f}% ({hits}/{total} executable lines)")
    print("Line coverage only; not branch coverage or proof of interoperability.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    report(args.build.resolve(), args.project.resolve())
