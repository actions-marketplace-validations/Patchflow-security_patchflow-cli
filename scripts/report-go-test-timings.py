#!/usr/bin/env python3
"""Report the slowest Go tests from a `go test -json` event stream."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def parse_timings(path: Path) -> list[tuple[float, str, str]]:
    timings: list[tuple[float, str, str]] = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("Action") not in {"pass", "fail"} or not event.get("Test"):
                continue
            timings.append(
                (
                    float(event.get("Elapsed", 0.0)),
                    str(event.get("Package", "")),
                    str(event["Test"]),
                )
            )
    return sorted(timings, reverse=True)


def render(timings: list[tuple[float, str, str]], limit: int) -> str:
    lines = ["### Slowest output-contract tests", "", "| Seconds | Test |", "| ---: | --- |"]
    for elapsed, package, test in timings[:limit]:
        lines.append(f"| {elapsed:.2f} | `{package}:{test}` |")
    if not timings:
        lines.append("| 0.00 | No completed test events found |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("events", type=Path)
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()

    report = render(parse_timings(args.events), max(args.limit, 1))
    print(report, end="")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write("\n" + report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
