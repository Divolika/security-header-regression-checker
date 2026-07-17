"""CLI for the security-header regression tester.

Compares two header snapshots (JSON) and reports security regressions. Also
provides a helper to turn a raw `curl -sI` style header dump into a snapshot.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

from .compare import Diff, SEVERITY_ORDER, Snapshot, compare


def load_snapshot(path: str, label: str) -> Snapshot:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return Snapshot.from_dict(label, raw)


def parse_raw_headers(text: str) -> Dict[str, object]:
    """Turn a raw HTTP header dump (e.g. `curl -sI`) into a snapshot dict.

    Repeated Set-Cookie headers are collected into a list.
    """
    result: Dict[str, object] = {}
    cookies: List[str] = []
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line or ":" not in line or line.startswith("HTTP/"):
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key.lower() == "set-cookie":
            cookies.append(value)
        else:
            result[key] = value
    if cookies:
        result["Set-Cookie"] = cookies
    return result


def format_text(diffs: List[Diff], baseline: str, candidate: str) -> str:
    if not diffs:
        return f"No security regressions from {baseline} to {candidate}."
    lines = [f"Comparing {baseline} (baseline) -> {candidate} (candidate)\n"]
    for d in diffs:
        lines.append(f"[{d.severity}] {d.header}: {d.message}")
        if d.baseline is not None:
            lines.append(f"    baseline:  {d.baseline}")
        if d.candidate is not None:
            lines.append(f"    candidate: {d.candidate}")
        lines.append("")
    counts: Dict[str, int] = {}
    for d in diffs:
        counts[d.severity] = counts.get(d.severity, 0) + 1
    summary = ", ".join(
        f"{counts[s]} {s.lower()}"
        for s in sorted(counts, key=lambda x: -SEVERITY_ORDER[x])
    )
    lines.append(f"Summary: {len(diffs)} differences ({summary})")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="header-regression",
        description="Diff security headers between two deployment snapshots.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    diff_p = sub.add_parser("diff", help="Compare two snapshot JSON files.")
    diff_p.add_argument("baseline", help="Baseline snapshot JSON (e.g. production).")
    diff_p.add_argument("candidate", help="Candidate snapshot JSON (e.g. staging).")
    diff_p.add_argument("-f", "--format", choices=["text", "json"], default="text")
    diff_p.add_argument(
        "--fail-on",
        choices=["HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Exit non-zero if a regression at/above this severity exists.",
    )

    cap_p = sub.add_parser(
        "capture",
        help="Convert a raw header dump (stdin or file) to a snapshot JSON.",
    )
    cap_p.add_argument("input", nargs="?", default="-", help="File or '-' for stdin.")
    cap_p.add_argument("-o", "--output", help="Write snapshot JSON here.")

    return p


def _cmd_diff(args) -> int:
    baseline = load_snapshot(args.baseline, "baseline")
    candidate = load_snapshot(args.candidate, "candidate")
    diffs = compare(baseline, candidate)

    if args.format == "json":
        print(json.dumps({"total": len(diffs), "differences": [d.__dict__ for d in diffs]}, indent=2))
    else:
        print(format_text(diffs, "baseline", "candidate"))

    threshold = SEVERITY_ORDER[args.fail_on]
    regressions = [d for d in diffs if d.kind != "added"]
    if any(SEVERITY_ORDER[d.severity] >= threshold for d in regressions):
        return 1
    return 0


def _cmd_capture(args) -> int:
    text = sys.stdin.read() if args.input == "-" else Path(args.input).read_text()
    snapshot = parse_raw_headers(text)
    rendered = json.dumps(snapshot, indent=2)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"Wrote snapshot to {args.output}", file=sys.stderr)
    else:
        print(rendered)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "diff":
            return _cmd_diff(args)
        if args.command == "capture":
            return _cmd_capture(args)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
