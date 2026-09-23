"""Command-line interface.

Exit codes: 0 = clean, 1 = findings at or above --fail-on, 2 = files could not be parsed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from iamscan import __version__
from iamscan.engine import scan_paths
from iamscan.models import Severity
from iamscan.report import FORMATTERS
from iamscan.rules import RULES

SEVERITY_CHOICES = [str(s) for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iamscan",
        description="Scan AWS IAM policies for over-broad permissions and privilege escalation.",
    )
    parser.add_argument("paths", nargs="*", help="policy files or directories (scanned for *.json)")
    parser.add_argument("-f", "--format", choices=sorted(FORMATTERS), default="text")
    parser.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    parser.add_argument("--fail-on", choices=SEVERITY_CHOICES + ["none"], default="high",
                        help="exit 1 if any finding is at or above this severity (default: high)")
    parser.add_argument("--min-severity", choices=SEVERITY_CHOICES, default="low",
                        help="hide findings below this severity")
    parser.add_argument("--ignore", default="", help="comma-separated rule IDs to skip")
    parser.add_argument("--list-rules", action="store_true", help="print all rules and exit")
    parser.add_argument("--version", action="version", version=f"iamscan {__version__}")
    return parser


def list_rules() -> str:
    return "\n".join(f"{r.id}  {str(r.severity).upper():<8} {r.title}" for r in RULES.values())


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_rules:
        print(list_rules())
        return 0
    if not args.paths:
        parser.error("at least one path is required")

    ignore = [i.strip() for i in args.ignore.split(",") if i.strip()]
    unknown = [i for i in ignore if i.upper() not in RULES]
    if unknown:
        parser.error(f"unknown rule ID(s): {', '.join(unknown)}")

    result = scan_paths(args.paths, ignore)
    floor = Severity.parse(args.min_severity)
    result.findings = [f for f in result.findings if f.severity >= floor]

    report = FORMATTERS[args.format](result)
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
    else:
        print(report)

    if result.errors:
        return 2
    if args.fail_on != "none":
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
