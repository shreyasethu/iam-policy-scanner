"""Run rules over policies and files."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from iamscan.models import Finding, Policy
from iamscan.parser import PolicyParseError, load_policy
from iamscan.rules import RULES

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".terraform"}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    files_scanned: int = 0


def sort_key(f: Finding) -> tuple:
    return (-f.severity, f.path, -1 if f.statement is None else f.statement, f.rule_id)


def scan_policy(policy: Policy, ignore: Iterable[str] = ()) -> list[Finding]:
    skipped = {i.upper() for i in ignore}
    findings = [f for r in RULES.values() if r.id not in skipped for f in r.run(policy)]
    return sorted(findings, key=sort_key)


def iter_policy_files(paths: Iterable[str | Path]) -> Iterator[Path]:
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for file in sorted(path.rglob("*.json")):
                if not SKIP_DIRS & set(file.relative_to(path).parts):
                    yield file
        else:
            yield path


def scan_paths(paths: Iterable[str | Path], ignore: Iterable[str] = ()) -> ScanResult:
    result = ScanResult()
    ignore = list(ignore)
    for file in iter_policy_files(paths):
        try:
            policy = load_policy(file)
        except (OSError, UnicodeDecodeError, PolicyParseError) as exc:
            result.errors.append(f"{file}: {exc}")
            continue
        if policy is None:
            continue  # JSON, but not an IAM policy
        result.files_scanned += 1
        result.findings.extend(scan_policy(policy, ignore))
    result.findings.sort(key=sort_key)
    return result
