"""Output formats: human text, JSON, SARIF 2.1.0, and GitHub Actions annotations."""

from __future__ import annotations

import json
from collections import Counter

from iamscan import __version__
from iamscan.engine import ScanResult
from iamscan.models import Finding, Severity
from iamscan.rules import RULES

# GitHub code scanning reads this to rank alerts (0.1-10).
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0",
}
SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
GITHUB_COMMAND = {
    Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
}


def _where(f: Finding) -> str:
    if f.statement is None:
        return f"{f.path} [policy-wide]"
    sid = f' "{f.sid}"' if f.sid else ""
    return f"{f.path}:{f.line} [statement {f.statement}{sid}]"


def summary(result: ScanResult) -> str:
    counts = Counter(f.severity for f in result.findings)
    parts = ", ".join(f"{counts[s]} {s}" for s in sorted(Severity, reverse=True))
    files = "file" if result.files_scanned == 1 else "files"
    return f"Scanned {result.files_scanned} policy {files}: {parts}"


def format_text(result: ScanResult) -> str:
    lines = []
    for f in result.findings:
        lines.append(f"{str(f.severity).upper():<8} {f.rule_id}  {_where(f)}")
        lines.append(f"         {f.title}: {f.message}")
    for error in result.errors:
        lines.append(f"ERROR    {error}")
    if lines:
        lines.append("")
    lines.append(summary(result))
    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    return json.dumps({
        "version": __version__,
        "files_scanned": result.files_scanned,
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }, indent=2)


def format_sarif(result: ScanResult) -> str:
    rules = [{
        "id": r.id,
        "name": r.title,
        "shortDescription": {"text": r.title},
        "fullDescription": {"text": r.description},
        "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
        "properties": {"security-severity": SECURITY_SEVERITY[r.severity],
                       "tags": ["security", "iam"]},
    } for r in RULES.values()]
    results = [{
        "ruleId": f.rule_id,
        "level": SARIF_LEVEL[f.severity],
        "message": {"text": f"{f.title}: {f.message}"},
        "properties": {"severity": str(f.severity),
                       "security-severity": SECURITY_SEVERITY[f.severity]},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.path},
            "region": {"startLine": f.line},
        }}],
    } for f in result.findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "iamscan", "version": __version__,
                                "informationUri": "https://github.com/", "rules": rules}},
            "results": results,
        }],
    }, indent=2)


def _escape(value: str, property: bool = False) -> str:
    value = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property:
        value = value.replace(":", "%3A").replace(",", "%2C")
    return value


def format_github(result: ScanResult) -> str:
    """Workflow commands that GitHub renders as inline PR annotations."""
    lines = [
        f"::{GITHUB_COMMAND[f.severity]} file={_escape(f.path, True)},line={f.line},"
        f"title={_escape(f'{f.rule_id} {f.title} ({f.severity})', True)}::{_escape(f.message)}"
        for f in result.findings
    ]
    lines += [f"::error::{_escape(e)}" for e in result.errors]
    lines.append(format_text(result))
    return "\n".join(lines)


FORMATTERS = {"text": format_text, "json": format_json, "sarif": format_sarif,
              "github": format_github}
