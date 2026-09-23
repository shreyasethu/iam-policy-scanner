from __future__ import annotations

from iamscan import parse_policy, scan_policy
from iamscan.models import Finding


def make_policy(*statements: dict):
    return parse_policy({"Version": "2012-10-17", "Statement": list(statements)}, "test.json")


def scan(*statements: dict) -> list[Finding]:
    return scan_policy(make_policy(*statements))


def rule_ids(*statements: dict) -> set[str]:
    return {f.rule_id for f in scan(*statements)}


def allow(action, resource="*", **extra) -> dict:
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}
