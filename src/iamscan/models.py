"""Core data model: severities, normalized policies, and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from fnmatch import fnmatchcase
from typing import Any


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        return cls[value.strip().upper()]


def action_matches(pattern: str, action: str) -> bool:
    """IAM action matching: case-insensitive, `*` and `?` wildcards."""
    return fnmatchcase(action.lower(), pattern.lower())


@dataclass
class Statement:
    index: int
    effect: str  # "allow" or "deny"
    sid: str | None = None
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    principal: Any = None
    conditions: dict[str, dict[str, Any]] = field(default_factory=dict)
    line: int = 1

    @property
    def is_allow(self) -> bool:
        return self.effect == "allow"

    @property
    def condition_keys(self) -> set[str]:
        return {key.lower() for block in self.conditions.values() for key in block}

    def condition_values(self, key: str) -> list[str]:
        """All values given for a condition key, across every operator."""
        values: list[str] = []
        for block in self.conditions.values():
            for k, v in block.items():
                if k.lower() == key.lower():
                    values.extend(v if isinstance(v, list) else [v])
        return [str(v) for v in values]

    def grants(self, action: str) -> bool:
        """Whether the Action/NotAction block covers `action` (ignores effect, resource, condition)."""
        if self.not_actions:
            return not any(action_matches(p, action) for p in self.not_actions)
        return any(action_matches(p, action) for p in self.actions)

    @property
    def has_wildcard_resource(self) -> bool:
        return "*" in self.resources

    @property
    def has_wildcard_principal(self) -> bool:
        return _contains_star(self.principal)

    @property
    def label(self) -> str:
        return f"statement {self.index}" + (f' "{self.sid}"' if self.sid else "")


def _contains_star(value: Any) -> bool:
    if value == "*":
        return True
    if isinstance(value, dict):
        return any(_contains_star(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_star(v) for v in value)
    return False


@dataclass
class Policy:
    path: str
    statements: list[Statement]

    def denies(self, action: str) -> bool:
        """True if an unconditional Deny on all resources blocks `action`.

        Conditional or resource-scoped Denies are ignored (conservative: we keep the finding).
        """
        return any(
            not s.is_allow
            and s.grants(action)
            and not s.conditions
            and s.has_wildcard_resource
            and not s.not_resources
            for s in self.statements
        )

    def allowing_statements(self, action: str) -> list[Statement]:
        if self.denies(action):
            return []
        return [s for s in self.statements if s.is_allow and s.grants(action)]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    path: str
    statement: int | None = None
    sid: str | None = None
    line: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": str(self.severity),
            "title": self.title,
            "message": self.message,
            "path": self.path,
            "statement": self.statement,
            "sid": self.sid,
            "line": self.line,
        }
