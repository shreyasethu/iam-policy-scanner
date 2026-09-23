"""Load IAM policy JSON into the normalized model.

Accepts raw policy documents as well as common wrappers produced by the AWS CLI
and CloudFormation-style exports (PolicyDocument, AssumeRolePolicyDocument,
PolicyVersion.Document), including URL-encoded document strings.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from iamscan.models import Policy, Statement

WRAPPER_KEYS = ("PolicyDocument", "AssumeRolePolicyDocument", "Document", "PolicyVersion")
_EFFECT_RE = re.compile(r'"Effect"\s*:')


class PolicyParseError(ValueError):
    pass


def _as_list(value: Any, field: str) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    raise PolicyParseError(f"{field} must be a string or list, got {type(value).__name__}")


def _decode(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("%"):
            text = unquote(text)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    return value


def find_document(data: Any) -> dict | None:
    """Return the policy document inside `data`, or None if it isn't a policy."""
    if not isinstance(data, dict):
        return None
    if "Statement" in data:
        return data
    for key in WRAPPER_KEYS:
        if key in data:
            found = find_document(_decode(data[key]))
            if found is not None:
                return found
    return None


def _statement_lines(text: str | None, count: int) -> list[int]:
    """Best-effort line number of each statement, via its "Effect" key."""
    if text is None:
        return [1] * count
    lines = [text.count("\n", 0, m.start()) + 1 for m in _EFFECT_RE.finditer(text)]
    return lines if len(lines) == count else [1] * count


def _parse_statement(raw: Any, index: int, line: int) -> Statement:
    if not isinstance(raw, dict):
        raise PolicyParseError(f"statement {index} must be an object")
    effect = str(raw.get("Effect", "")).lower()
    if effect not in ("allow", "deny"):
        raise PolicyParseError(f"statement {index}: Effect must be Allow or Deny")
    conditions = raw.get("Condition") or {}
    if not isinstance(conditions, dict):
        raise PolicyParseError(f"statement {index}: Condition must be an object")
    return Statement(
        index=index,
        effect=effect,
        sid=raw.get("Sid"),
        actions=_as_list(raw.get("Action"), "Action"),
        not_actions=_as_list(raw.get("NotAction"), "NotAction"),
        resources=_as_list(raw.get("Resource"), "Resource"),
        not_resources=_as_list(raw.get("NotResource"), "NotResource"),
        principal=raw.get("Principal"),
        conditions=conditions,
        line=line,
    )


def parse_policy(data: Any, path: str = "<memory>", text: str | None = None) -> Policy | None:
    document = find_document(data)
    if document is None:
        return None
    raw_statements = document["Statement"]
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    if not isinstance(raw_statements, list):
        raise PolicyParseError("Statement must be an object or list")
    lines = _statement_lines(text, len(raw_statements))
    statements = [_parse_statement(s, i, lines[i]) for i, s in enumerate(raw_statements)]
    return Policy(path=path, statements=statements)


def load_policy(path: str | Path) -> Policy | None:
    """Parse a policy file. Returns None for JSON that isn't an IAM policy."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyParseError(f"invalid JSON: {exc}") from exc
    return parse_policy(data, str(path), text)
