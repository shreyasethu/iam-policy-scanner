"""iamscan: static analysis for AWS IAM policies."""

from iamscan.engine import scan_paths, scan_policy
from iamscan.models import Finding, Policy, Severity, Statement
from iamscan.parser import load_policy, parse_policy

__all__ = [
    "Finding",
    "Policy",
    "Severity",
    "Statement",
    "load_policy",
    "parse_policy",
    "scan_paths",
    "scan_policy",
]
__version__ = "0.1.0"
