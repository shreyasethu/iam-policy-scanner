"""Detection rules.

IAM001-IAM009 inspect individual statements for over-broad grants and missing
conditions. IAM010-IAM022 evaluate the policy as a whole for privilege-escalation
paths (after Rhino Security Labs' AWS IAM escalation research), so a combination
split across several statements is still caught.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Iterator

from iamscan.models import Finding, Policy, Severity, Statement, action_matches

Check = Callable[["Rule", Policy], Iterable[Finding]]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    description: str
    check: Check

    def run(self, policy: Policy) -> list[Finding]:
        return list(self.check(self, policy))

    def finding(
        self,
        policy: Policy,
        message: str,
        statement: Statement | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            severity=severity or self.severity,
            title=self.title,
            message=message,
            path=policy.path,
            statement=statement.index if statement else None,
            sid=statement.sid if statement else None,
            line=statement.line if statement else 1,
        )


RULES: dict[str, Rule] = {}


def rule(id: str, severity: Severity, title: str, description: str) -> Callable[[Check], Check]:
    def register(check: Check) -> Check:
        RULES[id] = Rule(id, severity, title, description, check)
        return check

    return register


def _allows(policy: Policy) -> Iterator[Statement]:
    return (s for s in policy.statements if s.is_allow)


def _is_full_wildcard(pattern: str) -> bool:
    return pattern in ("*", "*:*")


def _is_full_admin(s: Statement) -> bool:
    """Already reported by IAM001; escalation findings on it would be noise."""
    return s.has_wildcard_resource and any(_is_full_wildcard(a) for a in s.actions)


# --- Over-broad permissions -------------------------------------------------

SENSITIVE_SERVICES = {
    "iam", "sts", "kms", "organizations", "secretsmanager",
    "ssm", "s3", "lambda", "ec2", "cloudtrail",
}

# Actions that only work with Resource "*", so "*" there is not over-broad.
RESOURCE_STAR_REQUIRED = {
    "sts:getcalleridentity", "cloudwatch:putmetricdata", "ecr:getauthorizationtoken",
    "xray:puttracesegments", "xray:puttelemetryrecords", "iam:getaccountsummary",
    "iam:getaccountpasswordpolicy", "iam:generatecredentialreport", "iam:getcredentialreport",
}
READ_ONLY_VERBS = ("list", "describe")

# Condition keys that restrict *who* can use a resource policy with Principal "*".
PRINCIPAL_SCOPING_KEYS = {
    "aws:sourcearn", "aws:sourceaccount", "aws:sourceowner", "aws:principalorgid",
    "aws:principalorgpaths", "aws:principalaccount", "aws:principalarn",
    "aws:sourcevpc", "aws:sourcevpce", "aws:sourceorgid", "aws:sourceorgpaths",
}

ASSUME_ROLE_ACTIONS = (
    "sts:assumerole", "sts:assumerolewithwebidentity", "sts:assumerolewithsaml",
)


@rule("IAM001", Severity.CRITICAL, "Full administrator access",
      'Allow with Action "*" on Resource "*" grants every permission in the account.')
def full_admin(r: Rule, policy: Policy) -> Iterator[Finding]:
    for s in _allows(policy):
        if any(_is_full_wildcard(a) for a in s.actions) and s.has_wildcard_resource:
            yield r.finding(policy, "Allows every action on every resource.", s)


@rule("IAM002", Severity.HIGH, "Wildcard action on specific resources",
      'Action "*" grants every current and future action on the listed resources.')
def wildcard_action(r: Rule, policy: Policy) -> Iterator[Finding]:
    for s in _allows(policy):
        if any(_is_full_wildcard(a) for a in s.actions) and not s.has_wildcard_resource:
            targets = ", ".join(s.resources or s.not_resources) or "(no resource)"
            yield r.finding(policy, f"Allows every action on {targets}.", s)


@rule("IAM003", Severity.HIGH, "Service-wide wildcard action",
      'Actions like "iam:*" grant every action in a service, including future ones. '
      "HIGH for security-sensitive services, MEDIUM otherwise.")
def service_wildcard(r: Rule, policy: Policy) -> Iterator[Finding]:
    for s in _allows(policy):
        services = sorted({a.split(":")[0].lower() for a in s.actions
                           if a.endswith(":*") and not _is_full_wildcard(a)})
        if not services:
            continue
        sensitive = [svc for svc in services if svc in SENSITIVE_SERVICES]
        severity = Severity.HIGH if sensitive else Severity.MEDIUM
        grants = ", ".join(f"{svc}:*" for svc in services)
        yield r.finding(policy, f"Grants every action in: {grants}.", s, severity)


def _needs_resource_scoping(pattern: str) -> bool:
    pattern = pattern.lower()
    service, _, name = pattern.partition(":")
    if not name or name == "*" or service == "*":
        return False  # covered by IAM001-IAM003
    if pattern in RESOURCE_STAR_REQUIRED or action_matches(pattern, "iam:passrole"):
        return False  # PassRole is covered by IAM007
    return not name.startswith(READ_ONLY_VERBS)


@rule("IAM004", Severity.MEDIUM, "Unscoped resource on mutating or data actions",
      'Resource "*" on actions that support resource-level permissions. List/Describe '
      'actions and actions that only accept "*" are exempt.')
def wildcard_resource(r: Rule, policy: Policy) -> Iterator[Finding]:
    for s in _allows(policy):
        if not s.has_wildcard_resource or s.conditions:
            continue
        actions = [a for a in s.actions if _needs_resource_scoping(a)]
        if actions:
            yield r.finding(policy, f'{", ".join(actions)} allowed on Resource "*" '
                                    "with no condition.", s)


@rule("IAM005", Severity.HIGH, "Allow with NotAction",
      "Allow + NotAction grants every action except those listed, including future actions.")
def allow_not_action(r: Rule, policy: Policy) -> Iterator[Finding]:
    for s in _allows(policy):
        if s.not_actions:
            yield r.finding(policy, "Allows every action except: "
                                    f"{', '.join(s.not_actions)}.", s)


@rule("IAM006", Severity.MEDIUM, "Allow with NotResource",
      "Allow + NotResource applies to every resource except those listed, including new ones.")
def allow_not_resource(r: Rule, policy: Policy) -> Iterator[Finding]:
    for s in _allows(policy):
        if s.not_resources:
            yield r.finding(policy, "Applies to every resource except: "
                                    f"{', '.join(s.not_resources)}.", s)


# --- Missing conditions ------------------------------------------------------

@rule("IAM007", Severity.HIGH, "iam:PassRole without iam:PassedToService",
      "PassRole without an iam:PassedToService condition lets the role be handed to any "
      "service. HIGH on Resource \"*\", MEDIUM when scoped to specific roles.")
def passrole_unconditioned(r: Rule, policy: Policy) -> Iterator[Finding]:
    for s in _allows(policy):
        explicit = [a for a in s.actions if not _is_full_wildcard(a)
                    and action_matches(a, "iam:passrole")]
        if explicit and "iam:passedtoservice" not in s.condition_keys:
            severity = Severity.HIGH if s.has_wildcard_resource else Severity.MEDIUM
            scope = "any role" if s.has_wildcard_resource else ", ".join(s.resources)
            yield r.finding(policy, f"Can pass {scope} to any AWS service.", s, severity)


@rule("IAM008", Severity.CRITICAL, "Role trust policy open to any principal",
      "A trust policy that lets Principal \"*\" assume the role with no condition lets "
      "anyone with an AWS account assume it.")
def open_trust(r: Rule, policy: Policy) -> Iterator[Finding]:
    for s in _allows(policy):
        if (s.has_wildcard_principal and not s.conditions
                and any(s.grants(a) for a in ASSUME_ROLE_ACTIONS)):
            yield r.finding(policy, "Any AWS principal can assume this role.", s)


@rule("IAM009", Severity.HIGH, "Public resource policy",
      'Resource policy with Principal "*" and no condition restricting the caller '
      "(aws:PrincipalOrgID, aws:SourceArn, aws:SourceAccount, VPC endpoint, ...).")
def public_resource_policy(r: Rule, policy: Policy) -> Iterator[Finding]:
    for s in _allows(policy):
        if not s.has_wildcard_principal:
            continue
        if s.actions and all(a.lower() in ASSUME_ROLE_ACTIONS for a in s.actions):
            continue  # trust policies are IAM008's job
        if not s.condition_keys & PRINCIPAL_SCOPING_KEYS:
            actions = ", ".join(s.actions or [f"NOT {a}" for a in s.not_actions])
            yield r.finding(policy, f"Anyone can call {actions}.", s)


# --- Privilege escalation ----------------------------------------------------

@dataclass(frozen=True)
class EscalationPath:
    """All of `requires` must be allowed; each entry is a tuple of alternatives."""
    requires: tuple[tuple[str, ...], ...]
    passed_to: str | None = None  # service principal PassRole must reach


def _self_scoped(s: Statement) -> bool:
    """User-self-service statements (Resource .../${aws:username}) can't touch others."""
    return bool(s.resources) and all("${aws:username}" in res for res in s.resources)


def _passrole_reaches(s: Statement, service: str) -> bool:
    allowed = s.condition_values("iam:PassedToService")
    return not allowed or any(action_matches(v, service) for v in allowed)


def _escalation_grants(policy: Policy, action: str, passed_to: str | None) -> list[Statement]:
    statements = [s for s in policy.allowing_statements(action) if not _self_scoped(s)]
    if action.lower() == "iam:passrole" and passed_to:
        statements = [s for s in statements if _passrole_reaches(s, passed_to)]
    return statements


def _match_path(policy: Policy, path: EscalationPath) -> list[tuple[str, Statement]] | None:
    matched = []
    for alternatives in path.requires:
        for action in alternatives:
            grants = _escalation_grants(policy, action, path.passed_to)
            if grants:
                matched.append((action, grants[0]))
                break
        else:
            return None
    return matched


def _escalation(id: str, severity: Severity, title: str, description: str,
                *paths: EscalationPath) -> None:
    def check(r: Rule, policy: Policy) -> Iterator[Finding]:
        for path in paths:
            matched = _match_path(policy, path)
            if matched and not all(_is_full_admin(s) for _, s in matched):
                via = "; ".join(f"{action} ({s.label})" for action, s in matched)
                first = matched[0][1] if len({s.index for _, s in matched}) == 1 else None
                yield r.finding(policy, f"{description} Granted by: {via}.", first)
                return

    rule(id, severity, title, description)(check)


def _p(*groups: str | tuple[str, ...], passed_to: str | None = None) -> EscalationPath:
    return EscalationPath(
        tuple(g if isinstance(g, tuple) else (g,) for g in groups), passed_to)


_escalation("IAM010", Severity.CRITICAL, "Privesc: iam:CreatePolicyVersion",
            "Can publish a new default version of a managed policy with arbitrary permissions.",
            _p("iam:CreatePolicyVersion"))
_escalation("IAM011", Severity.HIGH, "Privesc: iam:SetDefaultPolicyVersion",
            "Can roll a managed policy back to an older, more permissive version.",
            _p("iam:SetDefaultPolicyVersion"))
_escalation("IAM012", Severity.CRITICAL, "Privesc: attach managed policy",
            "Can attach any managed policy (e.g. AdministratorAccess) to a user, group, or role.",
            _p(("iam:AttachUserPolicy", "iam:AttachGroupPolicy", "iam:AttachRolePolicy")))
_escalation("IAM013", Severity.CRITICAL, "Privesc: put inline policy",
            "Can write an arbitrary inline policy onto a user, group, or role.",
            _p(("iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy")))
_escalation("IAM014", Severity.HIGH, "Privesc: iam:CreateAccessKey",
            "Can mint access keys for other IAM users and act as them.",
            _p("iam:CreateAccessKey"))
_escalation("IAM015", Severity.HIGH, "Privesc: console login profile",
            "Can set a console password for other IAM users and sign in as them.",
            _p(("iam:CreateLoginProfile", "iam:UpdateLoginProfile")))
_escalation("IAM016", Severity.HIGH, "Privesc: iam:AddUserToGroup",
            "Can add a user to any group, inheriting that group's permissions.",
            _p("iam:AddUserToGroup"))
_escalation("IAM017", Severity.CRITICAL, "Privesc: rewrite role trust policy",
            "Can rewrite a role's trust policy to trust itself, then assume the role.",
            _p("iam:UpdateAssumeRolePolicy", "sts:AssumeRole"))
_escalation("IAM018", Severity.HIGH, "Privesc: PassRole + Lambda",
            "Can create a Lambda function running as a privileged role and invoke it.",
            _p("iam:PassRole", "lambda:CreateFunction",
               ("lambda:InvokeFunction", "lambda:CreateEventSourceMapping"),
               passed_to="lambda.amazonaws.com"))
_escalation("IAM019", Severity.HIGH, "Privesc: PassRole + EC2",
            "Can launch an EC2 instance with a privileged instance profile and use its credentials.",
            _p("iam:PassRole", "ec2:RunInstances", passed_to="ec2.amazonaws.com"))
_escalation("IAM020", Severity.HIGH, "Privesc: PassRole + CloudFormation",
            "Can deploy a CloudFormation stack that runs as a privileged role.",
            _p("iam:PassRole", "cloudformation:CreateStack",
               passed_to="cloudformation.amazonaws.com"))
_escalation("IAM021", Severity.HIGH, "Privesc: Glue dev endpoint",
            "Can create or take over a Glue dev endpoint running as a privileged role.",
            _p("iam:PassRole", "glue:CreateDevEndpoint", passed_to="glue.amazonaws.com"),
            _p("glue:UpdateDevEndpoint"))
_escalation("IAM022", Severity.HIGH, "Privesc: lambda:UpdateFunctionCode",
            "Can replace the code of an existing Lambda function and run as its role.",
            _p("lambda:UpdateFunctionCode"))
