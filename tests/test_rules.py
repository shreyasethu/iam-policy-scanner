"""One positive and one negative case for every detection rule."""

import pytest
from conftest import allow, rule_ids, scan

from iamscan.models import Severity
from iamscan.rules import RULES

SELF = "arn:aws:iam::*:user/${aws:username}"
PASS_TO_EC2 = {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}

# rule_id -> (statements that must trigger it, statements that must not)
CASES = {
    "IAM001": ([allow("*")], [allow("*", "arn:aws:s3:::bucket/*")]),
    "IAM002": ([allow("*", "arn:aws:s3:::bucket")], [allow("s3:GetObject", "arn:aws:s3:::bucket/*")]),
    "IAM003": ([allow("iam:*")], [allow("iam:GetRole")]),
    "IAM004": ([allow("s3:PutObject")], [allow(["ec2:DescribeInstances", "sts:GetCallerIdentity"])]),
    "IAM005": ([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}],
               [{"Effect": "Deny", "NotAction": "iam:*", "Resource": "*"}]),
    "IAM006": ([{"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::secret/*"}],
               [{"Effect": "Deny", "Action": "s3:*", "NotResource": "arn:aws:s3:::public/*"}]),
    "IAM007": ([allow("iam:PassRole")],
               [allow("iam:PassRole", Condition={"StringEquals": {
                   "iam:PassedToService": "lambda.amazonaws.com"}})]),
    "IAM008": ([{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
               [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                 "Action": "sts:AssumeRole"}]),
    "IAM009": ([{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                 "Resource": "arn:aws:s3:::bucket/*"}],
               [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                 "Resource": "arn:aws:s3:::bucket/*",
                 "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}}]),
    "IAM010": ([allow("iam:CreatePolicyVersion")], [allow("iam:GetPolicyVersion")]),
    "IAM011": ([allow("iam:SetDefaultPolicyVersion")], [allow("iam:ListPolicyVersions")]),
    "IAM012": ([allow("iam:AttachRolePolicy")], [allow("iam:ListAttachedRolePolicies")]),
    "IAM013": ([allow("iam:PutUserPolicy")], [allow("iam:GetUserPolicy")]),
    "IAM014": ([allow("iam:CreateAccessKey")], [allow("iam:CreateAccessKey", SELF)]),
    "IAM015": ([allow("iam:UpdateLoginProfile")], [allow("iam:UpdateLoginProfile", SELF)]),
    "IAM016": ([allow("iam:AddUserToGroup")], [allow("iam:RemoveUserFromGroup")]),
    "IAM017": ([allow(["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"])],
               [allow("iam:UpdateAssumeRolePolicy")]),
    "IAM018": ([allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"])],
               [allow("iam:PassRole", Condition=PASS_TO_EC2),
                allow(["lambda:CreateFunction", "lambda:InvokeFunction"])]),
    "IAM019": ([allow(["iam:PassRole", "ec2:RunInstances"])], [allow("ec2:RunInstances")]),
    "IAM020": ([allow(["iam:PassRole", "cloudformation:CreateStack"])],
               [allow("cloudformation:CreateStack")]),
    "IAM021": ([allow("glue:UpdateDevEndpoint")], [allow("glue:GetDevEndpoint")]),
    "IAM022": ([allow("lambda:UpdateFunctionCode")], [allow("lambda:GetFunction")]),
}


def test_every_rule_has_a_case():
    assert set(CASES) == set(RULES)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires(rule_id):
    positive, _ = CASES[rule_id]
    assert rule_id in rule_ids(*positive)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_stays_quiet(rule_id):
    _, negative = CASES[rule_id]
    assert rule_id not in rule_ids(*negative)


# --- Severity tuning ---------------------------------------------------------

def _severity(rule_id, *statements):
    return next(f.severity for f in scan(*statements) if f.rule_id == rule_id)


def test_service_wildcard_severity_depends_on_service():
    assert _severity("IAM003", allow("iam:*")) == Severity.HIGH
    assert _severity("IAM003", allow("sqs:*")) == Severity.MEDIUM


def test_passrole_scoped_to_role_is_medium():
    assert _severity("IAM007", allow("iam:PassRole")) == Severity.HIGH
    scoped = allow("iam:PassRole", "arn:aws:iam::111122223333:role/app")
    assert _severity("IAM007", scoped) == Severity.MEDIUM


# --- Rule precision ----------------------------------------------------------

def test_full_admin_is_one_finding_not_fourteen():
    assert rule_ids(allow("*")) == {"IAM001"}


def test_full_admin_plus_second_statement_still_reports_combo():
    # iam:PassRole from a scoped statement + "*" elsewhere is still a real path
    ids = rule_ids(allow("iam:PassRole", "arn:aws:iam::111122223333:role/x"),
                   allow("*"))
    assert "IAM019" in ids


def test_conditioned_wildcard_resource_is_not_flagged():
    stmt = allow("s3:PutObject", Condition={"Bool": {"aws:SecureTransport": "true"}})
    assert "IAM004" not in rule_ids(stmt)


def test_unrelated_condition_does_not_make_public_policy_private():
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::b/*", "Condition": {"Bool": {"aws:SecureTransport": "true"}}}
    assert "IAM009" in rule_ids(stmt)


def test_trust_policy_is_not_double_reported_as_public_resource():
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}
    ids = rule_ids(stmt)
    assert "IAM008" in ids and "IAM009" not in ids


def test_conditioned_open_trust_is_left_to_review():
    stmt = {"Effect": "Allow", "Principal": {"Federated": "*"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:o/r:ref:refs/heads/main"}}}
    assert "IAM008" not in rule_ids(stmt)
