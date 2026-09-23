"""Policy-wide evaluation: wildcards, cross-statement combos, Deny, NotAction."""

from conftest import allow, rule_ids, scan


def test_action_wildcard_expands_to_escalation_action():
    assert "IAM013" in rule_ids(allow("iam:Put*"))
    assert "IAM010" in rule_ids(allow("iam:Create*"))


def test_combination_split_across_statements_is_detected():
    findings = scan(
        {"Sid": "Pass", **allow("iam:PassRole")},
        {"Sid": "Launch", **allow("ec2:RunInstances")},
    )
    finding = next(f for f in findings if f.rule_id == "IAM019")
    assert finding.statement is None  # spans statements
    assert '"Pass"' in finding.message and '"Launch"' in finding.message


def test_combination_in_one_statement_points_at_it():
    finding = next(f for f in scan(allow(["iam:PassRole", "ec2:RunInstances"]))
                   if f.rule_id == "IAM019")
    assert finding.statement == 0


def test_unconditional_deny_cancels_allow():
    ids = rule_ids(allow("iam:*"),
                   {"Effect": "Deny", "Action": "iam:CreatePolicyVersion", "Resource": "*"})
    assert "IAM010" not in ids
    assert "IAM012" in ids


def test_conditional_deny_does_not_cancel_allow():
    deny = {"Effect": "Deny", "Action": "iam:CreatePolicyVersion", "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}}
    assert "IAM010" in rule_ids(allow("iam:CreatePolicyVersion"), deny)


def test_resource_scoped_deny_does_not_cancel_allow():
    deny = {"Effect": "Deny", "Action": "iam:CreatePolicyVersion",
            "Resource": "arn:aws:iam::111122223333:policy/protected"}
    assert "IAM010" in rule_ids(allow("iam:CreatePolicyVersion"), deny)


def test_not_action_allow_grants_escalation():
    stmt = {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}
    assert {"IAM005", "IAM010", "IAM012"} <= rule_ids(stmt)


def test_not_action_excluding_iam_blocks_iam_paths():
    stmt = {"Effect": "Allow", "NotAction": ["iam:*", "sts:*"], "Resource": "*"}
    ids = rule_ids(stmt)
    assert "IAM010" not in ids and "IAM017" not in ids
    assert "IAM022" in ids  # lambda:UpdateFunctionCode is still allowed


def test_passrole_restricted_to_matching_service_still_escalates():
    to_lambda = {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}
    ids = rule_ids(allow("iam:PassRole", Condition=to_lambda),
                   allow(["lambda:CreateFunction", "lambda:InvokeFunction", "ec2:RunInstances"]))
    assert "IAM018" in ids
    assert "IAM019" not in ids


def test_lambda_path_needs_a_way_to_run_the_function():
    assert "IAM018" not in rule_ids(allow(["iam:PassRole", "lambda:CreateFunction"]))
    assert "IAM018" in rule_ids(
        allow(["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"]))


def test_glue_create_path_needs_passrole():
    assert "IAM021" not in rule_ids(allow("glue:CreateDevEndpoint"))
    assert "IAM021" in rule_ids(allow(["glue:CreateDevEndpoint", "iam:PassRole"]))


def test_self_service_policy_is_not_escalation():
    self_service = allow(["iam:CreateAccessKey", "iam:UpdateLoginProfile"],
                         "arn:aws:iam::*:user/${aws:username}")
    assert not {"IAM014", "IAM015"} & rule_ids(self_service)
