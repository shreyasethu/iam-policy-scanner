import json
from urllib.parse import quote

import pytest

from iamscan.parser import PolicyParseError, load_policy, parse_policy


def test_single_statement_object_and_string_action():
    policy = parse_policy({"Statement": {"Effect": "Allow", "Action": "S3:GetObject",
                                         "Resource": "arn:aws:s3:::b/*"}})
    [stmt] = policy.statements
    assert stmt.actions == ["S3:GetObject"]  # kept as written for messages
    assert stmt.grants("s3:getobject")
    assert stmt.resources == ["arn:aws:s3:::b/*"]


def test_url_encoded_document_inside_cli_wrapper():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    policy = parse_policy({"PolicyVersion": {"Document": quote(doc)}})
    assert policy.statements[0].actions == ["*"]


def test_cloudformation_style_wrappers():
    trust = {"AssumeRolePolicyDocument": {"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}}
    assert parse_policy(trust).statements[0].has_wildcard_principal


def test_non_policy_json_is_ignored():
    assert parse_policy({"name": "package.json"}) is None
    assert parse_policy([1, 2, 3]) is None


def test_invalid_effect_is_an_error():
    with pytest.raises(PolicyParseError):
        parse_policy({"Statement": [{"Effect": "Maybe", "Action": "*"}]})


def test_bad_action_type_is_an_error():
    with pytest.raises(PolicyParseError):
        parse_policy({"Statement": [{"Effect": "Allow", "Action": 5}]})


def test_statement_line_numbers(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(
        '{\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "*"\n    },\n'
        '    {\n      "Effect": "Deny",\n      "Action": "iam:*"\n    }\n  ]\n}\n')
    policy = load_policy(path)
    assert [s.line for s in policy.statements] == [4, 8]


def test_invalid_json_file(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json")
    with pytest.raises(PolicyParseError):
        load_policy(path)
