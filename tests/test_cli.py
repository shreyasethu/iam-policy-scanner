import json

import pytest

from iamscan.cli import main

ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
SAFE = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}]}
MEDIUM_ONLY = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}]}


@pytest.fixture
def write(tmp_path):
    def _write(name, content):
        path = tmp_path / name
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return str(path)
    return _write


def test_clean_policy_exits_zero(write, capsys):
    assert main([write("safe.json", SAFE)]) == 0
    assert "0 critical" in capsys.readouterr().out


def test_high_risk_policy_fails(write, capsys):
    assert main([write("admin.json", ADMIN)]) == 1
    out = capsys.readouterr().out
    assert "CRITICAL" in out and "IAM001" in out


def test_findings_are_severity_ranked(write, capsys):
    main([write("admin.json", ADMIN), write("medium.json", MEDIUM_ONLY), "--format", "json"])
    severities = [f["severity"] for f in json.loads(capsys.readouterr().out)["findings"]]
    order = ["critical", "high", "medium", "low"]
    assert severities == sorted(severities, key=order.index)


def test_fail_on_threshold(write):
    path = write("medium.json", MEDIUM_ONLY)
    assert main([path]) == 0
    assert main([path, "--fail-on", "medium"]) == 1
    assert main([write("admin.json", ADMIN), "--fail-on", "none"]) == 0


def test_ignore_rules(write, capsys):
    path = write("medium.json", MEDIUM_ONLY)
    assert main([path, "--fail-on", "medium", "--ignore", "IAM004"]) == 0


def test_unknown_ignore_rule_is_rejected(write):
    with pytest.raises(SystemExit):
        main([write("safe.json", SAFE), "--ignore", "IAM999"])


def test_min_severity_hides_findings(write, capsys):
    main([write("medium.json", MEDIUM_ONLY), "--min-severity", "high", "--format", "json"])
    assert json.loads(capsys.readouterr().out)["findings"] == []


def test_directory_scan_skips_non_policy_json(tmp_path, capsys):
    (tmp_path / "package.json").write_text('{"name": "x"}')
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "admin.json").write_text(json.dumps(ADMIN))
    assert main([str(tmp_path), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["files_scanned"] == 1


def test_parse_errors_exit_two(write, capsys):
    assert main([write("broken.json", "{nope")]) == 2
    assert "ERROR" in capsys.readouterr().out


def test_sarif_output(write, tmp_path):
    out = tmp_path / "out.sarif"
    main([write("admin.json", ADMIN), "--format", "sarif", "--output", str(out)])
    sarif = json.loads(out.read_text())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert len(run["tool"]["driver"]["rules"]) == 22
    result = next(r for r in run["results"] if r["ruleId"] == "IAM001")
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_github_annotations(write, capsys):
    main([write("admin.json", ADMIN), "--format", "github"])
    out = capsys.readouterr().out
    assert "::error file=" in out and "title=IAM001" in out


def test_list_rules(capsys):
    assert main(["--list-rules"]) == 0
    assert capsys.readouterr().out.count("IAM0") == 22
