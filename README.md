# iamscan

Static analyzer for AWS IAM policies. Finds over-broad permissions, missing conditions, and
privilege-escalation paths, ranks them by severity, and blocks pull requests that introduce
high-risk policies.

```
$ iamscan examples/policies/ci-deployer.json
HIGH     IAM018  examples/policies/ci-deployer.json [policy-wide]
         Privesc: PassRole + Lambda: Can create a Lambda function running as a privileged role
         and invoke it. Granted by: iam:passrole (statement 0 "PassAnyRole");
         lambda:createfunction (statement 1 "DeployLambdas"); lambda:invokefunction (statement 1 "DeployLambdas").
HIGH     IAM007  examples/policies/ci-deployer.json:6 [statement 0 "PassAnyRole"]
         iam:PassRole without iam:PassedToService: Can pass any role to any AWS service.
...
Scanned 1 policy file: 0 critical, 4 high, 1 medium, 0 low
```

## Install and run

```bash
pip install .
iamscan path/to/policies/            # scans *.json recursively; non-policy JSON is skipped
iamscan policy.json --fail-on medium # exit 1 on medium or worse (default: high)
iamscan . --format sarif -o iamscan.sarif
iamscan --list-rules
```

| Option | |
|---|---|
| `--format text\|json\|sarif\|github` | `github` emits inline PR annotations |
| `--fail-on SEVERITY\|none` | exit 1 when a finding is at or above this severity |
| `--min-severity SEVERITY` | hide lower-severity findings |
| `--ignore IAM004,IAM006` | skip rules |

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` a file could not be parsed.

Accepts raw policy documents and common wrappers: `PolicyDocument`, `AssumeRolePolicyDocument`,
and AWS CLI `get-policy-version` output (including URL-encoded documents).

## GitHub Action

```yaml
on:
  pull_request:
    paths: ["policies/**.json"]
permissions:
  contents: read
  security-events: write   # only needed for upload-sarif
jobs:
  iamscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: <owner>/iam-policy-scanner@v1
        with:
          paths: policies
          fail-on: high
          upload-sarif: "true"
```

On pull requests the action scans only the JSON files the PR adds or modifies (`changed-only`,
default `true`), annotates offending lines, writes a job summary, and fails the check at the
`fail-on` threshold. With `upload-sarif`, findings also appear in the repository's Security tab.

## Rules

| ID | Severity | Detects |
|---|---|---|
| IAM001 | Critical | `Action: "*"` on `Resource: "*"` (full admin) |
| IAM002 | High | `Action: "*"` on specific resources |
| IAM003 | High / Medium | Service-wide wildcards (`iam:*`); High for security-sensitive services |
| IAM004 | Medium | `Resource: "*"` on actions that support resource-level permissions |
| IAM005 | High | `Allow` + `NotAction` |
| IAM006 | Medium | `Allow` + `NotResource` |
| IAM007 | High / Medium | `iam:PassRole` without an `iam:PassedToService` condition |
| IAM008 | Critical | Role trust policy assumable by `Principal: "*"` with no condition |
| IAM009 | High | Resource policy with `Principal: "*"` and no caller-scoping condition |
| IAM010 | Critical | `iam:CreatePolicyVersion` |
| IAM011 | High | `iam:SetDefaultPolicyVersion` |
| IAM012 | Critical | `iam:Attach{User,Group,Role}Policy` |
| IAM013 | Critical | `iam:Put{User,Group,Role}Policy` |
| IAM014 | High | `iam:CreateAccessKey` on other users |
| IAM015 | High | `iam:{Create,Update}LoginProfile` on other users |
| IAM016 | High | `iam:AddUserToGroup` |
| IAM017 | Critical | `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` |
| IAM018 | High | `iam:PassRole` + `lambda:CreateFunction` + invoke or event source mapping |
| IAM019 | High | `iam:PassRole` + `ec2:RunInstances` |
| IAM020 | High | `iam:PassRole` + `cloudformation:CreateStack` |
| IAM021 | High | `iam:PassRole` + `glue:CreateDevEndpoint`, or `glue:UpdateDevEndpoint` |
| IAM022 | High | `lambda:UpdateFunctionCode` |

IAM010-IAM022 follow Rhino Security Labs' research on AWS IAM privilege escalation.

## How it evaluates policies

- **Wildcards are expanded.** `iam:Put*` matches `iam:PutUserPolicy`; `NotAction` is treated
  as "everything except".
- **Escalation is policy-wide.** `iam:PassRole` in one statement and `ec2:RunInstances` in
  another is still reported, with both statements cited.
- **Explicit Deny cancels Allow** when the Deny is unconditional and applies to `Resource: "*"`.
  Conditional or resource-scoped Denies are ignored, so those findings are kept (fail closed).
- **Known-safe patterns are excluded** to reduce false positives:
  - self-service statements scoped to `${aws:username}`
  - `iam:PassRole` restricted by `iam:PassedToService` to a different service than the escalation path needs
  - List/Describe actions and actions that only accept `Resource: "*"`
  - escalation findings on a full-admin statement (IAM001 already reports it)

## Limitations

- Evaluates one policy at a time. It does not combine identity policies, permission boundaries,
  SCPs, or session policies the way AWS does at request time.
- Reads JSON policy documents only, not Terraform or CloudFormation templates.
- Doesn't check resource ARNs against real accounts (for example, whether a trusted account is external).

## Related tools

[Parliament](https://github.com/duo-labs/parliament) lints policy grammar and
[Cloudsplaining](https://github.com/salesforce/cloudsplaining) reports on a whole account's
authorization details. iamscan targets the pull request: it reports escalation combinations that span
statements and fails the check before the policy merges.

## Development

```bash
pip install -e '.[dev]'
pytest --cov=iamscan
```

Every rule has a test that must trigger it and one that must not. `test_every_rule_has_a_case`
fails if a new rule is added without tests.
