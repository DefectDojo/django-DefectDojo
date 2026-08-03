---
title: "Regula"
toc_hide: true
---

Import a [Regula](https://regula.dev/) infrastructure-as-code policy report.

Regula evaluates Terraform, CloudFormation and Kubernetes manifests against compliance rules — CIS
benchmarks among them — and reports a result per rule per resource.

### File Types

JSON:

```
regula run path/to/terraform --format json > regula.json
```

### Only failed rules are imported

Regula reports **every rule it evaluated**, passes included. A real run over a five-resource
Terraform file produces 62 rule results, of which 40 are `PASS`.

A `PASS` is Regula confirming there is nothing wrong, so it is not a finding; importing them would
fill DefectDojo with items nobody can action. `WAIVED` results are excluded too — that state means an
operator has already decided the rule does not apply. Only `FAIL` becomes a finding.

### Severity

Regula grades its own rules, so severities here are the tool's:

| Regula `rule_severity` | Severity |
| --- | --- |
| `Critical` | Critical |
| `High` | High |
| `Medium` | Medium |
| `Low` | Low |
| `Informational` | Info |
| `Unknown` or unset | Medium |

Regula reports `Unknown` for a rule with no severity set, which includes custom rules. Those are real
policy failures, so they become Medium rather than Info.

### Identity

The same rule commonly fails against several resources in one template, and each is a separate
problem to fix. The identity of a finding is therefore the **rule id and resource id together**
(`FG_R00277:aws_s3_bucket.artifacts`), imported as `unique_id_from_tool`. Where several compliance
families map to a single rule, the pair still counts once.

### Sample Scan Data

Sample Regula scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/regula).

The samples are real Regula output over a deliberately misconfigured Terraform file — a
publicly-readable S3 bucket, SSH open to `0.0.0.0/0`, an unencrypted volume, a publicly-accessible
database and a CloudTrail without log-file validation. `regula_many_vuln.json` is the unfiltered run
and exists to prove the PASS filter: 62 results in, 22 findings out. The no-vuln sample is the same
run reduced to its passing results.

### Default Deduplication Hashcode Fields

The rule/resource pair is the primary deduplication identity. By default, DefectDojo falls back to
these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- file_path
- component_name
