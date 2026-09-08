---
title: "CloudFormation Guard"
toc_hide: true
---
Import AWS CloudFormation Guard reports in JSON format. cfn-guard evaluates a CloudFormation
template, Kubernetes manifest or other structured file against rules written in its own
policy-as-code language.

Generate a report with:

```
cfn-guard validate --data template.yaml --rules rules.guard --output-format json
```

Rules the file failed are reported under `not_compliant` and become Findings. The `compliant` and
`not_applicable` lists are not findings.

Each failing rule holds the clauses that did not hold, and a clause is shaped differently
depending on the comparison cfn-guard made — a `Unary` check for an existence test such as
`BucketEncryption exists`, and a `Binary` check for a comparison such as `CidrIp != '0.0.0.0/0'`.
Both are read, so a report mixing them does not import half its findings.

The resource path that failed (`/Resources/DataBucket/Properties`) is recorded as the component,
and the template line is recovered from the position cfn-guard embeds in its message, so a Finding
points at the line to edit. The value that was actually found is included in the description
alongside the rule's own violation message.

### Severity Mapping
cfn-guard has no severity concept. A rule either holds against the template or it does not, and
the tool has no notion of how exploitable a failure is — that depends entirely on what the rule
was written to check, which is the author's business and not visible in the report.

Every Finding is therefore imported as **Medium**, deliberately and uniformly. A fabricated
gradient would be worse than a constant here: any rule-name heuristic ("does the name mention
encryption?") would be guessing at the author's intent, and would be wrong in exactly the cases
that matter.

To grade cfn-guard findings, key off the rule name in `vuln_id_from_tool` — it is the rule's own
identifier and is stable — using DefectDojo's rule engine, rather than expecting the import to
have made the judgement.

### Sample Scan Data
Sample CloudFormation Guard scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cloudformation_guard).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- component_name
