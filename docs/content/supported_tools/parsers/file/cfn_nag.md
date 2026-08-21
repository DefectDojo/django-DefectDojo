---
title: "cfn-nag"
toc_hide: true
---

[cfn-nag](https://github.com/stelligent/cfn_nag) looks for **security** problems in AWS
CloudFormation templates — security groups open to the world, IAM policies with wildcard actions or
resources, unencrypted queues and buckets, rules without descriptions.

It pairs naturally with cfn-lint, which checks the same templates for correctness rather than
security, and the two rule sets do not overlap: a template can be perfectly valid and still fail
every cfn-nag rule.

### Field mapping

| cfn-nag | DefectDojo |
|---|---|
| `violations[].message` | `title` |
| `violations[].id` (e.g. `F38`, `W48`) | `vuln_id_from_tool` |
| `violations[].type` (`FAIL` / `WARN`) | `severity` (High / Medium) |
| `violations[].logical_resource_ids[i]` | `component_name` |
| `violations[].line_numbers[i]` | `line` |
| `filename` | `file_path` |
| `name`, `element_types`, sibling resources | `description` |

The message is the rule's own wording and is identical for every resource the rule fires on, which
makes it a stable title; the **resource** is what distinguishes one finding from the next.

A `FAIL` is a rule the template breaks. A `WARN` may or may not be a problem depending on intent —
`W2`, "cidr open to world on ingress", is legitimate on a load balancer and not on an instance — so the
two are not flattened to one severity. cfn-nag reports no CWE.

### One finding per resource, not per violation

A single cfn-nag violation can cover **several resources**. The unencrypted-queue rule `W48` fires once
for a template with two unencrypted queues, reporting parallel `logical_resource_ids` and `line_numbers`
lists rather than two violations.

The parser pairs those lists by index and emits one finding per resource, because a violation-level
finding could not be closed by fixing one of the two queues. The `many_vuln` fixture has nine violations
and yields **ten** findings for exactly this reason. Each finding names its siblings in the description
so a reader knows the rule fired elsewhere too.

### Sample Scan Data

Sample cfn-nag files are available at
[unittests/scans/cfn_nag](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cfn_nag).

### Generating an importable file

cfn-nag is a Ruby gem, and `cfn_nag_scan` takes a **directory**, not a file:

```bash
gem install cfn-nag
cfn_nag_scan --input-path ./templates --output-format json > cfn-nag.json
```

`filename` in the report is whatever path cfn-nag was given, so scanning `.` yields `./template.yaml`;
the parser drops that leading `./` and rewrites nothing else. Scan with a relative path if you want
portable paths in DefectDojo.

cfn-nag exits non-zero when it finds anything, so a CI step that fails the build on a non-zero exit will
stop before the report is uploaded.

The fixtures committed with this parser were produced with **cfn-nag 0.8.10** by three separate runs,
each against a directory containing one of the templates committed alongside them in
`unittests/scans/cfn_nag/`:

| Fixture | Findings |
|---|---|
| `cfn_nag_no_vuln.json` | 0 — `clean.yaml`, an encrypted queue |
| `cfn_nag_one_vuln.json` | 1 — `single.yaml`, one unencrypted queue |
| `cfn_nag_many_vuln.json` | 10 from 9 violations — `many.yaml`: an open security group, a wildcard IAM policy, two unencrypted queues |

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. The description carries the
resource name, which is what keeps two findings of one rule distinct.
