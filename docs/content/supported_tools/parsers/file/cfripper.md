---
title: "CFRipper"
toc_hide: true
---
Import CFRipper reports in JSON format. CFRipper audits CloudFormation templates for security
misconfiguration — wildcard IAM policies, privilege escalation, publicly exposed resources.

Generate a report with:

```
cfripper template.json --format json > cfripper.json
```

CFRipper checks security posture, which is distinct from the syntax and best-practice linting
that the existing cfn-lint and cfn-nag parsers cover.

### Severity Mapping
CFRipper assigns a risk value per rule, which DefectDojo maps directly:

| CFRipper risk_value | DefectDojo severity |
| --- | --- |
| HIGH | High |
| MEDIUM | Medium |
| LOW | Low |

Each finding names the resource that tripped the rule and CFRipper's rule mode (BLOCKING or
MONITOR).

### Sample Scan Data
Sample CFRipper scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cfripper).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
