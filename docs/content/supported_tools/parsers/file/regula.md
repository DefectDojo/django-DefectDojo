---
title: "Regula"
toc_hide: true
---
Import Regula reports in JSON format. Regula evaluates infrastructure as code — Terraform,
CloudFormation, Kubernetes manifests and Azure Resource Manager templates — against Open
Policy Agent rules.

Generate a report with:

```
regula run . --format json > regula.json
```

### Severity Mapping
Regula assigns its own severity per rule, which DefectDojo maps directly:

| Regula severity | DefectDojo severity |
| --- | --- |
| Critical | Critical |
| High | High |
| Medium | Medium |
| Low | Low |
| Informational | Info |

Regula reports every rule it evaluated against every resource, `PASS` results included. Only
`FAIL` results are imported. Each finding records the resource id, the provider and input
type, and links to the rule's remediation documentation.

### Sample Scan Data
Sample Regula scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/regula).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
- file_path
