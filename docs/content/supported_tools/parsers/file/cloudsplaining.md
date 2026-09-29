---
title: "Cloudsplaining"
toc_hide: true
---
Import Cloudsplaining results in JSON format. Cloudsplaining assesses AWS IAM policies for
overly permissive access, reading an account authorization details file.

Generate a report with:

```
aws iam get-account-authorization-details > account.json
cloudsplaining scan --input-file account.json
```

### Granularity
A single permissive policy can flag thousands of actions -- `PowerUserAccess` in
Cloudsplaining's own example results yields over three thousand under infrastructure
modification alone. Importing one Finding per action would bury the report, so DefectDojo
raises **one Finding per policy and risk category**, listing the flagged actions in the
description.

Policies that Cloudsplaining marks as excluded are kept in the results rather than removed, so
that the exclusion stays auditable. They are not imported.

### Severity Mapping
Cloudsplaining assigns no severity. It sorts risky actions into its own risk categories, and
its CLI treats resource exposure, privilege escalation and data exfiltration as the high
priority ones. DefectDojo maps the categories as follows:

| Cloudsplaining risk | DefectDojo severity |
| --- | --- |
| PrivilegeEscalation | Critical |
| DataExfiltration | High |
| ResourceExposure | High |
| CredentialsExposure | High |
| ServiceWildcard | Medium |
| InfrastructureModification | Low |

### Sample Scan Data
Sample Cloudsplaining scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cloudsplaining).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
