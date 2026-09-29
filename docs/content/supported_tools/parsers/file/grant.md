---
title: "Grant"
toc_hide: true
---
Import Grant reports in JSON format. Grant checks the licences in an SBOM or container image
against a licence policy.

Generate a report with:

```
grant check sbom.json -o json > grant.json
```

### Severity Mapping
Grant evaluates every package against the policy and records a decision. DefectDojo imports the
denials:

| Grant decision | DefectDojo severity |
| --- | --- |
| deny (forbidden or missing licence) | High |
| allow | not imported |

A denied package is a compliance defect — shipping it may breach the policy — so it imports as
High. A package with no declared licence at all is denied and called out as such. Packages the
policy allows are the compliant remainder and are not imported.

### Sample Scan Data
Sample Grant scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/grant).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- component_name
- component_version
- vuln_id_from_tool
