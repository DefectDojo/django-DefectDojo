---
title: "Grype"
toc_hide: true
---
Import Grype reports in JSON format. Grype scans an SBOM, container image or directory for
known vulnerabilities in its packages.

Generate a report with:

```
grype <image-or-dir-or-sbom> -o json > grype.json
```

### Severity Mapping
Grype assigns its own severity per match, which DefectDojo maps directly:

| Grype severity | DefectDojo severity |
| --- | --- |
| Critical | Critical |
| High | High |
| Medium | Medium |
| Low | Low |
| Negligible / Unknown | Info |

Each match carries the affected package and version, and where Grype provides them the CVE,
CWE, CVSS base score (the highest, when several sources report one) and the fixed version are
carried across. When the match's primary identifier is a GHSA advisory, any CVE it is aliased
to is recorded as the vulnerability id.

### Sample Scan Data
Sample Grype scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/grype).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
- component_version
