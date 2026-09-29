---
title: "2ms (too many secrets)"
toc_hide: true
---
Import 2ms reports in JSON format. 2ms scans repositories, filesystems and collaboration
platforms such as Confluence, Discord, Slack and Paligo for exposed secrets.

Generate a report with:

```
2ms filesystem --path . --report-path . --report-format json
```

### Severity Mapping
2ms assigns a severity and a CVSS score to each rule, and DefectDojo maps that scale
directly:

| 2ms severity | DefectDojo severity |
| --- | --- |
| Critical | Critical |
| High | High |
| Medium | Medium |
| Low | Low |
| Info | Info |

The `cvssScore` from the report is stored on the Finding. 2ms groups its results by the
identity it assigns each secret, so a secret found in several places produces one Finding
per location under the same group.

### Sample Scan Data
Sample 2ms scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/two_ms).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- file_path
- line
- description

The description is part of the hashcode because 2ms can report two different secrets at the
same line of the same file; title, file path and line alone do not tell them apart.
