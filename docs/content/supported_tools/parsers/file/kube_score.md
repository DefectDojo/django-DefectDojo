---
title: "kube-score"
toc_hide: true
---
Import kube-score reports in JSON format. kube-score performs static analysis of Kubernetes
object definitions and grades every check it runs.

Generate a report with:

```
kube-score score manifests/*.yaml --output-format json > kube-score.json
```

### Severity Mapping
kube-score does not assign severities. It grades each check on its own scale, and DefectDojo
maps that grade as follows:

| kube-score grade | DefectDojo severity |
| --- | --- |
| 1 (critical) | High |
| 5 (warning) | Medium |
| 10 (passing) | not imported |

Checks that kube-score marks as `skipped` express no opinion on the object and are not
imported, regardless of the grade attached to them.

### Sample Scan Data
Sample kube-score scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kube_score).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- component_name
- vuln_id_from_tool
