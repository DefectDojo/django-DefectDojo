---
title: "sbomqs"
toc_hide: true
---
Import sbomqs reports in JSON format. sbomqs scores the **quality** of an SBOM rather than
searching it for vulnerabilities: whether the document carries suppliers, licences, checksums
and the other elements required by NTIA minimum elements and BSI TR-03183 guidance.

Generate a report with:

```
sbomqs score sbom.json --json > sbomqs.json
```

### Severity Mapping
sbomqs has no severity concept. It scores each feature out of a maximum, and DefectDojo
derives severity from the size of the gap:

| Feature score | DefectDojo severity |
| --- | --- |
| 0 (element entirely absent) | Medium |
| below half of maximum | Low |
| at or above half of maximum | Info |
| at maximum | not imported |

Features sbomqs marks as ignored for the run are not imported. Because these Findings describe
gaps in a document rather than exploitable weaknesses, none of them carry a CVE or CWE.

### Sample Scan Data
Sample sbomqs scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/sbomqs).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
