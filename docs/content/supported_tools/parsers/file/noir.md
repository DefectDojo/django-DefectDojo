---
title: "Noir"
toc_hide: true
---
Import Noir reports in JSON format. Noir discovers the API attack surface of a codebase — every
route, its method and its parameters — directly from source.

Generate a report with:

```
noir -b . -f json > noir.json
```

### Scope and Severity
Noir reports **endpoints, not vulnerabilities**. Knowing the full attack surface is the value:
each discovered endpoint imports as **Info** inventory. Noir additionally tags endpoints it
considers security-relevant — an admin route, an endpoint taking a file path — and a tagged
endpoint imports as **Low** so it surfaces for review.

| Noir endpoint | DefectDojo severity |
| --- | --- |
| Tagged (admin, sensitive parameter, …) | Low |
| Untagged | Info |

Each endpoint is also attached to the Finding as a DefectDojo Endpoint.

### Sample Scan Data
Sample Noir scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/noir).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
