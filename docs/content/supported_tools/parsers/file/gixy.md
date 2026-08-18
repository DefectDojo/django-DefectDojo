---
title: "Gixy"
toc_hide: true
---
Import Gixy reports in JSON format. Gixy analyses nginx configuration for security
misconfiguration — HTTP splitting, host header issues, referrer and origin validation, version
disclosure.

Generate a report with:

```
gixy -f json nginx.conf > gixy.json
```

### Severity Mapping
Gixy assigns its own severity per finding, which DefectDojo maps directly:

| Gixy severity | DefectDojo severity |
| --- | --- |
| HIGH | High |
| MEDIUM | Medium |
| LOW | Low |

Each finding names the plugin that raised it and includes the offending configuration snippet.

### Sample Scan Data
Sample Gixy scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/gixy).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
