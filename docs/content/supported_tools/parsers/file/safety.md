---
title: "Safety"
toc_hide: true
---
Import Safety reports in JSON format. Safety checks installed Python packages against the
PyUp advisory database.

Generate a report with:

```
safety check --json --output safety.json
```

### Severity Mapping
PyUp assigns a severity only to some advisories. Its own `PVE-` advisories frequently carry
neither a CVE nor a severity, so DefectDojo maps what is present and defaults the rest to
Medium rather than inventing a scale:

| Safety severity | DefectDojo severity |
| --- | --- |
| critical | Critical |
| high | High |
| medium | Medium |
| low | Low |
| absent | Medium |

Advisories that carry a CVE have it recorded as a vulnerability id; PyUp's own numeric
advisory id is always kept in `vuln_id_from_tool`. Advisories the user has ignored stay in
Safety's report, flagged rather than removed, and are not imported.

### Sample Scan Data
Sample Safety scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/safety).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
- component_version
