---
title: "Python Taint"
toc_hide: true
---
Import Python Taint (pyt) reports in JSON format. Python Taint performs taint tracking — it
follows untrusted input from a source to a dangerous sink, rather than matching patterns.

Generate a report with:

```
pyt -j project/ > pyt.json
```

### Severity Mapping
Python Taint reports no severity. Every result is a completed flow from an untrusted source to
a dangerous sink — an exploitable path, not a hint — so all findings import as **High**.

Each finding records the source, the sink and the propagation trace between them, and anchors
on the sink line, where the dangerous operation happens.

### Sample Scan Data
Sample Python Taint scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/python_taint).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
