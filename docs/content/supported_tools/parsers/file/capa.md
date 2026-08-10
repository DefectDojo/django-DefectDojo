---
title: "capa"
toc_hide: true
---
Import capa reports in JSON format. capa identifies the capabilities of an executable — what
it is able to do — and maps each to MITRE ATT&CK and MBC.

Generate a report with:

```
capa -j sample.exe > capa.json
```

### Scope and Severity
capa reports **capabilities, not vulnerabilities**. "This binary can accept command line
arguments" or "this binary can encrypt data" is intelligence about a sample, not a defect in
it, and capa assigns no severity. Every capability therefore imports as **Info**, with its
ATT&CK and MBC techniques recorded in the description for triage.

capa also emits library and subscope rules, which exist only to build other matches. Those are
not capabilities of the sample and are not imported.

### Sample Scan Data
Sample capa scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/capa).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
