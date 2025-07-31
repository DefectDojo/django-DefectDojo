---
title: "AuditJS (OSSIndex)"
toc_hide: true
---
AuditJS scanning tool using OSSIndex database and generated with `--json` or `-j` option (<https://www.npmjs.com/package/auditjs>).

{{< highlight bash >}}
auditjs ossi --json > auditjs_report.json
{{< /highlight >}}

### Sample Scan Data
Sample AuditJS (OSSIndex) scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/auditjs).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
