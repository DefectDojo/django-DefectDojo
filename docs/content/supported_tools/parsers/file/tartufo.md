---
title: "Tartufo"
toc_hide: true
---
Import Tartufo reports in JSON format. Tartufo scans git history — not just the working tree —
for secrets, so a finding names the commit that introduced the string and the branch it is on.

Generate a report with:

```
tartufo --output-format json scan-local-repo . > tartufo.json
```

### Severity Mapping
Tartufo assigns no severity. A secret found in git history is treated as **High**: rewriting
history does not undo the exposure, so the credential must be considered compromised and
rotated. Tartufo's `signature` is a stable hash of the match and is stored as
`unique_id_from_tool` so a re-scan tracks the same finding.

### Sample Scan Data
Sample Tartufo scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/tartufo).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
