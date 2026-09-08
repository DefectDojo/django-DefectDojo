---
title: "Kingfisher"
toc_hide: true
---
Import Kingfisher reports in JSON format. Kingfisher scans source, git history and
filesystems for credentials, and where a provider allows it will actively validate a match
to establish whether the credential is still live.

Generate a report with:

```
kingfisher scan /path/to/repo --format json > kingfisher.json
```

### Severity Mapping
Kingfisher has no severity concept. It reports a confidence for each match, plus the result
of validating the credential against the provider. DefectDojo derives severity from both:

| Kingfisher signal | DefectDojo severity |
| --- | --- |
| Validation confirmed a live credential | Critical |
| Otherwise, confidence `high` | High |
| Otherwise, confidence `medium` | Medium |
| Otherwise, confidence `low` | Low |

A credential that validation reports as inactive keeps its confidence-derived severity — it
is still a secret committed to source, it is simply no longer usable.

Kingfisher's `fingerprint` is stored as `unique_id_from_tool`, so re-imports track the same
match across scans.

### Sample Scan Data
Sample Kingfisher scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kingfisher).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- file_path
- line
