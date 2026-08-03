---
title: "Kingfisher"
toc_hide: true
---

Import a [Kingfisher](https://github.com/mongodb/kingfisher) secret-scanning report.

### File Types

JSON or JSON Lines:

```
kingfisher scan /path/to/repo --format json --output kingfisher.json
```

Both `--format json` and `--format jsonl` are accepted.

Note that Kingfisher **validates** discovered credentials against the live provider by default. If
you do not want that — for example when scanning a repository whose secrets you are not authorised to
exercise — pass `--no-validate`. Reports produced either way parse the same.

### The secret value is not imported

Kingfisher includes the matched secret in its report. This parser deliberately does **not** copy it
into the finding. The rule, file, line and column are imported, which is enough to locate the
secret, and copying the credential itself would duplicate a live secret into the DefectDojo
database. Findings carry a reminder to revoke, rotate, and purge the value from version-control
history.

### Severity

Kingfisher emits no severity field, so severity is derived from the two signals it does report.
Validation status outranks confidence, because a credential confirmed to work is the most serious
thing a secret scanner can tell you:

| Kingfisher reports | Severity |
| --- | --- |
| `validation.status` = `Active` — the credential worked | Critical |
| `validation.status` = `Inactive` — the provider rejected it | Low |
| otherwise, `confidence` = `high` | High |
| otherwise, `confidence` = `medium` | Medium |
| otherwise, `confidence` = `low` | Low |
| neither signal recognised | Medium |

An `Inactive` credential stays a real finding rather than becoming Info: it is still committed in the
source and still needs purging from history. Nothing here maps to Info, because every finding is a
credential exposure and DefectDojo treats Info as non-actionable.

All findings are reported with **CWE-798** (use of hard-coded credentials), matching the CWE the
`trufflehog`, `trufflehog3`, `gitleaks` and `detect_secrets` parsers already use so that secret
findings agree across tools.

### A note on the JSON format

`--format json` writes **two concatenated JSON documents** — the findings, then a run summary — so a
plain JSON load of the file fails with "Extra data". `--format jsonl` likewise appends that summary
as a final line, and the summary carries a `findings` key of its own holding an integer count. This
parser walks the whole stream and skips the summary in both formats.

### Sample Scan Data

Sample Kingfisher scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kingfisher).

The clean and single-finding samples are real Kingfisher v1.110 output. The remaining cases were
built on that same real structure to cover the validation and confidence combinations, because
Kingfisher's detectors need realistic entropy to fire and the fixtures in this public repository
carry only marked-fake secret values. A test asserts that every secret value in the fixtures is
marked as fake.

### Default Deduplication Hashcode Fields

Kingfisher assigns every finding a fingerprint, which is imported as `unique_id_from_tool` and used
as the primary deduplication identity. By default, DefectDojo falls back to these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- file_path
- line
