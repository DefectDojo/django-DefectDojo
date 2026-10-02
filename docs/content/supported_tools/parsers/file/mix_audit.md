---
title: "Mix Audit"
toc_hide: true
---

Import the JSON report of
[`mix deps.audit`](https://github.com/mirego/mix_audit), which checks `mix.lock` against the Elixir
Security Advisories data.

### File Types

JSON, as written by `mix_audit`. Generated with **Elixir 1.17.3 / mix_audit 2.1**:

```
mix deps.get
mix deps.audit                                   # first run compiles dependencies
mix deps.audit --format json > mix_audit.json    # second run is clean JSON
```

**Run it twice.** The first `mix deps.audit` in a clean checkout prints compiler output *before* the
JSON, which makes the file unparseable. A second run emits JSON alone. This is the likeliest reason an
import fails, so the parser's error message names it.

Severity comes from the advisory (`critical`/`high`/`moderate`/`low`); an advisory with none recorded
is imported at Medium. `first_patched_versions` becomes the mitigation and `disclosure_date` becomes
the publish date.

**The Elixir advisory data has no CVE field.** Advisory ids are GHSA ids, and that is what is attached.

### Sample Scan Data

Sample Mix Audit scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/mix_audit).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- component_name
- component_version
- vuln_id_from_tool
