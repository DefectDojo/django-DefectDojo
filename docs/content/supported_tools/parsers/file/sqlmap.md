---
title: "sqlmap"
toc_hide: true
---

Import a report from [sqlmap](https://sqlmap.org/), which confirms SQL injection by exploiting it.

### File Types

Two artifacts are accepted, and which one you have decides what the finding can say:

- **The per-target log file** — `<output-dir>/<host>/log`. Written for every run, and the only place
  the confirmed **payload** appears. It does not contain the target URL (the URL is only in the
  directory name and in `target.txt`), so a finding imported from a log has no endpoint.
- **The CSV results file** — `<output-dir>/results-<timestamp>.csv`. Carries the **target URL**, so
  findings get an endpoint, but records only which techniques worked, not the payloads.

```
sqlmap -u 'https://target.example.com/item?id=1' --batch --output-dir=out
```

One finding is created per injectable parameter — not per confirmed technique. Every technique sqlmap
confirmed is listed in the description, with its title and payload when importing a log.

Findings are severity **High** with CWE-89. sqlmap only reports an injection point after confirming
the injection works, so this is not a pattern match that might be wrong; a confirmed injection is
often triaged up to Critical depending on what the affected data is worth, which is a question about
the application rather than something sqlmap measures.

Three sqlmap behaviours the parser accommodates, all covered by tests:

- **A run that finds nothing writes a zero-byte log** and a header-only CSV. Both parse to zero
  findings, because finding no injection is the ordinary result of scanning an application that binds
  its parameters.
- **Both artifacts are appended to, not overwritten.** Scanning the same target twice writes the
  report twice — the second one headed `sqlmap resumed the following injection point(s) from stored
  session`. Findings are keyed on place and parameter so a resumed run does not double them.
- **The CSV technique letter is the first letter of the technique name**, so an inline query is `I`
  there even though the `--technique` flag spells the same technique `Q`.

### Sample Scan Data

Sample sqlmap scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/sqlmap).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- endpoints

The description is deliberately left out: it records what the scan saw at the time (a response size,
a detected version, a timestamp, a payload) and that changes between two scans of an unchanged
target, which would import the same finding again on every rescan.
