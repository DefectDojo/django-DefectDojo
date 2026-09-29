---
title: "dockerfile_lint"
toc_hide: true
---
Import dockerfile_lint reports in JSON format. dockerfile_lint checks a Dockerfile against a
rule set covering build correctness and image hygiene.

Generate a report with:

```
dockerfile_lint -f Dockerfile -j > dockerfile_lint.json
```

### Scope and Severity
dockerfile_lint is a general Dockerfile linter, but several of its rules carry real security
weight — running as root, using the floating `latest` tag, and adding remote archives over
the network. Its own buckets double as its severity scale:

| dockerfile_lint bucket | DefectDojo severity |
| --- | --- |
| error | High |
| warn | Medium |
| info | Low |

Rules that apply to the file as a whole rather than to a line — a required `LABEL` that is
missing entirely, for instance — are reported by dockerfile_lint with a line number of `-1`.
Those Findings carry no line rather than a nonsensical one, and rules that ship without a
label take their title from the message instead.

### Sample Scan Data
Sample dockerfile_lint scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dockerfile_lint).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- line
