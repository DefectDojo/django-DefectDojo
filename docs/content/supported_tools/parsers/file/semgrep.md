---
title: "Semgrep JSON Report"
toc_hide: true
aliases:
  - "/en/connecting_your_tools/parsers/file/semgrep/"
---
Import Semgrep output (--json)

### Opengrep

[Opengrep](https://github.com/opengrep/opengrep) is a fork of Semgrep and emits the same JSON schema,
so its reports import with this parser — no separate scan type is needed:

```bash
opengrep scan --config <rules.yaml> --json --json-output=opengrep.json <path>
```

Verified against Opengrep 1.26.0: `check_id`, `path`, `start.line`, `extra.severity` and
`extra.metadata.cwe` are all read as they are for Semgrep, so severities and CWEs come through
unchanged. Note that Opengrep prefixes rule ids with the config path, exactly as Semgrep does, so the
finding title reflects where the rule file lives.

### Sample Scan Data
Sample Semgrep JSON Report scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/semgrep).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
