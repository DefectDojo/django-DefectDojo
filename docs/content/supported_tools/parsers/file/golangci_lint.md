---
title: "golangci-lint"
toc_hide: true
---

Import the security findings from a [golangci-lint](https://golangci-lint.run/) JSON report.

DefectDojo also ships a `gosec` parser for gosec's own JSON output. This parser exists because most
Go projects run gosec *through* golangci-lint in CI and never produce a standalone gosec report.

### File Types

JSON, from golangci-lint v2:

```
golangci-lint run --output.json.path report.json
```

### Only the security linters are imported

golangci-lint aggregates around a hundred linters, and nearly all of them report style or
correctness opinions. A `linters.default: all` run over a nine-function file readily produces more
style issues than security ones. Importing those as findings would bury real security issues.

This parser therefore imports findings from exactly two linters:

| Linter | What it reports |
| --- | --- |
| `gosec` | The Go security checker — weak crypto, command injection, TLS verification disabled, unsafe file permissions, and the rest of the `G`-numbered rules |
| `bidichk` | Dangerous bidirectional Unicode, i.e. the "Trojan Source" class |

Everything else is discarded, even when present in the report. Resource-leak and error-handling
linters (`bodyclose`, `sqlclosecheck`, `rowserrcheck`, `errcheck`, `noctx`) are **deliberately
excluded**: they find bugs, not weaknesses. Enabling only the security linters at scan time is still
recommended, but a report produced with a wider selection is filtered on import and is safe to
upload.

### Severity

golangci-lint v2 passes gosec's own `low`/`medium`/`high` through in each issue's `Severity` field,
so severities here are the tool's, not this parser's invention.

A golangci-lint `severity` configuration block can rewrite those values to `error`/`warning`/`info`;
both vocabularies are mapped. If a severity is absent or unrecognised the finding becomes **Medium**
— gosec's own default — rather than Info, because everything imported here is a security weakness
and DefectDojo treats Info as non-actionable.

### No CWE

golangci-lint does not carry gosec's CWE identifier through into its own output, so findings from
this parser have no CWE. The standalone `gosec` parser does preserve CWE, because gosec's native
JSON includes it. No CWE mapping is guessed from the rule id here.

### Sample Scan Data

Sample golangci-lint scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/golangci_lint).

The samples are real golangci-lint v2 output. `golangci_lint_mixed_linters.json` is a
`linters.default: all` run over the same input and exists to prove the filter: 19 issues, of which
only the 7 gosec ones are imported. The scanned input is committed as `sample_insecure_source.txt`
rather than `.go` so that it is not compiled or vetted as project code; its hardcoded-credential
case uses a plain high-entropy hex string, so nothing in the fixtures is provider-shaped.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file_path
- description
