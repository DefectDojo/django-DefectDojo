---
title: "Ruff"
toc_hide: true
---

Import the security findings from a [Ruff](https://docs.astral.sh/ruff/) SARIF report.

### File Types

SARIF (JSON). Ruff emits SARIF with `--output-format sarif`:

```
ruff check --select S --output-format sarif . > ruff.sarif
```

### Only the security ruleset is imported

Ruff is primarily a style and correctness linter — a `--select ALL` run over a small file readily
produces dozens of results about annotations, docstrings and copyright headers. Importing those as
findings would bury real security issues under lint opinions.

This parser therefore imports **only the `flake8-bandit` (`S`) rules** — rules whose id matches
`S<number>`, such as `S324` (insecure hash), `S608` (possible SQL injection) or `S105` (hardcoded
password). Every other rule family is discarded, even if it is present in the report. Selecting the
security rules at scan time as shown above is still recommended, but a report produced with a wider
selection is filtered on import and is safe to upload.

The filter is applied on both import paths DefectDojo can take, so the rule families cannot leak in
through the report-with-multiple-tests path.

### Severity

Ruff reports every rule at SARIF level `error` and sets no `security-severity` property, so all
imported findings land at **High**. That uniformity is Ruff's own reporting, not a mapping decision
in this parser — Ruff exposes no per-rule severity to map. Triage on the rule id
(`vuln_id_from_tool`) rather than the severity.

### Sample Scan Data

Sample Ruff scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ruff).

The samples are real `ruff check` output. `ruff_mixed_rulesets.sarif` is a `--select ALL` run over the
same input and exists to prove the filter: 35 results across the `ANN`, `CPY`, `D`, `EXE` and `S`
families, of which only the 9 `S` findings are imported. The scanned input is committed as
`sample_insecure_source.txt` rather than `.py` so that it is not linted as project code.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file_path
- description
