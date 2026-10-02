---
title: "Ruff"
toc_hide: true
---
Import Ruff reports in JSON format. Ruff is a fast Python linter that includes the
flake8-bandit security ruleset — its `S` codes cover shell injection, weak hashes, hardcoded
passwords and similar issues.

Generate a report with:

```
ruff check --output-format json > ruff.json
```

To scan only for security issues, select the bandit ruleset: `ruff check --select S`.

### Severity Mapping
A Ruff run can mix security findings with style, so DefectDojo weights by rule category, the
same way it treats the Prospector meta-tool:

| Ruff rule prefix | DefectDojo severity |
| --- | --- |
| `S` (flake8-bandit security rules) | Medium |
| everything else (`E`, `F`, `W`, …) | Low |

This keeps a real security finding such as `S602` (subprocess with `shell=True`) from being
buried among formatting warnings. The rule code is kept in `vuln_id_from_tool` so results can
be filtered by ruleset after import. This parser is distinct from the Bandit parser: it reads
Ruff's own JSON, not Bandit's.

### Sample Scan Data
Sample Ruff scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ruff).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
