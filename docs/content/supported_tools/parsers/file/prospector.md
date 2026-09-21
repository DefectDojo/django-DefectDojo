---
title: "Prospector"
toc_hide: true
---
Import Prospector reports in JSON format. Prospector runs several Python analysis tools —
pylint, pyflakes, dodgy, bandit and others — and reports their messages under a common shape.

Generate a report with:

```
prospector --output-format json > prospector.json
```

### Severity Mapping
Prospector is a meta-tool, and its messages range from style to security. DefectDojo weights
by the tool that raised each message so a real security finding is not lost among linter
noise:

| Prospector source | DefectDojo severity |
| --- | --- |
| dodgy, bandit (security tools) | High |
| pylint, pyflakes, pep8, … | Low |

The originating tool and its check code are recorded on every Finding, so results can be
filtered by source after import.

### Sample Scan Data
Sample Prospector scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/prospector).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
