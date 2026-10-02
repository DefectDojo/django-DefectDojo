---
title: "GuardDog"
toc_hide: true
---
Import GuardDog reports in JSON format. GuardDog inspects PyPI and npm packages for
indicators of malicious behaviour, using Semgrep rules over the package source plus metadata
heuristics.

Generate a report with:

```
guarddog pypi scan <package-or-path> --output-format json > guarddog.json
```

### Severity Mapping
GuardDog's rules fall into two families. A `threat-*` rule describes behaviour that is
suspicious in a package; a `capability-*` rule records that the package is *able* to do
something, which is an observation rather than an accusation.

Where GuardDog's risk engine correlates a rule into a scored risk, that risk carries its own
severity on GuardDog's low/medium/high scale, and it takes precedence:

| GuardDog signal | DefectDojo severity |
| --- | --- |
| Correlated risk, severity `high` | High |
| Correlated risk, severity `medium` | Medium |
| Correlated risk, severity `low` | Low |
| Uncorrelated `threat-*` rule | Medium |
| Uncorrelated `capability-*` rule | Info |

The package-level `risk_score` (`no_risks_detected`, `low`, `suspicious`, `high_risk`) is
recorded in each Finding's description rather than mapped onto severity, since it describes
the package as a whole rather than the individual match.

GuardDog reports every rule it ran, including the ones that did not match; only rules with at
least one match are imported.

### Sample Scan Data
Sample GuardDog scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/guarddog).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
- file_path
- line
