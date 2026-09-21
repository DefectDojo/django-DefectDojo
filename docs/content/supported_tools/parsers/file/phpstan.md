---
title: "PHPStan"
toc_hide: true
---
Import PHPStan reports in JSON format. PHPStan is a static analysis tool for PHP that checks
types, nullability, dead code and unreachable branches at a configurable strictness level.

Generate a report with:

```
phpstan analyse --error-format=json --no-progress > phpstan.json
```

Each diagnostic becomes one Finding, titled with PHPStan's rule identifier and the message, and
located at the file and line PHPStan reported. The identifier is stored in `vuln_id_from_tool`,
so a team can track or baseline an individual rule. PHPStan's `tip` — the hint it prints
suggesting how to resolve a diagnostic — is carried into the description when present.

### Severity Mapping
PHPStan assigns no severity. At a given analysis level a diagnostic is either reported or it is
not, and everything it reports it calls an error. It does, however, make two distinctions in its
own output that carry real weight, and severity is derived from those rather than from a flat
constant:

| PHPStan output | DefectDojo severity |
| --- | --- |
| top level `errors[]` entry | High |
| file diagnostic with `"ignorable": false` | Medium |
| file diagnostic with `"ignorable": true` | Low |

The reasoning:

- A **top level error** is not attached to any file. PHPStan emits these when it cannot complete
  the analysis — a missing configuration file, an unreadable path, an autoloader failure. The
  important fact is that some part of the codebase was never analysed, so the report is
  incomplete. That is worth more attention than any single type error, hence High.
- **`ignorable: false`** marks a diagnostic PHPStan will not let you suppress with
  `ignoreErrors` or a baseline. PHPStan reserves this for problems it considers non-negotiable,
  so it is the one place the tool itself signals that one diagnostic outranks another.
- **`ignorable: true`** covers the ordinary bulk of a report. These are genuine correctness and
  type-safety defects, but they are baselineable by design and are not demonstrated
  vulnerabilities, so they import as Low rather than filling a queue with Mediums.

Because severity here is derived from analysis metadata rather than from exploitability, teams
who want a particular PHPStan rule to carry more weight should raise it on the identifier in
`vuln_id_from_tool` rather than expect the level to reflect it.

PHPStan reports no CWE values, so imported Findings have no CWE.

### Sample Scan Data
Sample PHPStan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/phpstan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
