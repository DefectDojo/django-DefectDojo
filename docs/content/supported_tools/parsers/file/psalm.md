---
title: "Psalm"
toc_hide: true
---
Import Psalm results in SARIF format. Psalm is a static analysis tool for PHP that checks types,
nullability and dead code.

Generate a report with:

```
psalm --report=results.sarif
```

Each result becomes one Finding, titled with Psalm's issue type followed by its message (for
example `TypeDoesNotContainType: string cannot be identical to int`). The issue type leads
because it is the identifier that appears in `psalm.xml`, in baselines and in `--issues=`, so it
is what a team acts on. Psalm's SARIF `ruleId` is a bare number — its documentation shortcode —
which is recorded in the description and linked from the Finding's references.

### Severity Mapping
Psalm sorts every issue into one of two levels, error and info, and emits them as the SARIF
levels `error` and `note`. DefectDojo's shared SARIF mapping turns those into:

| Psalm issue level | SARIF level | DefectDojo severity |
| --- | --- | --- |
| error | error | High |
| info | note | Info |

Psalm has no finer scale than this, and no notion of exploitability, so there is no gradient to
reproduce. Which level a given issue type lands on is not fixed by Psalm: it is decided by the
`errorLevel` in the project's `psalm.xml` and by any per-issue configuration. A project running
at a strict error level will import the same code as High that a lenient project imports as
Info. That is Psalm's own judgement of the project, and it is carried through rather than
overridden here.

Psalm does not report CWE values, so imported Findings have no CWE.

### Sample Scan Data
Sample Psalm scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/psalm).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
