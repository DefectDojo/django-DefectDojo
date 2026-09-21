---
title: "Fickling"
toc_hide: true
---
Import Fickling safety-check reports in JSON format. Fickling statically analyses and
decompiles Python pickle files, which can execute arbitrary code when loaded.

Generate a report with:

```
fickling --check-safety --json-output fickling.json model.pkl
```

Note that `--json-output` only writes a file when `--check-safety` is also passed.

### Severity Mapping
Fickling returns a single verdict for the file on its own scale:

| Fickling verdict | DefectDojo severity |
| --- | --- |
| OVERTLY_MALICIOUS | Critical |
| LIKELY_OVERTLY_MALICIOUS | Critical |
| LIKELY_UNSAFE | High |
| SUSPICIOUS | Medium |
| LIKELY_SAFE | not imported |

Each observation behind the verdict — unsafe imports, unused variables assigned from calls —
becomes its own Finding carrying the file's verdict, so a malicious pickle does not collapse
into one undifferentiated result. Where Fickling returns a verdict with no itemised results,
a single Finding records the verdict.

A `LIKELY_SAFE` verdict is not imported. Fickling's own wording is that it "failed to detect
any overtly unsafe code, but the pickle file may still be unsafe" — it is an absence of
evidence, not a clean bill of health.

### Limitations
Fickling's JSON does not record which file was analysed, so Findings carry no file path.
Import one report per pickle if you need to tell them apart.

### Sample Scan Data
Sample Fickling scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/fickling).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- severity
