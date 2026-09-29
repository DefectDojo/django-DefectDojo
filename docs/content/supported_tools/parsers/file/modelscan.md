---
title: "ModelScan"
toc_hide: true
---
Import ModelScan reports in JSON format. ModelScan inspects serialized machine-learning
models (pickle, TensorFlow SavedModel, Keras, NumPy) for operators that are able to execute
code when the model is loaded.

Generate a report with:

```
modelscan -p /path/to/models -r json -o modelscan.json
```

### Severity Mapping
ModelScan assigns a severity to each unsafe operator it knows about, and DefectDojo maps that
scale directly:

| ModelScan severity | DefectDojo severity |
| --- | --- |
| CRITICAL | Critical |
| HIGH | High |
| MEDIUM | Medium |
| LOW | Low |

ModelScan reports an unsafe operator rather than a known vulnerability, so its findings carry
no CVE or CWE. The operator is recorded in `vuln_id_from_tool` as `module.operator`.

### Sample Scan Data
Sample ModelScan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/modelscan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- file_path
- vuln_id_from_tool
