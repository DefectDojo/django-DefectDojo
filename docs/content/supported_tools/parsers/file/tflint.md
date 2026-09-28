---
title: "TFLint"
toc_hide: true
---
Import TFLint reports in JSON format. TFLint lints Terraform configuration using its core
ruleset plus any enabled provider plugins, such as the AWS, Azure or Google rulesets.

Generate a report with:

```
tflint --format json > tflint.json
```

### Severity Mapping
TFLint attaches a severity to each rule, and DefectDojo maps that scale as follows:

| TFLint severity | DefectDojo severity |
| --- | --- |
| error | High |
| warning | Medium |
| notice | Info |

The `errors` array in a TFLint report holds problems TFLint hit while running (an unparseable
file, a missing plugin) rather than problems with the configuration, so it is not imported.

### Sample Scan Data
Sample TFLint scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/tflint).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
