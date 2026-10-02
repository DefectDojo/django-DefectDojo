---
title: "kubesec"
toc_hide: true
---
Import kubesec reports in JSON format. kubesec scores Kubernetes object definitions against a
fixed set of security rules and assigns each object an overall point score.

Generate a report with:

```
kubesec scan manifest.yaml > kubesec.json
```

### Severity Mapping
kubesec assigns no severity. It sorts each rule into one of three buckets and attaches a point
value, which DefectDojo maps as follows:

| kubesec bucket | DefectDojo severity |
| --- | --- |
| critical | High |
| advise | Low |
| passed | not imported |

The `advise` bucket lists hardening the object does not have yet rather than a weakness it
has, which is why it maps to Low. The `passed` bucket lists rules the object already
satisfies and is not imported. Each Finding records the rule's point value and the object's
overall score in its description.

### Sample Scan Data
Sample kubesec scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kubesec).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
- file_path
