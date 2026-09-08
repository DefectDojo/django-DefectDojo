---
title: "licensecheck"
toc_hide: true
---
Import licensecheck reports in JSON format. Unlike a plain licence inventory, licensecheck
evaluates each dependency's licence for **compatibility with the project's own licence**.

Generate a report with:

```
licensecheck -f json > licensecheck.json
```

### Severity Mapping
licensecheck assigns no severity, but it does make a compatibility judgement per dependency,
and DefectDojo maps that:

| licensecheck result | DefectDojo severity |
| --- | --- |
| Licence incompatible with the project | High |
| Licence compatible | Info |

An incompatible licence is a genuine compliance finding — shipping the dependency may violate
the project's own distribution terms. Compatible dependencies are recorded as informational
inventory, with the licence in `vuln_id_from_tool`.

DefectDojo does not decide your licence policy; licensecheck's own compatibility matrix does.
If your policy differs, triage on the recorded licence after import.

### Sample Scan Data
Sample licensecheck scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/licensecheck).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- component_name
- component_version
- vuln_id_from_tool
