---
title: "Pluto"
toc_hide: true
---
Import Pluto reports in JSON format. Pluto finds Kubernetes objects that use deprecated or
removed API versions, either in manifest files or in a live cluster's Helm releases.

Generate a report with:

```
pluto detect-files -d . -o json > pluto.json
```

### Severity Mapping
Pluto assigns no severity. It reports two booleans per object, and DefectDojo derives severity
from them:

| Pluto state | DefectDojo severity |
| --- | --- |
| `removed` | High |
| `deprecated` | Medium |

An object on an API version that has already been removed will not apply to a cluster running
that version at all, which is why it outranks one that is merely deprecated. Objects Pluto
inspected but flagged as neither are not imported.

The replacement API, the version the API was deprecated in and the version it was removed in
are all recorded on the Finding, and the mitigation names the migration target.

### Sample Scan Data
Sample Pluto scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/pluto).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
- file_path
