---
title: "kube-no-trouble (kubent)"
toc_hide: true
---
Import kube-no-trouble reports in JSON format. kubent finds Kubernetes objects using
deprecated API versions, reading manifest files, Helm releases or a live cluster.

Generate a report with:

```
kubent -f manifests/ -o json > kubent.json
```

### Severity Mapping
kubent assigns no severity, and unlike [Pluto](../pluto/) it does not distinguish an API that
is merely deprecated from one that has already been removed. Every object it reports is a
deprecated API usage, so all findings are imported as **Medium**.

The release the API is removed in is parsed out of kubent's ruleset name (for example
`Deprecated APIs removed in 1.16`) and recorded in the description, along with the release the
API was deprecated in and the replacement API.

If you want severity to reflect whether the API is already gone, use the Pluto parser instead:
Pluto reports an explicit `removed` flag.

### Sample Scan Data
Sample kubent scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kubent).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
