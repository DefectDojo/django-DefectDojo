---
title: "uv audit"
toc_hide: true
---
Import `uv audit` reports in JSON format. uv audits a project's locked dependency set against
the Python advisory databases.

Generate a report with:

```
uv audit --output-format json > uv-audit.json
```

### Schema stability
uv marks both the `audit` command and its JSON output as **experimental**, and warns that the
schema may change without notice. The report's own schema version is recorded in each
Finding's description so a report produced by a newer uv can be identified. If uv promotes the
command out of preview and changes the shape, this parser will need revisiting.

### Severity Mapping
uv audit reports advisories **without any severity**, exactly as pip-audit does. Every finding
is therefore imported as **Medium**, matching the existing pip-audit parser rather than
inventing a scale uv does not publish.

Each advisory is reported under its own identifier — typically a PYSEC id — with CVE and GHSA
identifiers listed as aliases. Only the CVE aliases are recorded as vulnerability ids; the
GHSA reference is kept in the description. Where uv reports fixed versions, the mitigation
names the upgrade target.

### Sample Scan Data
Sample uv audit scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/uv_audit).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
- component_version
