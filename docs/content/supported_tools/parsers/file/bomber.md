---
title: "bomber"
toc_hide: true
---
Import bomber reports in JSON format. bomber reads an existing SBOM (CycloneDX, SPDX or
Syft) and looks each component up against a vulnerability provider.

Generate a report with:

```
bomber scan --output json sbom.json > bomber.json
```

### Severity Mapping
bomber normalises every provider onto its own scale, which uses `MODERATE` where most tools
use medium:

| bomber severity | DefectDojo severity |
| --- | --- |
| CRITICAL | Critical |
| HIGH | High |
| MODERATE | Medium |
| LOW | Low |
| UNSPECIFIED | Info |

Package coordinates are reported as a purl and split into the component name and version.
Advisory identifiers are recorded in `vuln_id_from_tool`; those that are CVEs are additionally
attached as vulnerability ids, while provider-specific ids such as GHSA references are not.

### Sample Scan Data
Sample bomber scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/bomber).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
- component_version
