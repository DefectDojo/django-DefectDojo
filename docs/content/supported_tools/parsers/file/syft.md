---
title: "Syft"
toc_hide: true
---
Import Syft SBOMs in Syft's native JSON format. Syft catalogues the packages present in a
container image, directory or archive.

Generate an SBOM with:

```
syft scan dir:. -o syft-json > syft.json
```

Syft can also emit CycloneDX and SPDX, both of which DefectDojo parses separately. Use this
parser for Syft's native format, which carries its own artifact ids, CPEs and catalogue
metadata.

### Scope and Severity
Syft is an **SBOM generator, not a vulnerability scanner**. It reports what is installed and
never whether it is vulnerable, and it assigns no severity — so every catalogued package
imports as **Info** inventory.

To find vulnerabilities in the same material, feed the SBOM to a scanner such as Grype or
bomber, both of which DefectDojo also parses.

### Sample Scan Data
Sample Syft SBOMs can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/syft).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- component_name
- component_version
- vuln_id_from_tool
