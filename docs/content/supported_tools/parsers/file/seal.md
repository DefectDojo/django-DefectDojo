---
title: "Seal Security"
toc_hide: true
---
CSV report of the [Seal Security](https://www.seal.security) CLI.

Seal Security backports security fixes into "sealed" versions of open-source packages,
so a vulnerable dependency can be remediated without a major-version upgrade.

Generate the report with the `--csv` flag:

```
seal scan --csv results.csv
```

The export contains one row per vulnerable package. A row that lists several
vulnerability identifiers is imported as one Finding per identifier, so that each one
can be triaged and risk-accepted independently.

Identifiers are not always CVEs. Seal reports the most specific identifier it has for a
vulnerability, falling back to a GitHub advisory or Snyk identifier when no CVE is
assigned.

When Seal has a sealed version available for the package, `fix_available` is set on the
Finding and the mitigation names the sealed version to update to.

Findings for a vulnerability that reaches the project through an embedded (shaded)
package name the embedding package in the description. The Finding's component remains
the package that is actually present in the project.

### Severity

The CSV export has no severity column, so all Findings are imported as Medium unless
the report contains a `Score` column, in which case the score is mapped onto the
standard CVSS severity bands.

### Sample Scan Data
Sample Seal Security scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/seal).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vulnerability ids
- component name
- component version
