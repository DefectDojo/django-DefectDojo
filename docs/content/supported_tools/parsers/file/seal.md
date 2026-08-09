---
title: "Seal Security"
toc_hide: true
---
CSV report of the [Seal Security](https://www.seal.security) CLI.

Seal Security remediates vulnerable open-source dependencies without upgrading them to a
new major version. Rather than pointing at the next fixed release, it backports the
security fix onto the version already in use and publishes the result as a "sealed"
version of the same package, such as `lodash@4.17.15-sp1` for npm or `requests@2.19.1+sp1`
for PyPI. Because only the patch content changes, a sealed version is a drop-in
replacement, which is what makes it useful for dependencies where the fixed release
carries breaking changes.

Sealed packages are served through registry proxies, so consuming them is a package
manager configuration change rather than a code change. The CLI scans a project against
Seal's vulnerability data and reports, per vulnerable package, whether a sealed version
exists for the exact version in use.

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
