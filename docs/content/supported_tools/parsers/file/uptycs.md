---
title: "Uptycs"
toc_hide: true
---

Import an [Uptycs](https://www.uptycs.com/) vulnerabilities-query export.

This exists for organisations that cannot grant Uptycs API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Uptycs connector pulls the same
data over the API; this parser accepts the same data as a file.

### File Types

JSON — the query response, `{"items": [...]}`. A bare array works, as does an object naming the list
`rows`, `data` or `results`.

### One row becomes one finding per CVE

Uptycs reports **one row per vulnerable package**, listing every CVE against it. Each CVE is separately
fixable and separately triaged, so each becomes its own finding rather than one finding titled after all
of them. A row naming **no** CVE still becomes a single package finding — a vulnerable package is worth
recording even when Uptycs has attached no identifier.

The CVE list arrives either as a JSON array **or as a comma-separated string**; the string is split and
trimmed, because reading it whole would produce one finding titled after every CVE at once.

Every finding fanned out of one row **shares that row's severity**: the row carries one CVSS score for
the package rather than one per CVE, so the fan-out cannot grade them apart.

### Severity

Uptycs sends no severity word, so the row's CVSS score is the only signal — the standard ≥ 9 / ≥ 7 /
≥ 4 / > 0 bands, with an unscored row landing in Info. Scores may arrive quoted.

### Fields worth noting

- **Title** is `<CVE> in <package>`, or `Vulnerable package <package>` without one. A row with no package
  name reads as the literal word `package`.
- **Identity** is `uptycs-<asset id>-<package>[-<CVE>]`, so the same CVE on two hosts stays two findings
  — two machines to patch. The component is the package, so the hash alone would merge them; the asset id
  is what keeps them apart.
- **The other CVEs are listed in the description only when the row names more than one.** With a single
  CVE the title already says it.

### Sample Scan Data

Sample Uptycs scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/uptycs).

The samples cover a row with three CVEs as an array, a row with two as a comma-separated string, a row
with none, a row with no package name, a quoted score, and a row with no asset group. Host, package and
group names are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
