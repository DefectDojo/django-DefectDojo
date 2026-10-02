---
title: "Composer Audit"
toc_hide: true
---

Import the JSON report of PHP's built-in
[`composer audit`](https://getcomposer.org/doc/03-cli.md#audit), which checks the lock file against the
Packagist security advisories.

### File Types

JSON, as written by `composer audit`. Generated with **Composer 2.10.2**:

```
composer audit --format=json --locked > composer_audit.json
```

`--locked` audits `composer.lock`, so the packages do not have to be installed.

Severity comes from the advisory (`critical`/`high`/`medium`/`low`); an advisory with no severity
recorded is imported at Medium rather than dropped. Both identifiers are attached where present: the
`cve` field and the GitHub advisory id from `sources`. `cve` is frequently `null`, in which case the
GHSA id is the only public identifier the report carries.

One finding is created per package-and-advisory pair, so a single package with several advisories
produces several findings — each is separately fixable.

**`component_version` is deliberately not set.** A composer advisory names the affected version
*range*, never the version actually installed; that lives in `composer.lock` rather than in the report.

**Reproducing the sample data:** Composer 2.10 refuses to resolve a package that is affected by a
security advisory, so a project pinning vulnerable versions will not install at all. Generating a
non-empty audit requires turning that off explicitly:

```json
{ "config": { "policy": { "advisories": { "block": false } } } }
```

### Sample Scan Data

Sample Composer Audit scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/composer_audit).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- component_name
- vuln_id_from_tool
