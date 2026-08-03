---
title: "pnpm Audit"
toc_hide: true
---

Import the JSON report of
[`pnpm audit`](https://pnpm.io/cli/audit), which checks the lock file against the npm advisory database.

### File Types

JSON, as written by `pnpm audit`. Generated with **pnpm 11.18.0**:

```
pnpm audit --json > pnpm_audit.json
```

pnpm emits the **npm v6 `advisories` envelope** — an object keyed by numeric advisory id — rather than
the npm 7+ `vulnerabilities` shape. If you are comparing parsers, this one is closer to
`NPM Audit Scan` than to `NPM Audit v7+ Scan`.

Severity comes from the advisory (`critical`/`high`/`moderate`/`low`/`info`). A `CWE-nnn` string is
converted to the numeric CWE. The dependency paths are kept in the description, because they are what
tells a reader whether they can fix the package directly or have to go through a parent.

One finding is created per advisory *and installed version*: the same advisory can match two copies of
a package at different versions, and each is separately fixable.

**pnpm's report has no CVE field.** The GitHub advisory id is the only public identifier available, so
that is what is attached — no CVE is inferred.

### Sample Scan Data

Sample pnpm Audit scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/pnpm_audit).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- component_name
- component_version
- vuln_id_from_tool
