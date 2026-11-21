---
title: "Yocto CVE Check"
toc_hide: true
---

The [Yocto Project](https://www.yoctoproject.org/) builds custom embedded Linux images. Its CVE tooling
compares every recipe in an image against the NVD and writes a JSON manifest that records, for each
recipe, the CVEs that match it and whether each one is `Unpatched`, `Patched` or `Ignored`. This parser
imports that manifest, so the vulnerabilities in a firmware or device image can be tracked in DefectDojo
alongside the rest of a product's findings.

## Supported File Types

The parser accepts the Yocto cve-check JSON manifest. Two Yocto tools write this format:

| Yocto release | Tool | How to get the JSON manifest |
|---|---|---|
| 3.1 (dunfell) | `cve-check` class | `INHERIT += "cve-check"` and `CVE_CHECK_FORMAT_JSON = "1"` in `conf/local.conf` |
| 4.0 (kirkstone) to 5.3 (whinlatter) | `cve-check` class | `INHERIT += "cve-check"` in `conf/local.conf` (JSON is on by default) |
| 6.0 (wrynose) and later | `sbom-cve-check` | `bitbake-config-build enable-fragment core/yocto/sbom-cve-check` |

`cve-check` was removed from OpenEmbedded-Core in Yocto 6.0. Its replacement, `sbom-cve-check`, writes
the same manifest format by default (export type `yocto-cve-check-manifest`). Both are handled.

After building the image, the manifest is in `tmp/deploy/images/<machine>/`:

* `cve-check`: the image's `.json` file.
* `sbom-cve-check`: the image's `.sbom-cve-check.yocto.json` file.

Upload it using the **Yocto CVE Check** scan type, and leave the import's **Active** option unset so the
statuses described below are kept. The per-recipe JSON files that `cve-check` writes under `tmp/log/cve/`
use the same format and can also be imported.

The `.vex.json` file written by Yocto's `vex` class uses the same layout but carries no NVD scores, so
every finding imported from it is `Info`. Import the `cve-check` or `sbom-cve-check` manifest instead.

## Default Deduplication Hashcode Fields

DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
- component_version

Because the recipe version is part of the hash, upgrading a recipe to a version that is still affected
closes the finding for the old version and opens a new one for the new version.

### Sample Scan Data

Sample Yocto cve-check manifests can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/yocto_cve_check).

## Link To Tool

- [Yocto Project](https://www.yoctoproject.org/)
- [Checking for Vulnerabilities (Yocto Project manual)](https://docs.yoctoproject.org/dev-manual/vulnerabilities.html)
- [sbom-cve-check](https://github.com/bootlin/sbom-cve-check)

## JSON Format

The manifest is a JSON object with a `version` and a `package` list. Each package is a Yocto recipe with
an `issue` list of the CVEs that match it. Older releases write fewer fields; any field can be missing.

### Total Fields in JSON

- Total data fields: 19
- Total data fields parsed: 18
- Total data fields NOT parsed: 1 (`patch-file`, which Yocto writes only on `Patched` issues, and those are skipped)

### JSON Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Notes |
|---|---|---|
| package.name | component_name | Recipe name, also used in the title |
| package.version | component_version | Recipe version (with epoch when set), also used in the title |
| package.layer | description | Layer the recipe comes from (empty in sbom-cve-check output) |
| package.products | description | CPE product names and whether NVD has CVEs for them |
| package.cpes | description | Written by sbom-cve-check |
| issue.id | vuln_id_from_tool, vulnerability_ids, title | CVE identifier |
| issue.summary | description | NVD description, first line of the description |
| issue.status | active, is_mitigated, description | See Special Processing Notes |
| issue.detail | mitigation, description | Reason for the status, for example `version-in-range` or `not-applicable-config` |
| issue.description | mitigation, description | Free-text justification for the status |
| issue.scorev2 | severity, description | Used for severity only when there is no v3 or v4 score |
| issue.scorev3 | cvssv3_score, severity, description | |
| issue.scorev4 | cvssv4_score, severity, description | |
| issue.vector | description | Attack vector, for example `NETWORK` |
| issue.vectorString | cvssv3 or cvssv4, severity | Stored in the field that matches the vector's CVSS version |
| issue.modified | description | Date the NVD record was last modified |
| issue.link | references | NVD link |

</details>

### Additional Finding Field Settings (JSON Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field | Default Value | Notes |
|---|---|---|
| static_finding | True | The manifest is produced from build metadata, not a running system |
| dynamic_finding | False | |
| active | True | False when the CVE is closed as described below |

</details>

## Special Processing Notes

### Status Handling

| Yocto status | Result in DefectDojo |
|---|---|
| `Unpatched` | Active finding |
| `Unknown`, missing or `null` | Active finding (the status could not be determined, so the CVE is treated as still open) |
| `Patched` | Skipped. The CVE is fixed in the build, by version or by an applied patch |
| `Ignored` with detail `upstream-wontfix` | Active finding. Upstream does not plan to fix the CVE, so the vulnerable code is still in the image |
| `Ignored`, any other detail | Closed as Mitigated, with Yocto's reason (`detail` and `description`) in the Mitigation field |

Yocto files a CVE as `Ignored` when the image is not affected, for reasons such as
`not-applicable-config`, `not-applicable-platform`, `cpe-incorrect` or `disputed`. These are closed as
Mitigated rather than as False Positive or Out of Scope because Mitigated is the only closed state that
reimport reopens. Reimport therefore follows the Yocto status in both directions:

* A CVE that was imported as `Unpatched` and is marked `Ignored` (for example with `CVE_STATUS` in its
  recipe) or `Patched` in a later build is closed when that build's manifest is reimported.
* A CVE that was `Ignored` or `Patched` and becomes `Unpatched` again, for example after a kernel
  configuration change, is reopened.

`Patched` CVEs are not imported. Yocto includes them in the manifest by default
(`CVE_CHECK_REPORT_PATCHED = "1"`), often hundreds per image, and importing them would only add closed
findings. A finding that becomes `Patched` is closed on reimport because it is no longer in the report.

### Severity

Severity comes from the newest CVSS version that has a score, in the order v4, v3, v2. Yocto writes
`0.0` when a version has no score, and those are ignored, as are scores outside 0 to 10.

When the `vectorString` belongs to that newest scored version, severity is computed from the vector by
DefectDojo's standard CVSS handling. The vector is not always for the newest version: the NVD database
used by `cve-check` up to scarthgap keeps the CVSS v2 vector whenever one exists, even when the CVE also
has a v3 score. In that case, and for manifests without a `vectorString`, severity comes from the score:

| CVSS base score | v3 / v4 severity | v2 severity |
|---|---|---|
| 9.0 to 10.0 | Critical | High |
| 7.0 to 8.9 | High | High |
| 4.0 to 6.9 | Medium | Medium |
| 0.1 to 3.9 | Low | Low |
| no score | Info | Info |

CVSS v2 has no Critical band, so a v2-only CVE is at most High. A CVE with no score, common while it is
awaiting NVD analysis, is `Info`.

### Title Format

`<CVE id> in <recipe name>:<recipe version>`, for example `CVE-2024-6387 in openssh:9.6p1`. Titles over
500 characters are truncated, and the recipe name and version are truncated to fit their fields.

### Description Construction

The description starts with the NVD summary, followed by a table of the package and issue fields listed
above. Empty values, `0.0` scores and `UNKNOWN` placeholders are left out of the table.
