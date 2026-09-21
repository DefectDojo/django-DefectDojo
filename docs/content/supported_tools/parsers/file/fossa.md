---
title: "FOSSA"
toc_hide: true
---

Import a [FOSSA](https://fossa.com/) v2 issues export.

This exists for organisations that cannot grant FOSSA API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro FOSSA connector pulls the same
data over the API; this parser accepts the same data as a file.

### File Types

JSON, from FOSSA's `getIssues` endpoint:

```
curl -H "Authorization: Bearer $FOSSA_TOKEN" "https://app.fossa.com/api/v2/issues?category=all" > fossa.json
```

A bare JSON array of issues is accepted, as is the API's `issues` envelope.

### What is imported

Both of FOSSA's issue categories:

- **Security vulnerabilities** (`type: vulnerability`) — with CVE, CVSS score and vector, CWE,
  affected and patched version ranges, and FOSSA's upgrade advice.
- **Licensing and quality issues** — policy conflicts, unlicensed dependencies, denylisted
  dependencies, and the `risk_*` quality signals.

An issue is treated as a vulnerability when its type says so **or** when it carries
vulnerability-only fields (`cve`, `vulnId`, `cvssVector`). That belt-and-braces check is the
connector's: a missing or renamed type value must not silently downgrade a CVE to a licensing
finding, which would also change how it is graded.

### No file or line

FOSSA is SCA. An issue hangs off a dependency, never a file and line, so the dependency
coordinates — package locator, name, version, package manager, and direct/transitive depth — are the
only location a finding has. They are written into the description.

### Severity

For a **vulnerability**, FOSSA's own `critical`/`high`/`medium`/`low`. FOSSA reports `unknown` often
enough to matter, and in that case severity falls back to the standard CVSS v3 bands (≥9.0 Critical,
≥7.0 High, ≥4.0 Medium, >0 Low, otherwise Info).

For **licensing and quality** issues FOSSA publishes no severity at all, so this table is the
connector's and is mirrored here:

| FOSSA issue type | Severity |
| --- | --- |
| `policy_conflict` (a denial) | High |
| `blacklisted_dependency` | High |
| `policy_flag` (advisory) | Medium |
| `unlicensed_dependency`, `unlicensed_and_public` | Medium |
| `outdated_dependency`, `risk_*` quality signals | Low |
| an unrecognised `risk_*` signal | Low |
| anything else | Info |

Both spellings of the `risk_*` types are mapped: FOSSA's documentation table hyphenates
(`risk_empty-package`) while fossa-cli's wire format uses underscores (`risk_empty_package`).

### One issue, several projects

A single FOSSA issue can affect several projects at once, and the connector emits **one finding per
project**, suffixing the tool id with the project locator (`1001:custom+1/generic-app`). Without that
suffix the same dependency issue in two DefectDojo products would share a tool id and collapse into
one finding.

This parser reproduces that from the issue's own `projects` list. An export carrying no project
context cannot reproduce the suffix, so the tool id is then the issue id alone.

### Scan type and deduplication

The scan type is **`FOSSA - Connectors Import`** — identical to the string the FOSSA connector
reports, so a customer who uploads an export *and* later enables the connector gets one set of
findings that deduplicate rather than two copies of everything.

### Sample Scan Data

Sample FOSSA scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/fossa).

The samples are constructed from FOSSA's documented `getIssues` response schema, with generic package
names, placeholder CVE identifiers and generic project locators.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
