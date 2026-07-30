---
title: "SPDX"
toc_hide: true
---

[SPDX](https://spdx.dev/) (Software Package Data Exchange) is an ISO/IEC 5962 standard software bill of
materials format, and the format named alongside CycloneDX in US federal SBOM procurement guidance.

DefectDojo already supports CycloneDX; this parser covers the other half of the SBOM world. Any tool
that can emit SPDX becomes importable.

### Supported versions and serialisations

| | |
|---|---|
| SPDX 2.2 / 2.3, JSON | supported (`.json`) |
| SPDX 2.2 / 2.3, tag-value | supported (any other extension, e.g. `.spdx`) |
| SPDX 3.0 (JSON-LD) | **not supported yet** — rejected with a clear error rather than silently parsing zero packages |

Both serialisations go through the same mapping code, so a document exported either way produces
identical findings.

### What becomes a finding, and what does not

SPDX 2.x has **no vulnerability container**. It describes what software is present, not what is wrong
with it. This parser therefore behaves exactly like the CycloneDX parser:

* **Packages become component inventory**, recorded as dependency locations on the test (PURL, name,
  version, checksums, license expression). They do **not** become findings. An installed package is not
  a weakness, and creating one finding per package would fill a product with rows nobody can remediate.
* **Findings are created only from a genuine weakness signal**: an external reference in the `SECURITY`
  category whose reference type is advisory-shaped (`advisory`, `fix`, `url`, `swid`) **and** whose
  locator or comment names a vulnerability identifier (`CVE-…` or `GHSA-…`).

#### CPEs are identity, not vulnerabilities

SPDX puts CPE identifiers under `referenceCategory: SECURITY` as well, using reference types
`cpe22Type` and `cpe23Type`. A CPE says what a package *is*; it is not a vulnerability. Treating the
category alone as a weakness signal would turn every inventoried package into a bogus finding, so CPE
references are recorded in the finding description for identification and never create findings of
their own.

#### Licenses

`licenseConcluded` (preferred) or `licenseDeclared` is carried on the component's dependency location as
its license expression, the same field the CycloneDX parser populates. License information does **not**
become a finding — a license is a fact about a component, not a weakness. Use DefectDojo's own reporting
over the recorded component licenses instead.

### Severity

An SPDX advisory reference carries no severity, CVSS score or vector; the format has no field for them.
Every finding from this parser is therefore **Medium**. Medium rather than Info is deliberate: a real,
named CVE must not be filtered out of sight by a minimum-severity setting. Import the scanner's own
report alongside the SBOM when you need scored findings.

`NOASSERTION` and `NONE` are SPDX placeholders meaning "unknown" and are treated as absent throughout.

### Sample Scan Data

Sample SPDX files are available at
[unittests/scans/spdx](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/spdx).

### Generating an importable file

Any SPDX 2.2/2.3 producer works. With [syft](https://github.com/anchore/syft):

```bash
syft <image-or-directory> -o spdx-json > sbom.spdx.json
```

The fixtures committed with this parser were produced with **syft 1.50.0** by:

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  anchore/syft:latest alpine:3.10 -o spdx-json > sbom.spdx.json
```

Tag-value output instead of JSON:

```bash
syft <image-or-directory> -o spdx-tag-value > sbom.spdx
```

Other producers that emit SPDX 2.3 include `trivy sbom --format spdx-json`, `cdxgen`, and the
`spdx-sbom-generator` project.

### Default deduplication hashcode fields

`vuln_id_from_tool`, `component_name`, `component_version` — identical to CycloneDX, so the same SBOM
imported in either format deduplicates the same way.
