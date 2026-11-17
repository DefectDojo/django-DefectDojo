---
title: "CPE Locations"
description: "CPE locations record the platforms a finding affects, named by CPE vendor, product and version"
weight: 12
audience: pro
---

**CPE Locations** record a platform (an application, an operating system or a piece of hardware) named by a [Common Platform Enumeration](https://nvd.nist.gov/products/cpe) identifier such as `cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*`. A finding that names the CPE it affects carries it as a location, so you can see every finding on a given vendor, product and version, and every Asset that runs it.

> CPE Locations require the Locations feature. See [Locations Overview](/asset_modelling/locations/pro__locations_overview/).

## What They Model

Each CPE location stores the CPE's attributes in their own columns:

- **Part**: `a` for an application, `o` for an operating system, `h` for hardware.
- **Vendor**, **Product** and **Version**.
- The other CPE 2.3 attributes: update, edition, language, software edition, target software, target hardware and other. In the API they are `update`, `edition`, `cpe_language`, `sw_edition`, `target_sw`, `target_hw` and `other`.

An attribute the CPE leaves open is stored as `*` (any value); `-` means not applicable.

### Identity: one canonical CPE 2.3 string

DefectDojo accepts both CPE spellings and stores one canonical **CPE 2.3 formatted string**, which is the location's identity:

- A CPE 2.2 URI (`cpe:/a:apache:http_server:2.4.57`) and the matching 2.3 string are the same location.
- Values are lower-cased, so `Apache` and `apache` are one vendor.
- Attributes a CPE leaves out, or leaves empty, become `*`.
- Escapes are normalized: `1\.2\.3`, `1.2.3` and the 2.2 URI's `1%2e2%2e3` are one version.

Re-importing the same CPE in any of these spellings reuses the existing location rather than creating a new one.

A value that is not a CPE is skipped with a warning in the log, and the rest of the import carries on. DefectDojo rejects a CPE when:

- It starts with neither `cpe:2.3:` nor `cpe:/`.
- Its part is not `a`, `o` or `h`.
- It names no vendor or no product.
- It contains a space or a character outside printable ASCII.
- It is longer than the limits: 255 characters for each attribute, 2048 for the whole CPE.

## Where They Come From

### Parsers link CPEs to findings

A finding gets a CPE location only when its report ties that CPE to it. DefectDojo does not match findings to CPE locations by CPE string, vendor, product or version range. These parsers emit CPE locations:

| Parser | Where the CPE comes from |
| --- | --- |
| CycloneDX (JSON and XML) | The `cpe` field of the component a vulnerability affects |
| SPDX (JSON and tag-value) | The package's `cpe22Type` and `cpe23Type` external references, on the findings for that package |
| Dependency-Check | The CPEs Dependency-Check matched the dependency to: `identifiers/vulnerabilityIds/id`, and `identifier type="cpe"` in older reports |

An SBOM component with no vulnerability does not get a CPE location. It still appears as a Dependency location.

### Import CPEs: a plain list for an Asset

To record the platforms an Asset runs without importing a scan, open **Locations** and choose **Import CPEs**. Pick the Asset, then paste a list or upload a text file:

- One CPE per line, as a CPE 2.3 string or a CPE 2.2 URI.
- Blank lines and lines starting with `#` are ignored.
- Each valid CPE becomes a location tied to that Asset with no findings. A CPE that is already a location is linked to the Asset rather than created again.
- A line that repeats an earlier CPE, in any spelling, is counted once.
- Invalid lines are listed with the reason, and the valid lines are still imported.
- A list can have up to 10,000 lines, and an uploaded file can be up to 2 MB.

You need permission to add Locations to the Asset you pick.

## Finding CPE Locations

In the **Locations** list, filter by the **CPE** location type. Use the **Vendor** and **Product** filters to narrow the list to one platform.

## API

CPE locations are available on the public API:

- `GET /api/v2/cpe_locations/` lists them. Each of `cpe`, `vendor`, `product`, `version` and `part` takes a lookup suffix: `_exact`, `_contains`, `_starts_with`, `_ends_with` and `_includes`, each with a `_not_` variant. For example, `?vendor_exact=apache` or `?product_contains=kernel`. The bare `product` filter is different: it takes an Asset ID and lists the locations tied to that Asset.
- `POST /api/v2/cpe_locations/import/` imports a plain list for one Asset. Send `product` (the Asset ID) and either `file` (a text file, one CPE per line) or `cpes` (the same text in the request body). A list can have up to 10,000 lines, and a file can be up to 2 MB. The response has four keys:
  - `locations`: how many distinct CPEs the list named, all now tied to the Asset.
  - `created`: how many CPE locations the import created. The rest already existed and were linked to the Asset.
  - `duplicates`: how many lines repeated a CPE an earlier line named, in any equivalent spelling.
  - `rejected`: each invalid line, as `line` (its number), `value` and `reason`.

```bash
curl -X POST "https://defectdojo.example.com/api/v2/cpe_locations/import/" \
  -H "Authorization: Token <api_key>" \
  -F "product=42" \
  -F "file=@platforms.txt"
```
