---
title: "Working with SBOMs"
description: "Manage software dependencies and SBOMs as Locations"
audience: pro
weight: 5
---

DefectDojo Pro models software libraries as **Dependency Locations**. A Dependency is a Location subtype identified by a [Package URL (pURL)](https://github.com/package-url/purl-spec) and intended to represent a single library or package — `org.apache.logging.log4j:log4j-core@2.17.0`, `pypi/django@5.0.2`, `npm/react@18.2.0`, and so on.

Dependencies replace the previous **Components** model, which was attached only to Findings. With Locations, libraries can exist independently of any vulnerability — you can upload an SBOM to an Asset and then let Findings auto-attach to the dependencies they reference as scans come in.

## What a Dependency Holds

Every Dependency is uniquely identified by a pURL, decomposed into atomic fields you can search and filter on:

| Field | Meaning | Example |
| --- | --- | --- |
| `purl_type` | Library ecosystem | `npm`, `pypi`, `maven`, `cargo`, `nuget`, `gem` |
| `namespace` | Vendor or organisation | `org.apache.logging` |
| `name` | Library name | `log4j-core` |
| `version` | Specific version | `2.17.0` |
| `qualifiers` *(optional)* | Implementation details | `arch=amd64` |
| `subpath` *(optional)* | Path within an archive or monorepo | `src/lib/foo` |
| `artifact_hashes` *(optional)* | Fingerprints | SHA256 sums |
| `license_expression` *(optional)* | SPDX license expression | `Apache-2.0`, `MIT` |
| `file_path` *(optional)* | Where the library was found in the project | `package-lock.json` |

This atomic decomposition is what makes pURL-based search useful: you can ask *"all `pypi` packages in the `django` namespace at version 4.x"* and DefectDojo can answer that without parsing a free-text string.

## Owned-By vs Used-By

When a Dependency is associated with an Asset, the Asset Reference carries an optional **relationship** describing *how* the library belongs to the Asset:

- **`owned_by`** — *"this library is owned by this Asset"*. Use this for first-party libraries an Asset publishes or maintains.
- **`used_by`** — *"this library is used by this Asset"*. Use this for third-party dependencies an Asset consumes.

The same library can be `owned_by` one Asset and `used_by` several others, which is exactly the relationship you need to answer *"who consumes the package my team publishes?"* during vulnerability triage.

## Uploading an SBOM

To populate Dependencies in bulk, upload an SBOM file against a Product. The endpoint is:

```
POST /api/v2/sbom-import/
```

| Field | Description |
| --- | --- |
| `product` | The target Product (Asset) ID |
| `file` | The SBOM file |
| `scan_type` | The SBOM format — see supported formats below |
| `replace` *(optional)* | If `true`, stale Product associations not backed by an existing Finding reference are removed. Default: `false` (cumulative) |

The importer parses the file, extracts `Dependency` records, deduplicates them against existing Locations (creating new ones as needed), and creates Asset References linking each Dependency to the Product. The Pro UI exposes the same upload flow — see the **Upload SBOM** action on a Product's Locations tab.

### Supported Formats

The MVP ships parsers for the two dominant SBOM formats:

- **CycloneDX** — JSON and XML
- **SPDX** — JSON (v2 and v3), XML, and tag-value

SWID Tag format is not yet supported.

### Replace vs Append

By default, repeated uploads are **additive**: dependencies that already exist on the Asset are kept, new ones are added, and nothing is removed. This matches the typical workflow of incremental SBOM updates.

Set `replace=true` to prune. When replace mode is on, after a successful import the importer removes Product associations that were not present in the new SBOM **and** are not currently referenced by an active Finding. References tied to active Findings are preserved even in replace mode, so you do not lose vulnerability context just because a new SBOM omits a package.

## Findings That Reference Libraries

When a parser ingests a vulnerability tied to a library — for example, an SCA tool reporting `CVE-2021-44228` against `log4j-core@2.14.1` — the importer:

1. Looks up an existing Dependency Location by pURL, or creates a new one.
2. Creates a `LocationFindingReference` linking the Finding to the Dependency with status **Active**.
3. Creates a `LocationProductReference` so the Dependency also appears on the parent Product, if it isn't already.

Because Findings and SBOM uploads share the same underlying Dependency objects, a Finding ingested *before* an SBOM upload will be retroactively visible in the SBOM view, and vice versa.

## REST API

| Task | Endpoint |
| --- | --- |
| Upload an SBOM | `POST /api/v2/sbom-import/` |
| List Dependencies | `GET /api/v2/dependencies/` |
| Create a Dependency manually | `POST /api/v2/dependencies/` |
| List Dependency Locations | `GET /api/v2/location/?location_type=dependency` |
| Link a Dependency to a Finding | `POST /api/v2/location_findings/` |
| Link a Dependency to a Product (with `owned_by` / `used_by`) | `POST /api/v2/location_products/` |

Filters on `/api/v2/dependencies/` include the pURL component fields, tags, and ordering on `name`, `version`, and active-finding count.

## In the Pro UI

When Locations is enabled, the navigation exposes:

- **Locations / Dependencies** — Global list of every Dependency across the instance, with pURL filters.
- **Locations on a Product/Asset** — Per-Asset view that shows both URLs and Dependencies, with the **Upload SBOM** action surfaced on the Dependencies tab.
- **New Dependency** — Form to create a single library by entering its pURL components manually.
- **Findings detail** — A Finding that touches a library shows its Dependency Locations alongside any URL Locations, so you can see *"this CVE affects `log4j-core@2.14.1` on Asset 6 and Asset 9"* in one place.

## What's Not in the MVP

- **SWID Tag SBOM format** — Not parsed. CycloneDX or SPDX is required.
- **License risk scoring** — The `license_expression` field is captured when present in the SBOM, but DefectDojo does not yet flag findings on license incompatibility. License-based reporting is on the roadmap as a follow-up to the Locations MVP.
- **Container image and cloud resource Locations** — Future Location subtypes. For now, libraries discovered inside a container image are recorded as Dependencies; the container image itself is not yet a first-class Location.
