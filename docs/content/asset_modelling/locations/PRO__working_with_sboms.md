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

To populate Dependencies in bulk, upload an SBOM file against an Asset. The endpoint is:

```
POST /api/v2/sbom-import/
```

| Field | Description |
| --- | --- |
| `product` | The target Asset ID |
| `file` | The SBOM file |
| `scan_type` | The SBOM format — see supported formats below |
| `replace_dependencies` *(optional)* | If `true`, stale Asset associations not backed by an existing Finding reference are removed. Default: `false` (cumulative) |
| `version` *(optional)* | The Asset version this SBOM describes, e.g. `5.2.0`. Requires Asset Versions — see [below](#asset-versions-and-bom-snapshots) |

The importer parses the file, extracts `Dependency` records, deduplicates them against existing Locations (creating new ones as needed), and creates Asset References linking each Dependency to the Asset. The Pro UI exposes the same upload flow — see the **Upload SBOM** action on an Asset's Locations tab.

### Supported Formats

The MVP ships parsers for the two dominant SBOM formats:

- **CycloneDX** — JSON and XML
- **SPDX** — JSON (v2 and v3), XML, and tag-value

SWID Tag format is not yet supported.

### Replace vs Append

By default, repeated uploads are **additive**: dependencies that already exist on the Asset are kept, new ones are added, and nothing is removed. This matches the typical workflow of incremental SBOM updates.

Set `replace_dependencies=true` to prune. When replace mode is on, after a successful import the importer removes Asset associations that were not present in the new SBOM **and** are not currently referenced by an active Finding. References tied to active Findings are preserved even in replace mode, so you do not lose vulnerability context just because a new SBOM omits a package.

## Asset Versions and BOM Snapshots

An SBOM describes an Asset at a point in its release history — *the dependencies of Payments API 5.2.0* — but by default DefectDojo records only the Asset's current inventory. Re-uploading either accumulates forever or prunes, and *what shipped in 5.1?* is not a question the data can answer.

Deployments that opt in to **Asset Versions** can bind each upload to a version. This behavior is managed by deployment configuration: set `DD_V3_ASSET_VERSIONS=True` (self-hosted) or contact support (cloud). It is off by default, and while it is off nothing described in this section is recorded — uploads behave exactly as above.

A version is **metadata about an Asset, not another Asset**, and that distinction is the whole point. Modelling releases as child Assets copies every Finding into every release; one customer's 30,000 Findings became 360,000 that way. A Finding stays a single row on its Asset no matter how many versions mention it.

### Binding an upload to a version

Pass `version` to `POST /api/v2/sbom-import/`. The version is created on first sight, so there is no setup step.

If you omit it, the document's own subject version is used — `metadata.component.version` in CycloneDX, the root package's version in SPDX. Most producers stamp it, so uploads usually bind correctly without you passing anything. Omitting `version` *and* uploading a document that declares none leaves the import on the unversioned stream, which is today's behavior.

Versions carry **no ordering**. DefectDojo does not parse or compare version strings — package ecosystems disagree about what "newer" means — so nothing infers that 5.1 sits between 5.0 and 5.2. `released_at` on a version is an optional display and reporting hint.

### Snapshots supersede rather than merge

Each upload records a **BOM snapshot**: the components the document declared, the dependency relationships between them, and the document's own identity (specification, serial number, timestamp, and declared subject).

Uploading again for the same version and format **supersedes** the previous snapshot — the newest one is what per-version reads return — and the superseded snapshots remain queryable as history. Nothing is deleted. Snapshots are scoped per format, so a CycloneDX document and an SPDX document for the same release supersede independently instead of clobbering each other.

This is a separate axis from `replace_dependencies`, which still governs the Asset's aggregate dependency list. A snapshot answers *what did this document say*; the aggregate answers *what is on this Asset now*.

Snapshots also preserve the BOM's **structure**. Each component records whether the document listed it as a direct dependency of its subject, and component → component relationships are recorded as declared, so a per-version export reproduces the graph instead of flattening it (see [Exporting SBOMs and VEX](../pro__exporting_sboms_and_vex/#exporting-one-release)). CycloneDX JSON and XML and SPDX 2 JSON carry full structure; SPDX XML, tag-value, and v3 record components only.

### `found_in` and `fixed_in`

Scan imports contribute the other half of the version story. When an import or reimport carries a `version` — the field `/api/v2/import-scan/` and `/api/v2/reimport-scan/` already accept — and Asset Versions is enabled:

- Findings the import processes are recorded as **found_in** that version.
- Findings the import mitigates because the scan no longer reports them are recorded as **fixed_in** that version. Previously that version reached the record only as prose inside the auto-close note.

These claims are **additive and never withdrawn automatically**: an import that stops seeing a Finding does not un-say that an earlier version contained it. Because a Finding's mitigation timestamp is write-once while claims are per-version, a reopen-and-refix cycle appends a second `fixed_in` instead of rewriting the first. Re-importing the same version is a no-op.

The claims are what makes [per-version VEX](../pro__exporting_sboms_and_vex/#vex-for-one-release) possible: they let one Finding report *resolved in 5.2* and *exploitable in 5.1* without existing twice.

## Findings That Reference Libraries

When a parser ingests a vulnerability tied to a library — for example, an SCA tool reporting `CVE-2021-44228` against `log4j-core@2.14.1` — the importer:

1. Looks up an existing Dependency Location by pURL, or creates a new one.
2. Creates a `LocationFindingReference` linking the Finding to the Dependency with status **Active**.
3. Creates a `LocationProductReference` so the Dependency also appears on the parent Asset, if it isn't already.

Because Findings and SBOM uploads share the same underlying Dependency objects, a Finding ingested *before* an SBOM upload will be retroactively visible in the SBOM view, and vice versa.

## REST API

| Task | Endpoint |
| --- | --- |
| Upload an SBOM | `POST /api/v2/sbom-import/` |
| List Dependencies | `GET /api/v2/dependencies/` |
| Create a Dependency manually | `POST /api/v2/dependencies/` |
| List Dependency Locations | `GET /api/v2/location/?location_type=dependency` |
| Link a Dependency to a Finding | `POST /api/v2/location_findings/` |
| Link a Dependency to an Asset (with `owned_by` / `used_by`) | `POST /api/v2/location_products/` |
| List or create Asset versions | `GET` / `POST /api/v2/asset_versions/` |
| Record a `found_in` / `fixed_in` claim by hand | `POST /api/v2/finding_version_affects/` |

Filters on `/api/v2/dependencies/` include the pURL component fields, tags, and ordering on `name`, `version`, and active-finding count.

The two version endpoints follow the same rule as the rest of the Asset surface: reading is open to anyone who can already see the Asset, while writing requires edit permission on it plus `DD_V3_ASSET_VERSIONS`. Neither offers an update action, deliberately — a version is a name that exported documents and claims already point at, so renaming one would silently rewrite the meaning of every document exported under it, and a claim is stated or withdrawn rather than edited into a different claim. Hand-recorded claims are marked as such, so they stay distinguishable from the ones imports write.

## In the Pro UI

When Locations is enabled, the navigation exposes:

- **Locations / Dependencies** — Global list of every Dependency across the instance, with pURL filters.
- **Locations on an Asset/Asset** — Per-Asset view that shows both URLs and Dependencies, with the **Upload SBOM** action surfaced on the Dependencies tab.
- **New Dependency** — Form to create a single library by entering its pURL components manually.
- **Findings detail** — A Finding that touches a library shows its Dependency Locations alongside any URL Locations, so you can see *"this CVE affects `log4j-core@2.14.1` on Asset 6 and Asset 9"* in one place.

## Exporting

The inventory flows back out as well: an Asset's dependencies can be exported as a CycloneDX 1.6 or SPDX 2.3 SBOM, and its finding statuses as a CycloneDX VEX document. See [Exporting SBOMs and VEX](../pro__exporting_sboms_and_vex/).

## What's Not in the MVP

- **SWID Tag SBOM format** — Not parsed. CycloneDX or SPDX is required.
- **License risk scoring** — The `license_expression` field is captured when present in the SBOM, but DefectDojo does not yet flag findings on license incompatibility. License-based reporting is on the roadmap as a follow-up to the Locations MVP.
- **Container image and cloud resource Locations** — Future Location subtypes. For now, libraries discovered inside a container image are recorded as Dependencies; the container image itself is not yet a first-class Location.
