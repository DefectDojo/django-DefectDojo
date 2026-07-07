---
title: "Locations Overview"
description: "What Locations are and why they replace Endpoints"
audience: pro
weight: 1
---

**Locations** are a new asset-modelling tool in DefectDojo Pro. They replace the legacy **Endpoints** model and absorb the previous **Components** (library) data, giving DefectDojo a single, polymorphic way to describe *where* a Finding lives — whether that's a URL, a software dependency from an **SBOM**, or, in the future, a **cloud resource ID**, **container image**, or **code repository**.

Locations are currently in **Beta** and will need to be enabled on your instance. To enable Locations on your instance, contact [support@defectdojo.com](mailto:support@defectdojo.com).

## Why Replace Endpoints?

The original Endpoints model was built around URLs and IP addresses — it carried web-app fields like `protocol`, `host`, `port`, `path`, and a fixed status table that was tightly coupled to Findings. Three problems followed:

1. **Limited fidelity.** Endpoints could not cleanly describe non-URL assets such as third-party libraries, container images, or cloud resources, even though scanners increasingly produce findings about those things.
2. **Performance ceiling.** Per-Finding Endpoint_Status rows and the URL-shaped schema did not scale well at large customer volumes.
3. **Components were second-class.** Software libraries lived only as denormalised fields on a Finding, so a library could not exist independently of a vulnerability — making true SBOM management impossible.

Locations fix all three by introducing a **base `Location` object** with a typed payload, plus dedicated **subtypes** for each asset shape:

- **URL Locations** — functional equivalent of the old Endpoints, with the same protocol/host/port/path/query/fragment fields.
- **Dependency Locations** — software libraries identified by [Package URL (pURL)](https://github.com/package-url/purl-spec), used to model SBOM contents.
- **[Source Code Locations](/asset_modelling/locations/pro__source_code_locations/)** — where a static-analysis finding lives in source, identified by file path and line number. Scan-managed, and the substrate for [tracking findings as their code moves](/triage_findings/finding_deduplication/pro__location_drift_matching/).

Future Location types under consideration include cloud provider resource IDs (AWS ARN, Azure Resource ID, GCP Full Resource Name) and container images (registry/repository:tag and SHA256 fingerprints).

## Key Concepts

### Locations and Subtypes

A **Location** is the shared parent. It carries:

- A `Location Type` (e.g. `"url"`, `"dependency"`)
- A canonical `Location Value` string used for display, search, and de-duplication
- `Tags` and inherited tags from the parent Asset
- Metadata (custom key/value pairs)

A **subtype** (URL or Dependency) holds the structured fields specific to that kind of location. URLs and Dependencies always live alongside a parent Location object; the subtype's `Location Value` is generated from its structured fields.

### References

Locations are not directly attached to Products or Findings. Instead, two **Reference** objects link them:

- **Asset References** — relationships the Location has to Assets (e.g. `libFoo` is *owned by* Asset 6, *used by* Asset 9). Each reference carries a status (`Active` or `Mitigated`) and an optional **relationship** ("Used By" or "Owned By").
- **Finding References** — relationships the Location has to Findings. Each reference carries a richer status (`Active`, `Mitigated`, `False Positive`, `Risk Accepted`, `Out of Scope`) plus the auditor and audit time.

This separation is what allows a library to exist on a Product *without* needing a Finding — a missing capability in the old Components model.

### Auto-Association at Import Time

When a parser produces a Finding that references a URL or library, the importer:

1. Looks up an existing Location matching the URL or pURL; if none exists, it creates one.
2. Creates a Finding Reference linking the Finding to the Location with status `Active`.
3. Creates (or reuses) an Asset Reference so the Location also lives on the parent Asset.

Existing parsers have been updated to emit Location data when the feature flag is on, and to fall back to the legacy Endpoint model when it is off. No reconfiguration is needed when Locations are enabled — the next import will route through the Locations pipeline automatically.

## What's in the MVP

| Capability | Status |
| --- | --- |
| Foundational `Location`, `URL`, `Dependency` models | Shipped |
| REST API for Locations and References | Shipped (read-only `Location`, full CRUD on References) |
| Endpoint API read-compatibility shim | Shipped |
| Endpoint → URL one-way migration command | Shipped |
| Parser updates (URLs and dependencies) | Shipped for the major parsers |
| SBOM upload (CycloneDX, SPDX v2/v3) | Shipped via `/api/v2/sbom-import/` |
| Pro UI for Locations, URLs, Dependencies | Shipped (Beta) |
| pURL search/filter | Shipped |
| License tracking on dependencies | Partial (`license_expression` field) |
| SWID Tag SBOM format | Not in MVP |

## Where to Go Next

- **Enable the feature** — contact [support@defectdojo.com](mailto:support@defectdojo.com) to turn Locations on for your instance.
- **Migrate from Endpoints** — see [Migrating from Endpoints](../pro__migrating_from_endpoints) for what the migration preserves, and how the legacy Endpoint API behaves afterward.
- **Day-to-day URL workflows** — see [Working with URLs](../pro__working_with_urls).
- **SBOMs and dependencies** — see [Working with SBOMs](../pro__working_with_sboms).
