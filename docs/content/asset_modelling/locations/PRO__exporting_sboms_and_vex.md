---
title: "Exporting SBOMs and VEX"
description: "Export an Asset's dependency inventory as CycloneDX or SPDX, and its finding statuses as a CycloneDX VEX document"
audience: pro
weight: 7
---

DefectDojo Pro can serialize an Asset's current dependency inventory back out as a standards-compliant SBOM, and its vulnerability triage decisions as a machine-readable VEX document. Both are produced from the same [Dependency Locations](../pro__working_with_sboms/) that SBOM imports and scan findings populate, so whatever your scanners and uploads have accumulated is what the export describes — the documents are consumed by downstream tooling, compliance pipelines, and AI agents, not just humans.

Both endpoints require **Locations** to be enabled, and respect Asset-level permissions: an Asset the requesting user cannot view returns a 404.

## Exporting from the Asset page

The Asset page carries an **Export** panel offering the same data without going through the API, in one of three shapes:

| Export type | What the document contains |
| --- | --- |
| **SBOM** | The component inventory only. |
| **VEX** | The vulnerability analysis only — a standalone document describing the exploitability of this Asset's findings. |
| **SBOM with vulnerabilities (VDR)** | Both — the inventory with an embedded `vulnerabilities` block carrying the VEX analysis. |

Each choice names the format and specification version it produces, for example *SBOM — component inventory only (CycloneDX 1.6)*. Those labels are read from the server as the panel renders rather than written into the page, so they describe the document you will actually receive: when the exporters adopt a newer specification, the labels follow rather than going stale.

The Asset page and the API endpoints below emit the same specification version, so a document exported from either path is interchangeable with the other.

## Exporting an SBOM

```
GET /api/v2/sbom/{asset_id}/
GET /api/v2/sbom/{asset_id}/?spec=spdx
```

| Parameter | Values | Default |
| --- | --- | --- |
| `spec` | `cyclonedx` (CycloneDX 1.6 JSON), `spdx` (SPDX 2.3 JSON) | `cyclonedx` |
| `version` | An Asset version name, e.g. `5.2.0` | *(none — the current inventory)* |

The response is a downloadable JSON document (`Content-Disposition: attachment`). Components carry their Package URL, group/namespace, version, artifact hashes (algorithms each specification supports), and — when the SBOM import recorded one — the license expression for this Asset's use of the component.

Without a `version`, the export describes the Asset's **current** inventory, and its `dependencies` section declares root → component edges only: the aggregate inventory is a set of libraries, not a graph.

### Exporting one release

Deployments with [Asset Versions](../pro__working_with_sboms/#asset-versions-and-bom-snapshots) enabled can export a specific release instead of the current aggregate:

```
GET /api/v2/sbom/{asset_id}/?version=5.2.0
```

The document is then built from the BOM snapshot recorded for that version, which changes three things:

- **Components** are the ones that version's SBOM declared, with the licenses recorded for it — not everything the Asset has accumulated since.
- **`dependencies`** reproduces the structure the imported document declared — root → direct components, then component → component — instead of the flat root → everything fan.
- **The version** appears on `metadata.component` (SPDX: the root package's `versionInfo`), so the document says which release it describes.

A version the Asset does not have returns 404 rather than quietly exporting the aggregate inventory under a version label — a document labelled 5.2.0 that does not describe 5.2.0 is the wrong thing to hand a downstream consumer or a regulator. A version that exists but has no SBOM uploaded yet exports an empty inventory, correctly labelled with that version.

## Exporting a VEX document

```
GET /api/v2/sbom/{asset_id}/vex/
```

The VEX export is a standalone CycloneDX 1.6 document built from the statuses of findings attached to the Asset's dependencies. Component references are Package URLs — the same identifiers the SBOM export uses — so the pair can be consumed together without any reference translation. SPDX has no VEX profile, so this endpoint is CycloneDX-only.

Statement grouping: one vulnerability entry per (vulnerability ID × analysis state), with every affected component listed under `affects`. Findings without a vulnerability ID are omitted — VEX statements are keyed by vulnerability identifier.

### How DefectDojo statuses map to VEX analysis

The status of each **finding ↔ location edge** (where per-location triage lives) drives the analysis:

| DefectDojo status | VEX `analysis.state` | Notes |
| --- | --- | --- |
| Active | `exploitable` | |
| Risk Accepted | `exploitable` | with `response: ["will_not_fix"]` |
| Out of Scope | `not_affected` | |
| False Positive | `false_positive` | |
| Mitigated | `resolved` | |

When the same vulnerability × component pair carries conflicting statuses across findings, the **least-resolved status wins** — exporting `resolved` while any observation is still active would be the dangerous direction to be wrong in.

### VEX for one release

```
GET /api/v2/sbom/{asset_id}/vex/?version=5.2.0
```

With Asset Versions enabled, a VEX document can answer for a single release. A Finding carrying a `fixed_in` record for the requested version is reported `resolved` there, while the same Finding stays exploitable at the versions where it was found and on the Asset overall. That is the point of the model: one Finding row, per-version answers, rather than a copy of every Finding in every release.

Two deliberate conservatisms:

- A Finding mitigated on the Asset, but with no `fixed_in` record for the requested version, **keeps its status** for that version. Claiming a fix in a release requires evidence for that release.
- Nothing is inferred across versions. A Finding found in 5.0 and fixed in 5.2 says nothing here about 5.1, because version strings carry no ordering (see [Asset Versions](../pro__working_with_sboms/#asset-versions-and-bom-snapshots)).
