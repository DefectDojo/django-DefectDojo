---
title: "Exporting SBOMs and VEX"
description: "Export an Asset's dependency inventory as CycloneDX or SPDX, and its finding statuses as a CycloneDX VEX document"
audience: pro
weight: 7
---

DefectDojo Pro can serialize an Asset's current dependency inventory back out as a standards-compliant SBOM, and its vulnerability triage decisions as a machine-readable VEX document. Both are produced from the same [Dependency Locations](../pro__working_with_sboms/) that SBOM imports and scan findings populate, so whatever your scanners and uploads have accumulated is what the export describes — the documents are consumed by downstream tooling, compliance pipelines, and AI agents, not just humans.

Both endpoints require **V3 Locations** to be enabled, and respect Asset-level permissions: an Asset the requesting user cannot view returns a 404.

## Exporting an SBOM

```
GET /api/v2/sbom/{asset_id}/
GET /api/v2/sbom/{asset_id}/?spec=spdx
```

| Parameter | Values | Default |
| --- | --- | --- |
| `spec` | `cyclonedx` (CycloneDX 1.6 JSON), `spdx` (SPDX 2.3 JSON) | `cyclonedx` |

The response is a downloadable JSON document (`Content-Disposition: attachment`). Components carry their Package URL, group/namespace, version, artifact hashes (algorithms each specification supports), and — when the SBOM import recorded one — the license expression for this Asset's use of the component.

Two current-state boundaries to be aware of:

- The export describes the Asset's **current** inventory. Version-pinned snapshots (the SBOM of release 5.2 specifically) are on the roadmap alongside Asset versions.
- Imports flatten the dependency graph today, so the exported `dependencies` section declares root → component edges only.

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
