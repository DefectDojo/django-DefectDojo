---
title: "Exporting an AIBOM"
description: "Export an Asset's AI inventory as a CycloneDX 1.6 AI bill of materials, with evidence and authorization decisions"
weight: 10
audience: pro
---

An **AI bill of materials (AIBOM)** lists the AI components in an Asset: coding assistants, MCP servers, models, AI packages, AI services and agent skills. DefectDojo produces it as a CycloneDX 1.6 document from the [AI Inventory](../pro__ai_inventory/). It is the same export as the [SBOM](../pro__exporting_sboms_and_vex/), limited to the AI components, so the two pair by `bom-ref`.

> The AIBOM needs the **AI Inventory and Governance** feature (beta) turned on from the [Feature Flags page](/admin/feature_flags/pro__feature_flags/).

## From the Asset Page

On an Asset, open **Locations > Export SBOM & VEX** and choose **AI bill of materials (AIBOM)** as the export type. The format is CycloneDX 1.6. The file downloads as `<asset>-aibom.cdx.json`.

## From the API

```http
GET /api/v2/sbom/{asset_id}/?profile=ai
GET /api/v2/sbom/{asset_id}/?profile=ai&version=5.2.0
```

`profile=ai` is CycloneDX only. With `version`, the components are the ones that version's BOM snapshot recorded, and their AI facts are the Asset's current ones.

## What the Document Contains

- **Real component types.** `application` for assistants and skills, `library` for packages and packaged MCP servers, `machine-learning-model` for models. Remote AI APIs and remote MCP servers go in `services[]` with their endpoints.
- **A model card** for models when the task is known, such as `text-generation`.
- **DefectDojo properties** on every entry, using the same names the scanner writes:
  - `defectdojo:ai:category`, for example `mcp-server` or `sdk`;
  - `defectdojo:ai:provider`;
  - `defectdojo:ai:evidence`, one property per file path or config key;
  - `defectdojo:ai:authorization`: `authorized`, `unauthorized`, or `needs_review` when no policy has decided yet.

Component types also changed in the ordinary SBOM export: applications, models and services are exported with their real CycloneDX types instead of all being `library`.
