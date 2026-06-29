---
title: "CVSS Version Support"
description: "Which CVSS versions DefectDojo stores, displays, and accepts on Findings"
weight: 5
---

DefectDojo supports CVSS metadata on Findings, including the CVSS 4.0 standard.  This page describes which CVSS versions are stored end-to-end, where you can enter or view them, and what to expect from parser-side coverage.

## What DefectDojo stores

Findings can carry the following CVSS data:

| Version | Vector stored | Score stored | UI vector builder & calculator |
| --- | --- | --- | --- |
| **CVSS v4.0** | ✅ | ✅ | ✅ (Pro UI) |
| **CVSS v3 (v3.0 / v3.1)** | ✅ | ✅ | ✅ (Pro UI) |
| **CVSS v2** | Stored implicitly via the Finding's **Severity** field; no separate v2 vector field is stored | N/A | N/A |

Each Finding has dedicated `cvssv3` / `cvssv3_score` and `cvssv4` / `cvssv4_score` fields on the underlying model.  These are accessible via the API as well as the UI.

## Where to enter CVSS data manually

Both CVSSv3 and CVSSv4 can be entered manually on a Finding:

- **Edit Finding form** — paste a full CVSS vector string into the corresponding field.  When you save, DefectDojo parses the vector and computes the score automatically.
- **Vector builder (Pro UI)** — click the 🛠️ button next to the CVSSv3 or CVSSv4 entry on the Edit Finding form to open the vector builder.  Build the vector interactively, then click the calculator button to render a score from the resulting vector.

> CVSSv4 vector strings and the vector builder were added to the Pro UI in v2.50.3 (Sept 22, 2025), and the explicit calculator button alongside it landed in v2.51.1 (Oct 14, 2025).

## Display settings

The Finding view honors two system settings that control whether CVSSv3 and CVSSv4 data renders for users:

- **Enable CVSS 3 Display** — show CVSSv3 vectors and scores on Findings.
- **Enable CVSS 4 Display** — show CVSSv4 vectors and scores on Findings.

Both can be set independently under System Settings.  If both are enabled, both versions display side-by-side on Findings that carry both.

## Parser and tool coverage

DefectDojo can store CVSSv4 data on any Finding, but **whether a given parser populates the CVSSv4 fields depends on the upstream tool**:

- If the upstream tool emits CVSSv4 vectors or scores in its export format, the parser will typically map those fields.
- If the tool only emits CVSSv2 or CVSSv3 data, the parser will not synthesize a v4 vector — there is no v3-to-v4 conversion built in.
- Some older parsers may not yet map CVSSv4 fields even if the upstream tool emits them.  If you find a parser that omits CVSSv4 fields from a tool that does emit them, please raise an issue.

In the meantime, two paths give you full CVSSv4 coverage regardless of parser support:

1. **[Generic Findings Import](/supported_tools/parsers/generic_findings_import/)** — accepts `CVSSV4` (vector) and `CVSSV4_score` columns in CSV, and `cvssv4` / `cvssv4_score` keys in JSON.
2. **[Universal Parser](/import_data/pro/specialized_import/universal_parser/)** (Pro) — supports CVSSv4 vectors as a mappable field (added in v2.57.0, Apr 7, 2026).  Use this when your tool emits JSON or CSV with custom field names that the built-in parsers do not map.

Manual entry on the Edit Finding form remains available as the universal fallback for any tool or report that does not flow CVSSv4 through automatically.
