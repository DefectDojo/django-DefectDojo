---
title: "Finite State"
description: "How to set up the Finite State Upstream Connector for DefectDojo"
weight: 57
audience: pro
---
The Finite State connector imports **firmware and embedded-device findings** from Finite State. DefectDojo creates a Record for each **Asset**, which in Finite State is a **product line** rather than an individual firmware build.

This matters for how your data is organized: a product line's findings are the union of its builds' findings, with the build recorded on each finding as a tag and in the description. One Record therefore accumulates the history of a firmware line, instead of fragmenting into a separate Record per release.

#### Prerequisites

A Finite State **API token**. It is sent in the `X-Authorization` header — not `Authorization` — which the connector handles for you.

#### Connector Mappings

1. Enter your Finite State subdomain in the **Location** field — for example `https://acme.finitestate.io`. DefectDojo appends the API path itself.
2. Enter the API token in the **API Token** field.
3. Optionally, set **Import Every Firmware Build** to `true` to import findings from **every** build of each asset. Leave it blank to import only the **newest** build, which is what most teams want.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Merged duplicates and deleted findings are excluded automatically, so they never reach DefectDojo.
