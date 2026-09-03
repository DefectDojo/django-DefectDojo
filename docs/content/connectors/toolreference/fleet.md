---
title: "Fleet"
description: "How to set up the Fleet Upstream Connector for DefectDojo"
weight: 58
audience: pro
---
The Fleet connector imports **software vulnerabilities** and **failing compliance policies** from Fleet, as two separate finding types. DefectDojo creates a Record for each Fleet **team**.

Hosts that belong to no team still carry real vulnerabilities, so they are mapped to a synthetic **"No team"** Record rather than being dropped.

> **Teams are a Fleet Premium feature.** On a free Fleet deployment the team list is unavailable, so **every host** lands in the single synthetic Record. That is expected, not a mapping failure.

#### Prerequisites

A Fleet **API token**, from **Account Settings \> Get API token**. The connector needs **read access only** — on Fleet Premium you can issue a scoped API\-only user for it.

#### Connector Mappings

1. Enter your Fleet server URL in the **Location** field.
2. Enter the API token in the **API Token** field.
3. Optionally, enable **Skip software vulnerabilities** to leave out CVEs found on installed software. Leave it off to import them.
4. Optionally, enable **Skip compliance policies** to leave out failing osquery policy checks. Leave it off to import them under their own scan type.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Both imports are on by default — the two toggles exist to turn each off if you only want one kind of finding in DefectDojo.
