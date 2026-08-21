---
title: "Cobalt.io"
description: "How to set up the Cobalt.io Upstream Connector for DefectDojo"
weight: 37
audience: pro
---
The Cobalt.io connector uses the Cobalt.io API (v2) to pull pentest findings from your Cobalt.io organization. DefectDojo discovers every organization your API token can access and creates a separate Record for each **asset** (the unit Cobalt pentests).

#### Prerequisites

You will need a Cobalt.io **personal API token**. We recommend creating a dedicated service account for DefectDojo to clearly distinguish automated activity from manual team actions. Generate a token from **Settings \> API Tokens** in the Cobalt.io UI. Organization tokens are discovered automatically \- you do not need to supply them.

#### Connector Mappings

1. Enter the Cobalt.io API base URL in the **Location** field: `https://api.cobalt.io` (or your regional host, for example `https://api.us.cobalt.io`).
2. Enter your **personal API token** in the **Secret** field.
3. Optionally, enter an **Organization Token** to pin the sync to a single organization. When left blank, DefectDojo syncs every organization the personal API token can access.

DefectDojo maps each Cobalt.io **asset** as a separate Record. Findings are imported for each mapped asset, with their Cobalt.io state (for example `valid_fix`, `wont_fix`, `invalid`) driving the finding status in DefectDojo.
