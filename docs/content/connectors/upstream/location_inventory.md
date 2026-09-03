---
title: "Location Inventory from Connectors"
description: "Let asset connectors populate Locations directly on their mapped asset"
pro-feature: true
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Upstream Connectors are a DefectDojo Pro-only feature. Location inventory is a Beta feature behind the **Connector Location Inventory** feature flag, and requires the **Locations** (V3) feature.</span>

Asset connectors can report the individual resources inside a mapped asset as **Locations**. A cloud connector maps its account, project, or subscription to a DefectDojo Product; the instances, buckets, functions, and databases inside it then appear as Locations on that Product. The resources appear without waiting for a finding to reference them, so your inventory is visible before anything is wrong with it.

## How it works

1. A sync first reconciles the connector's asset list, exactly as before.
2. For each mapped Record, the connector then retrieves the asset's current, complete resource inventory from the vendor.
3. DefectDojo creates or updates a Location for each resource, and attaches it to the mapped Product with an **Active** status.

No mapping triage is needed for individual Locations. The Record's Product mapping is the only mapping in the path: Locations attach directly to that Product.

## Reconciliation

Each sync carries the complete inventory, so absence is meaningful:

* If a resource disappears vendor-side, DefectDojo sets its Location reference to **Mitigated**. Locations are never deleted by a sync.
* If a resource reappears, its reference returns to **Active**.
* A connector only ever transitions the Location references it created itself. References created by finding imports, or by a different connector configuration, are never touched.

## Enabling it

1. Enable the **Locations** feature (Settings → Feature Flags). Location inventory writes V3 Location rows, so it requires this.
2. Enable the **Connector Location Inventory** feature flag.
3. Ask your administrator to set `DD_CONNECTORS_ASSET_LOCATIONS=true` on the connectors service. This path is off by default.

## Volume protection

One asset can carry a large resource inventory. The connectors service refuses to send more than a configurable ceiling of locations per Record (default 10,000, `DD_CONNECTORS_MAX_LOCATIONS_PER_RECORD`) and logs the count for every Record on every sync. If a Record exceeds the ceiling, that Record's location sync fails loudly and the rest of the sync continues.
