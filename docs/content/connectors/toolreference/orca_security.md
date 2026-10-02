---
title: "Orca Security"
description: "How to set up the Orca Security Upstream Connector for DefectDojo"
weight: 100
audience: pro
---
The Orca Security connector imports **open alerts** from Orca — vulnerabilities, misconfigurations, malware and secrets alike. DefectDojo creates a Record for each **connected cloud account**.

#### Prerequisites

An Orca **API token**.

**Orca tokens are region-scoped**, so the token and the API host must belong to the same region. If a Sync fails to authenticate with a token you know is valid, check that the **Location** matches the token's region.

#### Connector Mappings

1. Enter your **region-matched** Orca API host in the **Location** field.
2. Enter your Orca API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each connected cloud account becomes a Record. Only **open** alerts are imported, so alerts you close in Orca are reflected in DefectDojo on the next Sync.
