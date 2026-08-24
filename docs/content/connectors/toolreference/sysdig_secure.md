---
title: "Sysdig Secure"
description: "How to set up the Sysdig Secure Upstream Connector for DefectDojo"
weight: 130
audience: pro
---
The Sysdig Secure connector imports **container / CNAPP vulnerability findings** from Sysdig Secure's vulnerability management API. It syncs the whole account across the configured scope(s) and creates a DefectDojo product for each scanned asset grouping.

#### Prerequisites

A Sysdig Secure **API token**: in Sysdig Secure, go to **Settings \> Sysdig Secure API Token** and copy the token. You also need your Sysdig **region URL** (for example `https://us2.app.sysdig.com`, `https://eu1.app.sysdig.com`, or your on\-premises host).

#### Connector Mappings

1. Enter your Sysdig region/base URL in the **Location** field.
2. Enter the API token in the **Secret** field.
3. Optionally set **Scopes** — a comma\-separated list of `runtime`, `registry`, and/or `pipeline` (leave blank for `runtime`, the deployed\-workload scope).
4. Optionally set **Runtime Asset Grouping** — how runtime results map to Assets: `cluster`, `namespace`, `workload`, or `image` (leave blank for `namespace`). Registry and pipeline results always group by image repository.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset grouping becomes a Record. For each scan result the connector imports every vulnerable package as a finding. **Runtime** findings (deployed workloads) are recorded as dynamic findings and tagged with their Kubernetes cluster / namespace / workload / container context; **registry** and **pipeline** findings are recorded as static image\-scan findings. Sysdig's `NEGLIGIBLE` severity maps to Info.
