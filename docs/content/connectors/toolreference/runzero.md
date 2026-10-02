---
title: "runZero"
description: "How to set up the runZero Upstream Connector for DefectDojo"
weight: 115
audience: pro
---
The runZero connector uses the runZero Export API to sync your whole organization's asset inventory into DefectDojo. It is primarily an **asset** connector: DefectDojo discovers every asset and creates a Record for each, grouped into an Organization by its runZero **site**. It can optionally also import runZero's vulnerabilities as findings.

#### Prerequisites

You will need an organization **Export Token** from runZero (Account → API), which is prefixed `XT`. The token is organization-scoped (the organization is encoded in the token), read-only, and is sent as a Bearer token — it is never logged. A community/starter tier is available.

#### Connector Mappings

1. Enter your runZero console URL in the **Location** field, for example `https://console.runzero.com`. The URL must be HTTPS.
2. Enter the Export Token in the **Secret** field.
3. Optionally set **Import Vulnerabilities** to `true` to also import runZero vulnerabilities as findings; leave it blank to sync assets only.
4. Optionally, set a **Minimum Severity** to limit which vulnerability findings are imported (applies only when vulnerabilities are imported).

DefectDojo maps each runZero **asset** to a Record (VEP): the display name comes from the asset's name or address, and its site, type, OS, addresses and tags are attached as attributes; the asset's **site** becomes its Organization. Assets are synced with a full export that DefectDojo reconciles (adds/removes). When **Import Vulnerabilities** is enabled, each runZero vulnerability becomes a finding on its asset — mapping the severity, CVSS score, CVE, affected service (`protocol://address:port`) endpoint and the remediation.

See the [runZero API documentation](https://help.runzero.com/) for more information.
