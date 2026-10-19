---
title: "CrowdStrike Falcon"
description: "How to set up the CrowdStrike Falcon Upstream Connector for DefectDojo"
weight: 41
audience: pro
---
The CrowdStrike Falcon connector imports **Spotlight vulnerabilities** and **EDR detections** from the Falcon platform, as two separate finding types (`CrowdStrike:Spotlight` and `CrowdStrike:Detections`). DefectDojo creates a Record for each Falcon **host**.

#### Prerequisites

A Falcon **API client** (Client ID and secret), created in the Falcon console under **Support \> API Clients and Keys**. Grant it the scopes for the data you want to import: **Hosts: Read** (required, for host discovery), **Vulnerabilities (Spotlight): Read** (for Spotlight findings), and **Alerts: Read** (for EDR detections). The two finding types are independent — if the client lacks a scope, that finding type is skipped rather than failing the sync, so a client without **Alerts: Read** still imports Spotlight vulnerabilities.

Create the API client in the CID that holds the hosts you want to import. If you use Falcon Flight Control, create it in the child CID the hosts belong to rather than in the parent CID. When you save the connector, DefectDojo reports how many hosts the client can see, and a client whose CID has no hosts is saved with a No Data Visible warning.

#### Connector Mappings

1. Enter your Falcon cloud's API base URL in the **Location** field, matching your console region — for example `https://api.crowdstrike.com` (US\-1), `https://api.us-2.crowdstrike.com` (US\-2), `https://api.eu-1.crowdstrike.com` (EU\-1), or `https://api.laggar.gcw.crowdstrike.com` (US\-GOV\-1).
2. Enter the API client's Client ID in the **Client ID** field.
3. Enter the API client's secret in the **Client Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Falcon host becomes a Record, named for its hostname, OS, and type. Only **open** and **reopened** Spotlight vulnerabilities are imported, so reimport closes remediated findings.

#### Asset Exposure

With [Asset Exposure](/triage_findings/finding_scoring/asset_exposure/) enabled, each sync also reads Spotlight's internet exposure assessment for the host. When Spotlight reports the host as internet-facing, the asset records **Externally Exposed**, with the hostname as evidence.

Spotlight's other answers record nothing. **Pending** means CrowdStrike has not finished assessing the host. **No** means only that the host is not internet-facing, which does not say whether it is isolated or reachable over a VPN or another network, so it is not treated as either.

The assessment comes from the host's Spotlight vulnerabilities, so it needs the **Vulnerabilities (Spotlight): Read** scope, and a host with no open Spotlight vulnerabilities at or above the connector's **Minimum Severity** reports no exposure. A client without that scope logs a warning and syncs everything else normally.
