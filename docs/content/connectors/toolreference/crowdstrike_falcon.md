---
title: "CrowdStrike Falcon"
description: "How to set up the CrowdStrike Falcon Upstream Connector for DefectDojo"
weight: 41
audience: pro
---
The CrowdStrike Falcon connector imports **Spotlight vulnerabilities** and **EDR detections** from the Falcon platform, as two separate finding types (`CrowdStrike:Spotlight` and `CrowdStrike:Detections`). DefectDojo creates a Record for each Falcon **host**.

#### Prerequisites

A Falcon **API client** (Client ID and secret), created in the Falcon console under **Support \> API Clients and Keys**. Grant it the scopes for the data you want to import: **Hosts: Read** (required, for host discovery), **Vulnerabilities (Spotlight): Read** (for Spotlight findings), and **Alerts: Read** (for EDR detections). The two finding types are independent — if the client lacks a scope, that finding type is skipped rather than failing the sync, so a client without **Alerts: Read** still imports Spotlight vulnerabilities.

#### Connector Mappings

1. Enter your Falcon cloud's API base URL in the **Location** field, matching your console region — for example `https://api.crowdstrike.com` (US\-1), `https://api.us-2.crowdstrike.com` (US\-2), `https://api.eu-1.crowdstrike.com` (EU\-1), or `https://api.laggar.gcw.crowdstrike.com` (US\-GOV\-1).
2. Enter the API client's Client ID in the **Client ID** field.
3. Enter the API client's secret in the **Client Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Falcon host becomes a Record, named for its hostname, OS, and type. Only **open** and **reopened** Spotlight vulnerabilities are imported, so reimport closes remediated findings.
