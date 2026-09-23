---
title: "Acunetix 360"
description: "How to set up the Acunetix 360 Upstream Connector for DefectDojo"
weight: 12
audience: pro
---
The Acunetix 360 connector imports **DAST vulnerability findings** from the Acunetix 360 cloud platform (the Invicti platform). DefectDojo discovers your account's scanned websites and creates a Record for each **website**; the findings for a website come from its latest completed scan.

**Please note:** this connector is for **Acunetix 360** (the cloud product at `online.acunetix360.com`). It is not for the on\-premises Acunetix Standard/Premium scanner, which has a different API.

#### Prerequisites

An Acunetix 360 account and an **API credential**: in Acunetix 360, open your account menu \> **API Settings**, and note the **API User ID** and generate an **API Token**. The connector authenticates with these as HTTP Basic credentials, so a dedicated service account is recommended to distinguish automated activity from manual team actions.

#### Connector Mappings

1. Enter your Acunetix 360 URL in the **Location** field: `https://online.acunetix360.com`.
2. Enter the API User ID in the **API User ID** field.
3. Enter the API Token in the **API Token** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each scanned website becomes a Record. Findings come from the website's latest completed scan; vulnerabilities Acunetix 360 has marked **Accepted Risk** or **False Positive** are still imported but flagged inactive (risk\-accepted or false\-positive) so the DefectDojo product reflects the vendor's triage.
