---
title: "HCL AppScan"
description: "How to set up the HCL AppScan Upstream Connector for DefectDojo"
weight: 73
audience: pro
---
The HCL AppScan connector uses the AppScan v4 REST API to import issues from **AppScan on Cloud (ASoC)** or a self-hosted **AppScan 360°** (both share the API). It syncs the whole account: DefectDojo discovers every application and creates a Record for each, then imports that application's issues (DAST, SAST and IAST) as findings.

#### Prerequisites

You will need an AppScan **API key** — a Key ID and Key Secret generated under your AppScan account settings (API Key). The connector exchanges them for a short-lived session token on each run; the Key ID, Key Secret and token are never logged.

#### Connector Mappings

1. Enter the AppScan console URL in the **Location** field: for ASoC use `https://cloud.appscan.com` (or `https://eu.cloud.appscan.com` for the EU region); for AppScan 360° use your instance host.
2. Set **Provider** to `ASOC` for AppScan on Cloud, or `A360` for a self-hosted AppScan 360°.
3. Enter the **API Key ID** and **API Key Secret**.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each AppScan **application** to a Record (VEP) and each **issue** to a finding: the title is the issue type with its domain / entity / cause-id / URL / path appended; the severity maps Informational → Info (Low/Medium/High/Critical pass through); the CWE, a labeled description, the remediation and advisory, and the host/port endpoint are carried over. Issues from static analysis are recorded as static findings and dynamic/interactive issues as dynamic findings; open issues are active and fixed/passed issues are mitigated.

See the [AppScan REST API documentation](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html) for more information.
