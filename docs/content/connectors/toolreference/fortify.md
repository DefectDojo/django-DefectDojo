---
title: "Fortify"
description: "How to set up the Fortify Upstream Connector for DefectDojo"
weight: 59
audience: pro
---
The Fortify connector imports SAST/DAST results from Fortify (OpenText/Micro Focus), covering both editions that share the platform: **SSC** (Software Security Center, self-hosted) and **Fortify on Demand (FoD)** (SaaS). It syncs the whole account: DefectDojo discovers every application (SSC project version / FoD release) and creates a Record for each, then imports that application's issues as findings.

#### Prerequisites

- **SSC**: a **FortifyToken** — create one in the SSC UI under **Administration → Token Management** (a CIToken/UnifiedLoginToken).
- **FoD**: an **OAuth2 API key** — a Client ID and Client Secret from **Settings → API** (with the `api-tenant` scope).

The token and OAuth secret are never logged.

#### Connector Mappings

1. Enter the Fortify base URL in the **Location** field: for SSC your server host (the connector adds `/ssc/api/v1`); for FoD the API host for your region, e.g. `https://api.ams.fortify.com`.
2. Set **Edition** to `SSC` or `FoD`.
3. For **FoD**, enter the OAuth **Client ID**; leave it blank for SSC.
4. In **Token / Client Secret**, enter the SSC FortifyToken or the FoD OAuth client secret.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each Fortify **application** to a Record and each **issue** to a finding: the severity comes from Fortify's own **friority** rating (Critical/High/Medium/Low), the title combines the issue category with its file and line, and the file path, line, kingdom, analyzer and engine type are carried over. Issues from static-analysis engines (SCA) are recorded as static findings and WebInspect (DAST) issues as dynamic findings; suppressed, removed and hidden issues are skipped, issues audited "Not an Issue" are marked false positive, and "Exploitable"/reviewed issues are marked verified.

See the [Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/) and [Fortify on Demand](https://api.ams.fortify.com/swagger/ui) API documentation for more information.
