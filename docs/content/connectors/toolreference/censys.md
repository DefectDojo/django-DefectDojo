---
title: "Censys"
description: "How to set up the Censys Upstream Connector for DefectDojo"
weight: 32
audience: pro
---
The Censys connector reads host assets from the Censys Platform and imports each host's exposed services as findings. It uses the Censys Platform global search API to enumerate the hosts you scope it to.

#### Prerequisites

You will need a Censys **Platform** account with API access:

* A **Personal Access Token**, created in the Censys Platform Console under Personal Access Tokens.
* Your **Organization ID**, shown on the same settings page under "Current Organization". API access to the search endpoint requires an organization, so a Starter tier or higher is needed. Free\-tier tokens have no organization ID and cannot use the search API.

Per\-host CVE and risk data is available only on Censys Core (enterprise) tiers, so on lower tiers findings represent exposed services rather than vulnerabilities.

See the [Censys Platform API documentation](https://docs.censys.com/reference/get-started) for more information.

#### Connector Mappings

1. Enter `https://api.platform.censys.io` in the **Location** field.
2. Enter your Personal Access Token in the **API Key** field.
3. Enter your **Organization ID**.
4. Enter a **Search Query** that scopes the import to your own assets, for example `host.autonomous_system.asn: <your ASN>` or `host.ip: 203.0.113.0/24`.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo creates a Record for each host and imports its exposed services as findings.
