---
title: "Lacework / FortiCNAPP"
description: "How to set up the Lacework / FortiCNAPP Upstream Connector for DefectDojo"
weight: 86
audience: pro
---
The Lacework / FortiCNAPP connector uses the Lacework v2 API to import **host and container vulnerabilities** for your whole Lacework account.

#### Prerequisites

You will need a Lacework **API key** — an API key id and secret, created in the Lacework console under **Settings → API keys**. The connector exchanges these for a short-lived access token on each sync; the key id, secret and token are never logged.

#### Connector Mappings

1. Enter your Lacework account URL in the **Location** field — for example `https://YOUR-ACCOUNT.lacework.net` (a bare account name is also accepted).
2. Enter the **API Key ID** and **API Secret**.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps the Lacework **account** to a Record (the whole-account scope). Each **container** and **host** vulnerability becomes a finding: the severity comes from Lacework's own rating, the affected package and version become the component, the fix version becomes the mitigation, and the affected image/host is recorded as tags. Container vulnerabilities are recorded as static findings (image scans) and host vulnerabilities as dynamic findings (running-host scans).

See the [Lacework API documentation](https://docs.lacework.net/api/v2/docs) for more information.
