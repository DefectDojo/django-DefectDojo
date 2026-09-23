---
title: "Shodan"
description: "How to set up the Shodan Upstream Connector for DefectDojo"
weight: 123
audience: pro
---
The Shodan connector uses the Shodan REST API to import the vulnerabilities (CVEs) Shodan has observed on your internet-exposed hosts. You provide a Shodan search query that scopes the import to your own assets; DefectDojo creates a Record for each matching host and imports its CVEs as findings.

#### Prerequisites

You will need a Shodan API key, found on your Shodan **Account** page. Host search with vulnerability data requires a Shodan membership or a paid API plan — the free tier cannot page through search results.

#### Connector Mappings

1. Enter `https://api.shodan.io` in the **Location** field.
2. Enter your Shodan API key in the **API Key** field.
3. In the **Search Query** field, enter a Shodan query that scopes the import to your organization's assets — for example `hostname:example.com`, `net:203.0.113.0/24`, or `org:"Example Inc"`. Only hosts matching this query are imported, so keep it scoped to infrastructure you own.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each matching host becomes a Record, and each CVE Shodan detected on that host's exposed services is imported as a finding — severity is derived from the CVSS score, with EPSS and CISA KEV context included where available. Each page of search results consumes one Shodan query credit.
