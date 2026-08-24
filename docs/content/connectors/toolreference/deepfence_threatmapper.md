---
title: "Deepfence ThreatMapper"
description: "How to set up the Deepfence ThreatMapper Upstream Connector for DefectDojo"
weight: 46
audience: pro
---
The Deepfence ThreatMapper connector uses the [ThreatMapper](https://github.com/deepfence/ThreatMapper) management-console REST API to import **vulnerability scan** results. DefectDojo discovers every node ThreatMapper has scanned — a container image, host, or container — and creates a Record for each, then imports that node's most recent completed scan as findings.

#### Prerequisites

You will need a ThreatMapper **API token**, found in the console under **Settings → User Management** (your user's API key). The connector exchanges it for a short-lived access token on each sync; the API token is never logged.

#### Connector Mappings

1. Enter your ThreatMapper console URL in the **Location** field (for example `https://threatmapper.example.com`).
2. In the **Secret** field, enter the ThreatMapper API token.
3. If your console uses a self-signed certificate, set **Skip TLS Verification** to `true`.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each scanned **node** to a Record and each **CVE** in its latest completed vulnerability scan to a finding. The severity comes from ThreatMapper's own rating, and the affected package, CVSS score, fix version (as mitigation), reference links, and a details block are carried over. Findings are recorded as dynamic findings and de-duplicated on the node, CVE, package and package path.

See the [ThreatMapper documentation](https://community.deepfence.io/threatmapper/docs/v2.5/) for more information.
