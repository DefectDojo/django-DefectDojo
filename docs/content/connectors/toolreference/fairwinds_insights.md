---
title: "Fairwinds Insights"
description: "How to set up the Fairwinds Insights Upstream Connector for DefectDojo"
weight: 56
audience: pro
---
The Fairwinds Insights connector uses the [Fairwinds Insights](https://insights.fairwinds.com) REST API to import **Kubernetes security findings** across your whole organization. DefectDojo enumerates every active **cluster** and creates a Record for each one, then imports that cluster's Security **action items** \(from Polaris, Trivy, Kube\-bench, OPA and the other Insights reports\) as findings — there is no per\-cluster configuration.

#### Prerequisites

You will need a Fairwinds Insights **organization** name and an **API token**. Create the token in the Insights app under **Organization Settings \> Tokens**; a `read_only` token is sufficient. The token is org\-scoped and is sent as a bearer token; it is never logged.

#### Connector Mappings

1. Keep the pre-filled **Location**, `https://insights.fairwinds.com`, or enter your Insights host explicitly.
2. Enter your Insights **Organization** name (the slug shown in your dashboard URL).
3. Enter the Insights API token in the **Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each active **cluster** to a Record and each Security **action item** to a finding: severity comes from Fairwinds' numeric score \(mapped to DefectDojo's Info–Critical\), the Fairwinds report that produced the item \(`polaris`, `trivy`, `kube-bench`, ...\) becomes a tool tag, the affected Kubernetes resource and container image are included, and any CVE identifiers are extracted. Findings are recorded as static findings and de\-duplicated on the Fairwinds action\-item id.

See the [Fairwinds Insights API documentation](https://insights.docs.fairwinds.com/technical-details/api/) for more information.
