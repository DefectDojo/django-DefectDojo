---
title: "Endor Labs"
description: "How to set up the Endor Labs Upstream Connector for DefectDojo"
weight: 54
audience: pro
---
The Endor Labs connector uses the Endor Labs REST API to sync an entire Endor Labs **namespace**. DefectDojo discovers each Endor **project** as a Record and imports that project's findings, carrying Endor's **reachability** verdict so you can prioritize vulnerabilities whose affected code is actually reachable.

#### Prerequisites

You will need an Endor Labs **API key** (a key identifier plus its secret) and the **namespace** you want to sync. Create the key in the Endor Labs platform under **Settings \> Access \> API Keys**; the key needs read access to the projects and findings in that namespace.

The connector authenticates by exchanging the API key and secret for a short-lived bearer token — the secret is used only for that exchange and is never stored in cleartext.

#### Connector Mappings

1. Enter `https://api.endorlabs.com` in the **Location** field. If your tenant is hosted in a different region, use that region's API base URL instead.
2. Enter the Endor Labs **Namespace** to sync (for example `your-org` or `your-org.team`).
3. Enter the **API Key** identifier.
4. Enter the **API Secret** paired with the key.
5. Optionally set **Traverse Child Namespaces** to `true` to also import findings from child namespaces of the configured namespace.
6. Optionally set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity are not imported.

DefectDojo creates a Record for each Endor Labs project in the namespace and imports its findings, mapping Endor severity levels to DefectDojo severities, the CVE/GHSA identifiers and CVSS score of each vulnerability, and Endor's reachability tags. The reachability verdict (for example *Reachable — vulnerable function is called* or *Unreachable*) is surfaced as the finding's Impact and as a tag.

For more information, see the **[Endor Labs REST API documentation](https://docs.endorlabs.com/rest-api/)**.
