---
title: "Cyberwatch"
description: "How to set up the Cyberwatch Upstream Connector for DefectDojo"
weight: 43
audience: pro
---
The Cyberwatch connector imports **CVEs and security (compliance) issues** from a Cyberwatch appliance, both kinds in a single Sync. DefectDojo creates a Record for each asset, or "server", the appliance knows about.

#### Prerequisites

A Cyberwatch **API key ID and secret key**, created in the appliance under **Profile \> API keys**. The secret is never logged.

#### Connector Mappings

1. Enter your Cyberwatch appliance URL in the **Location** field.
2. Enter the API key ID in the **API Key** field.
3. Enter the secret in the **Secret Key** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset becomes a Record, carrying both its CVEs and its compliance findings.

#### What a Sync imports

- **CVEs that are still open on the asset.** When Cyberwatch knows which installed software a CVE affects, there is one Finding per affected package, titled "CVE-XXXX-YYYY on *package*", with the package and its installed version as the component and the update that fixes it as the mitigation. A CVE affecting several packages on the same asset (for example one install per language of an office suite) becomes one Finding for each. Severity comes from the CVE's CVSS base score; a CVE Cyberwatch has not scored is imported as **Medium**. The EPSS score is carried over as well.
- **Security issues that are still active on the asset.** When one Cyberwatch rule applies to several items on the same asset, such as an "Obsolete application" rule that matches several outdated programs, each item is its own Finding, and the affected item is named in its title.

Every Finding is attached to the asset's hostname. A CVE that Cyberwatch marks as fixed, or a security issue that is no longer active, drops out of the next Sync, and DefectDojo then mitigates the matching Finding.

The connector reads the Cyberwatch API directly. The **Cyberwatch scan (Galeax)** file import is separate: it reads the JSON file produced by Galeax's export tool, not an API response.
