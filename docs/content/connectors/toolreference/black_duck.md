---
title: "Black Duck"
description: "How to set up the Black Duck Upstream Connector for DefectDojo"
weight: 26
audience: pro
---
The Black Duck connector imports **software composition analysis (SCA)** findings from a Black Duck (Synopsys / Black Duck) Hub instance. DefectDojo discovers every project in the instance and creates a Record for each **project**; the findings for a project come from the vulnerable BOM components of its selected version.

#### Prerequisites

A Black Duck **API token** for a user that can see the projects you want to import. In Black Duck, open your user menu \> **My Access Tokens** \> **Create New Token**, grant it (at least) read access, and copy the token when it is shown — it is displayed only once. The connector exchanges this token for a short\-lived bearer on each sync; it is never stored in cleartext beyond the connector's secret field.

#### Connector Mappings

1. Enter your Black Duck hub URL in the **Location** field — for example `https://your-company.app.blackduck.com`.
2. Enter the API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Black Duck project becomes a Record. By default the connector imports the project's **released** version (falling back to its first version); each vulnerable BOM component of that version becomes a finding, titled `{vulnerability} in {component}:{version}`.

This connector is distinct from the file-based Black Duck parsers — its findings use the dedicated **Black Duck - Connectors Import** scan type.
