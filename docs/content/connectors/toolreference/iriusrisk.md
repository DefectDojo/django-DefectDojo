---
title: "IriusRisk"
description: "How to set up the IriusRisk Upstream Connector for DefectDojo"
weight: 80
audience: pro
---
The IriusRisk connector uses an API token to pull threat modeling data from your IriusRisk instance.

#### Prerequisites

You will need an API token from your IriusRisk account. We recommend creating a dedicated service account for DefectDojo to clearly distinguish automated activity from manual team actions.

To generate an API token in IriusRisk:

1. Log in to your IriusRisk instance.
2. Navigate to your **User Profile** in the top-right menu.
3. Select **API Token** and generate a new token.

See the [IriusRisk API documentation](https://support.iriusrisk.com/hc/en-us/categories/360001148511) for more information.

#### Connector Mappings

1. Enter your IriusRisk instance URL in the **Location URL** field. For cloud-hosted instances this is typically `https://{your-subdomain}.iriusrisk.com`. For on-premise installations, use your instance's base URL.
2. Enter your **API Token** in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity will not be imported.
