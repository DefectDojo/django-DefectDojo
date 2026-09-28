---
title: "Mend"
description: "How to set up the Mend Upstream Connector for DefectDojo"
weight: 88
audience: pro
---
The Mend connector (formerly **WhiteSource**) uses the Mend API to import security findings from your Mend organization. DefectDojo creates a Record for each Mend **project**.

#### Prerequisites

You will need a Mend (service) user with a **User Key** (a personal access token) and your Mend **Organization UUID**. We recommend a dedicated service account so automated activity is easy to distinguish from manual team actions. Find the Organization UUID in the Mend App under **Administration > Organization UUID**.

#### Connector Mappings

1. Enter your Mend API URL in the **Location** field. This URL is **region-specific** — use the API base URL for the region your Mend organization is hosted in.
2. Enter the login email of the Mend user in the **Email** field.
3. Enter your Mend **Organization UUID** in the **Organization UUID** field.
4. Enter the Mend **User Key** in the **User Key** field.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.
