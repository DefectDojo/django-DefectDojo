---
title: "ServiceNow CMDB"
description: "How to set up the ServiceNow CMDB Upstream Connector for DefectDojo"
weight: 121
audience: pro
---
The ServiceNow CMDB connector is an **Asset Connector**: instead of importing findings, it reads Configuration Items (CIs) from your ServiceNow Configuration Management Database and creates a DefectDojo Asset for each CI, grouped into Organizations by CI class. No findings are imported.

#### Prerequisites

You will need a ServiceNow instance and an account that can read the CMDB tables over the ServiceNow Table API. We recommend a dedicated, read-only service account for DefectDojo. The account needs read access to the `cmdb_ci` tables you want to import.

#### Connector Mappings

1. Enter your ServiceNow instance URL in the **Location** field: `https://{your-instance}.service-now.com`.
2. Select or create a ServiceNow **Tool Configuration** holding the instance credentials (the ServiceNow username and password).

Each Configuration Item becomes a Record named after the CI, grouped by its **CI class** (for example, application, server, or business service). Discovery and Sync reconcile the CI list: new CIs appear as `NEW` Records, and a CI removed from the CMDB is flagged `MISSING` on the next Sync so your team can triage it. DefectDojo never silently deletes an Asset.
