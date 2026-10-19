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

#### Business Criticality

Each sync copies the CI's **Business Criticality** onto its Asset's **Criticality**, so the [Priority](/asset_modelling/pro_hierarchy/priority_sla/) of every Finding on the Asset reflects what your CMDB says about it. ServiceNow's values map like this:

| ServiceNow Business Criticality | DefectDojo Criticality |
| --- | --- |
| 1 - most critical | Very High |
| 2 - somewhat critical | High |
| 3 - less critical | Medium |
| 4 - not critical | Low |

The same values without their number prefix map the same way, and an instance whose choice list uses DefectDojo's own names (Very High, High, Medium, Low, Very Low, None) maps them directly. Matching ignores case.

Two rules keep the sync from overruling anyone:

* **A criticality a person set is never overwritten.** The connector only updates a Criticality it wrote itself and nobody has changed since. Once someone edits the field, in the UI or through the API, the CMDB stops updating it for that Asset. An Asset whose Criticality was already set before its first sync counts as set by a person.
* **A value the mapping does not cover is skipped,** with a warning in the sync log, rather than guessed at. The Asset keeps the Criticality it had.

A change in Criticality recalculates the Priority of the Asset's Findings.

#### Asset Type

The CI class also sets each Asset's [type](/asset_modelling/engagements_tests/pro__assets/#asset-types): servers and computers (for example `cmdb_ci_server`, `cmdb_ci_linux_server`, `cmdb_ci_computer`) are hosts, applications and services (`cmdb_ci_business_app`, `cmdb_ci_service`, `cmdb_ci_appl`) are services, and network gear (`cmdb_ci_netgear`, `cmdb_ci_ip_router`, `cmdb_ci_ip_switch`) is a device. A class DefectDojo does not map leaves the Asset unclassified, and a type someone set by hand is never overwritten.
