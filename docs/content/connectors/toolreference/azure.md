---
title: "Microsoft Azure"
description: "How to set up the Microsoft Azure Upstream Connector for DefectDojo"
weight: 147
audience: pro
---
The Microsoft Azure connector is an **asset connector**: instead of importing Findings, it reads your Azure tenant and creates one Asset per subscription, grouped by management group. Use it so the subscriptions your Microsoft Defender for Cloud findings land against already exist in DefectDojo instead of being created by hand.

#### What gets mapped

| Azure | DefectDojo |
|---|---|
| **Subscription** | Asset, named `<subscription name> (Azure Subscription: <subscription id>)` |
| **Management group** | Asset, named `<group name> (Azure Management Group: <group id>)`, and the Organization of everything directly beneath it |
| **Management group tree** | Asset hierarchy: tenant root group → management group → subscription |
| Subscription tags | Recorded on the Record in the `TAGS` attribute |

Subscription Assets use the same name Microsoft Defender for Cloud uses, so if you run both connectors, the findings land on the Asset this connector created rather than a duplicate.

Only **Enabled** and **Warned** subscriptions are imported. A subscription that is disabled or deleted drops out of the next sync and its Record is marked **MISSING** — DefectDojo never deletes an Asset on its own.

Individual Azure resources (virtual machines, App Services, AKS clusters, storage accounts) are not Assets. They arrive separately as Locations attached to these Assets.

#### Prerequisites

Create an Entra ID app registration and give it read access to Azure Resource Manager:

1. In the Azure portal, go to **Microsoft Entra ID > App registrations > New registration** and register an application for DefectDojo.
2. On the app's **Certificates & secrets** page, create a **client secret** and copy the value.
3. Assign the app's service principal the built-in **Reader** role at the **tenant root management group** (**Management groups > Tenant Root Group > Access control (IAM) > Add role assignment**). Reader at the root covers every management group and every subscription beneath it in one assignment.

Note the **Directory (tenant) ID** and the **Application (client) ID** from the app's Overview page.

#### If you cannot grant Reader at the root management group

Management group access is granted separately from subscription access, and many organizations do not hand it out. The connector handles that: if it cannot read your management groups, it logs a warning and imports a flat list of subscriptions with no hierarchy and no Organization grouping. Nothing fails. Grant the root assignment later and the hierarchy appears on the next Discover.

#### Connector Mappings

1. Enter `https://management.azure.com` in the **Location URL** field.
2. Enter the **Tenant ID**, **Client ID**, and **Client Secret** from the app registration.
3. Leave **Login URL** blank. Set it only for a sovereign cloud (for example `https://login.microsoftonline.us`), where the Location URL changes too.

With **Auto-Map** enabled, one Discover plus one Sync builds the whole Organization / Asset / hierarchy structure. With Auto-Map disabled, the discovered subscriptions and management groups appear as Records waiting for your mapping decision.

#### Limitations (v1)

* **Moving a subscription to a different management group does not move the Asset.** DefectDojo never overwrites an existing hierarchy edge. Re-map the Record to pick up the new parent.
* Renames in Azure do not rename an Asset that is already mapped. The Record keeps the name it had at mapping time.
* Resource groups are not imported as an extra hierarchy level.
* Sovereign clouds (US Gov, China) are untested.
