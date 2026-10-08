---
title: "Microsoft Defender for Cloud"
description: "How to set up the Microsoft Defender for Cloud Upstream Connector for DefectDojo"
weight: 90
audience: pro
---
The Microsoft Defender for Cloud connector imports vulnerability findings from **Microsoft Defender Vulnerability Management (MDVM)** as surfaced by Defender for Cloud — both **server** findings (Azure VM operating\-system and installed\-software CVEs) and **container\-registry** findings (container image CVEs), including severity, CVSS score, the affected package or image, and remediation. DefectDojo discovers the Azure **subscriptions** your service principal can read and creates a Record for each enabled subscription.

**Please note:** this Connector is distinct from the **Microsoft Defender** connector, which imports device findings from the Defender for Endpoint API. Defender for Cloud is an Azure Asset with a different API surface (Azure Resource Manager / Resource Graph) and permission model (Azure RBAC). Run whichever matches where your findings live — or both, if you use both Assets.

#### Prerequisites

You need one or more **Azure subscriptions with Microsoft Defender for Cloud enabled**, with the relevant Defender plans turned on for the resources you want scanned (under **Microsoft Defender for Cloud \> Environment settings**, then select your subscription):

* **Defender for Servers (Plan 2)** — Azure VM operating\-system and software CVE findings (agentless vulnerability scanning).
* **Defender for Containers** — container\-registry image CVE findings.

SQL vulnerability\-assessment and configuration/posture findings are intentionally **not** imported — this connector imports CVE vulnerabilities only.

The connector authenticates as a Microsoft Entra ID **app registration** using the client credentials flow:

1. In the [Azure portal](https://portal.azure.com), open **App registrations \> New registration**. Name it (for example `defectdojo-connector`), leave the defaults, and select **Register**.
2. On the app's **Overview** page, note the **Application (client) ID** and **Directory (tenant) ID**.
3. Open **Certificates & secrets \> New client secret**, set an expiry, and copy the secret **Value** immediately (it is shown only once). The Connector stops working when the secret expires, so note the date.
4. Grant the app read access to each subscription you want to import: open **Subscriptions**, select your subscription, then **Access control (IAM) \> Add \> Add role assignment**. Select the **Security Reader** role (or **Reader**), and on the **Members** tab assign it to the app you created — search for it by the app's **name** or **object ID**, as the picker does not match the client ID. Repeat for every subscription.

Unlike the device\-based Microsoft Defender connector, no API permissions or admin consent are required: Defender for Cloud access is governed entirely by the Azure RBAC role assignment above.

#### Connector Mappings

1. Enter `https://management.azure.com` in the **Location** field. (For sovereign clouds, use the matching ARM endpoint, for example `https://management.usgovcloudapi.net`.)
2. Enter the **Directory (tenant) ID** in the **Tenant ID** field.
3. Enter the **Application (client) ID** in the **Client ID** field.
4. Enter the client secret value in the **Client Secret** field.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each enabled Azure subscription becomes a Record. Findings are read through Azure Resource Graph, so they surface promptly once Defender for Cloud has scanned your resources — but the scans themselves run on Microsoft's schedule: container\-registry images are usually scanned within an hour of being pushed, while a VM's first agentless vulnerability scan can take several hours. A newly enabled subscription will legitimately Sync zero findings until its resources have been scanned.

#### Asset Grouping (optional)

By default the connector creates one Record, and so one asset, per Azure subscription. The **Asset Grouping** field, under **Import Filters** on the connector form, can split findings more finely:

| Asset Grouping | Records | Findings are imported on |
|---|---|---|
| **Subscription** (default) | one per subscription | the subscription Records |
| **Resource Group** | additionally, one per resource group under each subscription | the resource group Records |
| **Resource** | additionally, one per resource, under its resource group | the resource Records |

With **Resource**, a container image is not a resource of its own: every image of a container registry repository is grouped under that repository, because an image digest is a version of the repository. A resource outside any resource group is placed under a **No resource group** Record.

Resource Records are named `<resource> (<type>, <resource group>, <subscription>)`, for example `web-1 (VM, rg-web, Production / 00000000-0000-0000-0000-000000000000)` or `acr1/app (ACR repository, rg-registry, Production / ...)`. The subscription ID is always part of the name because subscription names are not unique.

With a finer grouping:

* The subscription Records keep the same identity and become **parent assets** with no findings of their own. When the Asset Hierarchy feature is enabled, DefectDojo relates each resource group asset to its subscription asset, and each resource asset to its resource group asset, with a `parent` relationship. Relationships created by the connector never overwrite relationships you created by hand.
* Each finding is imported once, on the asset of the resource it is about. The total number of findings is the same under every grouping.
* Resources are discovered from findings, so only resources with at least one open vulnerability at or above the minimum severity become Records. A resource whose last finding is fixed keeps its Record for 14 days so that the next Syncs close its findings, after which the Record is marked MISSING.
* Azure resource tags reach resource assets as asset tags, prefixed `azure:` (for example `azure:team:payments`). Tags you add yourself are never touched. Reading tags needs the **Reader** role on the subscription (Security Reader does not cover resource tags); without it, resource assets get no tags and nothing else changes.
* Container registry repository Records carry the repository's registry address, so the same repository reported by another connector can be recognized as the same asset.
* The connector makes one Azure Resource Graph query per Record on each Sync, paced below the Resource Graph throttling limit, so a Sync with thousands of resource Records takes longer than a subscription Sync. Memory use stays low because findings are processed one page at a time.

**Switching an existing connection to a finer grouping:** the field can be changed at any time. On the next discovery, the new Records appear for mapping; enable **Auto Map** on the connection when you change the grouping so findings move without a gap. On the next Sync, the subscription assets stop receiving findings and their previously imported findings are closed (the same findings are imported again on the new assets). Switching back reverses this: the subscription Records carry findings again (previously closed findings re-open as they re-match), and the finer Records close their findings and are then marked MISSING. Their assets are kept, so you can archive them at your convenience. Closing the findings of the parent assets needs DefectDojo and the connectors service from the same release or later.

#### Organization Placement (optional)

New assets from a Defender for Cloud connection are placed in the connector's default organization. The **Organization Placement** field can instead place them by Azure structure:

* **One per Subscription, Named by Subscription Name:** an organization per subscription, named after the subscription.
* **One per Subscription, Named by Subscription ID:** organizations named `Azure <subscription id>`.
* **One per Management Group:** an organization per nearest management group of the subscription, falling back to the subscription name when the management group cannot be read.

Organizations are created when they do not exist yet, and reused when they do. The field only affects assets created after it is set: assets that already exist are never moved.
