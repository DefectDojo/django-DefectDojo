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
