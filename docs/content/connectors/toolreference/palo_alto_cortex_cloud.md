---
title: "Palo Alto Cortex Cloud"
description: "How to set up the Palo Alto Cortex Cloud Upstream Connector for DefectDojo"
weight: 102
audience: pro
---
The Cortex Cloud connector (formerly **Prisma Cloud**) imports **cloud\-posture alerts** as findings (`Cortex Cloud:Posture`). DefectDojo creates a Record for each onboarded **cloud account**.

#### Prerequisites

A Prisma Cloud **Access Key** — an **Access Key ID** and a **Secret Key** — created under **Settings \> Access Control \> Access Keys**, and left **enabled** (the connector exchanges it at `/login` for a short\-lived token).

An access key inherits the **Role** of the user that created it, so that user's role must grant **View** access to **Cloud Accounts** (required, for account discovery) and **Alerts** (for the posture findings). A built\-in **Account Group Read Only** role, or a custom permission group with those two view permissions, is the minimum.

#### Connector Mappings

1. Enter your Prisma Cloud **API URL** in the **Location** field, matching your tenant's region — for example `https://api.prismacloud.io`, `https://api2.prismacloud.io`, or `https://api.eu.prismacloud.io`.
2. Enter the **Access Key ID**.
3. Enter the **Secret Key**.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each cloud account becomes a Record; only **open** posture alerts are imported.
