---
title: "Microsoft Defender"
description: "How to set up the Microsoft Defender Upstream Connector for DefectDojo"
weight: 89
audience: pro
---
The Microsoft Defender connector imports device vulnerability findings from **Microsoft Defender Vulnerability Management (MDVM)** — one finding per device / software version / CVE combination, including severity, CVSS score, exploitability level and recommended security updates. DefectDojo will discover your Defender **device groups** and create a Record for each one; devices that aren't assigned to any device group are collected under a synthetic **Unassigned** group.

Here a *device* is a single onboarded machine (identified by its Microsoft device ID), so one machine with several vulnerable software versions produces several findings. A tenant with thousands of devices can therefore produce a large number of findings; see [Importing in phases with device groups](#importing-in-phases-with-device-groups) below to bring them in a few device groups at a time.

**Please note:** this Connector is distinct from the file\-based **"MSDefender Parser"** scan type, which imports manually exported Defender files. Choose one import path per Asset to avoid duplicate findings.

#### Prerequisites

Your Microsoft tenant needs an active license that includes the Defender vulnerability export APIs: **Defender for Endpoint Plan 2**, **Microsoft Defender Vulnerability Management Standalone**, or MDE P1/P2 with the MDVM add\-on. (The MDVM *Add\-on* SKU on its own is not sufficient — it requires Defender for Endpoint Plan 2 underneath.)

The connector authenticates as a Microsoft Entra ID **app registration** using the client credentials flow. To create one:

1. In the [Azure portal](https://portal.azure.com), open **App registrations \> New registration**. Name it (for example `defectdojo-connector`), leave the defaults, and select **Register**.
2. On the app's **Overview** page, note the **Application (client) ID** and **Directory (tenant) ID**.
3. Open **API permissions \> Add a permission \> APIs my organization uses** and search for **WindowsDefenderATP**. If it doesn't appear, your tenant's Defender backend hasn't been provisioned yet: ensure the license is active, open [security.microsoft.com](https://security.microsoft.com) once, and retry after a few minutes.
4. Choose **Application permissions** (*not* Delegated — Delegated permissions never appear in the connector's service token), expand **Vulnerability**, check **Vulnerability.Read.All**, and select **Add permissions**.
5. Select **Grant admin consent** and confirm. The Status column must show a green check — without this step every API call returns a 403 error.
6. Open **Certificates & secrets \> New client secret**, set an expiry, and copy the secret **Value** immediately (it is only shown once). The Connector stops working when the secret expires, so note the date.

#### Connector Mappings

1. Enter `https://api.security.microsoft.com` in the **Location** field.
2. Enter the **Directory (tenant) ID** in the **Tenant ID** field.
3. Enter the **Application (client) ID** in the **Client ID** field.
4. Enter the client secret value in the **Client Secret** field.
5. Optionally, set **Device Groups** to a comma\-separated list of Defender RBAC device group names to import only those groups (see [Importing in phases with device groups](#importing-in-phases-with-device-groups)). Leave it blank to import every device group. Use `Unassigned` for devices that are not in any RBAC group.
6. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Defender device group becomes a Record. Microsoft regenerates the vulnerability snapshot the connector reads roughly every 6 hours, and newly onboarded devices can take up to \~24 hours to produce their first vulnerability data — a brand\-new tenant will legitimately Sync zero findings until devices are onboarded and assessed. License activation itself can also take \~20 minutes or more to reach the API ("No active license found" errors during that window resolve on their own).

#### Importing in phases with device groups

A large tenant can hold thousands of devices, which may be more findings than you want to bring in at once. Because the connector organizes everything by Defender RBAC device group, you can onboard a few groups at a time and keep the imported finding count limited to the groups you choose. There are two ways to control which device groups import:

* **Device Groups field (allowlist).** Set the **Device Groups** field on the connector to the group names you want. Only those groups are discovered and imported, and every other group is skipped. This is the simplest option when you already know which groups to bring in, and you can add more names later to onboard the next phase.
* **Record mapping.** With the field left blank, the connector discovers every device group and creates a Record for each. Map only the Records you want and leave the rest unmapped. Only mapped Records sync findings, so unmapped groups never import.

In both cases the org\-wide snapshot Microsoft provides is read in full on each Sync (the export API cannot filter by group on the server side), but findings are only imported for the groups you selected.

#### Setting a minimum severity per device group

The connector\-level **Minimum Severity** applies to every group. To use a different threshold for one device group, set a **severity override** on that group's Record after it has been discovered. The override applies only to that Record, so you can, for example, import everything from a production group while limiting a lab group to High and Critical.
