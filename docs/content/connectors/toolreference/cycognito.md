---
title: "CyCognito"
description: "How to set up the CyCognito Upstream Connector for DefectDojo"
weight: 44
audience: pro
---
The CyCognito connector imports **external attack surface (EASM) findings** from the CyCognito platform. By default DefectDojo creates a Record for each **discovered asset**, across every asset type CyCognito tracks — IPs, domains, certificates, web apps and IP ranges.

There is deliberately no per\-asset configuration: the point of an EASM source is that it finds assets nobody enumerated in advance, so newly discovered assets appear as Records without anyone editing a configuration.

#### Prerequisites

A CyCognito **API key**, created under **Settings \> API** in CyCognito. It is sent as the value of the `Authorization` header.

#### Connector Mappings

1. Enter `https://api.platform.cycognito.com` in the **Location** field.
2. Enter your CyCognito API key in the **API Key** field.
3. Optionally, set **Asset Grouping** to `organization` to create one Record per CyCognito **organization** instead of one per asset. Leave it blank for the default, one Record per asset.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Under **organization** grouping, assets that belong to no organization are collected into a Record named **Unattributed Assets**.
