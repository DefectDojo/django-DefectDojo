---
title: "Tenable.io"
description: "How to set up the Tenable.io Upstream Connector for DefectDojo"
weight: 131
audience: pro
---
The Tenable connector uses the **Tenable.io** REST API to fetch data.  Scans are pulled from the Tenable VM `/scans` endpoint.

On\-premise Tenable Connectors are not available at this time.

#### **Connector Mappings**

1. Enter <https://cloud.tenable.com> in the Location field.
2. Enter a valid **API key** in the Secret field.

See [Tenable's API Documentation](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm) for more info.

#### Asset Grouping

The **Asset Grouping** setting decides what each Record stands for. Depending on your naming settings, the field may be labeled **Product Grouping**.

- **Scan (Default)**: one Record per Tenable scan. Every host the scan covers is an endpoint on that Record's findings.
- **Tenable Asset**: one Record per Tenable asset (host), holding that asset's open findings from every scan. Use this when one scan covers many hosts and you want each host to be its own Asset in DefectDojo.

With **Tenable Asset**, discovery lists every Tenable asset with scan results, named by FQDN, then hostname, NetBIOS name, or IP address. Each sync runs one Tenable vulnerability export for the whole account and sends each asset's findings to its Record. A finding for an asset that has no Record yet is skipped until the next discovery lists that asset.

If you switch the setting on an existing connection, the next discovery lists the new Records to map. The Records from the previous setting are marked missing and keep the findings they already imported.
