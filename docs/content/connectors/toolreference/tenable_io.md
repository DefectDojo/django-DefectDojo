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

#### Credentialed scan tags

Every Tenable scan reports, for each host, whether it ran with credentials (Nessus plugin 19506, "Nessus Scan Information"). The connector reads that verdict and tags each imported finding with the credential status of the host it was found on:

- `credentialed-scan`: the host was scanned with credentials.
- `uncredentialed-scan`: the host was scanned without credentials.

A finding that spans several hosts carries both tags when those hosts disagree. Use the tag filter on the Findings list or in a report to split credentialed from uncredentialed results.

The tags follow the scan: when a host that was scanned without credentials is scanned with them, the next sync replaces `uncredentialed-scan` with `credentialed-scan` on its findings. Other tags you add yourself are left alone, except a tag whose name starts with `credentialed-scan` or `uncredentialed-scan` (such as `credentialed-scan-exempt`): the connector treats those as its own and removes them on the next sync.

Plugin 19506 is an Info severity plugin. With the **Scan** grouping, the connector asks for it even when the **Minimum Severity** is above Info, so the tags are applied either way (the plugin's own Info finding is still left out). With the **Tenable Asset** grouping, the tag is the host's most recent credential status across all of its scans, not the status of the scan that found the finding, and a Minimum Severity above Info drops the plugin from the export, so those findings get no credential tags.
