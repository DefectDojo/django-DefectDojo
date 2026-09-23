---
title: "Tenable Web App Scanning"
description: "How to set up the Tenable Web App Scanning Upstream Connector for DefectDojo"
weight: 132
audience: pro
---
The Tenable Web App Scanning connector imports **web application (DAST) findings** from Tenable Web App Scanning. It is a separate connector from Tenable (Vulnerability Management): the two Assets cover different assets and are configured independently, so you can use either or both.

DefectDojo creates a Record for each **scanned web application**. Applications are discovered from your Web App Scanning scan configurations; a configuration that has never run does not produce a Record until its first scan completes. When more than one configuration scans the same application, they share a single Record.

#### Prerequisites

Tenable **API keys** (an access key and a secret key) for a user with Web App Scanning permissions. In Tenable, go to **My Account \> API Keys** to generate them, and confirm the user can view the scans you want to import — keys limited to Vulnerability Management cannot read Web App Scanning data.

On\-premise Tenable connectors are not available at this time.

#### Connector Mappings

1. Enter <https://cloud.tenable.com> in the **Location** field.
2. Enter your **Access Key** and **Secret Key**.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Findings are imported with the severity Tenable reports for your account, including any severity your team has recast. Each finding carries the affected URL as an endpoint, the request parameter and payload that triggered it, and Tenable's proof and output as steps to reproduce, along with CWE, CVE, CVSS and EPSS values where the detecting plugin supplies them.

Only findings that are currently open or reopened are imported. A finding Tenable has marked fixed is closed in DefectDojo on the next sync.
