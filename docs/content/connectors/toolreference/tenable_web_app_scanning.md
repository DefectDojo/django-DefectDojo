---
title: "Tenable Web App Scanning"
description: "How to set up the Tenable Web App Scanning Upstream Connector for DefectDojo"
weight: 132
audience: pro
---
The Tenable Web App Scanning connector imports **web application (DAST) findings** from Tenable Web App Scanning. It is a separate connector from Tenable (Vulnerability Management): the two Assets cover different assets and are configured independently, so you can use either or both.

By default, DefectDojo creates a Record for each **scanned web application**. Applications are discovered from your Web App Scanning scan configurations; a configuration that has never run does not produce a Record until its first scan completes. When more than one configuration scans the same application, they share a single Record.

A scan configuration can target one URL, several URLs, or a Tenable tag. For a configuration that targets several URLs or a tag, DefectDojo reads the configuration's scan history and creates a Record for every web application it has scanned, named `<application> (<configuration name>)`. A web application added to a tag gets its Record after the configuration first scans it.

#### Prerequisites

Tenable **API keys** (an access key and a secret key) for a user with Web App Scanning permissions. In Tenable, go to **My Account \> API Keys** to generate them, and confirm the user can view the scans you want to import — keys limited to Vulnerability Management cannot read Web App Scanning data.

On\-premise Tenable connectors are not available at this time.

#### Connector Mappings

1. Enter <https://cloud.tenable.com> in the **Location** field.
2. Enter your **Access Key** and **Secret Key**.
3. Optionally, set **Web Application Tags** to import only the web applications that carry any of the listed Tenable tags. Separate tags with commas. Write `Category:Value` to match that tag, or just `Value` to match that value in any category; matching ignores case. Leave the field blank to import every web application. Web applications without a matching tag get no Record, and their findings are not imported. If you add a filter to an existing connection, the next discovery marks the Records of the web applications it excludes as missing; they keep the findings they already imported.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.
5. Optionally, set **Asset Grouping** (labeled **Product Grouping** under some naming settings):
    - **Web Application (Default)**: one Record per scanned web application.
    - **Scan Configuration**: one Record per scan configuration, holding the findings of every web application it scans, including those reached through a tag. A web application that two configurations scan appears in both Records.

If you switch Asset Grouping on an existing connection, the next discovery lists the new Records to map. The Records from the previous setting are marked missing and keep the findings they already imported.

Findings are imported with the severity Tenable reports for your account, including any severity your team has recast. Each finding carries the affected URL as an endpoint, the request parameter and payload that triggered it, and Tenable's proof and output as steps to reproduce, along with CWE, CVE, CVSS and EPSS values where the detecting plugin supplies them.

Only findings that are currently open or reopened are imported. A finding Tenable has marked fixed is closed in DefectDojo on the next sync.
