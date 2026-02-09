---
title: "Import Method Comparison"
description: "Learn how to import data manually, through the API, or via a connector"
weight: 1
aliases:
  - /en/connecting_your_tools/import_intro
---
One of the things we understand at DefectDojo is that every company’s security needs are completely different. There is no one-size-fits-all approach. As your organization changes, having a flexible approach is key, and DefectDojo allows you to connect your security tools in a flexible way to match those changes.

## Scan Upload Methods

When DefectDojo receives a vulnerability report from a security tool, it will create Findings based on the vulnerabilities contained within that report. DefectDojo acts as the central repository for these Findings where they can be triaged, remediated, or otherwise addressed by you and your team.

There are two main ways that DefectDojo can upload Finding reports.

* Via direct **import** through the UI
* Via **API** endpoint (allowing for automated data ingestion): See [API Docs](/automation/api/api-v2-docs/)

#### DefectDojo Pro Methods

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users have an additional three methods to handle reports and data:

* Via **Universal Importer** or **DefectDojo CLI**, command line tools which leverage the DefectDojo API: See [Universal Importer & DefectDojo-CLI guides](/import_data/pro/specialized_import/external_tools/)
* Via **Connectors** for certain tools, an ‘out of the box’ data integration: See [Connectors Guide](/import_data/pro/connectors/about_connectors/)
* Via **Smart Upload** for certain tools, an importer designed to handle infrastructure scans: See [Smart Upload Guide](/import_data/pro/specialized_import/smart_upload/)

### Comparing Upload Methods

|  | **UI Import** | **API** | **Connectors** <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span> | **Smart Upload**  <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span>|
| --- | --- | --- | --- | --- |
| **Supported Scan Types** | All: see [Supported Tools](/supported_tools/) | All: see [Supported Tools](/supported_tools/) | Anchore, AWS Security Hub, BurpSuite, Checkmarx ONE, Dependency-Track, Probely, Semgrep, SonarQube, Snyk, Tenable, Wiz | Nexpose, NMap, OpenVas, Qualys, Tenable |
| **Automation?** | Available via API: `/reimport` `/import` endpoints | Triggered from [CLI Tools](/import_data/pro/specialized_import/external_tools/) or external code | Connectors is an inherently automated feature | Available via API: `/smart_upload_import` endpoint |

### Product Hierarchy and organization

Each of these methods can create Product Hierarchy on the spot. Product Hierarchy refers to DefectDojo’s Product Types, Products, Engagements or Tests: objects in DefectDojo which help organize your data into relevant context.

* **Vulnerability data can be imported into an existing Product Hierarchy**. Product Types, Products, Engagements and Tests can all be created in advance, and then data can be imported to that location in DefectDojo.
* **The contextual Product Hierarchy can be created at the time of Import.** When importing a report, you can create a new Product Type, Product, Engagement and/or Test. This is handled by DefectDojo through the ‘auto-create context’ option.  In DefectDojo OS, this option can only be accessed through the API.  UI imports in DefectDojo OS will require Product Hierarchy to be created first.
