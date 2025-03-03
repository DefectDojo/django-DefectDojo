---
title: "Import Method Comparison"
description: "Learn how to import data manually, through the API, or via a connector"
weight: 1
---

One of the things we understand at DefectDojo is that every company’s security needs are completely different. There is no ‘one\-size\-fits\-all’ approach. As your organization changes, having a flexible approach is key.

DefectDojo allows you to connect your security tools in a flexible way to match those changes.

## Scan Upload Methods

When DefectDojo receives a vulnerability report from a security tool, it will create Findings based on the vulnerabilities contained within that report. DefectDojo acts as the central repository for these Findings where they can be triaged, remediated or otherwise addressed by you and your team.

There are four main ways that DefectDojo can upload Finding reports:

* Via direct **import** through the UI (“**Add Findings**”)
* Via **API** endpoint (allowing for automated data ingest)
* Via **Universal Importer**, a command-line tool which leverages the DefectDojo API
* Via **Connectors** for certain tools, an ‘out of the box’ data integration
* Via **Smart Upload** for certain tools, an importer designed to handle infrastructure scans

### Comparing Upload Methods

|  | **UI Import** | **API** | **Connectors** <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span> | **Smart Upload**  <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span>|
| --- | --- | --- | --- | --- |
| **Supported Scan Types** | All: see [Supported Tools](/en/connecting_your_tools/parsers) | All: see [Supported Tools](/en/connecting_your_tools/parsers) | Snyk, Semgrep, Burp Suite, AWS Security Hub, Probely, Checkmarx, Tenable | Nexpose, NMap, OpenVas, Qualys, Tenable |
| **Automation?** | Available via API: `/reimport` `/import` endpoints | Triggered from [CLI Importer](../external_tools) or external code | Connectors is inherently automated | Available via API: `/smart_upload_import` endpoint |

### Product Hierarchy

Each of these methods can create Product Hierarchy on the spot. Product Hierarchy refers to DefectDojo’s Product Types, Products, Engagements or Tests: objects in DefectDojo which help organize your data into relevant context.

* **Vulnerability data can be imported into an existing Product Hierarchy**. Product Types, Products, Engagements and Tests can all be created in advance, and then data can be imported to that location in DefectDojo.
* **The contextual Product Hierarchy can be created at the time of import.** When importing a report, you can create a new Product Type, Product, Engagement and/or Test. This is handled by DefectDojo through the ‘auto\-create context’ option.

# Next Steps

* If you have a brand new DefectDojo instance, learning how to use the [Import Scan Form](../import_scan_files/import_scan_ui) is a great starting point.
* If you want to learn how to translate DefectDojo’s organizational system into a robust pipeline, you can start by consulting our article on [Product Hierarchy](/en/working_with_findings/organizing_engagements_tests/product_hierarchy/).
* If you want to set up Connectors to work with a supported tool, see our [About Connectors](../connectors/about_connectors/) article.
