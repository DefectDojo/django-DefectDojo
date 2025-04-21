---
title: "Import Method Comparison"
description: "Learn how to import data manually, through the API, or via a connector"
weight: 1
---

One of the things we understand at DefectDojo is that every company’s security needs are completely different. There is no ‘one\-size\-fits\-all’ approach. As your organization changes, having a flexible approach is key.

DefectDojo allows you to connect your security tools in a flexible way to match those changes.

## Scan Upload Methods

When DefectDojo receives a vulnerability report from a security tool, it will create Findings based on the vulnerabilities contained within that report. DefectDojo acts as the central repository for these Findings where they can be triaged, remediated or otherwise addressed by you and your team.

There are two main ways that DefectDojo can upload Finding reports.

* Via direct **import** through the UI: [Import Scan Form](../import_scan_files/import_scan_ui)
* Via **API** endpoint (allowing for automated data ingest): See [API Docs](https://docs.defectdojo.com/en/api/api-v2-docs/)

#### DefectDojo Pro Methods

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users have an additional three methods to handle reports and data:

* Via **Universal Importer** or **DefectDojo CLI**, command line tools which leverage the DefectDojo API: See [External Tools](../external_tools/)
* Via **Connectors** for certain tools, an ‘out of the box’ data integration: See [Connectors Guide](../connectors/about_connectors/)
* Via **Smart Upload** for certain tools, an importer designed to handle infrastructure scans: See [Smart Upload Guide](../import_scan_files/smart_upload/)

### Comparing Upload Methods

|  | **UI Import** | **API** | **Connectors** <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span> | **Smart Upload**  <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span>|
| --- | --- | --- | --- | --- |
| **Supported Scan Types** | All: see [Supported Tools](/en/connecting_your_tools/parsers) | All: see [Supported Tools](/en/connecting_your_tools/parsers) | Snyk, Semgrep, Burp Suite, AWS Security Hub, Probely, Checkmarx, Tenable | Nexpose, NMap, OpenVas, Qualys, Tenable |
| **Automation?** | Available via API: `/reimport` `/import` endpoints | Triggered from [CLI Importer](../external_tools) or external code | Connectors is inherently automated | Available via API: `/smart_upload_import` endpoint |

### Product Hierarchy and organization

Each of these methods can create Product Hierarchy on the spot. Product Hierarchy refers to DefectDojo’s Product Types, Products, Engagements or Tests: objects in DefectDojo which help organize your data into relevant context.

* **Vulnerability data can be imported into an existing Product Hierarchy**. Product Types, Products, Engagements and Tests can all be created in advance, and then data can be imported to that location in DefectDojo.
* **The contextual Product Hierarchy can be created at the time of import.** When importing a report, you can create a new Product Type, Product, Engagement and/or Test. This is handled by DefectDojo through the ‘auto\-create context’ option.

## Using Import Methods (Pro UI)

In DefectDojo Pro, all of these methods can be accessed from the **Import** section of the sidebar.

![image](images/pro_import_sidebar.png)

The Pro UI allows you to create Product Types, Products and Engagements directly from the Import Scan form, so these objects are not required.

## Using Import Methods (Classic UI / Open Souce)

In DefectDojo OS, you can access the [Import Scan Form](../import_scan_files/import_scan_ui) from two locations:

* The Tests section of an Engagement:
    ![image](images/import_scan_os.png)
* The Findings section of the navigation bar on a Product:
    ![image](images/import_scan_os_2.png)

DefectDojo OS requires you to set up one or more Products / Product Types before you can import data through the UI.  See our article on [Product Hierarchy](/en/working_with_findings/organizing_engagements_tests/product_hierarchy/) for more information.
