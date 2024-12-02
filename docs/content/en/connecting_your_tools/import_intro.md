---
title: "Import Methods"
description: "Learn how to import data manually, through the API, or via a connector"
weight: 0
---

One of the things we understand at DefectDojo is that every company’s security needs are completely different. There is no ‘one\-size\-fits\-all’ approach. As your organization changes, having a flexible approach is key.

DefectDojo allows you to connect your security tools in a flexible way to match those changes.

# Scan Upload Methods

When DefectDojo receives a vulnerability report from a security tool, it will create Findings based on the vulnerabilities contained within that report. DefectDojo acts as the central repository for these Findings where they can be triaged, remediated or otherwise addressed by you and your team.

There are four main ways that DefectDojo can upload Finding reports:

* Via direct **import** through the UI (“**Add Findings**”)
* Via **API** endpoint (allowing for automated data ingest)
* Via **Connectors** for certain tools, an ‘out of the box’ data integration
* Via **Smart Upload** for certain tools, an importer designed to handle infrastructure scans


## Comparing Upload Methods

|  | **UI Import** | **API Import** | **Connectors** | **Smart Upload** |
| --- | --- | --- | --- | --- |
| **Supported Scan Types** | All (see **Supported Tools**) | All (see **Supported Tools**) | Snyk, Semgrep, Burp Suite, AWS Security Hub, Probely, Checkmarx, Tenable | Nexpose, NMap, OpenVas, Qualys, Tenable |
| **Can it be automated?** | Not directly, though method can be automated through API | Yes, calls to API can be made manually or via script | Yes, Connectors is a natively automated process which leverages your tool’s API to rapidly import data | Yes, can be automated via /smart\_upload\_import API endpoint |


## Product Hierarchy

Each of these methods can create Product Hierarchy on the spot. Product Hierarchy refers to DefectDojo’s Product Types, Products, Engagements or Tests: objects in DefectDojo which help organize your data into relevant context.


* **Vulnerability data can be imported into an existing Product Hierarchy**. Product Types, Products, Engagements and Tests can all be created in advance, and then data can be imported to that location in DefectDojo.
* **The contextual Product Hierarchy can be created at the time of import.** When importing a report, you can create a new Product Type, Product, Engagement and/or Test. This is handled by DefectDojo through the ‘auto\-create context’ option.

# Next Steps


* If you have a brand new DefectDojo instance, learning how to use the **Import Scan Form** is a great starting point.
* If you want to learn how to translate DefectDojo’s organizational system into a robust pipeline, you can start by consulting our article on **[Core Data Classes](https://support.defectdojo.com/en/articles/8545273-core-data-classes-overview)**.
* If you want to set up Connectors to work with a supported tool, see our **[Introducing Connectors](https://support.defectdojo.com/en/articles/9072654-introducing-connectors)** article.
