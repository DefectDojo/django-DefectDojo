---
title: "'Sync' Operations"
description: "Import data from your Connector into DefectDojo"
---

The primary ‘Job’ of a DefectDojo Connector is to import data from a security tool, and this process is handled by the Sync Operation.

On a daily basis, DefectDojo will look at each **Mapped** **Record** for new scan data. DefectDojo will then run a **Reimport**, which compares the state of each scan.

## The Sync Process

### Where is my vulnerability data stored?

* DefectDojo will create an **Engagement** nested under the Product specified in the **Record Mapping**. This Engagement will be called **Global Connectors**.
* The **Global Connectors** Engagement will track each separate Connection associated with the Product as a **Test**.
* On this sync, and each subsequent sync, the **Test** will store each vulnerability found by the tool as a **Finding**.

### How Sync handles new vulnerability data

Whenever Sync runs, it will compare the latest scan data against the existing list of Findings for changes. 

* If there are new Findings detected, they will be added to the Test as new Findings.
* If there are any Findings which aren’t detected in the latest scan, they will be marked as Inactive in the Test.

To learn more about Products, Engagements, Tests and Findings, see our [Product Hierarchy Overview](https://docs.defectdojo.com/en/working_with_findings/organizing_engagements_tests/product-hierarchy-overview/).

## Running Sync Manually

To have DefectDojo run a Sync operation off\-schedule:

1. Navigate to the **Manage Records \& Operations** page for the connector you want to use. From the **API Connectors** page, click the drop\-down menu on the Connector you wish to work with, and select Manage Records \& Operations.  
​
2. From this page, click the **Sync** button. This button is located next to the **Mapped Records** header.

![image](images/operations_sync.png)

# Next Steps

* Learn how to set up the flow of data into DefectDojo through a [Discover operation](https://docs.defectdojo.com/en/connecting_your_tools/connectors/operations_discover/).
* Adjust the schedule of your Sync and Discover operations by [Editing a Connector](https://docs.defectdojo.com/en/connecting_your_tools/connectors/add_edit_connectors/).
* Learn about Engagements, Tests and Findings with our guide to [Product Hierarchy](https://docs.defectdojo.com/en/working_with_findings/organizing_engagements_tests/product-hierarchy-overview/).
