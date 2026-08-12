---
title: "Managing Operations"
description: "Check the status of your Connector's Discover & Sync Operations"
aliases:
  - /import_data/pro/connectors/manage_operations/
  - /en/connecting_your_tools/connectors/manage_operations
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Upstream Connectors are a DefectDojo Pro-only feature.</span>

Once an Upstream Connector is set up, it will run two Operations on a recurring basis:

* **Discover** will learn the connected tool's structure, and will create records in DefectDojo of any unmapped data;
* **Sync** will import new Findings from the tool based on your mappings.

Both of these Operations are managed on the Operations page of a Connector. The table will also track past runs of these Operations so that you can ensure your Connector is up to date.

To access a Connector's Operations Page, open **Manage Records & Operations** for the Connector you wish to work with, and then switch to the **</\> Operations From (tool)** tab.

![image](images/operations_discover.png)

The **Manage Records & Operations** page can also be used to handle Records; which are the individual Product mappings of your connected tool.  See [Managing Records](../manage_records) for more information.

## The Operations Page

![image](images/operations_page.png)

Each entry on the Operations Page's table is a record of an operation event, with the following traits:

* **Type** describes whether the event was a **Sync** or a **Discover** operation.
* **Status** describes whether the event ran successfully.
* **Trigger** describes how the event was triggered \- was it a **Scheduled** operation which ran automatically, or a **Manual** operation which was triggered by a DefectDojo user?
* The **Start \& End Time** of each operation is recorded here, along with the **Duration**.

## When a Connector runs but imports nothing

An operation that succeeds is not the same as an operation that found something. If the account
you connected cannot see any data in the tool, Discover completes normally and finds nothing to
create, so the Connector reports success while importing no Findings.

The **Upstream Connectors** page flags this on the Connector's tile:

![image](images/connector_visibility_warning.png)

* **Connected, but nothing is visible** means the last operation succeeded and the tool reported
  no data at all for these credentials. This almost always means the account is missing a grant
  in the tool rather than in DefectDojo. Hover the warning to see what to grant for that
  specific tool.
* **All *n* records are missing from the tool** means the Connector previously saw data and no
  longer does. Records that disappear from the tool are kept and marked **Missing** rather than
  deleted, so your mappings survive. Common causes are a revoked permission, a rotated
  credential with a narrower scope, or projects deleted in the tool.

Both warnings clear on their own. Once the tool reports the data again, the next Discover
restores the records to **Good**, your existing mappings are reused, and Sync resumes importing.
You do not need to recreate the Connector. To check a fix immediately rather than waiting for the
next scheduled run, use [Run Discover Manually](#run-discover-manually).

## Discover Operations

The first step a DefectDojo Connector needs to take is to **Discover** your tool's environment to see how you're organizing your scan data.

Let's say you have a BurpSuite tool, which is set up to scan five different repositories for vulnerabilities. Your Connector will take note of this organizational structure and set up **Records** to help you translate those separate repositories into DefectDojos Product/Engagement/Test hierarchy.

### Creating New Records

Each time your Connector runs a **Discover** operation, it will look for new **Vendor\-Equivalent\-Products (VEPs)**. DefectDojo looks at the way the Vendor tool is set up and will create **Records** of VEPs based on how your tool is organized.

![image](images/operations_discover_2.png)

### Run Discover Manually

**Discover** operations will automatically run on a regular basis, but they can also be run manually. If you're setting up this Connector for the first time, you can click the **Discover** button next to the **Unmapped Records** header. After you refresh the page, you will see your initial list of **Records**.

![image](images/operations_discover_3.png)

To learn more about working with records and setting up mappings to Products, see our guide to [Managing Records](../manage_records).

## Sync Operations

On a daily basis, DefectDojo will look at each **Mapped Record** for new scan data. DefectDojo will then run a **Reimport**, which compares the state of existing scan data to an incoming report.

### Where is vulnerability data stored?

* DefectDojo will create an **Engagement** nested under the Product specified in the **Record Mapping**. This Engagement will be called **Global Connectors**.
* The **Global Connectors** Engagement will track each separate Connector associated with the Product as a **Test**.
* On this sync, and each subsequent sync, the **Test** will store each vulnerability found by the tool as a **Finding**.

### How Sync handles new vulnerability data

Whenever Sync runs, it will compare the latest scan data against the existing list of Findings for changes. 

* If there are new Findings detected, they will be added to the Test as new Findings.
* If there are any Findings which aren’t detected in the latest scan, they will be marked as Inactive in the Test.

To learn more about Products, Engagements, Tests and Findings, see our [Product Hierarchy Overview](/asset_modelling/os_hierarchy/product_hierarchy/).

### Running Sync Manually

To have DefectDojo run a Sync operation off\-schedule:

1. Navigate to the **Manage Records \& Operations** page for the connector you want to use. From the **Upstream Connectors** page, click the **Manage Configuration** drop\-down menu on the Connector you wish to work with, and select **Manage Records \& Operations**.  
​
2. From this page, click the **Sync** button. This button is located next to the **Mapped Records** header.

![image](images/operations_sync.png)