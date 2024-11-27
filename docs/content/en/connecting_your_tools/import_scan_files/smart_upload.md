---
title: "Smart Upload"
description: "Automatically route incoming Findings to the correct Product"
---

Smart upload is a specialized importer that ingests reports from **infrastructure scanning tools**, including:



* Nexpose
* NMap
* OpenVas
* Qualys
* Tenable


Smart Upload is unique in that it can split Findings from a scan file into separate Products. This is relevant in an Infrastructure scanning context, where the Findings may apply to many different teams, have different implicit SLAs, or need to be included in separate reports due to where they were discovered in your infrastructure.



Smart Upload handles this by sorting incoming findings based on the Endpoints discovered in the scan. At first, those Findings will need to be manually assigned, or directed into the correct Product from an Unassigned Findings list. However, once a Finding has been assigned to a Product, all subsequent Findings that share an Endpoint or Host will be sent to the same Product.



# Smart Upload menu options


The Smart Upload menu is stored in a collapsible section of the sidebar.



* **Add Findings allows you to import a new scan file, similar to DefectDojo’s Import Scan method**
* **Unassigned Findings lists all Findings from Smart Upload which have yet to be assigned to a Product.**


![image](images/smart_upload.png)

## The Smart Upload Form



The Smart Upload Import Scan form is essentially the same as the Import Scan form. See our notes on the **Import Scan Form** for more details.



![image](images/smart_upload_2.png)

# Unassigned Findings


Once a Smart Upload has been completed, any Findings which are not automatically assigned to a Product (based on their Endpoint) will be placed in the **Unassigned Findings** list. The first Smart Upload for a given tool does not yet have any method to Assign Findings, so each Finding from this file will be sent to this page for sorting.



Unassigned Findings are not included in the Product Hierarchy and will not appear in reports, filters or metrics until they have been assigned.



## Working with Unassigned Findings



![image](images/smart_upload_3.png)

You can select one or more Unassigned Findings for sorting with the checkbox, and perform one of the following actions:



* **Assign to New Product, which will create a new Product**
* **Assign to Existing Product which will move the Finding into an existing Product**
* **Disregard Selected Findings**, which will remove the Finding from the list


Whenever a Finding is assigned to a New or Existing Product, it will be placed in a dedicated Engagement called ‘Smart Upload’. This Engagement will contain a Test named according to the Scan Type (e.g. Tenable Scan). Subsequent Findings uploaded via Smart Upload which match those Endpoints will be placed under that Engagement \> Test.



## Disregarded Findings


If a Finding is Disregarded it will be removed from the Unassigned Findings list. However, the Finding will not be recorded in memory, so subsequent scan uploads may cause the Finding to appear in the Unassigned Findings list again.

