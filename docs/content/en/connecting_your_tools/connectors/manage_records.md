---
title: "Manage Records"
description: "Direct the flow of data from your tool into DefectDojo"
---

Once you have run your first Discover operation, you should see a list of Mapped or Unmapped records on the **Manage Records and Operations** page.




# What's a Record?


A Record is a connection between a DefectDojo **Product** and a **Vendor\-Equivalent\-Product**. You can use your Records list to control the flow of data between your tool and DefectDojo.



Records are created and updated during the **[Discover](https://support.defectdojo.com/en/articles/9056822-discover-operations)** operation, which DefectDojo runs daily to look for new Vendor\-Equivalent Products.




![image](images/manage_records.png)

Records have various attributes, including:


* The **State** of the Record
* The **Product** the Record imports data to
* When the Record was **First and Last Discovered** (by the **Discover** process)
* When the Record mapping was **Finalized** by a user
* A link to the DefectDojo **Product**


# How Records are Mapped


Each Record needs to have a Mapping assigned. The Mapping tells DefectDojo where to store the scan data from the tool. A Mapped Record assigns the Vendor\-Equivalent Product to a DefectDojo Product, and tells the Connector to start importing scan data to that location (as Engagements and Tests).



You can assign Mappings yourself, or you can have DefectDojo assign them automatically. 



## Auto\-Mapping


If you have **Auto\-Mapping** enabled, new Records will be Mapped to Products automatically. Each time DefectDojo **Discovers** a new Record, a matching DefectDojo Product will be automatically created for each Record**.** That Record will be stored under **Mapped Records** to indicate that it is ready to import data to DefectDojo.



If you don't have Auto\-Mapping enabled, you can make your own decisions about where you want data to flow. Each time the Connector finds a new Vendor\-Equivalent Product (via **Discover**), it will add a new Record to your **Unmapped Records** list, and you can then manually assign that Record to a new or existing Product in DefectDojo.



### Mapping \- Example Workflow:


David has just finished setting up a connector for his BurpSuite tool, and runs a Discover operation. David has Burp set up to scan 4 different 'Sites', and DefectDojo creates a new Record for each of those Sites.


* If David decides to use Auto\-Mapping, DefectDojo will create a new Product for each Site. From now on, when DefectDojo runs a Synchronize operation, the Connector will import scan data directly from the Site into the Product (via the Record mapping)  
​
* If David leaves Auto\-Mapping off, DefectDojo will still discover those 4 Sites and create Records, but it won't import any data until David creates the Mappings himself.  
​
* David can always change how these mappings are set up later. Maybe he wants to consolidate the output of a few different Burp Sites into a single Product. Or maybe he's looking to have a Product which records scan data from a few different tools \- including Burp. It's easy for David to change where Burp scan data is stored into DefectDojo by changing the Mapping of these Records.



# How Records interact with Products


Once a Record is Mapped, DefectDojo will be ready to import your tool’s scans through a Sync Operation. Connectors can work alongside other DefectDojo import processes or interactive testing.


* Record Mappings are designed to be non\-invasive. If you map a Product to a Record which contains existing Engagements or Findings, those existing Engagements and Findings will not be affected or overwritten by the data sync process.  
​
* All data created via a connector will be stored under a single Engagement called **Global Connectors**. That Engagement will create a separate Test for each Connector mapped to the Product.   
​

![image](images/manage_records_2.jpg)
This makes it possible to send scan data from multiple Connectors to the same Product. All of the data will be stored in the same Engagement, but each Connector will store data in a separate Test.



To learn more about Products, Engagements and Tests, see our [Core Data Classes Overview](https://support.defectdojo.com/en/articles/8545273-core-data-classes-overview).




# Record States \- Glossary


Each Record has an associated state to communicate how the Record is working.



### New


A New Record is an Unmapped Record which DefectDojo has Discovered. It can be Mapped to a Product or Ignored. To Map a new Record to a Product, see our guide on [Editing Records](https://support.defectdojo.com/en/articles/9072546-edit-ignore-or-delete-records).




### Good


'Good' indicates that a Record is Mapped and operating correctly. Future Discover Operations check to see if the underlying Vendor\-Equivalent Product still exists, to ensure that the Sync operation will run correctly.




### Ignored


'Ignored' Records have been successfully Discovered, but a DefectDojo user has decided not to map the data to a Product. If you wish to change a New or Mapped Record to Ignored, or re\-map an Ignored Record, see our guide on [Editing Records](https://support.defectdojo.com/en/articles/9072546-edit-ignore-or-delete-records).




## Warning States: Stale or Missing


If the connection between tool and DefectDojo changes, the state of a Record will change to let you know.



### Stale


A Mapping is moved to ‘Stale’ when a related Product, Engagement or Test has been deleted from DefectDojo. The mapping still exists, but there isn’t anywhere in DefectDojo for the Tool’s data to import to.



Stale records can be remapped to an existing Product, or Ignored if the scan data is no longer relevant.



### Missing


If a Record has been Mapped, but the source data (or Vendor\-Equivalent Product) is not being detected by DefectDojo, the Record will be labeled as **Missing**. 



DefectDojo Connectors will adapt to name changes, directory changes and other data shifts, so this is possibly because the related Vendor\-Equivalent Product was deleted from the Tool you’re using.



If you intended to remove the Vendor Equivalent Product from your tool, you can Delete a Missing Record. If not, you'll need to troubleshoot the problem within the Tool so that the source data can be Discovered correctly.

