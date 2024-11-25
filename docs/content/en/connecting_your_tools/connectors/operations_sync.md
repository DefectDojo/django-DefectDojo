---
title: "'Sync' Operations"
description: "Import data from your Connector into DefectDojo"
---

The primary ‘Job’ of a DefectDojo Connector is to import data from a security tool, and this process is handled by the Sync Operation.

On a daily basis, DefectDojo will look at each **Mapped** **Record** for new scan data. DefectDojo will then run a **Reimport**, which compares the state of each scan.

# The Sync Process

### Where is my vulnerability data stored?

* DefectDojo will create an **Engagement** nested under the Product specified in the **Record Mapping**. This Engagement will be called **Global Connectors**.
* The **Global Connectors** Engagement will track each separate Connection associated with the Product as a **Test**.
* On this sync, and each subsequent sync, the **Test** will store each vulnerability found by the tool as a **Finding**.

## How Sync handles new vulnerability data

Whenever Sync runs, it will compare the latest scan data against the existing list of Findings for changes. 

* If there are new Findings detected, they will be added to the Test as new Findings.
* If there are any Findings which aren’t detected in the latest scan, they will be marked as Inactive in the Test.

To learn more about Products, Engagements, Tests and Findings, see our [Core Data Classes Overview](https://support.defectdojo.com/en/articles/8545273-core-data-classes-overview).


# Running Sync Manually

To have DefectDojo run a Sync operation off\-schedule:

1. Navigate to the **Manage Records \& Operations** page for the connector you want to use. From the **API Connectors** page, click the drop\-down menu on the Connector you wish to work with, and select Manage Records \& Operations.  
​
2. From this page, click the **Sync** button. This button is located next to the **Mapped Records** header.

![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1004529047/60f9b6df50f0d760de32f4f8/tLFaONBcKeFaybG7_YPdNx0Pk8yU2aSaANDTWiWkRL1NK9LJKyw7YMOD9Q0W6KUj6rQT8G9WvSeQrpzmVFyHWPaCTN3H_pvvdNYQo3queMqyyiB33wdbJFzBDm_QDbUGdRpRcsr8gzIH4arl2_6zLeQ?expires=1729720800&signature=824ac56f5e429a6841c7230f3097512452145aeb02b356d875b7a527e3f15e72&req=dSAnEsx8lIFbXvMW1HO4zSTetF5h5nFufHIHQsC%2F9kC8JSzNlTSMZg1aDUs5%0A89TQ%0A)

# Next Steps


* Learn how to set up the flow of data into DefectDojo through a [Discover operation](https://support.defectdojo.com/en/articles/9056822-discover-operations).
* Adjust the schedule of your Sync and Discover operations by [Editing a Connector](https://support.defectdojo.com/en/articles/9056787-add-or-edit-a-connector).
* Learn about Engagements, Tests and Findings with our guide to [Core Data Classes](https://support.defectdojo.com/en/articles/8545273-core-data-classes-overview).
