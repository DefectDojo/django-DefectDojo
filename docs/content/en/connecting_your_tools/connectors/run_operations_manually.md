---
title: "How to run Operations manually"
description: "Run a Sync or Discover operation outside of schedule"
---

Connectors import data to DefectDojo on a regular interval (which you defined when adding the connector). However, if you want to import data manually (such as if you want to import historical data) you can follow this process:



Select the tool which you want to test from **Configured Connections,** and click the **Manage Configuration button.** From the drop\-down list, select **Manage Records and Operations.**



## Run Discover Manually


* To have DefectDojo search for, and import new records from the API, click the **🔎 Discover** button. This button is located next to the **Unmapped Records** header.

![image](images/run_operations_manually.png)
## Run Sync Manually


* To have DefectDojo import new data from each Mapped Record, click the **Sync** button. This button is located next to the **Mapped Records** header.

![image](images/run_operations_manually_2.png)

If there are no Mapped Records associated with this Connector, DefectDojo will not be able to import any data via Sync. You may need to run a Discover operation first, or map each record to a Product.

