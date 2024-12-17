---
title: "How to run Operations manually"
description: "Run a Sync or Discover operation outside of schedule"
---

Connectors import data to DefectDojo on a regular interval (which you defined when adding the connector). However, if you want to import data manually (such as if you want to import historical data) you can follow this process:



Select the tool which you want to test from **Configured Connections,** and click the **Manage Configuration button.** From the drop\-down list, select **Manage Records and Operations.**



## Run Discover Manually


* To have DefectDojo search for, and import new records from the API, click the **🔎 Discover** button. This button is located next to the **Unmapped Records** header.

![](https://downloads.intercomcdn.com/i/o/991836936/76086dea0cb2846d58bcb1fa/Screenshot+2024-03-14+at+2_21_22+PM.png?expires=1729720800&signature=0bb6b3d68adae5492db7928dbedec8559f10756593583259b65e25026988177e&req=fSkmHsp4lIJZFb4f3HP0gF3QGQtZ8dVqHD%2BP1iSP%2FmzeYzCXZIgTZHepumPU%0ACGw%3D%0A)
## Run Sync Manually


* To have DefectDojo import new data from each Mapped Record, click the **Sync** button. This button is located next to the **Mapped Records** header.

![](https://downloads.intercomcdn.com/i/o/991838900/4910dc9a0b353c218a5077e4/Screenshot+2024-03-14+at+2_23_17+PM.png?expires=1729720800&signature=3300a0e96e57dc864fc6b64ba8b87ecd5551f1c3cf5017b7bdb8bc9a276f1970&req=fSkmHsp2lIFfFb4f3HP0gK3OFXi%2B%2BLng5nWOhwpc%2BdJQdRYzv2w4BBZ%2BRIh5%0AXAE%3D%0A)

If there are no Mapped Records associated with this Connector, DefectDojo will not be able to import any data via Sync. You may need to run a Discover operation first, or map each record to a Product.

