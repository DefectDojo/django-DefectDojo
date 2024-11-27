---
title: "'Discover' Operations"
description: "Create Records, and direct the flow of scan data into DefectDojo"
---

Once you have a Connector set up, you can start making decisions about how data will flow from the tool into DefectDojo. This is managed through the Discovery process.



You can manage all of these processes from the **Manage Records \& Operations** page. From the **API Connectors** page, click the drop\-down menu on the Connector you wish to work with, and select Manage Records \& Operations.




![image](images/operations_discover.png)

# Creating New Records


The first step a DefectDojo Connector needs to take is to **Discover** your tool's environment to see how you're organizing your scan data.




Let's say you have a BurpSuite tool, which is set up to scan five different repositories for vulnerabilities. Your Connector will take note of this organizational structure and set up **Records** to help you translate those separate repositories into DefectDojos Product/Engagement/Test hierarchy.


Each time your Connector runs a **Discover** operation, it will look for new **Vendor\-Equivalent\-Products (VEPs)**. DefectDojo looks at the way the Vendor tool is set up and will create **Records** of VEPs based on how your tool is organized.




![image](images/operations_discover_2.png)


## Run Discover Manually


**Discover** operations will automatically run on a regular basis, but they can also be run manually. If you're setting up this Connector for the first time, you can click the **Discover** button next to the **Unmapped Records** header. After you refresh the page, you will see your initial list of **Records**.




![image](images/operations_discover_3.png)

# **Next Steps:**


* Learn how to [manage the Records](https://support.defectdojo.com/en/articles/9073083-managing-records) discovered by a Connector, and start importing data.
* If your Records have already been mapped (such as through Auto\-Map Records), learn how to import data via [Sync operations](https://support.defectdojo.com/en/articles/9124820-sync-operations).
