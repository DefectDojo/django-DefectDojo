---
title: "'Discover' Operations"
description: "Create Records, and direct the flow of scan data into DefectDojo"
---

Once you have a Connector set up, you can start making decisions about how data will flow from the tool into DefectDojo. This is managed through the Discovery process.



You can manage all of these processes from the **Manage Records \& Operations** page. From the **API Connectors** page, click the drop\-down menu on the Connector you wish to work with, and select Manage Records \& Operations.




![](https://downloads.intercomcdn.com/i/o/991931761/2369607091f047ab7d9fc8f7/Screenshot+2024-03-14+at+3_58_06+PM.png?expires=1729720800&signature=a4514b13c28657c59684f62d83a2a341a021974c3039c4c1eb589378813803cd&req=fSkmH8p%2FmodeFb4f3HP0gD4PB4jnqjGHlvfM6JxkdxjjZLvtUsa3sBPCZn0%2F%0Au4Q%3D%0A)

# Creating New Records


The first step a DefectDojo Connector needs to take is to **Discover** your tool's environment to see how you're organizing your scan data.




Let's say you have a BurpSuite tool, which is set up to scan five different repositories for vulnerabilities. Your Connector will take note of this organizational structure and set up **Records** to help you translate those separate repositories into DefectDojos Product/Engagement/Test hierarchy.


Each time your Connector runs a **Discover** operation, it will look for new **Vendor\-Equivalent\-Products (VEPs)**. DefectDojo looks at the way the Vendor tool is set up and will create **Records** of VEPs based on how your tool is organized.




![](https://downloads.intercomcdn.com/i/o/1004625297/5617e086a605102544ec5e37/Screenshot+2024-03-27+at+15_50_38+%281%29.png?expires=1729720800&signature=39ed2d006535fe6f3734ded90af212341d18725ac189fd6c93ef22efe83f22f0&req=dSAnEs98mINWXvMW1HO4zTo0ZAoA6if8rY3f2TjKX%2F98dBmwNaEs4%2B5s07hV%0Ab4FT%0A)


## Run Discover Manually


**Discover** operations will automatically run on a regular basis, but they can also be run manually. If you're setting up this Connector for the first time, you can click the **Discover** button next to the **Unmapped Records** header. After you refresh the page, you will see your initial list of **Records**.




![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1004506539/8f01b33b93821550f5198bd5/v8-yUUR6-EVcDMgbo4hOYp_5Q8gT96Zua_yqvPK2yubDZS0s_SVwFBwfKq4lPjuUJEfYtaLOL5syqJi0y_jND2aQj89l2xogKQaD4lO_alleK76L4WRbttxODT2Edui0erbhJ1xQApA0pws8X-opzc4?expires=1729720800&signature=5514f4b5a2d991188e7053d287a8e61f60301eb83cdae8384090808f224577b3&req=dSAnEsx%2Bm4RcUPMW1HO4zXucwJiAhf5WfVviwSTTFchq7bwThIMffCCban%2Bv%0AzwFl%0A)

# **Next Steps:**


* Learn how to [manage the Records](https://support.defectdojo.com/en/articles/9073083-managing-records) discovered by a Connector, and start importing data.
* If your Records have already been mapped (such as through Auto\-Map Records), learn how to import data via [Sync operations](https://support.defectdojo.com/en/articles/9124820-sync-operations).
