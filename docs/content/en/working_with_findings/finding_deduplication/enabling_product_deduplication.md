---
title: "Enabling Product-Level Deduplication"
description: "How to enable Deduplication at the Product level"
---

Deduplication can be implemented at either a Product level or at a more narrow Engagement level. This article describes the more common approach of deduplicating within a single Product.


1. Start by navigating to the System Settings page. This is nested under **Settings \> Pro Settings \> ⚙️System Settings** on the sidebar.



![image](images/Enabling_Product-Level_Deduplication.png)
2. **Deduplication and Finding Settings** are at the top of the **System Settings** menu.  
​


![image](images/Enabling_Product-Level_Deduplication_2.png)

## Enable Finding Deduplication


**Enable Finding Deduplication** will turn on the Deduplication Algorithm for all Findings. Deduplication will be triggered on all subsequent imports \- when this happens, DefectDojo will look at any Findings contained in the destination Product, and deduplicate as per your settings. 



## Delete Deduplicate Findings


**Delete Deduplicate Findings**, combined with the **Maximum Duplicates** field allows DefectDojo to limit the amount of Duplicate Findings stored. When this field is enabled, DefectDojo will only keep a certain number of Duplicate Findings.



Applying **Delete Deduplicate Findings** will begin a deletion process immediately. DefectDojo will look at each Finding with Duplicates recorded, and will delete old duplicate Findings until the Maximum Duplicate number has been reached.



For more information on how DefectDojo determines what to delete, see our guide to **[Deleting Deduplicate Findings](https://support.defectdojo.com/en/articles/9658110-delete-deduplicate-findings).**

