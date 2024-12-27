---
title: "Enabling Deduplication"
description: "How to enable Deduplication at the Product level"
weight: 2
---

Deduplication can be implemented at either a Product level or at a more narrow Engagement level.

## Deduplication for Products

1. Start by navigating to the System Settings page. This is nested under **Settings \> Pro Settings \> ⚙️ System Settings** on the sidebar.

![image](images/Enabling_Product-Level_Deduplication.png)

2. **Deduplication and Finding Settings** are at the top of the **System Settings** menu.  
​
![image](images/Enabling_Product-Level_Deduplication_2.png)

### Enable Finding Deduplication

**Enable Finding Deduplication** will turn on the Deduplication Algorithm for all Findings. Deduplication will be triggered on all subsequent imports \- when this happens, DefectDojo will look at any Findings contained in the destination Product, and deduplicate as per your settings. 

### Delete Deduplicate Findings

**Delete Deduplicate Findings**, combined with the **Maximum Duplicates** field allows DefectDojo to limit the amount of Duplicate Findings stored. When this field is enabled, DefectDojo will only keep a certain number of Duplicate Findings.

Applying **Delete Deduplicate Findings** will begin a deletion process immediately. DefectDojo will look at each Finding with Duplicates recorded, and will delete old duplicate Findings until the Maximum Duplicate number has been reached.

For more information on how DefectDojo determines what to delete, see our guide to **[Deleting Deduplicate Findings](../delete-deduplicate-findings/).**

## Deduplication for Engagements

Rather than Deduplicating across an entire Product, you can set a deduplication scope to be within a single Engagement exclusively.

### Edit Engagement page

* To enable Deduplication within a New Engagement, start with the **\+ New Engagement** option from the sidebar, which you can find by opening the **📥Engagements** sub\-menu.  
​
![image](images/Enabling_Deduplication_within_an_Engagement.png)

* To enable Deduplication within an existing Engagement: from the **All Engagements** page, select the **Edit Engagement** option from the **⋮** menu.   
​
![image](images/Enabling_Deduplication_within_an_Engagement_2.png)

* You can also open this menu from a specific **Engagement Page** by clicking the ⚙️Gear icon in the top\-right hand corner.  
​
![image](images/Enabling_Deduplication_within_an_Engagement_3.png)

### Completing the Edit Engagement form

1. Start by opening the **Optional Fields \+** menu at the bottom of the **Edit Engagement** form.
2. Click the ☐ **Deduplication Within This Engagement** box.
3. Submit the form.

![image](images/Enabling_Deduplication_within_an_Engagement_4.png)