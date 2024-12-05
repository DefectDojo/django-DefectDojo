---
title: "Enabling Product-Level Deduplication"
description: "How to enable Deduplication at the Product level"
---

Deduplication can be implemented at either a Product level or at a more narrow Engagement level. This article describes the more common approach of deduplicating within a single Product.


1. Start by navigating to the System Settings page. This is nested under **Settings \> Pro Settings \> ⚙️System Settings** on the sidebar.



![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1124595466/23510e2be09c57c31794ddbf/AD_4nXc_etHPxb2G3QGrOuEK3jNUcQevdHrW7fhe1DF-Oeom5oZFFdTmTmnM1tZpABw6ROzUbbu9DN9szFMKHCUxNWjqBOWKxk-AsYaVwpM4CPAAuKrMju_BqRLrl1vGIABLQaiXTEhVOSJOG5r71eSLuYMs1ZUQ?expires=1729720800&signature=15fe9ccd68bea2289aafaf51e2a0158bb8170f03cc21b6e2b5c8936eee5ba3f5&req=dSElEsx3mIVZX%2FMW1HO4zUxInD5pTrydt8XM8g5%2FosYwTdr%2FFJmlu8o7z1Ey%0AypWn%0A)
2. **Deduplication and Finding Settings** are at the top of the **System Settings** menu.  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1124595482/5c6e4140b748d743380db52a/AD_4nXczFRPMaaBteblXtLfkioIjnUmaYz5Z2voT_wskuvTBDFBoqWV7F8Ncte1qYrgwhZ-TYhvFYTNbQoEjj_dgbpGfnvWt-nJ3Jxo046VxDAA1YmPcZRmJQwprmTWpkNNKAoROh_lUWEtZiehwJ-v-MU8mqNR9?expires=1729720800&signature=477386cba875c6d0eef54c5a9657ccd17320ac1f5355e6d5c2604a81049065a2&req=dSElEsx3mIVXW%2FMW1HO4zfS9u6vQjS6vS8fDvrkeJ6fkTP%2FTlmiDVWCQsro%2F%0Aqjfg%0A)

## Enable Finding Deduplication


**Enable Finding Deduplication** will turn on the Deduplication Algorithm for all Findings. Deduplication will be triggered on all subsequent imports \- when this happens, DefectDojo will look at any Findings contained in the destination Product, and deduplicate as per your settings. 



## Delete Deduplicate Findings


**Delete Deduplicate Findings**, combined with the **Maximum Duplicates** field allows DefectDojo to limit the amount of Duplicate Findings stored. When this field is enabled, DefectDojo will only keep a certain number of Duplicate Findings.



Applying **Delete Deduplicate Findings** will begin a deletion process immediately. DefectDojo will look at each Finding with Duplicates recorded, and will delete old duplicate Findings until the Maximum Duplicate number has been reached.



For more information on how DefectDojo determines what to delete, see our guide to **[Deleting Deduplicate Findings](https://support.defectdojo.com/en/articles/9658110-delete-deduplicate-findings).**

