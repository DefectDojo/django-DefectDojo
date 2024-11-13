---
title: "Editing Findings"
description: "Change a Finding’s Status, or add more metadata as you resolve an issue"
---

If you want to add notes or update the language on a Finding to be more relevant to the current situation, you can do so through the Edit Finding form.



# Opening the Edit Finding Form


You can update a Finding by opening the **⚙️ Gear** **Menu** in the top and clicking **Edit Finding.**



![](https://downloads.intercomcdn.com/i/o/tj2vh1ie/1204632847/caabbaa73e3ef1bad6d5afd0c0c3/AD_4nXc-cAVmWrNapE3BCbl21cYhzGEzqrV0o4zodyvkqLDjYjqvNrBM67_otDPrXN2vsMYkNLdcZFzvVqezCgTUrRmQIzgtNvb4cRTE9kdpc88bpV8oSXOvNcHywzO-huexpt4P6fxGgPEsSDO6zJk8N3z5ZWUo?expires=1729720800&signature=22b34d4835d8a263cf7a88501eed00e460d632f75e0053937123db9133e7a411&req=dSInEs99n4lbXvMW1HO4zfYhXR6UzORlNJ7u6J8QRDrXXi9HNu3VCLIi6oKU%0ApZLf%0A)

This will open the **Edit Finding** form, where you can edit the metadata, change the Finding’s Status and add additional information.



![](https://downloads.intercomcdn.com/i/o/tj2vh1ie/1204632848/e42a82139f528b871c01165d9b4c/AD_4nXdFNE-8nMU2l4QB-XtB6-VIYSQQkBQV6ftDNSZVGQP8EMft5gsns2T-XW82aqa0qDFGvDe2lI6IBiz6doLZMQDQf3UhHROVy5IvrctL5CozTO2RbD_E_ucl75_dHk327Oh2Zi3Pw8wnkrtk_4iadpPdXlIP?expires=1729720800&signature=80692fc66497b589d53b91a22e47873bb3cc79201110a484add3a47969f5cff7&req=dSInEs99n4lbUfMW1HO4zbhYFPglAYUL38JRhBdLBlt3Yjr8W%2FF3HwChTLmN%0A5gmh%0A)
## Edit Finding Form: Fields


* **"Test" cannot be edited:** Findings always have to be associated with a Test object, and cannot be moved out of that context. However, the Engagement containing a Test can be moved to another Product.  
​
* **Found By** is the scan tool which discovered this Finding. Note that you can add additional scan tools beyond the tool associated with the Test.  
​
* **Title** is created from the scan report, but you can edit this title to be more meaningful if you need to. Note that this may affect Deduplication, as Deduplication generally uses the titles of Findings to identify duplicates.  
​
* **Date** is meant to represent the date the Finding was uncovered by the scanner \- not necessarily the date the Finding was imported into DefectDojo. This date is pulled from the scan report, but you can update this date to be more accurate if you need to (for example, if working with historical data, or if using a scanning tool which does not log discovery dates).  
​
* **Description** is the description of a Finding provided by the scan tool. You can add or remove information from the Finding Description if you wish.  
​
* **Severity** is calculated based on several factors. At a base level, this will be the Severity reported by a tool, but a Finding’s Severity can be affected by EPSS changes. You can also manually adjust the Finding’s Severity to an appropriate level.  
​
* **Tags** are generic text labels that you can use to organize your Findings via Filters \- or they can simply be used as shorthand to identify a specific Finding.  
​
* **Active / Verified** are the primary Finding statuses used by a tool. Active Findings are Findings that are currently active in your network and have been reported by a tool. Verified means that this Finding has been confirmed to exist by a team member.  
​
* **SAST / DAST** are labels used to organize your Findings into the context they were discovered in. Generally, this label is populated based on the scanning tool used, but you can adjust this to a more accurate level (for example, if the Finding was found by both a SAST and a DAST tool).
