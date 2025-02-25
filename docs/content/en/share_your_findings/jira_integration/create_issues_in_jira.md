---
title: "Send Finding data to Jira"
description: "Pushing DefectDojo Findings to a linked Jira Project"
weight: 3
---

Before you can create an Issue in Jira, you'll need to have:

* **[a Jira integration configured](../connect_to_jira/)**
* **[that same Jira integration linked to a Product](../add_jira_to_product/)**

Please see the guides above for help with this process.

## How Findings are pushed to Jira

A Product with a JIRA mapping can push Findings to Jira as Issues. This can be managed in two different ways:

* Findings can be created as Issues manually, per\-Finding.
* Findings can be pushed automatically if the '**Push All Issues**' setting is enabled on a Product. (This applies only to Findings that are **Active** and **Verified**).

Additionally, you have the option to push Finding Groups to Jira instead of individual Findings. This will create a single Issue which contains many related DefectDojo Findings.

## Pushing a Finding to Jira Manually

1. From a Finding page in DefectDojo, navigate to the **JIRA** heading. If the Finding does not already exist in JIRA as an Issue, the JIRA header will have a value of '**None**'.  
​
2. Clicking on the arrow next to the **None** value will create a new Jira issue. The State the issue is created in will depend on your team's workflow and Jira configuration with DefectDojo. If the Finding does not appear, refresh the page.   
​
![image](images/Creating_Issues_in_Jira.png)

3. Once the Issue is created, DefectDojo will create a link to the issue made up of the Jira key and the Issue ID. This link will also have a red trash can next to it, to allow you to delete the Issue from Jira.  
​
![image](images/Creating_Issues_in_Jira_2.png)

4. Clicking the Arrow again will push all changes made to an issue to Jira, and update the Jira Issue accordingly. If '**Push All Issues**' setting is enabled on the Finding's associated Product, this process will happen automatically.

## How Jira Issues and Findings interact

Jira issues will impact their associated Finding in certain ways.

### Jira Comments

* If a comment is added to a Jira Issue, the same comment will be added to the Finding, under the **Notes** section.
* Likewise, if a Note is added to a Finding, the Note will be added to the Jira issue as a comment.

### Jira Status Changes

The Jira Configuration on DefectDojo has entries for two Jira Transitions which will trigger a status change on a Finding.

* When the **'Close' Transition** is performed on Jira, the associated Finding will also Close, and become marked as **Inactive** and **Mitigated** on DefectDojo. DefectDojo will record this change on the Finding page under the **Mitigated By** heading.  
​
![image](images/Creating_Issues_in_Jira_3.png)

* When the **'Reopen' Transition** is performed on the Jira Issue, the associated Finding will be set as **Active** on DefectDojo, and will lose its **Mitigated** status.

## Push Finding Groups as Jira Issues

If you have Finding Groups enabled, you can push a Group of Findings to Jira as a single Issue rather than separate Issues for each Finding.

The Jira Issue associated with a Finding Group cannot be interacted with or deleted by DefectDojo, however. It must be deleted directly from the Jira instance.

### **Automatically Create and Push Finding Groups**

With Auto\-Push To Jira Enabled, and a Group By option selected on import:

As long as the Finding Groups are being created successfully, the Finding Group is what will automatically push to Jira as an Issue, not the individual Findings.

![image](images/Creating_Issues_in_Jira_4.png)

## Change Jira settings for a specific Engagement

Different Engagements within a Product can have different underlying Jira settings as a result. By default, Engagements will '**inherit Jira settings from product'**, meaning that they will share the same Jira settings as the Product they are nested under.

However, you can change an Engagement's **Product Key**, **Issue Template, Custom Fields, Jira Labels, Default Assignee** to be different from the default Product settings

You can access this page from the **Edit Engagement** page: **your\-instance.defectdojo.com/engagement/\[id]/edit**.

The Edit Engagement page can be found from the Engagement page, by clicking the ☰ menu next to the engagement's Description.

![image](images/Creating_Issues_in_Jira_5.png)
