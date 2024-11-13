---
title: "Creating Issues in Jira"
description: "Pushing DefectDojo Findings to a linked Jira Project"
---


Before you can create an Issue in Jira, you'll need to have


* **[a Jira integration configured](https://support.defectdojo.com/en/articles/8766815-set-up-a-jira-integration)**
* **[that same Jira integration linked to a Product](https://support.defectdojo.com/en/articles/8490492-add-jira-integration-to-a-product)**


Please see the guides above for help with this process.



# How Findings are pushed to Jira



A Product with a JIRA mapping can push Findings to Jira as Issues. This can be managed in two different ways:


* Findings can be created as Issues manually, per\-Finding.
* Findings can be pushed automatically if the '**Push All Issues**' setting is enabled on a Product. (This applies only to Findings that are **Active** and **Verified**).

Additionally, you have the option to push Finding Groups to Jira instead of individual Findings. This will create a single Issue which contains many related DefectDojo Findings.




# Pushing a Finding to Jira Manually


1. From a Finding page in DefectDojo, navigate to the **JIRA** heading. If the Finding does not already exist in JIRA as an Issue, the JIRA header will have a value of '**None**'.  
​
2. Clicking on the arrow next to the **None** value will create a new Jira issue. The State the issue is created in will depend on your team's workflow and Jira configuration with DefectDojo. If the Finding does not appear, refresh the page.   
​  
​


![](https://downloads.intercomcdn.com/i/o/910784359/572d851c9d8292d34dd7acc7/Screenshot+2023-12-15+at+10.11.32+AM.png?expires=1729720800&signature=1b913080cd7ccd29c6193cf33923c10c80925daa92143022a3f8d0cacff4245b&req=fSEnEcF6noRWFb4f3HP0gC6hrwobes4KCfUutw28q8xS3rYZCA9CZZvLlsRZ%0Avro%3D%0A)
  
​
3. Once the Issue is created, DefectDojo will create a link to the issue made up of the Jira key and the Issue ID. This link will also have a red trash can next to it, to allow you to delete the Issue from Jira.  
​


![](https://downloads.intercomcdn.com/i/o/910793636/2a9cd7316f118ef3e108a26a/Screenshot+2023-12-15+at+10.22.25+AM.png?expires=1729720800&signature=ff6f8c8c5ab7f7b50aa64795924805e04779cbfd9eb1991458b52c187fbe460f&req=fSEnEcB9m4JZFb4f3HP0gGKdXeVgqwRYF%2FvyituVBDqN28dqVMi%2FhmEppluu%0AUys%3D%0A)
4. Clicking the Arrow again will push all changes made to an issue to Jira, and update the Jira Issue accordingly. If '**Push All Issues**' setting is enabled on the Finding's associated Product, this process will happen automatically.



# How Jira Issues and Findings interact


Jira issues will impact their associated Finding in certain ways.



## Jira Comments


* If a comment is added to a Jira Issue, the same comment will be added to the Finding, under the **Notes** section.
* Likewise, if a Note is added to a Finding, the Note will be added to the Jira issue as a comment.

## Jira Status Changes


The Jira Configuration on DefectDojo has entries for two Jira Transitions which will trigger a status change on a Finding.


* When the **'Close' Transition** is performed on Jira, the associated Finding will also Close, and become marked as **Inactive** and **Mitigated** on DefectDojo. DefectDojo will record this change on the Finding page under the **Mitigated By** heading.  
​


![](https://downloads.intercomcdn.com/i/o/910797138/74e1c5ce3e09507d5c78b499/Screenshot+2023-12-15+at+10.26.37+AM.png?expires=1729720800&signature=01166d7f9f4ee3ed293e8ffc02afad7d4f519b7f72ba382a53b34e9754aeabaf&req=fSEnEcB5nIJXFb4f3HP0gKGxM4Pk6KLvrG1xOEGdbJCk%2FhkZvQmPj2YpZd%2F3%0AOXE%3D%0A)
* When the **'Reopen' Transition** is performed on the Jira Issue, the associated Finding will be set as **Active** on DefectDojo, and will lose its **Mitigated** status.

# Push Finding Groups as Jira Issues


If you have Finding Groups enabled, you can push a Group of Findings to Jira as a single Issue rather than separate Issues for each Finding.



The Jira Issue associated with a Finding Group cannot be interacted with or deleted by DefectDojo, however. It must be deleted directly from the Jira instance.



## **Automatically Create and Push Finding Groups**


With Auto\-Push To Jira Enabled, and a Group By option selected on import:


  
As long as the Finding Groups are being created successfully, the Finding Group is what will automatically push to Jira as an Issue, not the individual Findings.



![](https://downloads.intercomcdn.com/i/o/910810290/ac1144f3e392c0f116ce31d2/Screenshot+2023-12-15+at+10.42.58+AM.png?expires=1729720800&signature=a7806351286be98a7502fbeb96a63169eb12800589253109a69141fa72457dc0&req=fSEnHsh%2Bn4hfFb4f3HP0gIyL3dh8pgNDPRYkuGHdr6COFAOSTngChYgp1zWa%0A%2FLU%3D%0A)

# Change Jira settings for a specific Engagement


Different Engagements within a Product can have different underlying Jira settings as a result. By default, Engagements will '**inherit Jira settings from product'**, meaning that they will share the same Jira settings as the Product they are nested under.



However, you can change an Engagement's **Product Key**, **Issue Template, Custom Fields, Jira Labels, Default Assignee** to be different from the default Product settings


You can access this page from the **Edit Engagement** page: **your\-instance.defectdojo.com/engagement/\[id]/edit**.



The Edit Engagement page can be found from the Engagement page, by clicking the ☰ menu next to the engagement's Description.



![](https://downloads.intercomcdn.com/i/o/937440895/19a20d2976703a88fd1ec03d/Screenshot+2024-01-18+at+2.36.46+PM.png?expires=1729720800&signature=bec87928877d2ac08278b3bf55c4adad51fe790eb6f8afce0375281e539b14e6&req=fSMgEs1%2BlYhaFb4f3HP0gN%2FyTRYP9aPTp26R2XB063sOp%2BXtCV4UWdbUjbpa%0AawI%3D%0A)