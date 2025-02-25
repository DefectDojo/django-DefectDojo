---
title: "Connect a Jira Project to a Product"
description: "Set up a DefectDojo Product to push Findings to a JIRA board"
weight: 2
---

If you haven't already set up DefectDojo's Jira Configuration, you'll need to start by linking one or more Jira instances to DefectDojo.  
​  
See this guide for more information: [Connect DefectDojo To Jira](../connect_to_jira/).

Once a Jira configuration is connected to a Product, Jira and the Product will communicate to do the following:

* Use DefectDojo Findings to create Jira Issues, which automatically contain all relevant Finding information and links
* Bidirectional Sync, allowing for status updates and comments to be created on both the Jira and DefectDojo side.

Each Product in DefectDojo has its own settings which govern how Findings are converted to JIRA Issues. From here, you can decide the associated JIRA Project and set the default behaviour for creating Issues, Epics, Labels and other JIRA metadata.

## Link a Jira Project to a Product (Beta UI)

You can find this page by clicking the Gear menu - ⚙️ and opening the Jira Project Settings page.

![image](images/jira-project-settings.png)


## Link a Jira Project to a Product (Classic UI)

You can find this page by clicking the "**📝 Edit**" button under **Settings** on the Product page: `(defectdojo.com/product/{id})`.

​
![image](images/Add_a_Connected_Jira_Project_to_a_Product.png)

* You can link to a Product Settings page directly via `**yourcompany.**defectdojo.com/product/{id}/settings`.​

## List of Jira settings

Jira settings are located near the bottom of the Product Settings page.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_2.png)

### Jira Instance

If you have multiple instances of Jira set up, for separate products or teams within your organization, you can indicate which Jira Project you want DefectDojo to create Issues in. Select a Project from the drop\-down menu.

If this menu doesn't list any Jira instances, confirm that those Projects are connected in your global Jira Configuration for DefectDojo \- yourcompany.defectdojo.com/jira.

### Project key

This is the key of the Project that you want to use with DefectDojo.  The Project Key for a given project can be found in the URL.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

### Issue template

Here you can determine how much DefectDojo metadata you want to send to Jira. Select one of two options:

* **jira\_full**: Issues will track all of the parameters from DefectDojo \- a full Description, CVE, Severity, etc. Useful if you need complete Finding context in Jira (for example, if someone is working on this Issue who doesn't have access to DefectDojo).   

Here is an example of a **jira\_full** Issue:  
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** Issues will only track the DefectDojo link, the Product/Engagement/Test links, the Reporter and Environment fields. All other fields are tracked in DefectDojo only. Useful if you don't require full Finding context in Jira (for example, if someone is working on this Issue who mainly works in DefectDojo, and doesn't need the full picture in JIRA as well.)  
​  
​**Here is an example of a jira\_limited Issue:**​

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

### Component

If you manage your Jira project using Components, you can assign the appropriate Component for DefectDojo here.

**Custom fields**

If you don’t need to use Custom Fields with DefectDojo issues, you can leave this field as ‘null’. 

However, if your Jira Project Settings **require you** to use Custom Fields on new Issues, you will need to hard\-code these mappings.

**Jira Cloud now allows you to create a default Custom Field value directly in\-app. [See Atlassian's documentation on Custom Fields](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) for more information on how to configure this.**

Note that DefectDojo cannot send any Issue\-specific metadata as Custom Fields, only a default value. This section should only be set up if your JIRA Project **requires that these Custom Fields exist** in every Issue in your project.

Follow **[this guide](../using_custom_fields/)** to get started working with Custom Fields.

**Jira labels**

Select the relevant labels that you want the Issue to be created with in Jira, e.g. **DefectDojo**, **YourProductName..**

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

### Default assignee

The name of the default assignee in Jira. If left blank, DefectDojo will follow the default behaviour in your Jira Project when creating Issues.

## Additional Jira Options

### Enable Connection With Jira Project

Jira integrations can be removed from your instance only if no related Issues have been created.  If Issues have been created, there is no way to completely remove a Jira Instance from DefectDojo.

However, you can disable your Jira integration by disabling it at the Product level. This will not delete or change any existing Jira tickets created by DefectDojo, but will disable any further updates.

### Add Vulnerability Id as a Jira label

This allows you to add the Vulnerability ID data as a Jira Label automatically. Vulnerability IDs are added to Findings from individual security tools \- these may be Common Vulnerabilities and Exposures (CVE) IDs or a different format, specific to the tool reporting the Finding. 

### Enable Engagement Epic Mapping

In DefectDojo, Engagements represent a collection of work. Each Engagement contains one or more tests, which contain one or more Findings which need to be mitigated. Epics in Jira work in a similar way, and this checkbox allows you to push Engagements to Jira as Epics.

* An Engagement in DefectDojo \- note the three findings listed at the bottom.  
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* How the same Engagement becomes an Epic when pushed to JIRA \- the Engagement's Findings are also pushed, and live inside the Engagement as Child Issues.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

### Push All Issues

If checked, DefectDojo will automatically push any Active and Verified Findings to Jira as Issues. If left unchecked, all Findings will need to be pushed to Jira manually.

### Push Notes

If enabled, Jira comments will populate on the associated Finding in DefectDojo, under Notes on the issue(screenshot), and vice versa; Notes on Findings will be added to the associated Jira Issue as Comments. 

### Send SLA Notifications As Comments

If enabled, any Issue which breaches DefectDojo’s Service Level Agreement rules will have comments added to the Jira issue indicating this. These comments will be posted daily until the Issue is resolved.

Service Level Agreements can be configured under **Configuration \> SLA Configuration** in DefectDojo and assigned to each Product.

### Send Risk Acceptance Expiration Notifications As Comment?

If enabled, any Issue where the associated DefectDojo Risk Acceptance expires will have a comment added to the Jira issue indicating this. These comments will be posted daily until the Issue is resolved.

## Testing the Jira integration

### Test 1: Do Findings successfully push to Jira?

In order to test that the Jira integration is working properly, you can add a new blank Finding to the Product associated with Jira in DefectDojo. **Product \> Findings \> Add New Finding.**

Add whatever title severity and description you wish, and then click “Finished”. The Finding should appear as an Issue in Jira with all of the relevant metadata.

If Jira Issues are not being created correctly, check your Notifications for error codes.

* Confirm that the Jira User associated with DefectDojo's Jira Configuration has permission to create and update issues on that particular Jira Project.

### Test 2: Jira Webhooks send to DefectDojo

In order to test the Jira webhooks, add a Note to a Finding which also exists in JIRA as an Issue (for example, the test issue in the section above).

If the webhooks are configured correctly, you should see the Note in Jira as a Comment on the issue. 

If this doesn’t work correctly, it could be due to a Firewall issue on your Jira instance blocking the Webhook. 

* DefectDojo's Firewall Rules include a checkbox for **Jira Cloud,** which needs to be enabled before DefectDojo can receive Webhook messages from Jira.

# Next Steps

Learn how to create Jira Issues from your Product with **[this guide](../create_issues_in_jira).**
