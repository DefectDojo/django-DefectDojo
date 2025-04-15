---
title: "Jira Integration Guide"
description: "Work with the Jira integration"
weight: 3
---

DefectDojo's Jira integration can be used to push Finding data to one or more Jira Projects.  By doing so, you can integrate DefectDojo into your standard development workflow.  Here are some examples of how this can work:

* The AppSec team can selectively push Findings to a Jira Project used by developers, so that issue remediation can be appropriately prioritized alongside regular development.  Developers on this board don't need to access DefectDojo - they can keep all their work in one place.
* DefectDojo can push ALL Findings to a bidirectional Jira Project which the AppSec team uses, which allows them to split up issue validation.  This board keeps in sync with DefectDojo and allows for complex remediation workflows.
* DefectDojo can selectively push Findings from separate Products &/or Engagements to separate Jira Projects, to keep things in their proper context.

# Setting Up Jira
Setting Up Jira requires the following steps:
1. Connect a Jira Instance, either with a username / password or an API token.  Multiple instances can be linked.
2. Add that Jira Instance to one or more Products or Engagements within DefectDojo.
3. If you wish to use bidirectional sync, create a Jira Webhook which will send updates to DefectDojo.

## Step 1: Connect a Jira Instance

Connecting a Jira Instance is the first step to take when setting up DefectDojo’s Jira integration.  Please note Jira Service Management is currently not supported.

#### Required information from Jira

Atlassian uses different ways of authentication between Jira Cloud and Jira Data Center.

for **Jira Cloud**, you will need:
* a Jira URL, i.e. https://yourcompany.atlassian.net/
* an account with permissions to create and update issues in your Jira instance.  This can be:
    * A standard **username / password** combination
    * A **username / API Key** combination

for **Jira Data Center (or Server)**, you will need:
* a Jira URL, i.e. https://jira.yourcompany.com
* an account with permissions to create and update issues in your Jira instance.  This can be:
    * A **emailaddress / Personal Access Token** combination

Optionally, you can map:
* Jira Transitions to trigger Re-Opening and Closing Findings
* Jira Resolutions which can apply Risk Acceptance and False Positive statuses to Findings (optional)

Multiple Jira Projects can be handled by a single Jira Instance connection, as long as the Jira account / token used by DefectDojo has permission to create Issues in the associated Jira Project.

### Add a Jira Instance (Pro UI)

1. If you have not already done so, navigate to the System Settings page and check the box on **Enable Jira Integration**.

2. Navigate to the  **Enterprise Settings \> Jira Instances \> + New Jira Instance**  page from the DefectDojo sidebar.

![image](images/jira-instance-beta.png)

3. Select a **Configuration Name** for this Jira Instance to use in DefectDojo. This name is simply a label for the Instance connection in DefectDojo, and does not need to be related to any Jira data.

4. Select the URL for your company’s Jira instance \- likely similar to `https://**yourcompany**.atlassian.net` if you’re using a Jira Cloud installation.

5. Enter an appropriate authetication method in the Username / Password fields for Jira:
    * For standard **username / password Jira authentication**, enter a Jira Username and corresponding Password in these fields.
    * For authentication with a **user's API token (Jira Cloud)** enter the Username with the corresponding **API token** in the password field.
    * For authentication with a Jira **Personal Access Token (aka PAT, used in Jira Data Center and Jira Server only)**, enter the PAT in the password field.  Username is not used for authentication with a Jira PAT, but the field is still required in this form, so you can use a placeholder value here to identify your PAT.

Note that the user associated with this connection have permission to create Issues and access data in your Jira instance.

6. You will need to provide values for an Epic Name ID, Re-open Transition ID and Close Transition ID.  These values can be changed later.  While logged into Jira, you can access these values from the following URLs:
- **Epic Name ID**: visit `https://\<YOUR JIRA URL\>/rest/api/2/field` and search for Epic Name. Copy the number out of cf\[number] and paste it here.
- **Re-open Transition ID**: visit `https://\<YOUR JIRA URL\>/rest/api/latest/issue/\<ANY VALID ISSUE KEY\>/transitions? expand\-transitions.fields` to find the ID for your Jira instance. Paste it in the Reopen Transition ID field.
- **Close Transition ID**: Visit `https://\<YOUR JIRA URL\>/rest/api/latest/issue/\<ANY VALID ISSUE KEY\>/transitions? expand\-transitions.fields` to find the ID for your Jira instance. Paste it in the Close Transition ID field.

7. Select the Default issue type which you want to create Issues as in Jira. The options for this are **Bug, Task, Story** and **Epic** (which are standard Jira issue types) as well as **Spike** and **Security**, which are custom issue types. If you have a different Issue Type which you want to use, please contact [support@defectdojo.com](mailto:support@defectdojo.com) for assistance.

8. Select your Issue Template, which will determine the Issue Description when Issues are created in Jira.

The two types are:
\- **Jira\_full**, which will include all Finding information in Jira Issues
\- **Jira\_limited**, which will include a smaller amount of Finding information and metadata.
​
If you leave this field blank, it will default to **Jira\_full.**  If you need a different kind of template, Pro users can reach out to support@defectdojo.com

9. If you wish, enter the name of a Jira Resolution which will change the status of a Finding to Accepted or to False Positive (when the Resolution is triggered on the Issue).

The form can be submitted from here.  If you wish, you can further customize your Jira integration under Optional Fields.  Clicking this button will allow you to apply generic text to Jira Issues or change the mapping of Jira Severity Mappings.

### Add a Jira Instance (Classic UI / Open-Source)

1. If you have not already done so, navigate to the System Settings page and check the box on **Enable Jira Integration**. You will need to do this before the ⚙️ **Configuration \> JIRA** option shows up on the sidebar.
​
2. Navigate to the ⚙️ **Configuration \> JIRA**  page from the DefectDojo sidebar.
​
![image](images/Connect_DefectDojo_to_Jira.png)

3. You will see a list of all currently configured Jira Projects which are linked to DefectDojo. To add a new Project Configuration, click the wrench icon and choose either the **Add Jira Configuration (Express)** or **Add Jira Configuration** options.

#### Add Jira Configuration (Express)

The Express method allows for a quicker method of linking a Project. Use the Express method if you simply want to connect a Jira Project quickly, and you aren’t dealing with a complex Jira workflow.

![image](images/Connect_DefectDojo_to_Jira_2.png)

1. Select a name for this Jira Configuration to use in DefectDojo. This name is simply a label for the Instance connection in DefectDojo, and does not need to be related to any Jira data.
​
2. Select the URL for your company’s Jira instance \- likely similar to `https://**yourcompany**.atlassian.net` if you’re using a Jira Cloud installation.
​
3. Enter an appropriate authetication method in the Username / Password fields for Jira:
    * For standard **username / password Jira authentication**, enter a Jira Username and corresponding Password in these fields.
    * For authentication with a **user's API token (Jira Cloud)** enter the Username with the corresponding **API token** in the password field.
    * For authentication with a Jira **Personal Access Token (aka PAT, used in Jira Data Center and Jira Server only)**, enter the PAT in the password field.  Username is not used for authentication with a Jira PAT, but the field is still required in this form, so you can use a placeholder value here to identify your PAT.
​
4. Select the Default issue type which you want to create Issues as in Jira. The options for this are **Bug, Task, Story** and **Epic** (which are standard Jira issue types) as well as **Spike** and **Security**, which are custom issue types. If you have a different Issue Type which you want to use, please contact [support@defectdojo.com](mailto:support@defectdojo.com) for assistance.
​
5. Select your Issue Template, which will determine the Issue Description when Issues are created in Jira.

The two types are:
\- **Jira\_full**, which will include all Finding information in Jira Issues
\- **Jira\_limited**, which will include a smaller amount of Finding information and metadata.
​
If you leave this field blank, it will default to **Jira\_full.**
​
6. Select one or more Jira Resolution types which will change the status of a Finding to Accepted (when the Resolution is triggered on the Issue). If you don’t wish to use this automation, you can leave the field blank.
​
7. Select one or more Jira Resolution types which will change the status of a Finding to False Positive (when the Resolution is triggered on the Issue). If you don’t wish to use this automation, you can leave the field blank.
​
8. Decide whether you wish to send SLA Notifications as a comment on a Jira issue.
​
9. Decide whether you wish to automatically sync Findings with Jira. If this is enabled, Jira Issues will automatically be kept in sync with the related Findings. If this is not enabled, you will need to manually push any changes made to a Finding after the Issue has been created in Jira.
​
10. Select your Issue key. In Jira, this is the string associated with an Issue (e.g. the word **‘EXAMPLE’** in an issue called **EXAMPLE\-123**). If you don’t know your issue key, create a new Issue in the Jira Project. In the screenshot below, we can see that the issue key on our Jira Project is **DEF**.
​
![image](images/Connect_DefectDojo_to_Jira_3.png)
​
11. Click **Submit.** DefectDojo will automatically look for appropriate mappings in Jira and add them to the configuration. You are now ready to link this configuration to one or more Products in DefectDojo.

#### Add Jira Configuration (Standard)

The Standard Jira Configuration adds a few additional steps to allow for more precise control over Jira mappings and interactions. This can be changed after a Jira configuration has been added, even if it was created using the Express method.
​
### Additional Form Options

* **Epic Name ID:** If you have multiple Epic types in Jira, you can specify the one you want to use by finding its ID in the Jira Field Spec.
​
To obtain the 'Epic name id' visit `https://\<YOUR JIRA URL\>/rest/api/2/field` and search for Epic Name. Copy the number out of cf\[number] and paste it here.
​  ​
* **Reopen Transition ID:** If you want a specific Jira Transition to Reopen an issue, you can specify the Transition ID here. If using the Express Jira Configuration, DefectDojo will automatically find an appropriate Transition and create the mapping.
​
Visit `https://\<YOUR JIRA URL\>/rest/api/latest/issue/\<ANY VALID ISSUE KEY\>/transitions? expand\-transitions.fields` to find the ID for your Jira instance. Paste it in the Reopen Transition ID field.
​
* **Close Transition ID:** If you want a specific Jira Transition to Close an issue, you can specify the Transition ID here. If using the **Express Jira Configuration**, DefectDojo will automatically find an appropriate Transition and create the mapping.
​
Visit `https://\<YOUR JIRA URL\>/rest/api/latest/issue/\<ANY VALID ISSUE KEY\>/transitions? expand\-transitions.fields` to find the ID for your Jira instance. Paste it in the Close Transition ID field.
​
* **Mapping Severity Fields:** Each Jira Issue has an associated Priority, which DefectDojo will automatically assign based on the Severity of a Finding. Enter the names of each Priority which you want to map to, for Info, Low, Medium, High and Critical Severities.

* **Finding Text** \- if you want to add additional standardized text to each Issue created, you can enter that text here. This is not text that maps to any field in Jira, but additional text that is added to the Issue Description. "**Created by DefectDojo**" for example.

Comments (in Jira) and Notes (in DefectDojo) can be kept in sync. This setting can be enabled once the Jira configuration has been added to a Product, via the **Edit Product** form.

## Step 2: Connect a Product or Engagement to Jira

Each Product or Engagement in DefectDojo has its own settings which govern how Findings are converted to JIRA Issues. From here, you can decide the associated JIRA Project and set the default behaviour for creating Issues, Epics, Labels and other JIRA metadata.

### Add Jira to a Product or Engagement (Pro UI)

You can find this page by clicking the Gear menu on a Product or Engagement - ⚙️ and opening the Jira Project Settings page.

![image](images/jira-project-settings.png)

#### Jira Instance

If you have multiple instances of Jira set up, for separate products or teams within your organization, you can indicate which Jira Project you want DefectDojo to create Issues in. Select a Project from the drop\-down menu.

If this menu doesn't list any Jira instances, confirm that those Projects are connected in your global Jira Configuration for DefectDojo \- yourcompany.defectdojo.com/jira.

#### Project key

This is the key of the Project that you want to use with DefectDojo.  The Project Key for a given project can be found in the URL.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Issue template

Here you can determine how much DefectDojo metadata you want to send to Jira. Select one of two options:

* **jira\_full**: Issues will track all of the parameters from DefectDojo \- a full Description, CVE, Severity, etc. Useful if you need complete Finding context in Jira (for example, if someone is working on this Issue who doesn't have access to DefectDojo).   

Here is an example of a **jira\_full** Issue:  
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** Issues will only track the DefectDojo link, the Product/Engagement/Test links, the Reporter and Environment fields. All other fields are tracked in DefectDojo only. Useful if you don't require full Finding context in Jira (for example, if someone is working on this Issue who mainly works in DefectDojo, and doesn't need the full picture in JIRA as well.)  
​  
​**Here is an example of a jira\_limited Issue:**​

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Component

If you manage your Jira project using Components, you can assign the appropriate Component for DefectDojo here.

**Custom fields**

If you don’t need to use Custom Fields with DefectDojo issues, you can leave this field as ‘null’. 

However, if your Jira Project Settings **require you** to use Custom Fields on new Issues, you will need to hard-code these mappings.

Note that DefectDojo cannot send any Issue\-specific metadata as Custom Fields, only a default value. This section should only be set up if your JIRA Project **requires that these Custom Fields exist** in every Issue in your project.

Follow **[this guide](#custom-fields-in-jira)** to get started working with Custom Fields.

**Jira labels**

Select the relevant labels that you want the Issue to be created with in Jira, e.g. **DefectDojo**, **YourProductName..**

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Default assignee

The name of the default assignee in Jira. If left blank, DefectDojo will follow the default behaviour in your Jira Project when creating Issues.

### Add Jira to a Product or Engagement (Classic UI / Open-Source)

In the Classic UI, you can find Jira settings by opening the Edit Product or Edit Engagement form. "**📝 Edit**" button under **Settings** on the page:

![image](images/Add_a_Connected_Jira_Project_to_a_Product.png)

#### List of Jira settings

Jira settings are located near the bottom of the Product Settings page.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_2.png)

#### Jira Instance

If you have multiple instances of Jira set up, for separate products or teams within your organization, you can indicate which Jira Project you want DefectDojo to create Issues in. Select a Project from the drop\-down menu.

If this menu doesn't list any Jira instances, confirm that those Projects are connected in your global Jira Configuration for DefectDojo \- yourcompany.defectdojo.com/jira.

#### Project key

This is the key of the Project that you want to use with DefectDojo.  The Project Key for a given project can be found in the URL.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Issue template

Here you can determine how much DefectDojo metadata you want to send to Jira. Select one of two options:

* **jira\_full**: Issues will track all of the parameters from DefectDojo \- a full Description, CVE, Severity, etc. Useful if you need complete Finding context in Jira (for example, if someone is working on this Issue who doesn't have access to DefectDojo).   

Here is an example of a **jira\_full** Issue:  
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** Issues will only track the DefectDojo link, the Product/Engagement/Test links, the Reporter and Environment fields. All other fields are tracked in DefectDojo only. Useful if you don't require full Finding context in Jira (for example, if someone is working on this Issue who mainly works in DefectDojo, and doesn't need the full picture in JIRA as well.)  
​  
​**Here is an example of a jira\_limited Issue:**​

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Component

If you manage your Jira project using Components, you can assign the appropriate Component for DefectDojo here.

**Custom fields**

If you don’t need to use Custom Fields with DefectDojo issues, you can leave this field as ‘null’. 

However, if your Jira Project Settings **require you** to use Custom Fields on new Issues, you will need to hard\-code these mappings.

**Jira Cloud now allows you to create a default Custom Field value directly in\-app. [See Atlassian's documentation on Custom Fields](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) for more information on how to configure this.**

Note that DefectDojo cannot send any Issue\-specific metadata as Custom Fields, only a default value. This section should only be set up if your JIRA Project **requires that these Custom Fields exist** in every Issue in your project.

Follow **[this guide](#custom-fields-in-jira)** to get started working with Custom Fields.

**Jira labels**

Select the relevant labels that you want the Issue to be created with in Jira, e.g. **DefectDojo**, **YourProductName..**

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Default assignee

The name of the default assignee in Jira. If left blank, DefectDojo will follow the default behaviour in your Jira Project when creating Issues.

### Additional Form Options

#### Enable Connection With Jira Project

Jira integrations can be removed from your instance only if no related Issues have been created.  If Issues have been created, there is no way to completely remove a Jira Instance from DefectDojo.

However, you can disable your Jira integration by disabling it at the Product level. This will not delete or change any existing Jira tickets created by DefectDojo, but will disable any further updates.

#### Add Vulnerability Id as a Jira label

This allows you to add the Vulnerability ID data as a Jira Label automatically. Vulnerability IDs are added to Findings from individual security tools \- these may be Common Vulnerabilities and Exposures (CVE) IDs or a different format, specific to the tool reporting the Finding. 

#### Enable Engagement Epic Mapping (For Products)

In DefectDojo, Engagements represent a collection of work. Each Engagement contains one or more tests, which contain one or more Findings which need to be mitigated. Epics in Jira work in a similar way, and this checkbox allows you to push Engagements to Jira as Epics.

* An Engagement in DefectDojo \- note the three findings listed at the bottom.  
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* How the same Engagement becomes an Epic when pushed to JIRA \- the Engagement's Findings are also pushed, and live inside the Engagement as Child Issues.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Push All Issues

If checked, DefectDojo will automatically push any Active and Verified Findings to Jira as Issues. If left unchecked, all Findings will need to be pushed to Jira manually.

#### Push Notes

If enabled, Jira comments will populate on the associated Finding in DefectDojo, under Notes on the issue(screenshot), and vice versa; Notes on Findings will be added to the associated Jira Issue as Comments. 

#### Send SLA Notifications As Comments

If enabled, any Issue which breaches DefectDojo’s Service Level Agreement rules will have comments added to the Jira issue indicating this. These comments will be posted daily until the Issue is resolved.

Service Level Agreements can be configured under **Configuration \> SLA Configuration** in DefectDojo and assigned to each Product.

#### Send Risk Acceptance Expiration Notifications As Comment?

If enabled, any Issue where the associated DefectDojo Risk Acceptance expires will have a comment added to the Jira issue indicating this. These comments will be posted daily until the Issue is resolved.

### Engagement-Level Jira Settings

Different Engagements within a Product can have different underlying Jira settings as a result. By default, Engagements will '**inherit Jira settings from product'**, meaning that they will share the same Jira settings as the Product they are nested under.

However, you can change an Engagement's **Product Key**, **Issue Template, Custom Fields, Jira Labels, Default Assignee** to be different from the default Product settings

You can access this page from the **Edit Engagement** page: **your\-instance.defectdojo.com/engagement/\[id]/edit**.

The Edit Engagement page can be found from the Engagement page, by clicking the ☰ menu next to the engagement's Description.

![image](images/Creating_Issues_in_Jira_5.png)

## Step 3: Configure Bidirectional Sync: Jira Webhook

The Jira integration allows for bidirectional sync via webhook. DefectDojo receives Jira notifications at a unique address, which can allow for Jira comments to be received on Findings, or for Findings to be resolved via Jira depending on your configuration.

### Locating your Jira Webhook URL

Your Jira Webhook is located on the System Settings form under **Jira Integration Settings**: **Enterprise Settings \> System Settings** from the sidebar.

![image](images/Configuring_the_Jira_DefectDojo_Webhook.png)

### Creating the Jira Webhook

1. Visit `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. Click 'Create a Webhook'.
3. For the field labeled 'URL' enter: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. The Web Hook Secret is listed under the Jira Integration Settings as listed above.
4. Under 'Comments' enable 'Created'. Under Issue enable 'Updated'.
5. Make sure your JIRA instance trusts the SSL certificate used by your DefectDojo instance. For JIRA Cloud DefectDojo must use [a valid SSL/TLS certificate, signed by a globally trusted certificate authority](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

Note that you do not need to create a Secret within Jira to use this webhook. The Secret is built into DefectDojo's URL, so simply adding the complete URL to the Jira Webhook form is sufficient.

DefectDojo's Jira Webhook only accepts requests from the Jira API.

#### Testing the Webhook

Once you have one or more Issues created from DefectDojo Findings, you can test the Webhook by adding a Comment to one of those Findings. The Comment should be received by the Jira webhook as a note.

If this doesn’t work correctly, it could be due to a Firewall issue on your Jira instance blocking the Webhook.

* DefectDojo's Firewall Rules include a checkbox for **Jira Cloud,** which needs to be enabled before DefectDojo can receive Webhook messages from Jira.

## Testing the Jira integration

#### Test 1: Do Findings successfully push to Jira?

In order to test that the Jira integration is working properly, you can add a new blank Finding to the Product associated with Jira in DefectDojo. **Product \> Findings \> Add New Finding.**

Add whatever title severity and description you wish, and then click “Finished”. The Finding should appear as an Issue in Jira with all of the relevant metadata.

If Jira Issues are not being created correctly, check your Notifications for error codes.

* Confirm that the Jira User associated with DefectDojo's Jira Configuration has permission to create and update issues on that particular Jira Project.

#### Test 2: Jira Webhooks send to DefectDojo

In order to test the Jira webhooks, add a Note to a Finding which also exists in JIRA as an Issue (for example, the test issue in the section above).

If the webhooks are configured correctly, you should see the Note in Jira as a Comment on the issue. 

If this doesn’t work correctly, it could be due to a Firewall issue on your Jira instance blocking the Webhook. 

* DefectDojo's Firewall Rules include a checkbox for **Jira Cloud,** which needs to be enabled before DefectDojo can receive Webhook messages from Jira.

## Disconnecting from Jira

Jira integrations can be removed from your instance only if no related Issues have been created.  If Issues have been created, there is no way to completely remove a Jira Instance from DefectDojo.

However, you can disable your Jira integration by disabling it at the Product level.  From the **Edit Product** form (Classic UI) or from the **Jira Product Settings** (Beta UI) you can uncheck the "Enable Connection With Jira Project" option.  This will not delete or change any existing Jira tickets created by DefectDojo, but will disable any further updates.

# Pushing Findings To Jira

## Pushing Findings To Jira
A Product with a JIRA mapping can push Findings to Jira as Issues. This can be managed in two different ways:

* Findings can be created as Issues manually, per\-Finding.
* Findings can be pushed automatically if the '**Push All Issues**' setting is enabled on a Product. (This applies only to Findings that are **Active** and **Verified**).

Additionally, you have the option to push Finding Groups to Jira instead of individual Findings. This will create a single Issue which contains many related DefectDojo Findings.

### Pushing a Finding Manually

1. From a Finding page in DefectDojo, navigate to the **JIRA** heading. If the Finding does not already exist in JIRA as an Issue, the JIRA header will have a value of '**None**'.  
​
2. Clicking on the arrow next to the **None** value will create a new Jira issue. The State the issue is created in will depend on your team's workflow and Jira configuration with DefectDojo. If the Finding does not appear, refresh the page.   
​
![image](images/Creating_Issues_in_Jira.png)

3. Once the Issue is created, DefectDojo will create a link to the issue made up of the Jira key and the Issue ID. This link will also have a red trash can next to it, to allow you to delete the Issue from Jira.  
​
![image](images/Creating_Issues_in_Jira_2.png)

4. Clicking the Arrow again will push all changes made to an issue to Jira, and update the Jira Issue accordingly. If '**Push All Issues**' setting is enabled on the Finding's associated Product, this process will happen automatically.

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

### Automatically Create and Push Finding Groups

With Auto\-Push To Jira Enabled, and a Group By option selected on import:

As long as the Finding Groups are being created successfully, the Finding Group is what will automatically push to Jira as an Issue, not the individual Findings.

![image](images/Creating_Issues_in_Jira_4.png)

## Custom Fields in Jira
<span style="background: rgba(243, 122, 78,0.5">DefectDojo does not currently support passing any Issue\-specific information into these Custom Fields \- these fields will need to be updated manually in Jira after the issue is created. Each Custom Field will only be created from DefectDojo with a default value.</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud now allows you to create a default Custom Field value directly in\-app. [See Atlassian's documentation on Custom Fields](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) for more information on how to configure this.</span>

DefectDojo's built\-in Jira Issue Types (**Bug, Task, Story** and **Epic)** are set up to work 'out of the box'. Data fields in DefectDojo will automatically map to the corresponding fields in Jira. By default, DefectDojo will assign Priority, Labels and a Reporter to any new Issue it creates.

Some Jira configurations require additional custom fields to be accounted for before an issue can be created. This process will allow you to account for these custom fields in your DefectDojo \-\> Jira integration, ensuring that issues are created successfully. These custom fields will be added to any API calls sent from DefectDojo to a linked Jira instance.

If you don’t already use Custom Fields in Jira, there is no need to follow this process.

1. Recording the names of your Custom Fields in Jira (**Jira UI**)
2. Determine the Key values for the new Custom Fields (Jira Field Spec Endpoint)
3. Locate the acceptable data for each Custom Field, using the Key values as a reference (Jira Issue Endpoint)
4. Create a Field Reference JSON block to track all of the Custom Field Keys and acceptable data (Jira Issue Endpoint)
5. Store the JSON block in the associated DefectDojo Product, to allow Custom Fields to be created from Jira (DefectDojo UI)
6. Test your work and ensure that all required data is flowing from Jira properly

#### Step 1: Record the names of your Custom Fields in Jira

Jira supports a variety of different Context Fields, including Date Pickers, Custom Labels, Radio Buttons. Each of these Context Fields will have a different Key value that can be found in the Jira API.

Write down the names of each required Custom Field, as you will need to search through the Jira API to find them in the next step.

**Example of a Custom Field list (your Custom Field names will be different):**

* DefectDojo Custom URL Field
* Another example of a Custom Field
* ...

#### Step 2: Finding your Jira Custom Field Key Values

Start this process by navigating to the Field Spec URL for your entire Jira instance.

Here is an example of a Field Spec URL:

`https://yourcompany\-example.atlassian.net/rest/api/2/field`

The API will return a long string of JSON, which should be formatted into readable text (using a code editor, browser extension or <https://jsonformatter.org/>).

The JSON returned from this URL will contain all of your Jira custom fields, most of which are irrelevant to DefectDojo and have values of `“Null”`. Each object in this API response corresponds to a different field in Jira. You will need to search for the objects that have `“name”` attributes which match the names of each Custom Field you created in the Jira UI, and then note the value of their “key” attribute.

![image](images/Using_Custom_Fields.png)

Once you’ve found the matching object in the JSON output, you can determine the “key” value \- in this case, it's `customfield_10050`.

Jira generates different key values for each Custom Field, but these key values do not change once created. If you create another Custom Field in the future, it will have a new key value.

**Expanding our Custom Field list:**

* “DefectDojo Custom URL Field” \= customfield\_10050
* “Another example of a Custom Field” \= customfield\_12345
* ...

#### Step 3 \- Finding the Custom Fields on a Jira Issue

Locate an Issue in Jira that contains the Custom Fields which you recorded in Step 2\. Copy the Issue Key for the title (should look similar to “`EXAMPLE-123`”) and navigate to the following URL:

`https://yourcompany\-example.atlassian.net/rest/api/2/issue/EXAMPLE\-123`

This will return another string of JSON.

As before, API output will contain lots of `customfield_##` object parameters with `null` values \- these are custom fields that Jira adds by default, which aren’t relevant to this issue. It will also contain `customfield_##` values that match the Custom Field Key values that you found in the previous step. Unlike with the Field Spec output, you won’t see names identifying any of these custom fields, which is why you needed to record the key values in Step 2\.

![image](images/Using_Custom_Fields_2.png)

**Example:**  
We know that `customfield_10050` represents the DefectDojo Custom URL Field because we recorded it in Step 2\. We can now see that `customfield_10050` contains a value of `“https://google.com”` in the `EXAMPLE-123` issue.

#### Step 4 \- Creating a JSON Field Reference from each Jira Custom Field Key

You’ll now need to take the value of each of the Custom Fields from your list and store them in a JSON object (to use as a reference). You can ignore any Custom Fields that don’t correspond to your list.

This JSON object will contain all of the default values for new Jira Issues. We recommend using names that are easy for your team to recognize as ‘default’ values that need to be changed: ‘`change-me.com`’, ‘`Change this paragraph.`’ etc.

**Example:**

From step 3, we now know that Jira expects a URL string for "`customfield_10050`”. We can use this to build our example JSON object.

Say we had also located a DefectDojo\-related short text field, which we identified as "`customfield_67890`”. We would look at this field in our second API output, look at the associated value, and reference the stored value in our example JSON object as well.  
​  
Your JSON object will start to look like this as you add more Custom Fields to it.

```
{  
	"customfield_10050": "https://change-me.com",  
	"customfield_67890": "This is the short text custom field."  
}
```

Repeat this process until all of the DefectDojo\-relevant custom fields from Jira have been added to your JSON Field Reference.

#### Data types \& Jira Syntax

Some fields, such as Date fields, may relate to multiple custom fields in Jira. If that is the case, you’ll need to add both fields to your JSON Field Reference.

```
  "customfield_10040": "1970-01-01",  
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

Other fields, such as the Label field, may be tracked as a list of strings \- please make sure your JSON Field Reference uses a format that matches API output from Jira.

```
// a list of custom labels on a Jira object  
  "customfield_10042": [  
    "custom-label-one",  
    "this-is-default",  
    "change-me-please"  
  ],
```

Other custom fields may contain additional, contextual information that should be removed from the Field Reference. For example, the Custom Multichoice Field contains an extra block in the API output, which you’ll need to remove, as this block stores the current value of the field.

* you should remove the extra object from this field:

```
"customfield_10047": [  
    {  
      "value": "A"  
    },  
    {  
      "self": "example.url...",  
      "value": "C",  
      "id": "example ID"  
    }  
]
```
* instead, you can shorten this to the following and disregard the second part: 

```
"customfield_10047": [      
   {        
      "value": "A"  
   }  
] 
```

#### Example Completed Field Reference

Here is a complete JSON Field Reference, with in\-line comments explaining what each custom field pertains to. This is meant as an all\-encompassing example. Your JSON will contain different key values and data points depending on the Custom Values you want to use during issue creation.

```
{  
  "customfield_10050": "https://change-me.com",  
   
  "customfield_10049": "This is a short text custom field",  
   
// two different fields, but both correspond to the same custom date attribute  
  "customfield_10040": "1970-01-01",  
  "customfield_10041": "1970-01-01T03:30:00.000+0200",  
   
// a list of custom labels on a Jira object  
  "customfield_10042": [  
    "custom-label-one",  
    "this-is-default",  
    "change-me-please"  
  ],  
   
// custom number field  
  "customfield_10043": 0,  
   
// custom paragraph field  
  "customfield_10044": "This is a very long winded way to say CHANGE ME PLEASE",  
   
// custom radio button field  
  "customfield_10045": {  
    "value": "radio button option"  
  },  
   
// custom multichoice field   
  "customfield_10047": [  
    {  
      "value": "A"  
    }  
  ],  
   
// custom checkbox field  
  "customfield_10039": [  
    {  
      "value": "A"  
    }  
  ],  
   
// custom select list (singlechoice) field  
  "customfield_10048": {  
    "value": "1"  
  }  
}
```

#### Step 5 \- Adding the Custom Fields to a DefectDojo Product

You can now add these custom fields to the associated DefectDojo Product, in the Custom Fields section. Once again,

* Navigate to Edit Product \- defectdojo.com/product/ID/edit .
* Navigate to Custom fields and paste the JSON Field Reference as plain text in the Custom Fields box.
* Click ‘Submit’.

#### Step 6 \- Testing your Jira Custom Fields from a new Finding:

Now, when you create a new Finding in the Jira\-associated Product, Jira will automatically create all of these Custom Fields in Jira according to the JSON block contained within. These Custom Fields will be created with the default (“change\-me\-please”, etc.) values.

Within the Product on DefectDojo, navigate to the Findings \> Add New Finding page. Make sure the Finding is both Active and Verified to ensure that it pushes to Jira, and then confirm on the Jira side that the Custom Fields are successfully created without any inconsistencies.