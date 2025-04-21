---
title: "Connect DefectDojo to Jira"
description: "Set up a Jira Configuration in DefectDojo - step 1 of working with Jira"
weight: 1
---

Connecting a Jira Instance is the first step to take when setting up DefectDojo’s Jira integration.

#### Required information from Jira

You will need:
* a Jira URL
* an account with permissions to create and update issues in your Jira instance.  This can be:
    * A standard **username / password** combination
    * A **username / API Key** combination **(Jira Cloud)**
    * A **Personal Access Token (aka PAT, used in Jira Data Center and Jira Server only)**

Optionally, you can map:
* Jira Transitions to trigger Re-Opening and Closing Findings
* Jira Resolutions which can apply Risk Acceptance and False Positive statuses to Findings (optional)

Multiple Jira Projects can be handled by a single Jira Instance connection, as long as the Jira account / token used by DefectDojo has permission to create Issues in the associated Jira Project.

#### How Findings are pushed

Connecting a Jira instance does not cause any Findings to push right away \- this is simply the first step. Once the Jira Instance connection is created, it must be associated with a Product or an Engagement before any information will push to Jira. 

If you already have a Jira Instance connection set up, you can use **[this guide](../add_jira_to_product)** for help with adding this integration to a Product.

## Add a Jira Instance (Pro UI)

1. If you have not already done so, navigate to the System Settings page and check the box on **Enable Jira Integration**.

2. Navigate to the  **Enterprise Settings \> Jira Instances \> + New Jira Instance**  page from the DefectDojo sidebar.  

![image](images/jira-instance-beta.png)

3. Select a **Configuration Name** for this Jira Instance to use in DefectDojo. This name is simply a label for the Instance connection in DefectDojo, and does not need to be related to any Jira data.  

4. Select the URL for your company’s Jira instance \- likely similar to https://**yourcompany**.atlassian.net if you’re using a Jira Cloud installation.  

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

## Add a Jira Instance (Legacy UI / Open-Source)

1. If you have not already done so, navigate to the System Settings page and check the box on **Enable Jira Integration**. You will need to do this before the ⚙️ **Configuration \> JIRA** option shows up on the sidebar.  
​
2. Navigate to the ⚙️ **Configuration \> JIRA**  page from the DefectDojo sidebar.  
​

![image](images/Connect_DefectDojo_to_Jira.png)


3. You will see a list of all currently configured JIRA Projects which are linked to DefectDojo. To add a new Project Configuration, click the wrench icon and choose either the **Add JIRA Configuration (Express)** or **Add JIRA Configuration** options.

### Add JIRA Configuration (Express)

The Express method allows for a quicker method of linking a Project. Use the Express method if you simply want to connect a Jira Project quickly, and you aren’t dealing with a complex Jira workflow.

![image](images/Connect_DefectDojo_to_Jira_2.png)

1. Select a name for this Jira Configuration to use in DefectDojo. This name is simply a label for the Instance connection in DefectDojo, and does not need to be related to any Jira data.  
​
2. Select the URL for your company’s Jira instance \- likely similar to https://**yourcompany**.atlassian.net if you’re using a Jira Cloud installation.  
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

### Add Jira Configuration (Standard)

The Standard Jira Configuration adds a few additional steps to allow for more precise control over Jira mappings and interactions. This can be changed after a Jira configuration has been added, even if it was created using the Express method.  
​
### Additional Configuration Options

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

## Configure Bidirectional Sync: Jira Webhook

The Jira integration allows for bidirectional sync via webhook. DefectDojo receives Jira notifications at a unique address, which can allow for Jira comments to be received on Findings, or for Findings to be resolved via Jira depending on your configuration.

### Locating your Jira Webhook URL

Your Jira Webhook is located on the System Settings form under **Jira Integration Settings**: **Enterprise Settings \> System Settings** from the sidebar.

![image](images/Configuring_the_Jira_DefectDojo_Webhook.png)

### Configuring Jira to send updates to your Webhook

1. Visit `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. Click 'Create a Webhook'.
3. For the field labeled 'URL' enter: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. The Web Hook Secret is listed under the Jira Integration Settings as listed above.
4. Under 'Comments' enable 'Created'. Under Issue enable 'Updated'.

Note that you do not need to create a Secret within Jira to use this webhook. The Secret is built into DefectDojo's URL, so simply adding the complete URL to the Jira Webhook form is sufficient.

DefectDojo's Jira Webhook only accepts requests from the Jira API.

### Testing the Webhook

Once you have one or more Issues created from DefectDojo Findings, you can test the Webhook by adding a Comment to one of those Findings. The Comment should be received by the Jira webhook as a note.

If this doesn’t work correctly, it could be due to a Firewall issue on your Jira instance blocking the Webhook.

* DefectDojo's Firewall Rules include a checkbox for **Jira Cloud,** which needs to be enabled before DefectDojo can receive Webhook messages from Jira.

## Disconnecting from Jira

Jira integrations can be removed from your instance only if no related Issues have been created.  If Issues have been created, there is no way to completely remove a Jira Instance from DefectDojo.

However, you can disable your Jira integration by disabling it at the Product level.  From the **Edit Product** form (Classic UI) or from the **Jira Product Settings** (Beta UI) you can uncheck the "Enable Connection With Jira Project" option.  This will not delete or change any existing Jira tickets created by DefectDojo, but will disable any further updates.

See our guide on [Adding Jira To a Product](../add_jira_to_product) for more information on Product-level settings.

## Next steps

* Now that you've set up your Jira Configuration, **[link it to one or more of your Products](../add_jira_to_product)** to have your Findings populate into Jira.
