---
title: "Connect DefectDojo to Jira"
description: "Set up a Jira Configuration in DefectDojo - step 1 of working with Jira"
---

Jira Configurations are the starting point for DefectDojo’s Jira integration. You can add multiple configurations to a DefectDojo instance, to allow for many different linked Jira Projects and boards.

Adding a configuration does not cause any Findings to push right away \- this is simply the first step. Once the Jira Configuration is created, it must be added to a Product before any information will push to Jira. See **[this guide](https://docs.defectdojo.com/en/jira_integration/add-a-connected-jira-project-to-a-product/)** for help with adding this integration to a Product.

## The Jira Configuration Page

The first step of setting up a Jira configuration is to add a Project to DefectDojo.

1. If you have not already done so, navigate to the System Settings page and check the box on **Enable Jira Integration**. You will need to do this before the ⚙️ **Configuration \> JIRA** option shows up on the sidebar.  
​
2. Navigate to the ⚙️**Configuration \> JIRA**  page from the DefectDojo sidebar.  
​
![image](images/Connect_DefectDojo_to_Jira.png)


3. You will see a list of all currently configured JIRA Projects which are linked to DefectDojo. To add a new Project Configuration, click the wrench icon and choose either the **Add JIRA Configuration (Express)** or **Add JIRA Configuration** options.

## Add JIRA Configuration (Express)

The Express method allows for a quicker method of linking a Project. Use the Express method if you simply want to connect a Jira Project quickly, and you aren’t dealing with a complex Jira workflow.

![image](images/Connect_DefectDojo_to_Jira_2.png)

1. Select a name for this Jira Configuration to use on DefectDojo.  
​
2. Select the URL for your company’s Jira instance \- likely similar to https://**yourcompany**.atlassian.net if you’re using a Jira Cloud installation.  
​
3. Enter your Username and Password for Jira. Alternatively, if your Jira instance uses a Personal Access Token (**PAT**) for authentication, you should instead enter the **PAT** in the Password field. The Username will not be used for authentication with **PAT**, but you can use this field as a label to indicate the name of the **PAT** you're using.  
​
4. Select the Default issue type which you want to create Issues as in Jira. The options for this are **Bug, Task, Story** and **Epic** (which are standard Jira issue types) as well as **Spike** and **Security**, which are custom issue types. If you have a different Issue Type which you want to use, please contact [support@defectdojo.com](mailto:support@defectdojo.com) for assistance.  
​
5. Select your Issue Template \- the two types are:  
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

## Add Jira Configuration (Standard)

The Standard Jira Configuration adds a few additional steps to allow for more precise control over Jira mappings and interactions. This can be changed after a Jira configuration has been added, even if it was created using the Express method.  
​
## Additional Configuration Options

* **Epic Name ID:** If you have multiple Epic types in Jira, you can specify the one you want to use by finding its ID in the Jira Field Spec.  
​  
To obtain the 'Epic name id' visit https://\<YOUR JIRA URL\>/rest/api/2/field and search for Epic Name. Copy the number out of cf\[number] and paste it here.  
​  ​
* **Reopen Transition ID:** If you want a specific Jira Transition to Reopen an issue, you can specify the Transition ID here. If using the Express Jira Configuration, DefectDojo will automatically find an appropriate Transition and create the mapping.  
​
Visit https://\<YOUR JIRA URL\>/rest/api/latest/issue/\<ANY VALID ISSUE KEY\>/transitions? expand\-transitions.fields to find the ID for your Jira instance. Paste it in the Reopen Transition ID field.  
​
* **Close Transition ID:** If you want a specific Jira Transition to Close an issue, you can specify the Transition ID here. If using the **Express Jira Configuration**, DefectDojo will automatically find an appropriate Transition and create the mapping.  
​  
Visit https://\<YOUR JIRA URL\>/rest/api/latest/issue/\<ANY VALID ISSUE KEY\>/transitions? expand\-transitions.fields to find the ID for your Jira instance. Paste it in the Close Transition ID field.  
​
* **Mapping Severity Fields:** Each Jira Issue has an associated Priority, which DefectDojo will automatically assign based on the Severity of a Finding. Enter the names of each Priority which you want to map to, for Info, Low, Medium, High and Critical Severities.  

* **Finding Text** \- if you want to add additional standardized text to each Issue created, you can enter that text here. This is not text that maps to any field in Jira, but additional text that is added to the Issue Description. "**Created by DefectDojo**" for example.

Comments (in Jira) and Notes (in DefectDojo) can be kept in sync. This setting can be enabled once the Jira configuration has been added to a Product, via the **Edit Product** form.

# Next steps

Now that you've set up your Jira Configuration, **[link it to one or more of your Products](https://docs.defectdojo.com/en/jira_integration/add-a-connected-jira-project-to-a-product/)** to have your Findings populate into Jira.
