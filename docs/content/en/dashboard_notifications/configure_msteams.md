---
title: "Configure a Microsoft Teams Integration"
description: "Set up Microsoft Teams to receive notifications"
---

**You will need Superuser access to use the System Settings page, which is required to complete this process.**

Like with Slack, Microsoft Teams can receive notifications to a specific channel. To do this, you will need to **set up an incoming webhook** on the channel where you wish to receive messages.

1. Complete the process listed in the **[Microsoft Teams Documentation](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=dotnet)** for creating a new Incoming Webhook. Keep your unique webhook.office.com link handy as you will need it in subsequent steps.  
​
![image](images/Configure_a_Microsoft_Teams_Integration.png)
2. In DefectDojo, navigate to **Configuration \> System Settings** from the sidebar.
3. Check the **Enable Microsoft Teams notifications** box. This will open a hidden section of the form, labeled **‘Msteams ur**l’.  
​
![image](images/Configure_a_Microsoft_Teams_Integration_2.png)
4. Paste the webhook.office.com URL (created in Step 1\) in the **Msteams url** box. Your Teams app will now listen to incoming Notifications from DefectDojo and post them to the channel you selected.

## Notes on the Teams integration

* Slack cannot apply any RBAC rules to the Teams channel that you are creating, and will therefore be sharing notifications for the entire DefectDojo system. There is no method in DefectDojo to filter system\-wide Teams notifications by a Product Type, Product or Engagement.
* DefectDojo cannot send personal notifications to users on Microsoft Teams.
