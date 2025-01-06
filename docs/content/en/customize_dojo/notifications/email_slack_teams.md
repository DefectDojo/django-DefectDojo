---
title: "Set up Email, Slack or Teams notifications"
description: "Set up Microsoft Teams to receive notifications"
---

**You will need Superuser access to use the System Settings page, which is required to complete this process.**

Notifications can be pushed to Slack or Teams when certain events trigger in DefectDojo.

## Slack Notifications Setup

DefectDojo can post Slack notifications in two different ways: 

* System\-wide notifications, which will be sent to a single Slack channel
* Personal notifications, which will only be sent to specific users.

Here is an example of a Slack Notification sent from DefectDojo:  
​
![image](images/Configure_a_Slack_Integration.png)

DefectDojo does not have a dedicated Slack app, but one can be easily created for your workspace by following this guide. A Slack app is required for both System and Personal notifications to be sent correctly.

### Create a Slack application

To set up a Slack connection to DefectDojo, you’ll need to create a custom Slack app.

1. Begin this process from the Slack Apps page: <https://api.slack.com/apps>.
2. Click ‘**Create New App**’.
3. Select ‘**From App Manifest**’.
4. Select your Slack workspace from the menu.
5. Enter your App Manifest \- you can copy and paste this JSON file, which includes all the permission settings required to allow the Slack integration to run.  
​
```
{  
   "_metadata": {  
     "major_version": 1,  
     "minor_version": 1  
   },  
   "display_information": {  
     "name": "DefectDojo",  
     "description": "Notifications from DefectDojo. See https://docs.defectdojo.com/en/notifications/configure-a-slack-integration/ for configuration steps.",  
     "background_color": "#0000AA"  
   },  
   "features": {  
       "bot_user": {  
           "display_name": "DefectDojo Notifications"  
       }  
   },  
   "oauth_config": {  
     "scopes": {  
       "bot": [  
         "chat:write",  
         "chat:write.customize",  
         "chat:write.public",  
         "incoming-webhook",  
         "users:read",  
         "users:read.email"  
       ]  
     },  
     "redirect_urls": [  
       "https://slack.com/oauth/v2/authorize"  
     ]  
   }  
 }
```

Review the App Summary, and click Create App when you’re done. Complete the installation by clicking the **Install To Workplace** button.

### Configure your Slack integration in DefectDojo

You’ll now need to configure the Slack integration on DefectDojo to complete the integration.

**You will need Superuser access to access DefectDojo's System Settings page.**

1. Navigate to the App Information page for your Slack App, from <https://api.slack.com/apps>. This will be the app that was created in the first section \- **Create a Slack application**.  
​
2. Find your OAuth Access Token. This can be found in the Slack sidebar \- **Features / OAuth \& Permissions**. Copy the **Bot User OAuth Token.  
​**

![image](images/Configure_a_Slack_Integration_2.png)

3. Open DefectDojo in a new tab, and navigate to **Configuration \> System Settings** from the sidebar. (In the Beta UI, this form is located under **Enterprise Settings > System Settings**.)
4. Check the **Enable Slack notifications** box.
5. Paste the **Bot User OAuth Token** from Step 1 in the **Slack token** field.
6. The **Slack Channel** field should correspond to the channel in your workspace where you want your notifications to be written by a DefectDojo bot.
7. If you want to change the name of the DefectDojo bot, you can enter a custom name here. If not, it will use **DefectDojo Notifications** as determined in the Slack App Manifest.

Once this process is complete, DefectDojo can send System\-wide notifications to this channel. Select the Notifications which you want to send from the [System Notifications page]().

![image](images/Configure_a_Slack_Integration_3.png)

#### Notes on System\-Wide Notifications in Slack:

Slack cannot apply any RBAC rules to the Slack channel that you are creating, and will therefore be sharing notifications for the entire DefectDojo system. There is no method in DefectDojo to filter system\-wide Slack notifications to a Product Type, Product or Engagement.

If you want to apply RBAC\-based filtering to your Slack messages, enabling personal notifications from Slack is a better option.

### Send Personal notifications to Slack

If your team has a Slack integration enabled (through the above process), individual users can also configure notifications to send directly to your personal Slackbot channel.

1. Start by navigating to your personal Profile page on DefectDojo. Find this by clicking the 👤 **icon** in the top\-right corner. Select your DefectDojo Username from the list. (👤 **paul** in our example)  
​
![image](images/Configure_a_Slack_Integration_4.png)

2. Set your **Slack Email Address** in the menu. This field is nested underneath **Additional Contact Information** in DefectDojo.

You can now [set specific notifications](../about_notifications/) to be sent to your personal Slackbot channel. Other users on your Slack channel will not receive these messages.

## Microsoft Teams Notifications Setup

Microsoft Teams can receive notifications to a specific channel. To do this, you will need to **set up an incoming webhook** on the channel where you wish to receive messages.

1. Complete the process listed in the **[Microsoft Teams Documentation](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=dotnet)** for creating a new Incoming Webhook. Keep your unique webhook.office.com link handy as you will need it in subsequent steps.  
​
![image](images/Configure_a_Microsoft_Teams_Integration.png)
2. In DefectDojo, navigate to **Configuration \> System Settings** from the sidebar. (In the Beta UI, this form is located under **Enterprise Settings > System Settings**.)
3. Check the **Enable Microsoft Teams notifications** box. This will open a hidden section of the form, labeled **‘Msteams url**’.  
​
![image](images/Configure_a_Microsoft_Teams_Integration_2.png)
4. Paste the webhook.office.com URL (created in Step 1\) in the **Msteams url** box. Your Teams app will now listen to incoming Notifications from DefectDojo and post them to the channel you selected.

### Notes on the Teams integration

* Slack cannot apply any RBAC rules to the Teams channel that you are creating, and will therefore be sharing notifications for the entire DefectDojo system. There is no method in DefectDojo to filter system\-wide Teams notifications by a Product Type, Product or Engagement.
* DefectDojo cannot send personal notifications to users on Microsoft Teams.

## System-Wide Email Notifications Setup

Notifications from DefectDojo can also be sent to a specific email address.

1. From the System Settings page (**Configuration > System Settings** in the Classic UI, or **Enterprise Settings > System Settings** in the Beta UI) navigate to Enable Mail (email) Notifications. 

2. Check the **Enable mail notifications** box, and then enter the email address where you want these notifications to be sent (mail notifications to).

![image](images/notifs_email.png)

Note that DefectDojo cannot apply RBAC filtering to these emails - they will be sent for all activity in DefectDojo.  If you prefer to send a more customized set of email notifications, it is better to set up [Personal Notifications](../configure_personal_notifs) with a user or service account that is linked to the appropriate address.

