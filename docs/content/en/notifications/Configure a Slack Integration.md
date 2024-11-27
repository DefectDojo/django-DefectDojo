---
title: "Configure a Slack Integration"
description: "Set up Slack to receive notifications from DefectDojo"
---

DefectDojo can post Slack notifications in two different ways: 


* System\-wide notifications, which will be sent to a single Slack channel
* Personal notifications, which will only be sent to specific users.

Here is an example of a Slack Notification sent from DefectDojo:  
​


![image](images/Configure_a_Slack_Integration.png)

DefectDojo does not have a dedicated Slack app, but one can be easily created for your workspace by following this guide. A Slack app is required for both System and Personal notifications to be sent correctly.




## Create a Slack application


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
     "description": "Notifications from DefectDojo. See https://support.defectdojo.com/en/articles/8863522-configure-slack for configuration steps.",  
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




## Configure your Slack integration in DefectDojo


You’ll now need to configure the Slack integration on DefectDojo to complete the integration.



**You will need Superuser access to access DefectDojo's System Settings page.**



1. Navigate to the App Information page for your Slack App, from <https://api.slack.com/apps>. This will be the app that was created in the first section \- **Create a Slack application**.  
​
2. Find your OAuth Access Token. This can be found in the Slack sidebar \- **Features / OAuth \& Permissions**. Copy the **Bot User OAuth Token.  
​**


![image](images/Configure_a_Slack_Integration_2.png)
3. Open DefectDojo in a new tab, and navigate to **Configuration \> System Settings** from the sidebar.
4. Check the **Enable Slack notifications** box.
5. Paste the **Bot User OAuth Token** from Step 1 in the **Slack token** field.
6. The **Slack Channel** field should correspond to the channel in your workspace where you want your notifications to be written by a DefectDojo bot.
7. If you want to change the name of the DefectDojo bot, you can enter a custom name here. If not, it will use **DefectDojo Notifications** as determined in the Slack App Manifest.

Once this process is complete, DefectDojo can send System\-wide notifications to this channel. Select the Notifications which you want to send from the [System Notifications page](https://support.defectdojo.com/en/articles/8944889-defectdojo-notifications#h_225047bdae).



![image](images/Configure_a_Slack_Integration_3.png)

## Notes on System\-Wide Notifications in Slack**:**


Slack cannot apply any RBAC rules to the Slack channel that you are creating, and will therefore be sharing notifications for the entire DefectDojo system. There is no method in DefectDojo to filter system\-wide Slack notifications to a Product Type, Product or Engagement.



If you want to apply RBAC\-based filtering to your Slack messages, enabling personal notifications from Slack is a better option.




## Send Personal notifications to Slack


If your team has a Slack integration enabled (through the above process), individual users can also configure notifications to send directly to your personal Slackbot channel.


1. Start by navigating to your personal Profile page on DefectDojo. Find this by clicking the 👤 **icon** in the top\-right corner. Select your DefectDojo Username from the list. (👤 **paul** in our example)  
​


![image](images/Configure_a_Slack_Integration_4.png)
2. Set your **Slack Email Address** in the menu. This field is nested underneath **Additional Contact Information** in DefectDojo.


You can now [set specific notifications](https://support.defectdojo.com/en/articles/8944889-defectdojo-notifications) to be sent to your personal Slackbot channel. Other users on your Slack channel will not receive these messages.


