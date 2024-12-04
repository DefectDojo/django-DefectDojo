---
title: "Configure a Slack Integration"
description: "Set up Slack to receive notifications from DefectDojo"
---

DefectDojo can post Slack notifications in two different ways: 


* System\-wide notifications, which will be sent to a single Slack channel
* Personal notifications, which will only be sent to specific users.

Here is an example of a Slack Notification sent from DefectDojo:  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/962178718/43edf527dd90ff3cdb9091d2/R4qt835O2gUnuDNS77H-7sIbmyOMPUy4V5H74MtLMGA9bQsINUdNYvzQTSkf1HQqvUfGHpCU3Qv0xIqkjqD3rlAMvoPleJv6RzZMzVSQRbQT5byXCezD_Sa-NzHQvpGu6ul7KAi_79io_HMfTPLLcL4?expires=1729720800&signature=cb78397a3593ea0ea17310b2aa4fc2a975cffcd207e869bfdf53b64fd55c793d&req=fSYlF852moBXFb4f3HP0gN2UAA5Sb1IfVjD8vnOmZttQHSPf7f6HcXfGzZbM%0AeFM%3D%0A)

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


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/962178744/a59023b7d47dedbcbb7cd3d4/na4CvmsQk_CMrPS2ZvVvVebWIjUkx9GE7NntAIC7Wb1u5vuHByReMjwuYNIekAZIL-tFkYZ9g7c2OS2sP-p9DAUSHlFsE_kkojG5QvjZ1iLO4GYWUa_ZUox2v7yCFNHu46cZyJLAeuC00CogZxsszq4?expires=1729720800&signature=97966950516e644f0268e0286c505926b19b66fa2f719ef53a279a73bd34e7f5&req=fSYlF852moVbFb4f3HP0gOK4lfqm2vEPAzPt%2FdIJ5HOzq9vFYtr%2BpYja6TZI%0A6R8%3D%0A)
3. Open DefectDojo in a new tab, and navigate to **Configuration \> System Settings** from the sidebar.
4. Check the **Enable Slack notifications** box.
5. Paste the **Bot User OAuth Token** from Step 1 in the **Slack token** field.
6. The **Slack Channel** field should correspond to the channel in your workspace where you want your notifications to be written by a DefectDojo bot.
7. If you want to change the name of the DefectDojo bot, you can enter a custom name here. If not, it will use **DefectDojo Notifications** as determined in the Slack App Manifest.

Once this process is complete, DefectDojo can send System\-wide notifications to this channel. Select the Notifications which you want to send from the [System Notifications page](https://support.defectdojo.com/en/articles/8944889-defectdojo-notifications#h_225047bdae).



![](https://defectdojo-inc.intercom-attachments-7.com/i/o/962178761/a5f24f6490b1a043a188441c/R4qt835O2gUnuDNS77H-7sIbmyOMPUy4V5H74MtLMGA9bQsINUdNYvzQTSkf1HQqvUfGHpCU3Qv0xIqkjqD3rlAMvoPleJv6RzZMzVSQRbQT5byXCezD_Sa-NzHQvpGu6ul7KAi_79io_HMfTPLLcL4?expires=1729720800&signature=d43c41e2c6db5c91e49f9c56cbfd21b97e7d84003c3523e65ea07d6d8c154d93&req=fSYlF852modeFb4f3HP0gCrJC5g33foXGAruLI5W3hglBldbY7jvtb8I8wvC%0AwQ0%3D%0A)

## Notes on System\-Wide Notifications in Slack**:**


Slack cannot apply any RBAC rules to the Slack channel that you are creating, and will therefore be sharing notifications for the entire DefectDojo system. There is no method in DefectDojo to filter system\-wide Slack notifications to a Product Type, Product or Engagement.



If you want to apply RBAC\-based filtering to your Slack messages, enabling personal notifications from Slack is a better option.




## Send Personal notifications to Slack


If your team has a Slack integration enabled (through the above process), individual users can also configure notifications to send directly to your personal Slackbot channel.


1. Start by navigating to your personal Profile page on DefectDojo. Find this by clicking the 👤 **icon** in the top\-right corner. Select your DefectDojo Username from the list. (👤 **paul** in our example)  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/962178777/e91b86cd53793fdfd1b9e9e5/P8dPmKcDtxlXDUHl0gndW0vV_7yYSYczHwF2YkB7Q_xBIvww8ezjJfvu9FIY-4AJn7LWHHZRNY285MmC-5jHQmbwd2O251o_0iOVIbJ_BTnErP4gH_9kfV1Jz1CGtBVqDe9lnIGxbqErHGvnElDvekM?expires=1729720800&signature=69aaeabbb05167d590c91797a44a3e204bd8053091482f9d3b969bf2e1db68ec&req=fSYlF852moZYFb4f3HP0gLhK3cg%2BSrGOEvpkHTnb%2BmHfKk8Tj4wCUH9CmhTy%0AfqI%3D%0A)
2. Set your **Slack Email Address** in the menu. This field is nested underneath **Additional Contact Information** in DefectDojo.


You can now [set specific notifications](https://support.defectdojo.com/en/articles/8944889-defectdojo-notifications) to be sent to your personal Slackbot channel. Other users on your Slack channel will not receive these messages.


