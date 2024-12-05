---
title: "Configure a Microsoft Teams Integration"
description: "Set up Microsoft Teams to receive notifications"
---

**You will need Superuser access to use the System Settings page, which is required to complete this process.**



Like with Slack, Microsoft Teams can receive notifications to a specific channel. To do this, you will need to **set up an incoming webhook** on the channel where you wish to receive messages.



1. Complete the process listed in the **[Microsoft Teams Documentation](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=dotnet)** for creating a new Incoming Webhook. Keep your unique webhook.office.com link handy as you will need it in subsequent steps.  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/962180558/8d817d194ca71a420ec7f194/6Iw6VyzxVrgYJmEKYZ5gvkZgNbz5H5A5VzC41oeyNeLTkY3h24xjx-IlfhjQBJbbKtF9SdMp4VlL968WZ4BAs2FNCKABVvqKN6H7ysiFkIrAWll4CTZrYCzSvs0gJg4jFrWtWVDMQozMB5BTv-uE-5Y?expires=1729720800&signature=e8830debf4a2ce0cfe37bbd0db34f2546a384cc2d1cdb7da74a626a6d179d19b&req=fSYlF8F%2BmIRXFb4f3HP0gPLFIDf%2BmJ2lTnC0cGqSE%2BrN2f0NGLhZCqcGa4go%0AkPo%3D%0A)
2. In DefectDojo, navigate to **Configuration \> System Settings** from the sidebar.
3. Check the **Enable Microsoft Teams notifications** box. This will open a hidden section of the form, labeled **‘Msteams ur**l’.  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/962180570/66d613918362dd0e07f3cf34/K0Fx__nnRpEPf01jo0QQjOOeIo8wBFOew5ZbA4S3SE7loW1qfS9YxvUlS2f2OF1E52SgPiefP3eozh7Rmpee_f5AjS8sBrIHHYSpAYl7h0dUNPn6i89k48ulQk8eSl28q3S_kK7KafjZMJ2VRu7A_PM?expires=1729720800&signature=45dfcd45785169b13d866c71902efbadf0d6752e4992e5fc0af58e3f4ee7682b&req=fSYlF8F%2BmIZfFb4f3HP0gBC6zfYgJ9CJ7kYYs0o3vgn66vKuoG2LaE7wC0J2%0AdS4%3D%0A)
4. Paste the webhook.office.com URL (created in Step 1\) in the **Msteams url** box. Your Teams app will now listen to incoming Notifications from DefectDojo and post them to the channel you selected.


## Notes on the Teams integration


* Slack cannot apply any RBAC rules to the Teams channel that you are creating, and will therefore be sharing notifications for the entire DefectDojo system. There is no method in DefectDojo to filter system\-wide Teams notifications by a Product Type, Product or Engagement.
* DefectDojo cannot send personal notifications to users on Microsoft Teams.
