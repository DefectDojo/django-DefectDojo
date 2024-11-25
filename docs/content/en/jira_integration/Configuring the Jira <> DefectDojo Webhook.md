---
title: "Configuring the Jira <> DefectDojo Webhook"
description: "How to create a webhook within Jira to push updates to DefectDojo"
---

The Jira integration allows for bidirectional sync via webhook. DefectDojo receives Jira notifications at a unique address, which can allow for Jira comments to be received on Findings, or for Findings to be resolved via Jira depending on your configuration.




# Locating your Jira Webhook URL


Your Jira Webhook is located on the System Settings form under **Jira Integration Settings**: **Enterprise Settings \> System Settings** from the sidebar.



![](https://downloads.intercomcdn.com/i/o/1124842050/a844a3ca5bb139961e1e5f55/Screenshot+2024-07-25+at+2_11_59+PM.png?expires=1729720800&signature=4e310776d71ec2d5692e730256dac89ccd3dbcec84bdc9b54d046445353df34f&req=dSElEsF6n4FaWfMW1HO4zUvviECqSfGZgBjFH42oXvwEqut4AG4Qfkmo4x%2Fd%0AmwA%2F%0A)

# Configuring Jira to send updates to your Webhook


1. Visit **https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**
2. Click 'Create a Webhook'.
3. For the field labeled 'URL' enter: [https://](https:) \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>. The Web Hook Secret is listed under the Jira Integration Settings as listed above.
4. Under 'Comments' enable 'Created'. Under Issue enable 'Updated'.

Note that you do not need to create a Secret within Jira to use this webhook. The Secret is built into DefectDojo's URL, so simply adding the complete URL to the Jira Webhook form is sufficient.



DefectDojo's Jira Webhook only accepts requests from the Jira API.




# Testing the Webhook


Once you have one or more Issues created from DefectDojo Findings, you can test the Webhook by adding a Comment to one of those Findings. The Comment should be received by the Jira webhook as a note.



If this doesn’t work correctly, it could be due to a Firewall issue on your Jira instance blocking the Webhook.


* DefectDojo's Firewall Rules include a checkbox for **Jira Cloud,** which needs to be enabled before DefectDojo can receive Webhook messages from Jira.

  
​

