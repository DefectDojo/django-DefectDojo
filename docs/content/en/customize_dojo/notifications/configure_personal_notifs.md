---
title: "Set Personal Notifications"
description: "Configure notifications for a personal account"
---

## Configure Personal notifications

Personal Notifications are sent in addition to System\-Wide Notifications, and will apply to any Product, Product Type or other data type that you have access to. Personal Notification preferences only apply to a single user, and can only be set on the account which is configuring them.

![image](images/Configure_System_&_Personal_Notifications.png)

System notifications are set by a DefectDojo Superuser and cannot be opted out of by an individual user.

1. Start from the Notifications page (⚙️**Configuration \> Notifications** in the sidebar).
2. From the **Scope** drop down menu, you can select which set of notifications you wish to edit.
3. Select Personal Notifications.
4. Check the notification method which you wish to use for each type of notification. You can select more than one.

Personal Notifications cannot be sent via Microsoft Teams, as Teams only allows for posting Global notifications in a single channel.

### Receive Personal notifications for a specific Product

In addition to standard personal notifications, DefectDojo Users can also receive notifications for activity on a specific Product. This is helpful when there are certain Products which a user needs to monitor more closely.

![image](images/Configure_System_&_Personal_Notifications_3.png)

This configuration can be changed from the **Notifications** section on the **Product** page: e.g. `your-instance.defectdojo.com/product/{id}`.

From here, you can set whether you want to receive **🔔 Alert**, **Mail** or **Slack** notifications for actions taken on this particular Product. These notifications apply in addition to any system\-wide notifications you are already receiving. 

Microsoft Teams cannot send personal notifications of any kind, so Teams notifications cannot be chosen from this menu.

Personal email notifications will always be sent to the email associated with your DefectDojo login. To set up a personal Slack account to receive notifications, see our [Guide](../email_slack_teams/#send-personal-notifications-to-slack).