---
title: "Set System-Wide Notifications"
description: "How to configure Personal & System notifications"
---

DefectDojo has two different kinds of notifications: **Personal** (sent to a single account) and **System** (which are sent to all users).

Both an account’s Personal Notifications and the global System Notifications can be configured from the same page: **⚙️Configuration \> Notifications** in the sidebar.

![image](images/Configure_System_&_Personal_Notifications.png)

## Configure System notifications (Classic UI)

**You will need Superuser access to change System\-wide notifications.**

1. Start from the Notifications page (⚙️ **Configuration \> Notifications** in the sidebar).
2. From the Scope drop down menu, you can select which set of notifications you wish to edit.
3. Select System Notifications.
4. Check the notification delivery method which you wish to use for each type of notification. You can select more than one.

![image](images/Configure_System_&_Personal_Notifications_2.png)

To set destinations for system wide email notifications (Email, Slack or MS Teams), see our [Guide](../email_slack_teams).

## Template Notifications

Superusers also have access to a "Template" form.  The Template Form allows you to set the default Personal Notifications that are enabled for any new user.

## Where System Notifications Are Sent

System notifications will be sent to:
- the single email address specified in System Settings (if enabled)
- any DefectDojo users with accounts and appropriate RBAC permissions
- the System-wide Slack or Teams account.

As with any notification in DefectDojo, System Notifications will only be sent to users that have access to the relevant data.  So even if Product Notifications are set up System-Wide, users will only receive notifications for the Products that they have access to view.

This restriction does not apply to System Notifications that are sent to a specific Email or Slack channel.

See our guide on [Role-Based Access Control](../../user_management/about_perms_and_roles/) for more information on RBAC and setting permissions.

However, the connected System Email, Slack and Teams accounts cannot apply RBAC as they are not associated with a specific DefectDojo user.  **All selected system-wide notifications will be sent to these locations, so you should ensure that these channels can only be accessed by specific people in your organization.**