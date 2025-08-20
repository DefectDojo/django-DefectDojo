---
title: "About Notifications & 🔔 Alerts"
description: "Learn about notifications, in-app alerts"
---

DefectDojo keeps you up to date in a variety of ways. Notifications can be sent for upcoming Engagements, user Mentions, SLA expiry, and other events in the software.

This article contains an overview of notifications at both System\-wide and Personal levels.

## Notification Types

DefectDojo handles notifications in two different ways::

* **System\-Wide Notifications** are sent to all users.
* **Personal Notifications are set by individual users, and will be received in addition to any System\-Wide Notifications.**

In both cases, [Role-Based Access Control](../../user_management/about_perms_and_roles/) rules apply, so users will not receive activity notifications for Products or Product Types (or their related objects) which they don’t have access to.

## Notification Delivery Methods

There are four delivery methods for DefectDojo notifications:

* DefectDojo can share **🔔 Alerts,** stored as a list in the DefectDojo interface
* DefectDojo can send notifications to an **Email** address
* DefectDojo can send notifications to **Slack,** in either a shared or individual channel
* DefectDojo can also send notifications to **Microsoft Teams** in a shared channel

Notifications can be sent to multiple destinations simultaneously.

Receiving Slack and Teams notifications will require you to have a working integration. For more info on setting this integration up, see our [Guide](../email_slack_teams).

## In-App Alerts

DefectDojo’s Alerts system keeps you up to date with all Product or system activity.

### The Alerts List

The Alerts List is always visible in the top\-right hand corner of DefectDojo, and contains a compact list of notifications. Clicking on each Alert will take you directly to the relevant page in DefectDojo.

You can open your Alerts List by clicking on the **🔔▼ icon** on the top right hand corner:

![image](images/About_In-App_Alerts.png) 

To see all of your notifications, along with additional detail, you can click the **See All Alerts \>** button, which will open the **Alerts Page**.

You can also **Clear All Alerts \>** from the Alerts List.

### The Alerts Page

The Alerts Page stores all of your Alerts in DefectDojo with additional detail. On this page, you can read descriptions of each Alert in DefectDojo, and remove them from the Alerts queue once you no longer need them.

![image](images/About_In-App_Alerts_2.png)

To remove one or more Alerts from the Alerts Page, check the empty box next to it, and then click the **Remove selected** button in the bottom\-right corner of the Page.

### Notes On Alerts

* Reading an Alert, or opening the Alerts Page will not remove any Alerts from the count next to the bell icon. This is so that you can easily access past alerts to use them as reminders or a personal activity log.
* Using the **Clear All Alerts \>** function in the Alerts Menu will also completely clear the **Alerts Page**, so use this feature with care.
* Removing an Alert only affects your own Alerts List \- it will not affect any other user’s Alerts.
* Removing an Alert does not remove any import history or activity logs from DefectDojo.

## Open-Source Considerations

### Specific overrides

System notification settings (scope: system) describe the sending of notifications to superadmins. User notification settings (scope: personal) describe sending notifications to the specific user.

However, there is a specific use-case when the user decides to disable notifications (to decrease noise) but the system setting is used to override this behavior. These overrides apply only to `user_mentioned` and `review_requested` by default.

The scope of this setting is customizable (see environment variable `DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP`).

For more information about this behavior see the [related pull request #9699](https://github.com/DefectDojo/django-DefectDojo/pull/9699/)

### Webhooks (experimental)

DefectDojo also supports webhooks that follow the same events as other notifications (you can be notified in the same situations). Details about setup are described in [related page](/en/open_source/notification_webhooks/how_to).
