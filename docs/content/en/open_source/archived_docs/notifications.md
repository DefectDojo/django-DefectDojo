---
title: "Notifications"
description: "DefectDojo can inform you about changes on different channels."
draft: false
weight: 6
exclude_search: true
---

## Notifications

![Notification settings](images/notifications_1.png)

DefectDojo can inform you of different events in a variety of ways. You
can be notified about things like an upcoming engagement, when someone
mentions you in a comment, a scheduled report has finished generating,
and more.

The following notification methods currently exist:
 - Email
 - Slack
 - Microsoft Teams
 - Webhooks
 - Alerts within DefectDojo (default)

You can set these notifications on a global scope (if you have
administrator rights) or on a personal scope. For instance, an
administrator might want notifications of all upcoming engagements sent
to a certain Slack channel, whereas an individual user wants email
notifications to be sent to the user\'s specified email address when a
report has finished generating.

Users can define notifications on a product level as well, and these settings will be applied only for selected products.

In order to identify and notify you about things like upcoming
engagements, DefectDojo runs scheduled tasks for this purpose. These
tasks are scheduled and run using Celery beat, so this needs to run for
those notifications to work.

DefectDojo allows `template` to be used, administrator can use this feature to define which notification should be received by newly created users.

### Slack

#### Basic Integration
This method will allow DefectDojo to send Global notifications to a Slack channel.  It can also send Personal notifications to an individual user's Slackbot.

To configure Slack messaging, you will first need to create a new Slack app at https://api.slack.com/apps.  

This app can be created from scratch, or from a JSON manifest which includes all necessary scopes and bot functionality.  This manifest can be copied and pasted into the Slack App wizard when you select 'Build From Manifest'.

<details>
    <summary>JSON Manifest</summary>

~~~
{
  "_metadata": {
    "major_version": 1,
    "minor_version": 1
  },
  "display_information": {
    "name": "DefectDojo",
    "description": "Notifications from DefectDojo",
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
~~~

</details>

Choose the channel where you want to post Global notifications during the 'Create From Manifest' process.  Personal notifications will appear in a user's Slackbot if they have their Slack Email Address specified on their user profile.

#### Scopes

The following scopes have to be granted to your Slack App.  If the App was created from the JSON Manifest above, these permission scopes will already be set correctly.

![Slack OAuth scopes](images/slack_scopes.png)

#### Token

The Slack Bot Token needs to be pasted in the DefectDojo System Settings, nested underneath the 'Enable slack notifications' checkbox.  This token can be found in the Features / OAuth & Permissions section on the Slack App settings.

![Slack token](images/slack_tokens.png)

#### Examples of Slack notifications

![Add Product](images/slack_add_product.png)

![Import Scan](images/slack_import_scan.png)


### Microsoft Teams

Microsoft Teams does not provide an easy way to send messages to a personal
channel. Therefore, DefectDojo can only send system scope notifications
to Microsoft Teams.

To activate notifications to Microsoft Teams, you have to:
- Configure an Incoming Webhook in a Teams channel and copy the URL of the webhook to the clipboard
- Activate `Enable Microsoft Teams notifications` in the System Settings
- Paste the URL of the Incoming Webhook into the field `Msteams url`

## Specific overrides

System notification settings (scope: system) describe the sending of notifications to superadmins. User notification settings (scope: personal) describe sending notifications to the specific user.

However, there is a specific use-case when the user decides to disable notifications (to decrease noise) but the system setting is used to override this behavior. These overrides apply only to `user_mentioned` and `review_requested` by default.

The scope of this setting is customizable (see environmental variable `DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP`).

For more information about this behavior see the [related pull request #9699](https://github.com/DefectDojo/django-DefectDojo/pull/9699/)

## Webhooks (experimental)

DefectDojo also supports webhooks that follow the same events as other notifications (you can be notified in the same situations). Details about setup are described in [related page](../../notification_webhooks/how_to).
