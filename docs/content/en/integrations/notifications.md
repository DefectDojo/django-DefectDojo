---
title: "Notifications"
description: "DefectDojo can inform you about changes on different channels."
draft: false
weight: 6
---

## Notifications

![Notification settings](../../images/notifications_1.png)

DefectDojo can inform you of different events in a variety of ways. You
can be notified about things like an upcoming engagement, when someone
mentions you in a comment, a scheduled report has finished generating,
and more.

The following notification methods currently exist:
 - Email
 - Slack 
 - Microsoft Teams
 - Alerts within DefectDojo

You can set these notifications on a global scope (if you have
administrator rights) or on a personal scope. For instance, an
administrator might want notifications of all upcoming engagements sent
to a certain Slack channel, whereas an individual user wants email
notifications to be sent to the user\'s specified email address when a
report has finished generating.

Microsoft Teams does not provide an easy way to send messages to a personal
channel. Therefore, DefectDojo can only send system scope notifications
to Microsoft Teams.

In order to identify and notify you about things like upcoming
engagements, DefectDojo runs scheduled tasks for this purpose. These
tasks are scheduled and run using Celery beat, so this needs to run for
those notifications to work.

### Slack

#### Scopes

The following scopes have to be granted.

![Slack OAuth scopes](../../images/slack_scopes.png)

#### Token

The bot token has to be chosen and put in your System Settings

![Slack token](../../images/slack_tokens.png)

### Microsoft Teams

To activate notifications to Microsoft Teams, you have to:
- Configure an Incoming Webhook in a Teams channel and copy the URL of the webhook to the clipboard
- Activate `Enable Microsoft Teams notifications` in the System Settings
- Paste the URL of the Incoming Webhook into the field `Msteams url`
