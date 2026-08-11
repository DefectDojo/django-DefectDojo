---
title: "Messaging Connectors"
description: "Send alerts from DefectDojo to Slack, Microsoft Teams, email, or Amazon SNS."
weight: 4
audience: pro
---

**Availability:** Messaging Connectors are a beta feature. Enable **Messaging Connectors** on the Feature Flags page. Because alerts are routed by rules, **Rules Engine 2.0** must be enabled as well.

Messaging Connectors send alerts from DefectDojo to a chat service, to an email address, or to an Amazon SNS topic. They sit beside the ticketing and incident-management connectors on the same **Downstream Connectors** page, and they are configured the same way: create a connection once, then decide what should be sent to it.

Ticketing connectors and messaging connectors answer different questions. A ticketing connector creates and updates a ticket that tracks one Finding over time. A messaging connector posts a message about something that just happened, such as an import that brought in new High and Critical Findings. A message has no status to transition and no ticket to keep in sync, so the two are configured separately and neither affects the other.

## What you can send

Alerts are routed by Rules Engine 2.0. A rule decides **when** to send (a trigger), **which** Findings qualify (conditions), and **where** the message goes (a notify node addressing your connection and channel).

This means the filters available to an alert are the same ones available to a rule: severity, scope, tags, status, and anything else a rule condition can express. Several different alerts going to several different channels are simply several rules.

## The four vendors

| Vendor | What you provide | How many destinations per connection |
| --- | --- | --- |
| Slack | A bot token from a Slack app | Many. Each destination names a channel ID. |
| Microsoft Teams | A Power Automate workflow URL | One. The URL decides the channel. |
| Email | Nothing. The instance mail server is used. | Many. Each destination names recipients. |
| Amazon SNS | An AWS access key allowed to publish | Many. Each destination names a topic ARN. |

Each is set up the same way: add the connection under **Connect > Downstream**, then create an alert
that addresses it.

## Set up a Slack connection

You need a Slack app with a bot token. If your workspace already has one for DefectDojo you can reuse it.

### 1. Create a Slack app

1. Go to [https://api.slack.com/apps](https://api.slack.com/apps) and select **Create New App**, then **From scratch**.
2. Name the app (for example, DefectDojo) and pick the workspace it should post to.
3. Open **OAuth & Permissions** and add these **Bot Token Scopes**:
   - `chat:write` (required): lets the app post messages.
   - `chat:write.public` (optional): lets the app post to any public channel without being invited to it first. Without this scope you must invite the bot to each channel you want to use.
4. Select **Install to Workspace** and approve the app.
5. Copy the **Bot User OAuth Token**. It starts with `xoxb-`.

### 2. Add the connection in DefectDojo

1. Go to **Connect > Downstream**.
2. In the **Messaging** section, find the Slack tile and select **Add Configuration**.
3. Enter:
   - **Location**: your Slack workspace URL, for example `https://your-workspace.slack.com`. This is used for display and links only.
   - **Identifier**: a label that tells this connection apart from others, for example `Security workspace`.
   - **Bot Token**: the `xoxb-` token you copied.
4. Save. DefectDojo validates the token against Slack immediately, so an incorrect or revoked token is reported here rather than the first time an alert fires.

You can add as many Slack connections as you need. Separate connections are how you reach more than one workspace.

### 3. Find the channel ID

Slack destinations take a channel **ID**, not a channel name.

1. In Slack, open the channel and select its name at the top.
2. Scroll to the bottom of the **About** tab.
3. Copy the **Channel ID**. It looks like `C0123456789`.

If the app does not have the `chat:write.public` scope, invite it to the channel as well: type `/invite @your-app-name` in the channel.

## Set up a Microsoft Teams connection

Teams uses a **Power Automate workflow URL**. Classic Office 365 connectors are retired, and this
route needs no app registration and no tenant admin consent: somebody with rights to the channel
creates the flow and pastes the URL it returns.

**One connection posts to one channel.** The workflow URL decides where the message goes, so a
second channel means a second connection rather than a second destination.

### 1. Create the workflow

1. In Teams, open the channel you want to post to, select the **...** menu next to the channel name, then **Workflows**.
2. Choose the **Post to a channel when a webhook request is received** template.
3. Confirm the team and channel, then select **Add workflow**.
4. Copy the URL the workflow gives you. It is a long `https://` address on a Microsoft Power Automate host.

Treat this URL as a password. Anyone holding it can post to that channel.

### 2. Add the connection in DefectDojo

1. Go to **Connect > Downstream**.
2. In the **Messaging** section, find the Microsoft Teams tile and select **Add Configuration**.
3. Enter:
   - **Location**: your Teams or Microsoft 365 URL. This is used for display and links only.
   - **Instance Label**: a label naming the channel this connection reaches, for example `Security / Alerts`.
   - **Workflow URL**: the URL you copied.
4. Save.

DefectDojo checks the URL's shape on save (it must be `https://` and on a Microsoft workflow host) but does not post to it. A workflow URL has no way to be tested other than sending a message, and a surprise message in a channel on save is worse than finding out later. Use **Send test message** when you are ready.

A Teams destination has one optional field, a channel label, which only labels the delivery record. The workflow URL already decides the destination.

## Set up an Email connection

Email needs no credential. DefectDojo sends through the mail server this instance already uses for notifications, so there is nothing new to configure and no second place for SMTP to be wrong.

1. Go to **Connect > Downstream**.
2. In the **Messaging** section, find the Email tile and select **Add Configuration**.
3. Enter:
   - **Location**: the sender identity to display, for example `mailto:defectdojo@example.com`.
   - **Instance Label**: a label that tells this connection apart from others.
4. Save.

Saving fails if this instance has no mail server or no sender address configured, because nothing sent over the connection would leave the building. Configure SMTP under **Settings > System Settings** first.

Recipients are set on the alert, not on the connection, so one Email connection serves every alert. An email destination takes up to 50 addresses; past that, use a distribution address.

## Set up an Amazon SNS connection

SNS is different in kind from the other three: DefectDojo publishes one message to a topic, and AWS
fans it out to whatever is subscribed, which may be email addresses, SMS numbers, a Lambda function,
an HTTPS endpoint, or an SQS queue. DefectDojo does not know or care which.

### 1. Create an access key that can publish

1. In the AWS console, create (or pick) an IAM user or role for DefectDojo.
2. Attach a policy allowing `sns:Publish` on the topics you intend to use. Naming the topic ARNs explicitly is better than allowing all of them.
3. Create an access key for it and copy both halves. AWS shows the secret access key once.

If the topic is encrypted with a KMS key, the same principal also needs `kms:GenerateDataKey` and `kms:Decrypt` on that key, or every publish is refused.

### 2. Add the connection in DefectDojo

1. Go to **Connect > Downstream**.
2. In the **Messaging** section, find the Amazon SNS tile and select **Add Configuration**.
3. Enter:
   - **Location**: a URL for display and links only, for example your AWS console URL.
   - **Instance Label**: a label that tells this connection apart from others, for example `Production AWS account`.
   - **Access Key ID**: the key ID, which looks like `AKIAIOSFODNN7EXAMPLE`.
   - **Secret Access Key**: the secret half.
4. Save.

DefectDojo checks the credential with AWS immediately, so a wrong or deleted key is reported here rather than the first time an alert fires. That check confirms only that the credential is valid; whether it may publish to a given topic is checked when you set the destination.

**There is no region to enter.** The region is part of the topic ARN, so one connection can publish to topics in more than one region, and there is no second setting that can disagree with the ARN.

### 3. Find the topic ARN

An SNS destination takes the topic's ARN.

1. In the SNS console, open the topic.
2. Copy the **ARN** from the top of the page. It looks like `arn:aws:sns:us-east-1:123456789012:security-alerts`.

Unlike a Teams workflow URL, an ARN is not a secret: it names a topic, and publishing to it requires the credential on the connection. That is why one SNS connection can serve many topics.

FIFO topics (an ARN ending in `.fifo`) are not supported. They require a message group and a deduplication ID, which are ordering rules an alert has nothing to supply. Use a standard topic.

## Send a test message

Anywhere a messaging destination is configured, **Send test message** delivers a short message through exactly the same path a real alert uses, and reports what the vendor said.

Use it to confirm the things that are easy to get wrong: for Slack, that the channel ID is right and the bot can post there; for Teams, that the workflow URL still works; for email, that the address is deliverable; for SNS, that the key may publish to that topic. The vendor's own answer is passed through, so a missing Slack invite reads as a message telling you to invite the bot rather than a generic failure.

A successful test also clears a connection that has been automatically disabled (see [When a connection stops working](#when-a-connection-stops-working)).

## Create an alert

There are two ways in. Both produce the same thing: a Rules Engine 2.0 rule.

### The alerts page

The short route, for the common case of announcing new findings from an import.

1. Go to **Connect > Downstream** and select **Create Alert** on a messaging connection, or open **Messaging Alerts** directly.
2. Select **New Alert** and fill in:
   - **Name**: what this alert is for, for example `New highs to the security channel`.
   - **Alert**: what it is about. **New findings from an import** is currently the only option.
   - **Send over**: the messaging connection.
   - **Where it delivers**: the vendor's own destination field, so a Slack channel ID, an optional Teams channel label, a list of email addresses, or an SNS topic ARN.
   - **Severity**: the floor, from **Critical only** through **Every severity**.
   - **Mode**: **Simulate** records what would have been sent without sending it, **Live** actually sends.
3. Select **Create Alert**.

The page lists the alerts it created, with the trigger, the severity floor, and a toggle to enable or disable each one.

Start in **Simulate** if you want to see what an alert would have caught before anyone's channel hears about it. The rule runs, the deliveries are recorded, and nothing is sent.

Alerts are rules, so they can also be opened in the rule editor from the same list. Once a rule has been edited into something the form cannot express, such as a second branch or a second message, the list offers the rule editor instead of the form, rather than a form that would quietly flatten the extra work.

### The rule editor

The full route, for anything the form does not cover.

1. Go to **Automation > Rules Engine 2.0** and create a rule.
2. Add a trigger. For alerts about newly imported Findings, use the Finding event trigger on **created**. Imports are batched, so one import produces one alert rather than one per Finding.
3. Add conditions for what should qualify, for example a minimum severity of High.
4. Add a message node for the vendor you want (**Send a Slack Message**, **Send a Microsoft Teams Message**, **Send an Email**, or **Publish to an SNS Topic**) and set:
   - **Connection**: the messaging connection you created.
   - **Destination**: the vendor's destination, so a channel ID for Slack, an optional channel label for Teams, recipients for email, or a topic ARN for SNS.
5. Save the rule and enable it.

Nothing is sent when no Findings match the conditions, so a rule filtered to High and above stays quiet on an import that only brought in Low Findings.

### Rules written before Messaging Connectors

A message node sends over a connection, and only over a connection. The Slack, Teams, and email nodes previously fell back to the instance-wide settings under **Settings > Notifications** when no connection was chosen. They no longer do.

A rule written that way keeps running, and its message node records a skipped delivery saying it names no connection. To fix it, open the rule, choose a connection and a destination on the node, and save. A delivery that was already recorded can be replayed from the deliveries list once the node names a connection.

The connection is a required field on every message node, so the rule editor asks for one before the rule can be saved.

## When a connection stops working

A revoked bot token, a deleted workflow, or a deleted AWS access key fails every alert it serves. Rather than recording the same failure for every event, DefectDojo counts consecutive credential failures per destination and stops sending after a few of them. The connection reports which destination was disabled and why.

To recover: fix the credential (reinstall the Slack app and paste the new token, recreate the Teams workflow and paste the new URL, or create a new AWS access key), then either send a test message to that destination, which re-enables it on success, or use the re-enable action directly.

Only credential failures cause this. A message rejected because a Slack channel ID is wrong, the bot is not invited, an email address does not exist, or an IAM policy does not allow publishing to one topic does not disable anything, because the credential is fine and correcting the destination or the policy should work immediately.

## Alerts and notifications together

Messaging Connectors do not replace notifications. The instance-wide Slack, Teams, and email settings under **Settings > Notifications**, personal notifications, and the notification matrix all keep working exactly as configured. They are what announces DefectDojo's own events; a Messaging Connector is what a rule you wrote sends over.

One thing to watch: if an alert posts to the same channel or address that the instance-wide setting already announces to, that destination receives both messages. Configure one or the other for a given destination.

## Limitations

- Message wording is not customizable yet. Alerts use DefectDojo's built-in wording.
- Messages are one-way. DefectDojo does not read replies, and there are no buttons or interactive elements in the message.
- Threads, message editing, and direct messages to individual users are not supported. Personal notifications continue to use the existing notification system.
- One Teams connection reaches one channel, because the workflow URL is what addresses the channel.
- SNS messages are plain text. A topic can fan out to email, SMS, Lambda and HTTPS subscribers at once, so there is no single format that suits all of them, and no per-protocol variant is published.
- SNS FIFO topics are not supported.
- Reports and other attachments cannot be sent yet. Alerts are messages with links back to DefectDojo.
- The alerts page covers new findings from an import. Anything else is built in the rule editor.
