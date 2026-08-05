---
title: "Messaging Connectors"
description: "Send alerts from DefectDojo to Slack."
weight: 4
audience: pro
---

**Availability:** Messaging Connectors are a beta feature. Enable **Messaging Connectors** on the Feature Flags page. Because alerts are routed by rules, **Rules Engine 2.0** must be enabled as well.

Messaging Connectors send alerts from DefectDojo to a chat service. They sit beside the ticketing and incident-management connectors on the same **Downstream Connectors** page, and they are configured the same way: create a connection once, then decide what should be sent to it.

Ticketing connectors and messaging connectors answer different questions. A ticketing connector creates and updates a ticket that tracks one Finding over time. A messaging connector posts a message about something that just happened, such as an import that brought in new High and Critical Findings. A message has no status to transition and no ticket to keep in sync, so the two are configured separately and neither affects the other.

## What you can send

Alerts are routed by Rules Engine 2.0. A rule decides **when** to send (a trigger), **which** Findings qualify (conditions), and **where** the message goes (a notify node addressing your connection and channel).

This means the filters available to an alert are the same ones available to a rule: severity, scope, tags, status, and anything else a rule condition can express. Several different alerts going to several different channels are simply several rules.

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

## Send a test message

Anywhere a Slack destination is configured, **Send test message** posts a short message through exactly the same path a real alert uses, and reports what Slack said.

Use it to confirm two things that are easy to get wrong: that the channel ID is the right one, and that the bot can post there. Slack's own answer is passed through, so a missing invite reads as a message telling you to invite the bot rather than a generic failure.

A successful test also clears a connection that has been automatically disabled (see [When a connection stops working](#when-a-connection-stops-working)).

## Create an alert

1. Go to **Automation > Rules Engine 2.0** and create a rule.
2. Add a trigger. For alerts about newly imported Findings, use the Finding event trigger on **created**. Imports are batched, so one import produces one alert rather than one per Finding.
3. Add conditions for what should qualify, for example a minimum severity of High.
4. Add a **Send a Slack Message** node and set:
   - **Connection**: the Slack connection you created.
   - **Destination**: the channel ID.
5. Save the rule and enable it.

Nothing is sent when no Findings match the conditions, so a rule filtered to High and above stays quiet on an import that only brought in Low Findings.

### Existing rules keep working

A **Send a Slack Message** node that names no connection keeps using the workspace-wide Slack settings from **Settings > Notifications**, exactly as before. Nothing changes for rules that were configured that way. The connection field is optional, and choosing one is what moves a node onto its own token and channel.

## When a connection stops working

A revoked or replaced bot token fails every alert it serves. Rather than recording the same failure for every event, DefectDojo counts consecutive credential failures per channel and stops sending after a few of them. The connection reports which destination was disabled and why.

To recover: fix the credential (usually by reinstalling the Slack app and pasting the new token), then either send a test message to that channel, which re-enables it on success, or use the re-enable action directly.

Only credential failures cause this. A message rejected because a channel ID is wrong or the bot is not invited does not disable anything, because the credential is fine and correcting the destination should work immediately.

## Alerts and notifications together

Messaging Connectors are additive. The workspace-wide Slack setting under **Settings > Notifications**, personal notifications, and the notification matrix all keep working exactly as configured.

One thing to watch: if a rule posts to the same channel that the workspace-wide Slack setting already announces to, that channel receives both messages. Configure one or the other for a given channel.

## Limitations

- Slack is the first messaging vendor. Microsoft Teams and Email follow.
- Message wording is not customizable yet. Alerts use DefectDojo's built-in wording.
- Messages are one-way. DefectDojo does not read replies, and there are no buttons or interactive elements in the message.
- Threads, message editing, and direct messages to individual users are not supported. Personal notifications continue to use the existing notification system.
