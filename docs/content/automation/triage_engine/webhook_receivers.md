---
title: "Webhook Receivers"
description: "Let other tools talk back to DefectDojo: receive webhooks, find the Findings they are about, and act on them"
weight: 8
audience: pro
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Triage Engine is a DefectDojo Pro-only feature.</span>

A **Webhook Receiver** gives the Triage Engine an inbound URL. Any tool that can send a webhook (Jira, a ticketing system, a CI pipeline, an internal service) posts to it, and the rules that listen to the receiver decide what happens next: close a Finding, reopen it, add a note, raise an alert.

Receivers live under **Triage Engine > Webhook Receivers**. There are two kinds:

- **Supported webhooks**, such as Jira. You enter a secret and pick a few behaviours, and DefectDojo builds and maintains the rule for you.
- **Custom webhooks**, for anything else. You paste an example payload and build the rule yourself with the same nodes a supported webhook uses.

## How a delivery is handled

1. The sender posts to the receiver's URL, `https://<your DefectDojo>/api/webhooks/in/<receiver>/<token>/`.
2. The **webhook gateway** stores the delivery and answers the sender immediately. If DefectDojo is restarting or busy, nothing is lost: the gateway delivers it as soon as DefectDojo is back, retrying for several hours before it gives up.
3. DefectDojo checks the delivery (its token and, where the sender signs, its signature), records it as a **receipt**, and hands it to every enabled rule that listens to this receiver.
4. Each rule runs as usual. **Runs** shows what each one did.

Nothing in the payload travels through the engine except as data. A payload cannot run code, reach another receiver's data, or touch a Finding the rule's owner cannot see.

## Turning on two-way sync for a Downstream Connector

For a connector that supports it (Jira today), the fastest route is the connection itself:

1. Open **Connect > Downstream**, then the Jira connection.
2. Choose **Turn On Two-way Sync**. This creates a Jira receiver already bound to this connection.
3. Enter the webhook secret you will give Jira, review the behaviours, and save. The receiver and its rule start **disabled**.
4. Follow the **Setup** tab: in Jira, open **System > WebHooks**, create a webhook with the receiver's URL and secret, and subscribe it to **Issue updated** and **Comment created**. Limit its JQL to the projects your connector pushes to.
5. Enable the receiver. From then on, the **Receipts** tab shows each delivery and the **Rules** tab links to the rule that acts on them.

Binding the receiver to its connection matters when you have more than one Jira site: ticket keys such as `SEC-101` are only unique within one site, so a bound receiver only ever matches the tickets its own connection created.

### What Jira changes do

| In Jira | On the linked Finding |
|---------|-----------------------|
| The issue moves to a **Done** status category | The Finding closes. Its resolution decides how: mitigated by default, a false positive or an accepted risk when the resolution is in that list. |
| The issue leaves the Done category | A closed Finding reopens. Findings in a Finding Group stay closed unless you turn on **Also Reopen Finding Groups**, because Jira cannot say which member should reopen. |
| Somebody comments | The comment is added to the Finding as a note, once. Comments DefectDojo posted itself are recognized and skipped. |

Closure follows the issue's **status category**, never the status name or the resolution alone. Workflows that leave a resolution on a reopened issue, or set a default resolution on new ones, therefore behave correctly.

The resolution lists live on the connector's **status mapping**, under **Coming Back From Jira**, so each Jira project can say what its own resolutions mean. Left empty, they use the classic Jira integration's resolution mappings when you have one.

### Sending notes to Jira

On the same connector, **Push Notes as Comments** on an issue tracker mapping posts each new note on a Finding to its Jira issue as a comment, made by the connection's account. Nobody on your team needs Jira write access for it.

- **Private notes are never posted.** Mark a note private to keep an internal discussion out of Jira.
- The comment reads `(Author name): note text`, so the Jira audience can see who wrote it.
- A note on a grouped Finding goes to the Finding Group's issue.
- Notes created by Triage Engine rules, including the notes two-way sync adds from Jira comments, are never sent back.
- Editing or deleting a note does not change the Jira comment.

## Building a rule for a custom webhook

1. **New Webhook Receiver**, then **Custom Webhook**. Give it a label and choose how the sender authenticates.
2. Save. The **Setup** tab shows the URL to give the sender.
3. On **Sample Payload**, paste an example from the sender's documentation, or send one for real. **Parse** lists every path in it, such as `webhook.payload.issue.key`, with an example value and a copy button.
4. **Create a Rule** opens the editor with an **On an Inbound Webhook** trigger for this receiver. Add **Find Findings by a Value** to turn a payload value into Findings, then any Findings or Egress nodes.
5. **Preview** runs the rule against the sample, or against a payload you paste into **Test With a Payload**, and changes nothing.

See the [Node Reference](../node_reference/) for **On an Inbound Webhook**, **Find Findings by a Value**, **Apply the Ticket's Status** and **Add a Ticket Comment as a Note**.

## Authentication

Every receiver URL carries a random 256-bit token. With the webhook gateway in front, a delivery whose token does not match is answered `401` by the gateway and never stored. Without it, DefectDojo answers it like an unknown URL. On top of the token, a receiver can require:

| Mode | The sender proves itself by |
|------|-----------------------------|
| **URL Token Only** | The token alone. For senders that cannot sign, such as Jira Data Center. |
| **Shared Secret Header** | Sending a fixed secret in a header you name. |
| **HMAC-SHA256 Signature** | Signing the body with a shared secret, in a header you name (Jira Cloud uses `X-Hub-Signature` with the prefix `sha256=`). |
| **HTTP Basic** | A username and password. |
| **Vendor Scheme** | The supported webhook's own verification, where it has one. |

**Rotate Token** issues a new URL; the old one stops working at once. Secrets are encrypted at rest and never shown again after you save them.

## Receipts

A receipt is written for every delivery to a known receiver, including the ones that were refused, so "the sender says it sent it and nothing happened" is always answerable.

| Status | Meaning |
|--------|---------|
| **Dispatched** | Accepted, and at least one enabled rule was woken. |
| **No Listeners** | Accepted, but no enabled rule listens to this receiver. |
| **Rejected** | Refused. The reason says why: authentication failed, the body was too large, not JSON, or an unsupported content type. |
| **Replayed** | Sent into the rules again by a person, with **Replay**. |

A receipt keeps the body and the headers you choose to keep. `Authorization`, cookies and the receiver's own secret header are never stored. Retries of one event are recognized and recorded once. Receipts are deleted after 180 days by default; the receipts page says when each one goes.

## The webhook gateway

The gateway is what makes a delivery durable before DefectDojo has seen it. Many senders, Jira Data Center among them, do not resend a webhook that failed, and Jira Cloud retries for about half an hour at most. With the gateway in front, a DefectDojo restart or a busy moment costs nothing.

The receiver's **Gateway** tab shows what the gateway holds for it: recent deliveries, where each one is in its retries, and any the gateway gave up on, with **Replay** for those. Turning a receiver off pauses delivery of new events; events that arrive while it is off can be replayed from this tab once it is on again.

The gateway is on by default in every DefectDojo Pro deployment. Operators configure it with the settings in [Configuration](../configuration/#webhook-receivers). A deployment can also run without it, in which case DefectDojo answers the receiver URL itself and a delivery during an outage is lost unless the sender retries.

### Turning inbound webhooks off

The **Inbound Webhooks** feature flag, under **Settings > Feature Flags**, is on by default. Turn it off to stop inbound webhook traffic at once, for example while you investigate a misbehaving sender:

- Every receiver URL answers `503` with a `Retry-After` header, and nothing is recorded.
- DefectDojo stops talking to the webhook gateway. Receivers saved in the meantime wait to register.
- The **Receipts** and **Gateway** tabs show a warning that inbound webhooks are off, and the receivers list shows the gateway as **Turned Off**.

Nothing already captured is lost. The gateway keeps each delivery and retries it for about four and a half hours, and senders that retry will try again. When you turn the flag back on, DefectDojo registers any waiting receivers right away. A delivery the gateway gave up on in the meantime is listed under **Dead Letters** on the **Gateway** tab, where **Replay** sends it again.

Turning the Triage Engine off answers every receiver URL with `404` instead, whatever this flag says.

## Permissions

Webhook receivers use the Triage Engine permissions. Viewing needs **Rule View**, creating needs **Rule Add**, changing, rotating, replaying or syncing needs **Rule Edit**, and deleting needs **Rule Delete**. A receiver belongs to the person who created it; others do not see it, and a rule can only listen to a receiver its owner can see. Binding a receiver to a Downstream Connector connection also needs permission to view integrations.

A rule a receiver generates is **managed**: the editor shows it read-only, because the receiver rebuilds it whenever its settings change. **Detach and Edit** turns it into an ordinary rule that starts from the working graph.
