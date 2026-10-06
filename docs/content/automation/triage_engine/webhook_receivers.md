---
title: "Webhook Receivers"
description: "Let other tools talk back to DefectDojo: receive webhooks, find the Findings they are about, and act on them"
weight: 3
audience: pro
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Triage Engine is a DefectDojo Pro-only feature.</span>

A **Webhook Receiver** gives the Triage Engine an inbound URL. Any tool that can send a webhook (Jira, a ticketing system, a CI pipeline, an internal service) posts to it, and the rules that listen to the receiver decide what happens next: close a Finding, reopen it, add a note, raise an alert.

Receivers live under **Triage Engine > Webhook Receivers**. There are two kinds:

- **Supported webhooks**, such as Jira. You enter a secret and pick a few behaviors, and DefectDojo builds and maintains the rule for you.
- **Custom webhooks**, for anything else. You paste an example payload and build the rule yourself with the same nodes a supported webhook uses.

## How a delivery is handled

1. The sender posts to the receiver's URL, `https://<your DefectDojo>/api/webhooks/in/<receiver>/<token>/`.
2. Where the **webhook gateway** is deployed, it checks the token, stores the delivery and answers the sender immediately. If DefectDojo is restarting or busy, the gateway delivers it once DefectDojo is back, retrying for about four and a half hours. Without the gateway, DefectDojo answers the sender itself.
3. DefectDojo checks the delivery (its token or the gateway's signature and, where the sender signs, the sender's signature), records it as a **receipt**, and hands it to every enabled rule that listens to this receiver.
4. Each rule runs as usual. **Runs** shows what each one did.

Nothing in the payload travels through the engine except as data. A payload cannot run code, reach another receiver's data, or touch a Finding the rule's owner cannot see.

## Turning on two-way sync for a Downstream Connector

For a connector that supports it (Jira today), the fastest route is the connection itself:

1. Open **Connect > Downstream**, then the Jira connection.
2. Choose **Turn On Two-way Sync**. This creates a Jira receiver already bound to this connection.
3. Enter the webhook secret you will give Jira, review the behaviors, and save. The receiver and its rule start **disabled**.
4. Follow the **Setup** tab: in Jira, open **System > WebHooks**, create a webhook with the receiver's URL and secret, and subscribe it to **Issue updated** and **Comment created**. Limit its JQL to the projects your connector pushes to. A Jira Data Center version that offers no webhook secret cannot sign, so switch the receiver to **URL Token Only** for it.
5. Enable the receiver. From then on, the **Receipts** tab shows each delivery and the **Rules** tab links to the rule that acts on them.

A connection has at most one two-way sync receiver. When someone else already turned it on, the connection's **Two-way Sync** card says **Managed by another user** instead of offering to create a second one.

Binding the receiver to its connection matters when you have more than one Jira site: ticket keys such as `SEC-101` are only unique within one site, so a bound receiver only ever matches the tickets its own connection created. If the connection is deleted, DefectDojo switches its receiver off and says why on the receiver; choose a new connection and turn it back on.

### What Jira changes do

| In Jira | On the linked Finding |
|---------|-----------------------|
| The issue moves to a **Done** status category | The Finding closes. Its resolution decides how: mitigated by default, a false positive or an accepted risk when the resolution is in that list. |
| The issue leaves the Done category | A closed Finding reopens. Findings in a Finding Group stay closed unless you turn on **Also Reopen Finding Groups**, because Jira cannot say which member should reopen. |
| Somebody comments | The comment is added to the Finding as a note, once, with its Jira formatting (bold, italic, underline, code, links, lists, headings, quotes and tables) shown as the note's formatting. Mentions and images attached in Jira stay as plain text. Comments DefectDojo posted itself are recognized and skipped. |

Closure follows the issue's **status category**, never the status name or the resolution alone. Workflows that leave a resolution on a reopened issue, or set a default resolution on new ones, therefore behave correctly. A change is only made on a Finding the receiver's owner may edit, and an event older than the last one applied to the issue is ignored, so a late retry cannot undo a newer change.

The lists live on the connector's **status mapping**, under **Coming Back From Jira**, so each Jira project can say what its own statuses and resolutions mean:

- **Closing Status Categories** and **Reopening Status Categories** take Jira's status category keys: `new` (To Do), `indeterminate` (In Progress) and `done`. By default `done` closes, and `new` and `indeterminate` reopen.
- **False Positive Resolutions** and **Accepted Risk Resolutions** take Jira resolution names.

A list left empty uses the receiver's default. For an issue linked through the classic Jira integration, the resolutions come from the classic Jira instance configured for the issue's own site, so give each classic instance the base URL of its Jira site (for example `https://your-organization.atlassian.net`). With exactly one classic instance, its resolution mappings are also the receiver's defaults for Downstream Connector tickets. With several, no instance's resolutions are imposed on another site's tickets: set them on each mapping.

### Sending notes to Jira

On the same connector, **Push Notes as Comments** on an issue tracker mapping posts new notes on a Finding to its Jira issue as comments, made by the connection's account. Nobody on your team needs Jira write access for it.

- Every public note attached to a linked Finding is posted, whichever way it was added: the API (`POST /api/v2/findings/{id}/notes/`), the classic UI, the Pro UI, a bulk edit, or closing a Finding with a note.
- **Private notes are never posted.** Mark a note private to keep an internal discussion out of Jira.
- The comment reads `(Author name): note text`, so the Jira audience can see who wrote it. The note is sent in full, up to Jira's comment length limit (a longer one is cut and ends with `[truncated]`).
- Markdown in the note is converted to Jira formatting, underline included. Anything that would ping a Jira user, embed an image or open a macro is escaped and shows as plain text.
- A note on a grouped Finding goes to the Finding Group's issue. A bulk action that adds the same note to many members of one group posts it there once: the same text is not posted to the same group issue twice within ten minutes.
- Notes created by Triage Engine rules, including the notes two-way sync adds from Jira comments, are never sent back.
- Editing or deleting a note does not change the Jira comment.

Posting comments needs a go-integrators version that provides it. When DefectDojo is upgraded before go-integrators, or go-integrators is rolled back, each mapping records one integration error saying so (rather than one per note), and posting is tried again an hour later. Upgrade go-integrators, or turn off **Push Notes as Comments** on the mapping.

## Building a rule for a custom webhook

1. **New Webhook Receiver**, then **Custom Webhook**. Give it a label and choose how the sender authenticates.
2. Save. The **Setup** tab shows the URL to give the sender.
3. On **Sample Payload**, paste an example from the sender's documentation, or send one for real, and **Submit** it. The tab lists every path in it, such as `webhook.payload.issue.key`, with an example value and a copy button.
4. **Create a Rule** opens the editor with an **On an Inbound Webhook** trigger for this receiver. Add **Find Findings by a Value** to turn a payload value into Findings, then any Findings or Egress nodes.
5. **Preview** runs the rule against the sample, or against a payload you paste into **Test With a Payload**, and changes nothing. A webhook rule has no manual **Run**: it runs when its receiver records a delivery.

See the [Node Reference](../node_reference/) for **On an Inbound Webhook**, **Find Findings by a Value**, **Apply the Ticket's Status** and **Add a Ticket Comment as a Note**.

## Authentication

Every receiver URL carries a random 256-bit token. A delivery whose token does not match is answered `404`, exactly like a URL that does not exist, so nobody can learn which receivers exist by guessing. With the webhook gateway in front, the gateway checks the token and stores nothing for a mismatch. On top of the token, a receiver can require:

| Mode | The sender proves itself by |
|------|-----------------------------|
| **URL Token Only** | The token alone. For senders that cannot sign, such as Jira Data Center versions without a webhook secret. |
| **Shared Secret Header** | Sending a fixed secret in a header you name. |
| **HMAC-SHA256 Signature** | Signing the body with a shared secret, in a header you name (Jira Cloud uses `X-Hub-Signature` with the prefix `sha256=`). |
| **HTTP Basic** | A username and password. |
| **Vendor Scheme** | The supported webhook's own verification, where it has one. |

**Rotate Token** issues a new URL; the old one stops working at once. Deliveries the gateway already captured under the old token are still delivered. Secrets are encrypted at rest and never shown again after you save them.

Deleting a receiver retires its URL right away: from then on it answers like any unknown URL. A deleted receiver's URL name is never given to a new receiver, so a new receiver with the same label never sees the old one's deliveries.

## Receipts

A receipt is written for every delivery to a known receiver, including the ones that were refused, so "the sender says it sent it and nothing happened" is always answerable.

| Status | Meaning |
|--------|---------|
| **Received** | Recorded, and about to be handed to the rules. |
| **Dispatched** | Accepted, and at least one enabled rule was woken. |
| **No Listeners** | Accepted, but no enabled rule listens to this receiver. |
| **Dispatch Failed** | Recorded, but DefectDojo's task queue refused it (for example during a broker outage). The sender is told to retry, and DefectDojo also tries again every 15 minutes, a limited number of times. |
| **Rejected** | Refused. The reason says why: authentication failed, the body was too large, not JSON, or an unsupported content type. Only the size and a digest of a refused body are kept. |
| **Replayed** | Sent into the rules again by a person, with **Replay**. |

**Replay** sends an accepted receipt's payload into the rules again, as a new receipt. It is refused while the receiver is off, and a rejected receipt cannot be replayed.

A receipt keeps the body and the headers you choose to keep. The receiver token, `Authorization`, cookies and the receiver's own secret header are never stored. Receipts are deleted after 180 days by default; the receipts page says when each one goes.

### Retries of the same event

Senders retry, and a retry should not act twice. How a repeat is recognized depends on how receiver URLs are served:

- **With the gateway**, the gateway recognizes a sender's retry by the receiver's **dedupe header** (for Jira, `X-Atlassian-Webhook-Identifier`) together with a hash of the body, and stores it once. Without a dedupe header on the receiver, a sender's retry is processed again. DefectDojo records each gateway event once, so the gateway's own retries and replays never act twice.
- **Without the gateway**, DefectDojo remembers deliveries for a day (`DD_RULES_V2_WEBHOOK_DEDUPE_WINDOW_SECONDS`). With a dedupe header on the receiver, a repeat is the same header value with the same body, and a delivery without the header is never treated as a repeat. Without a dedupe header, two identical bodies within the window count once. Set the window to `0` for a sender whose legitimate repeats are byte-identical.

## The webhook gateway

The gateway is what makes a delivery durable before DefectDojo has seen it. Many senders, Jira Data Center among them, do not resend a webhook that failed, and Jira Cloud retries for about half an hour at most. With the gateway in front, a DefectDojo restart or a busy moment costs nothing.

The receiver's **Gateway** tab shows what the gateway holds for it: recent deliveries, where each one is in its retries, and any the gateway gave up on (**Dead Letters**), with **Replay** for those. Turning a receiver off pauses delivery of new events; events that arrive while it is off can be replayed from this tab once it is on again.

The gateway retries a delivery DefectDojo could not take for about four and a half hours, then keeps it as a dead letter. DefectDojo replays dead letters by itself, a bounded number per receiver, once DefectDojo or the gateway has recovered from an outage, when the **Inbound Webhooks** flag is turned back on, and when a worker starts. It only replays deliveries that failed for a reason that can pass (DefectDojo unavailable, too busy, or not answering). A delivery DefectDojo refused on purpose, such as a wrong signature or token, a disabled receiver, or a body that is too large or not JSON, would only be refused again, so it stays a dead letter. **Replay** on the **Gateway** tab sends any of them again by hand, for example after you correct a receiver's secret.

The gateway runs in the Docker Compose bundles, and in the Helm chart when `webhookGateway.enabled` is on. Elsewhere, including the ECS task definitions, DefectDojo answers receiver URLs itself, and a delivery during an outage is lost unless the sender retries. Operators configure it with the settings in [Configuration](../configuration/#webhook-receivers). The receivers list shows the gateway's state at the top: **Healthy**, **Unreachable**, **Not Started** when its database schema is missing (an administrator has to create it, see [Configuration](../configuration/#database-role-and-schema)), or **Turned Off**.

### Turning inbound webhooks off

The **Inbound Webhooks** feature flag, under **Settings > Feature Flags**, is on by default. Turn it off to stop inbound webhook traffic at once, for example while you investigate a misbehaving sender:

- DefectDojo refuses every delivery with `503` and records nothing. Without the gateway the sender gets that answer, with a `Retry-After` header. With the gateway, the gateway keeps capturing deliveries and retrying them.
- DefectDojo stops talking to the webhook gateway. Receivers saved in the meantime wait to register.
- The **Receipts** and **Gateway** tabs show a warning that inbound webhooks are off, and the receivers list shows the gateway as **Turned Off**.

Nothing already captured is lost. The gateway keeps each delivery and retries it for about four and a half hours, and senders that retry will try again. When you turn the flag back on, DefectDojo registers any waiting receivers and replays the dead letters that piled up meanwhile.

Turning the Triage Engine off refuses deliveries the same way, whatever this flag says.

## Permissions

Webhook receivers use the Triage Engine permissions. Viewing needs **Rule View**, creating needs **Rule Add**, changing, rotating, replaying or syncing needs **Rule Edit**, and deleting needs **Rule Delete**.

- A receiver belongs to the person who created it. Others do not see it, except superusers, who see every receiver.
- A rule can only listen to a receiver its owner can see.
- Labels are unique among one person's receivers, so two people can each have a receiver called "Jira".
- Binding any receiver, custom or supported, to a Downstream Connector connection needs permission to view that connection.
- A connection has at most one two-way sync receiver.

A rule a receiver generates is **managed**: the editor shows it read-only, because the receiver rebuilds it whenever its settings change. **Detach and Edit** turns it into an ordinary rule that starts from the working graph. The receiver then leaves the detached rule alone, even when its settings change, until you choose **Regenerate** on the receiver.
