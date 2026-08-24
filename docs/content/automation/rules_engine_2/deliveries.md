---
title: "Deliveries"
description: "The ledger of everything rules send outward, and how retries and replay work"
weight: 5
audience: pro
aliases:
  - /automation/rules_engine_v2/deliveries/
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Rules Engine 2.0 is a DefectDojo Pro-only feature.</span>

Every outbound side effect a rule produces is one row in the delivery ledger. **Rules Engine 2.0 > Deliveries** lists them.

The row is written **before** any network call happens, and it holds exactly what would be, or was, sent. That is what makes egress auditable rather than a log line you hope somebody kept, and it is why **Simulate** is not a separate code path: a simulated send is the same row with the dispatch step skipped.

## What a delivery records

| Field | Meaning |
|-------|---------|
| **Run** and **Node** | Which run and which egress node produced it. |
| **Finding** | The Finding it is about, for a per-Finding send. Batch sends record the group instead. |
| **Channel** | What kind of send it is. |
| **Target** | The resolved destination: a JIRA project key, a channel, a URL, an address. |
| **Title** | A one-line description of the send. |
| **Payload** | Exactly what would be, or was, sent. |
| **Mode** | `simulate` or `live`. |
| **Status** | Where the delivery got to. |
| **Attempts** | How many sends have been tried, against the maximum allowed. |
| **Last error** | Why the last attempt failed, or why the delivery was skipped. |
| **Response** | What the destination said back. |
| **External reference** and **URL** | The ticket key, message id or file path the destination returned, and a link to it when there is one. |

## Channels

| Channel | Produced by |
|---------|-------------|
| **JIRA** | Create a JIRA Issue |
| **Downstream connector** | Create a Downstream Ticket |
| **Slack** | Send a Slack Message, and report announcements sent to Slack |
| **Microsoft Teams** | Send a Microsoft Teams Message |
| **Email** | Send an Email, and report announcements sent by email |
| **Webhook** | Call a Webhook |
| **Report** | Generate a Report |
| **In-app alert** | Raise an In-App Alert |

## Statuses

| Status | Meaning |
|--------|---------|
| `simulated` | The rule was in Simulate mode. Nothing was sent, and nothing ever will be. |
| `skipped` | Something already covered this send, or gating declined it. The reason is in the last error field. |
| `pending` | Recorded in Live mode, waiting for its delivery task. |
| `dispatched` | Handed to the integration service, waiting for confirmation. |
| `sent` | Confirmed delivered. |
| `failed` | Permanently rejected, for example a 4xx or a vendor error. Can be replayed. |
| `dead` | Retries exhausted, or no confirmation ever arrived. Can be replayed. |

`skipped` is worth dwelling on. Skips are recorded rather than silent, because "the rule did nothing" and "the rule did nothing because this Finding already had a ticket" are different answers, and only one of them is a problem.

There are three common reasons for a skip, and the last error field always says which:

* **Idempotency.** Something already covered this send.
* **The channel is switched off.** A rule with a Slack node on an instance where Slack is disabled records a skip explaining that, rather than failing. A rule saved while a channel was on should not start erroring when somebody turns it off. See [node availability](../node_reference/#when-a-channel-is-unavailable).
* **The per-Finding send ceiling was reached.** A node sending one message per Finding stops after 1,000 in a single run by default, and records how many it did not send about.

### Payload fidelity

The ledger is honest about how close the recorded payload is to the real wire body, because that varies by channel.

| Fidelity | Meaning |
|----------|---------|
| `exact` | Byte-equivalent to what was sent. |
| `rendered` | Rendered by the real helpers, but send-time gating may still trim it. |
| `dojo request` | The exact request handed to the integration service. The vendor-specific payload is composed downstream. |
| `summary` | A description of the send rather than a reproduction of it. A generated report is the example: the file is built from live data at send time, so a stored copy of it would be wrong the moment anything changed. |

## The double-send guard

Only one **active** delivery can exist per idempotency key, enforced in the database rather than by convention. Active means `pending`, `dispatched` or `sent`.

A second send that would collide with an active one becomes a `skipped` row with its reason recorded. It is never a silent no-op, and it is never a duplicate ticket.

Because `simulated`, `skipped`, `failed` and `dead` rows do not hold a claim, a failed delivery can be replayed in place without a second row fighting it for the same key.

## Retries

A live delivery is retried automatically. Each row carries its own attempt count and its own ceiling, six attempts by default, so a failing destination cannot take its siblings down with it. Retries back off between attempts.

When the last retry is spent, the row is marked `dead` rather than left sitting at `pending`. Exhaustion is visible, not silent.

If a worker is killed mid-send, the message is redelivered. The row is locked and its status re-checked before anything is sent again, so a redelivery cannot become a double-send.

Deliveries handed to the integration service move to `dispatched` and wait for a confirmation callback. If no callback arrives within six hours, the row is marked `dead` so it can be replayed. That window is deliberately generous: a downstream queue backing up for an hour is normal, and burying a row too eagerly would turn a replay into a duplicate ticket.

## Replaying a delivery

A `failed` or `dead` delivery can be resent from the Deliveries page. The ledger records when it was replayed and by whom.

Replay needs **Rule Edit**.

Replay re-sends the recorded payload. For a report, that regenerates the report from current data, because the payload is a description of what to generate rather than the file itself.

## Simulate

In Simulate mode, every egress node writes its delivery row with status `simulated`, full payload, and resolved target, then stops. No dispatch is registered, so nothing can send later however the run unwinds. Preview behaves the same way, and does not even insert the rows.

This is the intended way to review a rule before letting it out: enable it in Simulate, let it run against real Findings, then read the payloads it recorded.

Remember that Simulate holds back **only** the outbound sends. Findings nodes still change Findings.

## Retention

Deliveries are kept for **180 days** by default, after which a retention job prunes them.

This is the fastest-growing table in the feature, because a node sending one message per item writes a row per item, in Simulate mode as well as Live. The default is a real window rather than "keep everything", so the growth does not quietly become your problem.

You are told about it rather than left to discover it. A delivery's detail shows the retention window and the date that row will be deleted, and the date is recalculated on read, so changing the window takes effect immediately.

Set the window longer if you need a longer outbound audit trail, or to `0` to keep everything. See [Configuration](../configuration/#retention).

## Deliveries from Asset rules

A notification sent by an Asset rule lands in the outbox like any other delivery. A per-item send names its Asset the way a per-Finding send names its Finding, and the row links to the Asset.

Visibility follows the row's subject. A row about one Asset is visible to anyone who can view that Asset. A batch row (a digest) has no single subject and quotes the names of everything its send covered, so it stays behind the global Finding viewing grant, exactly as Finding digests do.

Two rendering details worth knowing when reading recorded payloads:

- An Asset digest counts its batch by business criticality ("7 asset(s): 2 very high, 5 unclassified") where a Finding digest counts by severity.
- A webhook body from an Asset rule carries `"entity": "asset"` and an `assets` list with each Asset's identifying fields; its `findings` list is present and empty, so a receiver written against the Finding shape keeps parsing.
