---
title: "Configuration"
description: "Deployment level settings for Triage Engine"
weight: 7
audience: pro
aliases:
  - /automation/rules_engine_v2/configuration/
  - /automation/rules_engine_2/configuration/
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Triage Engine is a DefectDojo Pro-only feature.</span>

Triage Engine works out of the box. The settings on this page are for deployments that need to tune throughput, retention, or outbound network policy. All of them are applied the same way as any other DefectDojo setting (see [Configuration](/get_started/open_source/configuration/)).

Triage Engine is configured separately from the original Rules Engine. The two engines share no tuning, so a `DD_RULES_ENGINE_*` setting does not affect Triage Engine and a `DD_RULES_V2_*` setting does not affect the original engine.

```python
DD_RULES_V2_EVENT_BATCH=(int, 500),
DD_RULES_V2_CHUNK_SIZE=(int, 1000),
DD_RULES_V2_STALLED_AFTER_MINUTES=(int, 30),
DD_RULES_V2_RUN_TIME_LIMIT_MINUTES=(int, 360),
DD_RULES_V2_ALLOW_PRIVATE_EGRESS=(bool, False),
DD_RULES_V2_DELIVERY_RETENTION_DAYS=(int, 180),
DD_RULES_V2_RUN_RETENTION_DAYS=(int, 180),
DD_RULES_V2_ENVELOPE_TEXT_MAX_CHARS=(int, 8000),
DD_RULES_V2_MAX_PER_ITEM_SENDS=(int, 1000),
```

## Throughput

### Findings per event (`DD_RULES_V2_EVENT_BATCH`)

**Default: 500.**

How many Finding ids a single event carries. Events cross an asynchronous boundary, so they are kept small enough to stay a cheap message. A larger write fans out into several events, each of which becomes its own run.

Raising this produces fewer, larger runs. Lowering it produces more, smaller ones.

### Findings per chunk (`DD_RULES_V2_CHUNK_SIZE`)

**Default: 1000.**

How many Findings a run holds in memory at once. A run is processed in chunks, so this is a memory knob and **not** a ceiling on what a rule handles: a rule always processes everything its scope matches.

An envelope is roughly 2.7KB per Finding, so the default holds a few megabytes at a time. Raising it trades memory for fewer round trips. Lowering it does the reverse.

### Envelope text cap (`DD_RULES_V2_ENVELOPE_TEXT_MAX_CHARS`)

**Default: 8000. Set to 0 to disable.**

How many characters of `description`, `mitigation` and `impact` an item carries.

Those three fields are most of an envelope's size. The cap exists for the unusual case of a Finding with a very large description, where a full chunk of them would be far bigger than the chunk size suggests. It is generous enough that an ordinary instance never notices it.

Note that this affects what conditions and templates can see. A condition matching against the tail of a very long description will not see text beyond the cap.

## Run lifetime

### Stall window (`DD_RULES_V2_STALLED_AFTER_MINUTES`)

**Default: 30.**

How long a run may go without a heartbeat before it is treated as abandoned, marked as errored, and its per-rule lock released.

A run stamps a heartbeat after each chunk, so this is measured from the last heartbeat rather than from the start. A long sweep that is still making progress is never mistaken for a crashed worker, which is what lets the window stay short.

### Run time limit (`DD_RULES_V2_RUN_TIME_LIMIT_MINUTES`)

**Default: 360, which is six hours.**

The longest a single run may take before the worker kills it.

This is a guard against a rule that will never finish while holding a worker slot and its rule's execution lock. It is deliberately generous, because a chunked sweep over a very large scope is a workload this engine is built for.

## Retention

Two jobs bound the three tables this feature grows. Both default to **180 days**, and both take `0` to disable pruning entirely.

Retention is surfaced in the product rather than left implicit: the API serves both the window and the date a given record will be deleted, and the pages that show a run or a delivery say it in a sentence. The date is computed on read, so changing the window takes effect immediately rather than applying only to new records.

### `DD_RULES_V2_DELIVERY_RETENTION_DAYS`

**Default: 180.**

How many days a finished delivery is kept.

This is the fastest-growing table in the feature. A per-item egress node writes up to a chunk's worth of rows per run, including in Simulate mode. Raise it if you need a longer outbound audit trail, and lower it if volume is a problem.

### `DD_RULES_V2_RUN_RETENTION_DAYS`

**Default: 180.**

How many days a finished run is kept, along with its per-node rows and its Finding provenance.

The run side grows faster than deliveries do, because provenance is one row per Finding per mutation node per run. An hourly rule over a large scope generates a lot of it.

A run that still holds deliveries is kept until those are pruned, so setting a shorter run window than delivery window does not orphan anything.

## Outbound destination validation

Two node settings take a destination as free text rather than from a configured object: the **URL** on Call a Webhook, and the **To** on Send an Email. Both are validated when the rule is saved.

For webhook URLs:

* Only `http` and `https` are accepted. Other schemes are rejected outright.
* The URL must have a host.
* By default, a host that resolves to a loopback, link-local, private, reserved or multicast address is rejected.

For email addresses, an empty address is rejected, and so is one containing a newline, which is header injection.

The reason for the network check is that the worker sending the request usually sits inside your cluster and can reach far more of the internal network than the person authoring the rule can. Without the check, a free-text URL is a request forgery primitive: point it at a metadata service or an internal admin port and the response comes back through the delivery ledger.

This is defence in depth rather than the only control. Rule Edit is close to administrative anyway. It is worth having so that the blast radius of one over-granted role is not "read any internal HTTP endpoint", and so a typo fails at save time with a clear message instead of at send time with a connection error.

### Allowing private addresses (`DD_RULES_V2_ALLOW_PRIVATE_EGRESS`)

**Default: off.**

Turns off the network address check, so webhooks may post to loopback, link-local and private addresses. Scheme and shape validation still applies.

Turn this on if you genuinely webhook to something on a private address, which a self-hosted chat or webhook receiver normally is.

## Per-Finding send ceiling

### `DD_RULES_V2_MAX_PER_ITEM_SENDS`

**Default: 1000. Set to 0 to remove the ceiling.**

The most per-item sends a single egress node will record in one run.

A node with **One Message per Item** turned on produces one delivery row and one queued task per item. Because a run has no item cap, a rule with a very broad scope and per-item sending on would otherwise mean an unbounded number of both. The ceiling is per node per run and counts items of either kind: a Finding rule's Findings and an Asset rule's Assets spend the same budget.

Past this ceiling the node records a **visible skip** saying how many items it did not send about. It does not fail the run, and it does not silently stop.

## Webhook receivers

These settings bound what a [webhook receiver](../webhook_receivers/) accepts.

### `DD_RULES_V2_WEBHOOK_MAX_BODY_BYTES`

**Default: 1048576 (1 MiB).**

The largest body a receiver accepts. A larger delivery is refused and recorded as a rejected receipt. The gateway reads the same setting. When the gateway is on, nginx also caps the body in front of it through `DD_WEBHOOK_GATEWAY_MAX_BODY` (default `1m`), so raise both together.

### `DD_RULES_V2_WEBHOOK_DEDUPE_WINDOW_SECONDS`

**Default: 86400 (one day).**

Without the gateway, how long a delivery id from the receiver's dedupe header is remembered, so a sender's retry is recorded once. With the gateway, the gateway deduplicates and this setting is unused.

### `DD_RULES_V2_WEBHOOK_RATE_LIMIT`

**Default: 600.**

The most deliveries one receiver accepts per minute. Past it, a delivery is answered `429` with a `Retry-After` header, and the gateway retries it later.

### `DD_RULES_V2_RECEIPT_RETENTION_DAYS`

**Default: 180.**

How many days a receipt is kept. `0` keeps receipts forever.

### The webhook gateway

The gateway runs as its own `webhook-gateway` service and delivers to DefectDojo over the internal network. It stores every delivery in DefectDojo's own database, in a schema of its own (`whook` by default), which DefectDojo creates on startup, so there is nothing to provision. It is on by default in the Docker Compose bundles and in the Helm chart (`webhookGateway.enabled`).

To stop inbound webhook traffic without redeploying, turn off the **Inbound Webhooks** feature flag. See [Turning inbound webhooks off](../webhook_receivers/#turning-inbound-webhooks-off).

| Setting | Default | Notes |
|---------|---------|-------|
| `DD_WEBHOOK_GATEWAY_MODE` | `whook` | `whook` puts the gateway in front of every receiver. `direct` has DefectDojo answer receiver URLs itself, with no durability during an outage. |
| `DD_WEBHOOK_GATEWAY_URL` | `http://webhook-gateway:8080` | The gateway's admin address. |
| `DD_WEBHOOK_GATEWAY_ADMIN_TOKEN` | empty | The token DefectDojo uses to configure the gateway. It must match the gateway's `WHOOK_ADMIN_TOKEN`, and the gateway refuses to start without one. |
| `DD_WEBHOOK_GATEWAY_DELIVER_BASE_URL` | `https://nginx:7443` | Where the gateway delivers. It must be reachable from the gateway and must not be public. |
| `DD_WEBHOOK_GATEWAY_MAX_ATTEMPTS` | `12` | Delivery attempts before the gateway gives up on an event. The wait starts at 2 seconds and triples each time, up to an hour, so twelve attempts cover about four and a half hours. |
| `DD_WEBHOOK_GATEWAY_SCHEMA` | `whook` | The schema inside DefectDojo's database that holds the gateway's tables. DefectDojo creates it on startup. |
| `WEBHOOK_GATEWAY_ENABLED` | `true` | On the nginx and gateway containers: whether nginx routes receiver URLs to the gateway. Off, the gateway idles. Set it together with `DD_WEBHOOK_GATEWAY_MODE`. |

Every ten minutes DefectDojo reconciles the gateway with its receivers, so a gateway that lost its configuration recovers on its own. `manage.py reconcile_webhook_gateway` does the same on demand.

## Related settings

Some Triage Engine nodes use system-wide integration configuration rather than their own:

* **Send a Slack Message** uses the system Slack token, and falls back to the system Slack channel when the node names none.
* **Send a Microsoft Teams Message** uses the Microsoft Teams webhook from system settings.
* **Create a JIRA Issue** uses the Asset's JIRA configuration for the summary, description and priority.
* **Raise an In-App Alert** respects each recipient's own **Rules Engine Match** notification setting.
