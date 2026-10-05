---
title: "Configuration"
description: "Deployment level settings for Triage Engine"
weight: 8
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

A node with **One Message per Item** turned on, and **Generate a Report** with One Report per Finding or per Asset, produces one delivery row and one queued task per item. Because a run has no item cap, a rule with a very broad scope and per-item sending on would otherwise mean an unbounded number of both. The ceiling is per node per run and counts items of either kind: a Finding rule's Findings and an Asset rule's Assets spend the same budget.

Past this ceiling the node records a **visible skip** saying how many items it did not send about. It does not fail the run, and it does not silently stop.

## Webhook receivers

These settings bound what a [webhook receiver](../webhook_receivers/) accepts.

### `DD_RULES_V2_WEBHOOK_MAX_BODY_BYTES`

**Default: 1048576 (1 MiB).**

The largest body a receiver accepts. A larger delivery is refused and recorded as a rejected receipt. The Docker Compose bundles and the Helm chart (`webhookGateway.maxBodyBytes`) feed this one value to DefectDojo, to the gateway and to nginx's limit on receiver URLs, so change it in one place: set it in the deployment's environment (or the chart value), not on one container.

### `DD_RULES_V2_WEBHOOK_DEDUPE_WINDOW_SECONDS`

**Default: 86400 (one day). `0` turns it off.**

Without the gateway, how long DefectDojo remembers a delivery so a sender's retry is recorded once. With a dedupe header on the receiver, a repeat is the same header value with the same body. Without one, two identical bodies within the window count once. With the gateway, the gateway recognizes a sender's retries (by the dedupe header together with a hash of the body) and DefectDojo records each gateway event once, so this setting is unused. See [Retries of the same event](../webhook_receivers/#retries-of-the-same-event).

### `DD_RULES_V2_WEBHOOK_RATE_LIMIT`

**Default: 600. `0` turns it off.**

Without the gateway, the most deliveries one receiver accepts per minute. Past it, a delivery is answered `429` with a `Retry-After` header, and refused deliveries count too. Deliveries from the gateway skip it, because the gateway limits what it accepts itself (see [Rate limits](#rate-limits)).

### `DD_RULES_V2_RECEIPT_RETENTION_DAYS`

**Default: 180.**

How many days a receipt is kept. `0` keeps receipts forever.

### The webhook gateway

The gateway runs as its own `webhook-gateway` service. nginx sends receiver URLs to it, and it delivers to DefectDojo over nginx's internal listener, signing each delivery so DefectDojo accepts deliveries only from it. It stores every delivery in DefectDojo's own database, in a schema of its own.

DefectDojo itself defaults to serving receiver URLs directly (`DD_WEBHOOK_GATEWAY_MODE=direct`). The gateway is turned on explicitly where it is deployed: the Docker Compose bundles set `DD_WEBHOOK_GATEWAY_MODE=whook` and `WEBHOOK_GATEWAY_ENABLED=true`, and the Helm chart does the same when `webhookGateway.enabled` is on. The ECS task definitions run without it, in direct mode. Upgrading an existing installation to a release with the gateway is covered in [Adding the Webhook Gateway on Upgrade](/releases/pro/webhook-gateway/).

To stop inbound webhook traffic without redeploying, turn off the **Inbound Webhooks** feature flag. See [Turning inbound webhooks off](../webhook_receivers/#turning-inbound-webhooks-off).

| Setting | Default | Notes |
|---------|---------|-------|
| `DD_WEBHOOK_GATEWAY_MODE` | `direct` | `whook` puts the gateway in front of every receiver. `direct` has DefectDojo answer receiver URLs itself, with no durability during an outage. The Docker Compose bundles set `whook`. |
| `WEBHOOK_GATEWAY_ENABLED` | `true` in the Docker Compose bundles | On the nginx and gateway containers: whether nginx routes receiver URLs to the gateway. Off, the gateway idles. Set it together with `DD_WEBHOOK_GATEWAY_MODE`: `true` with `whook`, `false` with `direct`. |
| `DD_WEBHOOK_GATEWAY_URL` | `http://webhook-gateway:8080` | The gateway's admin address. Never routed by nginx. |
| `DD_WEBHOOK_GATEWAY_DELIVER_BASE_URL` | `https://nginx:7443` | Where the gateway delivers. It must be reachable from the gateway and must not be public. |
| `DD_WEBHOOK_GATEWAY_MAX_ATTEMPTS` | `12` | Delivery attempts before the gateway gives up on an event and keeps it as a dead letter. The wait starts at 2 seconds and triples each time, up to an hour, so twelve attempts cover about four and a half hours. |
| `DD_WEBHOOK_GATEWAY_SCHEMA` | `whook` | The schema inside DefectDojo's database that holds the gateway's tables. DefectDojo's initializer and the gateway both read it, so set it once for the whole deployment. Empty skips creating it, for a deployment that creates it itself. |
| `DD_WEBHOOK_GATEWAY_DB_ROLE` | `auto` | The gateway's own database login role. `auto` names it after DefectDojo's database (`<database>_webhook_gateway`), so installations that share one PostgreSQL server never share a role. Set a name to choose it yourself. Empty (not unset) has the gateway use DefectDojo's database credentials instead. |
| `DD_WEBHOOK_GATEWAY_ADMIN_TOKEN` | derived | The token DefectDojo uses to configure the gateway. |
| `DD_WEBHOOK_GATEWAY_SECRET_KEY` | derived | The key the gateway encrypts stored receiver tokens with. |
| `DD_WEBHOOK_GATEWAY_DELIVERY_SECRET` | derived | The key the gateway signs its deliveries to DefectDojo with. |
| `DD_WEBHOOK_GATEWAY_DB_PASSWORD` | derived | The password of the gateway's database role. |

Every ten minutes, whenever a worker starts, and whenever the gateway refuses DefectDojo's admin token, DefectDojo reconciles the gateway with its receivers, so a gateway that lost its configuration recovers on its own. `manage.py reconcile_webhook_gateway` does the same on demand, and `--replay-dead-letters` also sends every enabled receiver's dead letters back to the gateway's delivery queue.

#### Gateway secrets

Each installation derives its own gateway secrets from `DD_SECRET_KEY`, one per purpose (the admin token, the secret key, the delivery secret and the database role's password), so there is nothing to generate or ship. A variable from the table above that is set and not empty is used instead of the derived value. In the Docker Compose bundles, DefectDojo's `init` container writes the resolved values to a volume only it and the gateway mount (`webhook_gateway_secrets`), so the gateway never receives `DD_SECRET_KEY` itself. The Helm chart derives them from `dojo.secretKey` and renders them into its Secret; see the chart's installation guide for an existing Secret.

Because the gateway secrets follow `DD_SECRET_KEY`, they are only as private as it is. DefectDojo warns at startup (system check `pro.W002`) while the gateway is in use and `DD_SECRET_KEY` is still a value shipped in DefectDojo's deployment files.

#### Changing the secret key or the gateway secrets

Changing `DD_SECRET_KEY`, or any explicit gateway secret, changes what DefectDojo and the gateway have to agree on. While they disagree, the gateway answers senders with a server error when it cannot decrypt a receiver's stored secret, and DefectDojo answers the gateway's deliveries with a server error when their signature does not verify. Both are retried, so nothing is dropped, but keep the gap short:

1. Restart DefectDojo (the web containers and every Celery worker) and the gateway together. In the Docker Compose bundles, let `init` run first: it writes the new secrets and sets the gateway role's new password.
2. DefectDojo re-registers every receiver with the gateway when a worker starts, so the gateway reseals each receiver's token with the new key. To do it at once, run `manage.py reconcile_webhook_gateway`.

The same reconcile also runs every ten minutes and after the gateway refuses DefectDojo's admin token, so an installation that restarted out of step catches up on its own.

#### Database role and schema

DefectDojo's initializer creates the gateway's login role (`DD_WEBHOOK_GATEWAY_DB_ROLE`) and its schema (`DD_WEBHOOK_GATEWAY_SCHEMA`), owned by that role, inside DefectDojo's database. The role can use its own schema and nothing else of DefectDojo's.

- Creating the role needs `CREATEROLE` on DefectDojo's database user. Without it, the gateway uses DefectDojo's credentials, confined to its schema by `search_path` only, and the initializer logs the statements a database administrator can run to give it a role of its own.
- Creating the schema needs `CREATE` on DefectDojo's database. Without it, the initializer logs the exact `CREATE SCHEMA` (or `GRANT`) statement to run, the gateway refuses to start and prints the same statement, and the receivers list shows the gateway as **Not Started**.
- PostgreSQL roles belong to the whole server, not to one database, so the initializer marks the role it creates with a comment naming DefectDojo's database. It never changes the password of, or grants anything to, an existing role marked for a different database (or not marked at all), which may belong to another installation on the same server. It uses such a role as it is only when the role already accepts the configured password; otherwise the gateway uses DefectDojo's credentials and the initializer logs why.

The statements, with your own database, user and password:

```sql
CREATE ROLE <database>_webhook_gateway LOGIN PASSWORD '<password>';
GRANT CONNECT ON DATABASE <database> TO <database>_webhook_gateway;
CREATE SCHEMA IF NOT EXISTS whook AUTHORIZATION <database>_webhook_gateway;
```

Then set `DD_WEBHOOK_GATEWAY_DB_PASSWORD` to that password. Without a dedicated role, `CREATE SCHEMA IF NOT EXISTS whook AUTHORIZATION <DefectDojo's database user>;` is enough.

#### Connection budget

The gateway holds at most `WHOOK_DB_MAX_CONNS` connections (default 5; `webhookGateway.database.maxConnections` in the Helm chart) on DefectDojo's database server, on top of DefectDojo's own. Count them against the server's `max_connections`, or a managed database's connection limit.

#### Rate limits

nginx allows each sender address `DD_WEBHOOK_RECEIVER_RATE` receiver requests (default `100r/s`, burst `DD_WEBHOOK_RECEIVER_BURST`, default 1000), and the gateway accepts `WHOOK_INGEST_RATE` deliveries per second per receiver (default 100, burst `WHOOK_INGEST_BURST`, default 1000). Both answer `429` above the limit, which senders retry.

## Related settings

Some Triage Engine nodes use system-wide integration configuration rather than their own:

* **Send a Slack Message** uses the system Slack token, and falls back to the system Slack channel when the node names none.
* **Send a Microsoft Teams Message** uses the Microsoft Teams webhook from system settings.
* **Create a JIRA Issue** uses the Asset's JIRA configuration for the summary, description and priority.
* **Raise an In-App Alert** respects each recipient's own **Rules Engine Match** notification setting.
