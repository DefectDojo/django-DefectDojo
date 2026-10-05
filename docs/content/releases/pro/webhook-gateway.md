---
title: "Adding the Webhook Gateway on Upgrade"
toc_hide: true
weight: -20260928
description: "What an existing self-hosted DefectDojo Pro installation gets with the webhook gateway, what a database administrator may need to run, how to verify it, and how to roll it back."
audience: pro
---

DefectDojo Pro can put a **webhook gateway** in front of Triage Engine [webhook receivers](/automation/triage_engine/webhook_receivers/), the URLs Jira and other tools post to for [two-way sync](/connectors/toolreference/jira/#two-way-sync). The gateway stores each webhook and answers the sender before DefectDojo is involved, then delivers it with retries, so a DefectDojo restart or short outage loses nothing.

This page is for operators upgrading an existing self-hosted installation to the first release that ships the gateway. Most installations have nothing to do: the upgrade creates everything the gateway needs. Read on if your database user has restricted privileges, if you count database connections, or if you want to know what to check and how to roll back.

## What changes

### Docker Compose

The Docker Compose bundles turn the gateway on (`DD_WEBHOOK_GATEWAY_MODE=whook` and `WEBHOOK_GATEWAY_ENABLED=true`). An upgrade with `dojo-compose-cli` brings:

- **A new container and image**, `webhook-gateway`, from the same registry and version as the rest of DefectDojo Pro. The standard image is published for `linux/amd64` and `linux/arm64`; FIPS deployments use the `-fips` variant, published for `linux/amd64`. Air-gapped installations need this image in the transferred bundle too.
- **Two new nginx files** in the deployment directory, `nginx/webhook-gateway.conf` and `nginx/webhook-direct.conf`, bind-mounted into the nginx container. `dojo-compose-cli deploy download` fetches them with the rest of the deployment files.
- **A new named volume**, `webhook_gateway_secrets`. DefectDojo's `init` container writes the gateway's secrets and database URL there, and only `init` and the gateway mount it.
- **A schema and a database role** inside DefectDojo's existing database (see below). No new database is needed.

### Kubernetes

The Helm chart runs the gateway when `webhookGateway.enabled` is on. Check the value's default in the chart version you install: a chart may ship it off until the DefectDojo Pro release that publishes the gateway image. With it off, DefectDojo serves receiver URLs itself (`DD_WEBHOOK_GATEWAY_MODE=direct`). With it on, the gateway pod's `webhook-gateway-db-setup` init container prepares the same schema and role described below and prints the statements to run when it cannot. An installation that uses `dojo.existingSecret` keeps the gateway off until you add its keys to your Secret and set `webhookGateway.existingSecretHasKeys`, because the chart cannot derive them without seeing `dojo.secretKey`.

### ECS

The ECS task definitions do not include the gateway. They set `DD_WEBHOOK_GATEWAY_MODE=direct`, so DefectDojo answers receiver URLs itself and nothing below applies.

## The database schema and role

The gateway keeps its tables in a schema of its own, `whook` by default (`DD_WEBHOOK_GATEWAY_SCHEMA`), inside DefectDojo's database. It logs in with a role of its own, named after DefectDojo's database by default (`<database>_webhook_gateway`, set with `DD_WEBHOOK_GATEWAY_DB_ROLE`), which owns that schema and can use nothing else of DefectDojo's. Because PostgreSQL roles belong to the whole server, each installation on a shared server gets its own role, and DefectDojo never changes a role that was created for another database.

On startup, DefectDojo creates both when they are missing, using DefectDojo's own database user:

- Creating the role needs `CREATEROLE`. The admin user of most managed databases has it, and so does DefectDojo's user in a new installation of the Docker Compose bundle with a bundled database. A bundled database created before this release does not grant it: run `ALTER USER <DefectDojo database user> CREATEROLE;` once as the `postgres` user, then restart DefectDojo. Without it, the gateway connects with DefectDojo's credentials, confined to its schema by `search_path` only, and `init` logs the statements that would give it a role of its own.
- Creating the schema needs `CREATE` on DefectDojo's database, which the database's owner always has. Without it, `init` logs the exact statement to run, the gateway refuses to start and prints the same statement, and the receivers list shows the gateway as **Not Started**.

When DefectDojo's user may do neither, have a database administrator run the following once, with your database name and a password of your choosing, connected to DefectDojo's database:

```sql
CREATE ROLE <database>_webhook_gateway LOGIN PASSWORD '<password>';
GRANT CONNECT ON DATABASE <database> TO <database>_webhook_gateway;
CREATE SCHEMA IF NOT EXISTS whook AUTHORIZATION <database>_webhook_gateway;
```

Then set `DD_WEBHOOK_GATEWAY_DB_PASSWORD` to that password in the deployment's environment, so DefectDojo hands the gateway the same one. To keep the gateway on DefectDojo's own credentials instead, set `DD_WEBHOOK_GATEWAY_DB_ROLE` to an empty value and create only the schema:

```sql
CREATE SCHEMA IF NOT EXISTS whook AUTHORIZATION <DefectDojo's database user>;
```

## Secrets

The gateway needs an admin token, a key that encrypts stored receiver tokens, a key it signs its deliveries to DefectDojo with, and its database role's password. Each installation derives its own from `DD_SECRET_KEY`, so there is nothing to generate before the upgrade, and the gateway container never receives `DD_SECRET_KEY` itself. The Helm chart derives them from `dojo.secretKey`. To manage one yourself, set `DD_WEBHOOK_GATEWAY_ADMIN_TOKEN`, `DD_WEBHOOK_GATEWAY_SECRET_KEY`, `DD_WEBHOOK_GATEWAY_DELIVERY_SECRET` or `DD_WEBHOOK_GATEWAY_DB_PASSWORD`; a value that is set wins over the derived one.

Because the derived secrets follow `DD_SECRET_KEY`, an installation still running on the `DD_SECRET_KEY` from DefectDojo's deployment files gets a startup warning (system check `pro.W002`). Give it its own key. When you change `DD_SECRET_KEY` later, restart DefectDojo, its workers and the gateway together; see [Changing the secret key or the gateway secrets](/automation/triage_engine/configuration/#changing-the-secret-key-or-the-gateway-secrets).

## Connections and rate limits

- The gateway holds at most 5 connections to DefectDojo's database server by default (`WHOOK_DB_MAX_CONNS`; `webhookGateway.database.maxConnections` in the Helm chart), on top of DefectDojo's own. Count them against the server's `max_connections`, or a managed database's connection limit. During a Kubernetes rollout two gateway pods briefly run at once.
- nginx allows each sender address 100 receiver requests per second by default (`DD_WEBHOOK_RECEIVER_RATE`, burst `DD_WEBHOOK_RECEIVER_BURST`, 1000), and the gateway accepts 100 deliveries per second per receiver (`WHOOK_INGEST_RATE`, burst `WHOOK_INGEST_BURST`, 1000). Both answer `429` above the limit, which senders retry.
- The largest webhook body is `DD_RULES_V2_WEBHOOK_MAX_BODY_BYTES` (1 MiB by default), one value that nginx, the gateway and DefectDojo all read.

## Verifying the upgrade

1. **The initializer prepared the database.** In the `init` container's log, look for:

    ```
    Prepared the webhook gateway's database role and schema
    Wrote the webhook gateway's secrets
    ```

    `Prepared the webhook gateway's schema (it uses DefectDojo's database credentials)` means the role could not be created and the gateway uses DefectDojo's user. `Could not prepare the webhook gateway's database; see the warning above` means the schema could not be created either: run the statements from the warning.

    ```bash
    docker compose logs init | grep -i "webhook gateway"
    ```

2. **The gateway is running and healthy.** Its health check fails while it cannot reach its database.

    ```bash
    docker compose ps webhook-gateway
    ```

3. **The gateway created its tables.** Connected to DefectDojo's database with `psql`:

    ```
    \dt whook.*
    ```

    lists the gateway's tables once it has started. `\du *_webhook_gateway` shows its role.

4. **DefectDojo can reach it.** In DefectDojo, open **Triage Engine > Webhook Receivers**. The top of the list shows the gateway as **Healthy**. **Unreachable** means DefectDojo cannot reach the gateway container, **Not Started** means its schema is missing, and **Turned Off** means the **Inbound Webhooks** feature flag is off.

On Kubernetes, the gateway pod's setup log shows the same preparation:

```bash
kubectl logs -n <namespace> deploy/<release>-webhook-gateway -c webhook-gateway-db-setup
```

## Running without the gateway

To have DefectDojo answer receiver URLs itself, set `WEBHOOK_GATEWAY_ENABLED=false` and `DD_WEBHOOK_GATEWAY_MODE=direct` together (on Kubernetes, `webhookGateway.enabled: false`). Receivers keep working, but a delivery that arrives while DefectDojo is down is lost unless the sender retries it.

## Rolling back

A release without the gateway does not need anything the gateway added, but three things outlive a rollback and should be removed by hand:

- **The gateway container.** An older bundle has no `webhook-gateway` service, so a plain `docker compose up` leaves the running one behind, still holding database connections. Remove it with:

    ```bash
    docker compose up -d --remove-orphans
    ```

- **The secrets volume.** Once the gateway container is gone:

    ```bash
    docker volume rm <project>_webhook_gateway_secrets
    ```

- **The schema and the role.** The schema holds captured webhook bodies and headers for up to 30 days (90 for failed deliveries). Drop it once nothing needs to be replayed from it, and drop the role if DefectDojo created it:

    ```sql
    DROP SCHEMA whook CASCADE;
    DROP ROLE <database>_webhook_gateway;
    ```

On a release without webhook receivers, their URLs answer `404`, and senders retry for their own retry window.
