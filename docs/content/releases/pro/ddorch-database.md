---
title: "Adding the dd-orch Database on Upgrade"
toc_hide: true
weight: -20260501
description: "Provisioning the dojodb-ddorch PostgreSQL database and pointing DefectDojo Pro at it on an existing self-hosted installation."
audience: pro
---

Starting with 2.57.3, DefectDojo Pro requires a second PostgreSQL database, `dojodb-ddorch`, used by the new `ddorch` orchestrator service. The existing `dojodb` database continues to be used by the main Django application.

This guide walks through adding `dojodb-ddorch` to an existing self-hosted PostgreSQL instance and pointing DefectDojo at it.

## Prerequisites

- PostgreSQL 16 is already installed and running on the DB server.
- The `dojodbusr` role already exists with a known password.
- `dojodb` is already created and reachable from the DefectDojo app server.
- `listen_addresses` in `postgresql.conf` is already configured for remote access.
- You have upgraded to the release that ships the `ddorch` and `ddorch-workers` services.

> **A note on the database name:** `dojodb-ddorch` contains a hyphen, so it must be double-quoted in every SQL statement (`"dojodb-ddorch"`). If you prefer to avoid the quoting, use `dojodb_ddorch` (underscore) and drop the quotes throughout the rest of this guide.

## Part 1: Provision the Database

### 1. Create the new database

On the PostgreSQL server, open a `psql` session as the `postgres` superuser:

```bash
sudo -i -u postgres psql --username postgres
```

Create the database, grant privileges to the existing `dojodbusr` role, and transfer ownership:

```sql
CREATE DATABASE "dojodb-ddorch";
GRANT ALL PRIVILEGES ON DATABASE "dojodb-ddorch" TO dojodbusr;
ALTER DATABASE "dojodb-ddorch" OWNER TO dojodbusr;
\q
```

**Example session:**

```
root@dbserver:~# sudo -i -u postgres psql --username postgres
psql (16.8)
Type "help" for help.

postgres=# CREATE DATABASE "dojodb-ddorch";
CREATE DATABASE
postgres=# GRANT ALL PRIVILEGES ON DATABASE "dojodb-ddorch" TO dojodbusr;
GRANT
postgres=# ALTER DATABASE "dojodb-ddorch" OWNER TO dojodbusr;
ALTER DATABASE
postgres=# \q
```

> **PostgreSQL 15+ note:** Ownership covers schema rights for the owner, but if you ever connect as a non-owner role you will also need to grant schema privileges inside the new database:
>
> ```sql
> \c "dojodb-ddorch"
> GRANT ALL ON SCHEMA public TO dojodbusr;
> ```

### 2. Allow the app server to connect

Edit `/etc/postgresql/16/main/pg_hba.conf` and add a new line for `dojodb-ddorch` next to the existing `dojodb` entry.

**(a) Preferred — restrict to the DefectDojo app server's IP.**

Supposing the app server's IP is `9.9.9.9`, add:

```
host  dojodb-ddorch  dojodbusr  9.9.9.9/32  scram-sha-256
host  postgres  dojodbusr  9.9.9.9/32  scram-sha-256
```

**(b) Alternative — allow from any host.**

```
host  dojodb-ddorch  dojodbusr  0.0.0.0/0  scram-sha-256
host  postgres  dojodbusr  0.0.0.0/0  scram-sha-256
```

> **Note:** The lines in `pg_hba.conf` are whitespace-delimited. The easiest way to add this line is to copy/paste the existing `dojodb` line and change the database name.

**Alternative using `echo` (if no text editor is available):**

```bash
# For specific IP (replace 9.9.9.9 with your app server IP):
echo "host  dojodb-ddorch  dojodbusr  9.9.9.9/32  scram-sha-256" | sudo tee -a /etc/postgresql/16/main/pg_hba.conf
echo "host  postgres  dojodbusr  9.9.9.9/32  scram-sha-256" | sudo tee -a /etc/postgresql/16/main/pg_hba.conf

# OR for all hosts:
echo "host  dojodb-ddorch  dojodbusr  0.0.0.0/0  scram-sha-256" | sudo tee -a /etc/postgresql/16/main/pg_hba.conf
echo "host  postgres  dojodbusr  0.0.0.0/0  scram-sha-256" | sudo tee -a /etc/postgresql/16/main/pg_hba.conf

```

### 3. Reload PostgreSQL

Changes to `pg_hba.conf` only require a reload — no restart is needed:

```bash
sudo systemctl reload postgresql
```

Verify the reload was picked up:

```bash
sudo systemctl status postgresql
```

### 4. Verify connectivity from the app server

From the **DefectDojo app server**, confirm `dojodbusr` can reach the new database. Replace `<db-server-ip>` with your DB server's IP and `<password>` with the password set for `dojodbusr`:

```bash
psql "host=<db-server-ip> dbname=dojodb-ddorch user=dojodbusr password=<password>" -c "SELECT 1;"
```

A successful response of `?column?` with a value of `1` confirms the database is reachable and the credentials are valid.

## Part 2: Point DefectDojo at the New Database

Only the `ddorch` service connects to the new database directly. The main Django application reaches the orchestrator over gRPC, so `DD_DATABASE_URL` does **not** change.

### 1. Set the orchestrator database URL

The `ddorch` service reads its connection string from the `DD_ORCH_DATABASE_URL` environment variable and **automatically appends `-ddorch` to the database name** in whatever URL you pass it. This means you can reuse the same connection string you already use for the main Django application — no need to construct a second URL by hand.

In your `.env` file (or equivalent override mechanism), set `DD_ORCH_DATABASE_URL` to point at your existing main database (the `dojodb` one, *not* `dojodb-ddorch`):

```bash
DD_ORCH_DATABASE_URL=postgres://dojodbusr:<password>@<db-server-ip>:5432/dojodb
```

| Placeholder | Value |
|---|---|
| `<password>` | The password set for `dojodbusr` |
| `<db-server-ip>` | IP or hostname of your PostgreSQL server |

On startup, ddorch rewrites the database name in this URL from `dojodb` to `dojodb-ddorch` and connects to the database you created in Part 1.

> **Note on special characters in the password:** If the password contains `@`, `:`, `/`, `#`, or `?`, URL-encode it (for example, `@` becomes `%40`). Alphanumeric passwords need no encoding.

### 2. Restart the orchestrator services

From the deployment directory, recreate the two orchestrator containers so they pick up the new environment:

```bash
docker compose up -d ddorch ddorch-workers
```

Docker Compose will detect the environment change and recreate the containers. The `ddorch` service runs its own schema migrations against `dojodb-ddorch` on startup — no manual migration command is required.

### 3. Verify ddorch connected and migrated the new database

The most direct signal that the database is correctly wired up is the ddorch startup log. Check the last hundred lines:

```bash
docker compose logs ddorch --tail=100
```

Look for three log lines in sequence:

```
{"level":"INFO","msg":"Appending database name to DATABASE_URL","from":"dojodb","to":"dojodb-ddorch"}
INFO Running migrations current_schema_version=<N> next_version=<M> migrations_to_apply=<K>
{"level":"INFO","msg":"starting server","port":9871}
```

What each line proves:

- **`Appending database name to DATABASE_URL ... to: dojodb-ddorch`** — ddorch received your URL and derived the orch database name correctly.
- **`Running migrations ... migrations_to_apply=0`** — ddorch connected to `dojodb-ddorch` and found the schema at the expected version. On a first-ever boot against a fresh database you may see `migrations_to_apply=<N>` with a non-zero value and no subsequent error — this means ddorch just created the tables from scratch. Both outcomes indicate success.
- **`starting server ... port:9871`** — ddorch is up and listening.

If instead you see an error such as `FATAL: password authentication failed`, `no pg_hba.conf entry for host`, or `database "dojodb-ddorch" does not exist`, the database is not reachable — revisit Part 1 before proceeding.

Also confirm both orchestrator containers are running:

```bash
docker compose ps ddorch ddorch-workers
```

Both should report `Up`. With ddorch migrated and the workers container running, your installation is now using the new `dojodb-ddorch` database.
