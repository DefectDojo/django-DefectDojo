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

Only the `ddorch` service connects to the new database directly. The main Django application reaches the orchestrator over HTTP, so no changes to `DD_DATABASE_URL` are required.

### 1. Set the orchestrator database URL

The `ddorch` service reads its connection string from the `DD_ORCH_DATABASE_URL` environment variable. Add or update the following entry in your `.env` file (or equivalent override mechanism), replacing the placeholders with your values:

```bash
DD_ORCH_DATABASE_URL=postgres://dojodbusr:<password>@<db-server-ip>:5432/dojodb-ddorch
```

| Placeholder | Value |
|---|---|
| `<password>` | The password set for `dojodbusr` |
| `<db-server-ip>` | IP or hostname of your PostgreSQL server |

> **Note on special characters in the password:** If the password contains `@`, `:`, `/`, `#`, or `?`, URL-encode it (for example, `@` becomes `%40`). Alphanumeric passwords need no encoding.
>
> **Note on the hyphenated database name:** Hyphens are valid in URL path segments, so `dojodb-ddorch` does **not** need to be encoded or quoted in the `DD_ORCH_DATABASE_URL` value.

### 2. Restart the orchestrator services

From the deployment directory, recreate the two orchestrator containers so they pick up the new environment:

```bash
docker compose up -d ddorch ddorch-workers
```

Docker Compose will detect the environment change and recreate the containers. The `ddorch` service initializes its own schema on first startup — no manual migration command is required.

### 3. Verify the services started cleanly

Check the `ddorch` logs for a successful database connection and schema initialization:

```bash
docker compose logs ddorch --tail=100
```

You should see log lines indicating that the database connection succeeded and the service is listening on port `9871`. If you see connection errors, double-check the following:

- The `pg_hba.conf` entry added in Part 1 allows the app server's IP.
- PostgreSQL was reloaded (`sudo systemctl reload postgresql`) after the `pg_hba.conf` edit.
- The password in `DD_ORCH_DATABASE_URL` matches the password set for `dojodbusr`.
- The DB server is reachable from the app server (re-run the `psql` check from Part 1, Step 4).

Also confirm the workers container is running and connected to `ddorch`:

```bash
docker compose ps ddorch ddorch-workers
docker compose logs ddorch-workers --tail=50
```

### 4. Confirm end-to-end from the main application

Finally, confirm the main Django container can reach the orchestrator. From the `dojo` container:

```bash
docker compose exec dojo curl -kf https://ddorch:9871/health
```

A `200 OK` response confirms the orchestrator is healthy and the main app can talk to it. Your installation is now using the new `dojodb-ddorch` database.
