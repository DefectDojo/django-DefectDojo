---
title: "Sandbox Mode (self-hosted)"
description: "Turn on the DefectDojo Pro sandbox on a self-hosted instance with one setting, and what it creates in your database"
draft: false
weight: 10
audience: pro
---

The [sandbox](/admin/sandbox/pro__sandbox/) is a practice copy of DefectDojo Pro served under `/sandbox/` by the same containers, on its own databases next to your production database. This page covers turning it on for a self-hosted instance. It is off by default.

## Turning it on

Set one setting and restart:

| Deployment | Setting |
| --- | --- |
| Docker Compose | `DD_SANDBOX_ENABLED=true` |
| Kubernetes (Helm) | `sandbox.enabled: true` |

On its next start, DefectDojo's initializer creates the sandbox's databases and database roles, loads the sample data, checks that the sandbox and production cannot reach each other's data, and only then shows the **Production/Sandbox** switch. The first start takes a few minutes longer while the sandbox databases are built; later starts take seconds.

Optionally, set `DD_SANDBOX_PERSONA_PASSWORD` (Helm: `sandbox.personaPassword`) to let people sign in to the sandbox as the reader, writer and owner personas.

## Requirements

DefectDojo's database user needs two attributes to create the sandbox:

* `CREATEROLE`, to create the sandbox's two login roles;
* `CREATEDB`, so the sandbox's admin role can create and reset the sandbox databases.

The database user of a new Docker Compose installation with the bundled database has both. On a managed database (Amazon RDS, Google Cloud SQL, Azure Database for PostgreSQL), the administrator user the provider creates has both; a user created with SQL may not. To check, connect as DefectDojo's database user and run:

```sql
SELECT rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user;
```

If either is false, either have a database administrator grant them:

```sql
ALTER ROLE <DefectDojo database user> CREATEROLE CREATEDB;
```

or set `DD_SANDBOX_PROVISION_URL` (Helm: `sandbox.provisionUrl`) to a connection URL for a role that has them. DefectDojo then creates the sandbox with that role and uses its own user for everything else.

## What it creates

Everything is named after your production database, so several installations sharing one PostgreSQL server never collide. For a production database named `dojodb`:

| Object | Name | Purpose |
| --- | --- | --- |
| Database | `dojodb_sandbox` | The live sandbox |
| Database | `dojodb_sandbox_tpl_empty` | Template for **Wipe Sandbox** |
| Database | `dojodb_sandbox_tpl_seeded` | Template for **Reset Sample Data** |
| Role | `dojodb_sandbox` | What the sandbox connects as; it can reach only the sandbox databases |
| Role | `dojodb_sandbox_admin` | Owns the three sandbox databases, to reset them |

Both roles' passwords are derived from `DD_SECRET_KEY`, so there is nothing to generate or store. Each role carries a comment naming the production database it belongs to, and DefectDojo never changes a role that was created for a different database.

At rest the three databases take a few hundred megabytes. What people add to the sandbox counts against the same license capacity as production, so the sandbox can never grow past what your license allows. Files uploaded in the sandbox are kept under `sandbox/` in the media directory.

## How the two are kept apart

* Production's database user cannot connect to the sandbox databases.
* The sandbox roles cannot read anything in the production database. When DefectDojo's database user owns the production database, the sandbox roles cannot even connect to it.
* Every start ends with a check that tries each direction and refuses to show the sandbox if any of them is open.

## When the switch does not appear

If the sandbox is on but no switch appears, the initializer could not prepare it. Production is never affected: a sandbox failure is reported and the start continues. Look for `Sandbox preparation failed` in the initializer's output:

```bash
# Docker Compose
docker compose logs init | grep -i sandbox
# Kubernetes
kubectl logs -n <namespace> -l app.kubernetes.io/component=initializer --tail=-1 | grep -i sandbox
```

The message names the cause, most often a missing `CREATEROLE` or `CREATEDB`. Fix it and restart; the switch appears once the next start succeeds.

## Backups and offboarding

The sandbox databases are separate from your production database. A backup of the production database alone does not include the sandbox; back up the `_sandbox` databases too if you want to keep sandbox work. An offboarding export contains production's data only.

## Turning it off and removing it

Set `DD_SANDBOX_ENABLED=false` (Helm: `sandbox.enabled: false`) and restart. The switch disappears and `/sandbox/` stops answering. The sandbox databases and roles stay, so turning it back on restores the sandbox as it was.

To remove them, connect as DefectDojo's database user (or an administrator) and run, with your database name:

```sql
DROP DATABASE dojodb_sandbox WITH (FORCE);
ALTER DATABASE dojodb_sandbox_tpl_empty IS_TEMPLATE false;
DROP DATABASE dojodb_sandbox_tpl_empty;
ALTER DATABASE dojodb_sandbox_tpl_seeded IS_TEMPLATE false;
DROP DATABASE dojodb_sandbox_tpl_seeded;
DROP ROLE dojodb_sandbox_admin;
DROP ROLE dojodb_sandbox;
```

## Settings reference

Only `DD_SANDBOX_ENABLED` is needed. The rest override defaults.

| Setting | Helm value | Default | Meaning |
| --- | --- | --- | --- |
| `DD_SANDBOX_ENABLED` | `sandbox.enabled` | `false` | Turns the sandbox on. |
| `DD_SANDBOX_URL_PREFIX` | `sandbox.urlPrefix` | `sandbox` | The URL segment the sandbox is served under. |
| `DD_SANDBOX_PERSONA_PASSWORD` | `sandbox.personaPassword` | empty | Password of the reader, writer and owner personas. Empty: personas cannot sign in. |
| `DD_SANDBOX_PROVISION_URL` | `sandbox.provisionUrl` | empty | A role to create the sandbox with instead of DefectDojo's own database user. |
| `DD_SANDBOX_DATABASE_URL` | `sandbox.databaseUrl` | derived | Use your own role and database for the sandbox instead of the derived ones. |
| `DD_SANDBOX_ADMIN_DATABASE_URL` | `sandbox.adminDatabaseUrl` | derived | Use your own admin role (connected to the `postgres` maintenance database) instead of the derived one. |

With Helm, `sandbox.existingSecret` names a Secret holding any of the last four instead of setting them inline.
