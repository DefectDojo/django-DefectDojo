---
title: "Restoring a Self-Hosted Deployment"
description: "Bring a backed-up DefectDojo Pro deployment back on the same host or a new one: configuration and keys, both databases, uploaded files, and the same pinned version, for Docker Compose and Kubernetes"
draft: false
weight: 5
audience: pro
---

This page is the other half of [Backing Up a Self-Hosted Deployment](/get_started/pro/onprem/backing_up/). It walks through putting a deployment back from those backups, onto the host it came from or onto a new one.

A restore puts back the same four things a backup captures: the configuration and encryption keys, the databases, the uploaded files, and the application itself at the version that wrote the data. Restore all four, then check the result with the [restore checklist](/get_started/pro/onprem/backing_up/#confirming-a-backup-is-restorable) before anyone relies on it.

## Before you start

**Restore the version you backed up.** The database schema belongs to the version that wrote it. Bringing a backup up on a newer version runs that version's migrations against it, which makes the restore an upgrade as well. Restore onto the original version first, confirm it works, then upgrade as a separate step.

**There are two databases.** Alongside the main database (`dojodb` by default), the orchestrator keeps its state in a second one with `-ddorch` added to the name, for example `dojodb-ddorch`. Back up and restore both. If the second one is missing, the orchestrator creates an empty one at startup and the state of background work from before the backup is lost.

**Restore the keys with the database.** Encrypted credentials only decrypt with the keys that encrypted them. Connector and integration credentials use `DD_SECRET_KEY`, and Tool Configuration credentials use `DD_CREDENTIAL_AES_256_KEY`. A mismatch fails quietly rather than with an error, which is why it gets its own entry under [Common problems](#common-problems).

## Docker Compose

These steps assume a backup taken as described in [Backing Up a Self-Hosted Deployment](/get_started/pro/onprem/backing_up/), which leaves you with:

| File | What it holds |
| --- | --- |
| `etc-defectdojo.tar.gz` | `/etc/defectdojo/compose.config` (the encrypted CLI configuration, including both encryption keys), `/etc/defectdojo/dojopro.lic`, and the systemd unit `/etc/systemd/system/defectdojo-compose.service` |
| `opt-dojo.tar.gz` | `/opt/dojo`, including uploaded files in `media`, your `customizations`, and your `certs` |
| `dojodb.dump`, `dojodb-ddorch.dump` | Custom-format dumps of the two databases |

You also need the `DOJO_CLI_KEY` value that encrypted `compose.config`. Without it the configuration cannot be read, and there is no way to recover it. If you still have the systemd unit, the key is in it as `Environment=DOJO_CLI_KEY=...`.

Commands below run as root. Export the key for the session and pass it through `sudo` with `-E`:

```bash
export DOJO_CLI_KEY="your-key"
```

If you are restoring onto the same host and its files are intact, skip to [step 4](#4-restore-the-databases).

### 1. Prepare the host

On a new host, install Docker Engine with the compose plugin and put `dojo-compose-cli` at `/usr/bin/dojo-compose-cli`. Use the CLI version the old host ran if you can; `dojo-compose-cli --version` shows it.

Do not run `first-install`. On an empty host it generates new encryption keys that do not match your database, and on a host whose configuration you have already restored it stops with `first-install can only be run on a fresh setup`.

### 2. Restore the configuration and files

```bash
sudo tar -xzpf etc-defectdojo.tar.gz -C /
sudo tar -xzpf opt-dojo.tar.gz -C /
sudo systemctl daemon-reload
sudo systemctl enable defectdojo-compose
```

Enable the service but do not start it yet. The `dojosrv` user does not have to exist on the new host: the CLI creates it and fixes ownership of these files when the application starts.

Confirm the key works and check which version the configuration pins:

```bash
sudo -E dojo-compose-cli config print
```

The output should show `Initialized : true` and a `DefectDojo Version` such as `3.3.200`. A `message authentication failed` error means `DOJO_CLI_KEY` is not the one that encrypted this configuration.

If the version reads `latest`, set it to the version the backup came from before you go further, otherwise the next step fetches whatever is newest:

```bash
sudo -E dojo-compose-cli config set --version <x.y.z>
```

### 3. Pull that version's images

```bash
sudo -E dojo-compose-cli app pull-images
```

This also unpacks that version's deployment files into `/opt/v<x.y.z>-dojo`, beside `/opt/dojo`. Your restored files in `/opt/dojo` are left as they are.

### 4. Restore the databases

{{< tabs "restore-compose-db" >}}
{{< tab "containerized-db" >}}
With the `containerized-db` deployment type, PostgreSQL keeps its data in the Docker volume `dojo_defectdojo_data`, which is not part of `/opt/dojo`. Let the CLI create the database server first, then replace its contents with your dumps.

On a new host, start the application once. It comes up with an empty database:

```bash
sudo -E dojo-compose-cli app start
```

Stop every container that uses the database, leaving `postgres` and `redis` running:

```bash
sudo docker ps --format '{{.Names}}' | grep -v -x -E 'postgres|redis' | xargs sudo docker stop
```

Replace both databases and restore the dumps:

```bash
sudo docker exec postgres psql -U postgres -v ON_ERROR_STOP=1 \
  -c 'DROP DATABASE dojodb WITH (FORCE)' -c 'DROP DATABASE "dojodb-ddorch" WITH (FORCE)' \
  -c 'CREATE DATABASE dojodb OWNER dbusr' -c 'CREATE DATABASE "dojodb-ddorch" OWNER dbusr'
sudo docker exec -i postgres pg_restore -U dbusr -d dojodb --no-owner --no-privileges --exit-on-error < dojodb.dump
sudo docker exec -i postgres pg_restore -U dbusr -d dojodb-ddorch --no-owner --no-privileges --exit-on-error < dojodb-ddorch.dump
```

`dbusr` and `dojodb` are the defaults for this deployment type. If you set your own `DD_DATABASE_URL`, use its user and database name.

Do not start PostgreSQL on its own with `docker compose up postgres`. Run that way, it misses the settings the CLI normally passes in, skips the script that creates the DefectDojo role and database, and leaves you with an empty server.
{{< /tab >}}
{{< tab "separate-db" >}}
With the `separate-db` deployment type, restore onto your database server before you start the application. Create both databases owned by the application's user, then restore into them:

```bash
createdb -h <db_host> -U postgres -O <db_user> dojodb
createdb -h <db_host> -U postgres -O <db_user> dojodb-ddorch
pg_restore -h <db_host> -U <db_user> -d dojodb --no-owner --no-privileges --exit-on-error dojodb.dump
pg_restore -h <db_host> -U <db_user> -d dojodb-ddorch --no-owner --no-privileges --exit-on-error dojodb-ddorch.dump
```

If the database now has a different name, or lives on a different server, point the application at it. The orchestrator's database name follows the main one, so restore it as `<new_name>-ddorch`:

```bash
sudo -E dojo-compose-cli environment add -k DD_DATABASE_URL -v 'postgres://<db_user>:<password>@<db_host>:5432/<new_name>'
```

If your backup came from the `dojo-db-backup` tool, it is a gzipped plain SQL dump of the main database only. Create the database first and name it with `-d`. Without `-d`, `psql` loads every table into the `postgres` database and still reports success:

```bash
gunzip defectdojo-db_<timestamp>.sql.gz
createdb -h <db_host> -U postgres -O <db_user> dojodb
psql -h <db_host> -U <db_user> -d dojodb -v ON_ERROR_STOP=1 -f defectdojo-db_<timestamp>.sql
```

That tool does not back up the `-ddorch` database, so restore that from a `pg_dump` of its own.
{{< /tab >}}
{{< /tabs >}}

### 5. Start and check

```bash
sudo -E dojo-compose-cli app start
```

Use `app start` rather than `app restart`. `app restart` only works on a running stack, and stops with `the instance of DefectDojo is not running` otherwise.

Confirm the deployed version matches the configuration:

```bash
sudo -E dojo-compose-cli validate deploy-version
```

Then work through the [restore checklist](/get_started/pro/onprem/backing_up/#confirming-a-backup-is-restorable).

## Kubernetes

These steps assume an external PostgreSQL database, which is the chart's default. The chart's bundled PostgreSQL is intended for development only. From the backup you need:

| File | What it holds |
| --- | --- |
| `values.yaml` | The output of `helm get values`. If you set secrets inline, it includes `dojo.secretKey` and `dojo.credentialAES256Key`. |
| `secrets.yaml` | The Secrets your release references but Helm does not create, such as TLS certificates, image pull secrets, and any `existingSecret` holding the keys, the license, or the database password |
| The chart version | From `helm get metadata`, for example `3.3.200` |
| `dojodb.dump`, `dojodb-ddorch.dump` | Custom-format dumps of the two databases, unless you restore through your database provider |
| `media.tar.gz` | Uploaded files, unless your storage backend has its own backups |

Restore into a namespace with the same name as the original. The internal TLS certificates name the namespace in their SANs, so a different namespace also means issuing new internal certificates, as described in the installation guide.

### 1. Recreate the namespace and Secrets

```bash
kubectl create namespace <namespace>
kubectl apply -n <namespace> -f secrets.yaml
```

### 2. Restore the databases

Restore the databases before you install the chart. The initializer then finds a schema that is already current and applies nothing.

With a managed service, restore both databases through the provider's point-in-time recovery or snapshot restore. From dumps, create both databases owned by the application's user, then restore into them. The client pods below follow the same pattern as the installation guide's connectivity check:

```bash
kubectl run psql-create --rm -i --restart=Never --image=postgres:16 -n <namespace> \
  --env="PGPASSWORD=<admin-password>" -- \
  psql -h <db_host> -U <admin_user> -v ON_ERROR_STOP=1 \
  -c 'CREATE DATABASE dojodb OWNER <db_user>' -c 'CREATE DATABASE "dojodb-ddorch" OWNER <db_user>'
kubectl run pg-restore --rm -i --restart=Never --image=postgres:16 -n <namespace> \
  --env="PGPASSWORD=<db-password>" -- \
  pg_restore -h <db_host> -U <db_user> -d dojodb --no-owner --no-privileges --exit-on-error < dojodb.dump
kubectl run pg-restore-ddorch --rm -i --restart=Never --image=postgres:16 -n <namespace> \
  --env="PGPASSWORD=<db-password>" -- \
  pg_restore -h <db_host> -U <db_user> -d dojodb-ddorch --no-owner --no-privileges --exit-on-error < dojodb-ddorch.dump
```

### 3. Install the same chart version

Install the version the backup came from, with the saved values:

```bash
helm install dojopro oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version <chart-version> -n <namespace> -f values.yaml
```

If the database has a new host, name, or password, override `database.host`, `database.name`, `database.user`, and `database.password` (or `database.existingSecret`) on the same command or in `values.yaml`.

Check that the initializer job completed and that it found nothing to migrate:

```bash
kubectl get job -n <namespace> -l app.kubernetes.io/component=initializer
kubectl logs -n <namespace> -l app.kubernetes.io/component=initializer -c initializer | grep -A1 "Operations to perform"
```

`No migrations to apply` confirms the database and the chart version match. If the log shows migrations being applied, the chart is newer than the version that wrote the backup.

### 4. Restore uploaded files

If your storage backend has its own backups (EFS, Filestore, Cloud Storage, S3, or NFS), restore from those, using the same storage settings as before. From a `media.tar.gz` taken as described in [Backing Up a Self-Hosted Deployment](/get_started/pro/onprem/backing_up/#uploaded-files), stream it back into the application container once it is running:

```bash
kubectl rollout status -n <namespace> deploy/dojopro-django
kubectl exec -i -n <namespace> deploy/dojopro-django -c uwsgi -- tar -xzf - -C /app/media < media.tar.gz
```

### 5. Check the result

Work through the [restore checklist](/get_started/pro/onprem/backing_up/#confirming-a-backup-is-restorable). `helm get metadata dojopro -n <namespace>` should show the chart version you meant to restore.

## Common problems

**Connector or integration credentials are blank, with no error.** `DD_SECRET_KEY` is not the one they were encrypted with. They decrypt to nothing rather than failing, so the connector looks unconfigured. Tool Configuration credentials are unaffected. The stored values are intact: put the original key back and restart, and they read correctly again.

**Tool Configuration credentials do not work.** `DD_CREDENTIAL_AES_256_KEY` does not match. As above, the data is intact and the original key fixes it.

**`message authentication failed` from `dojo-compose-cli`.** `DOJO_CLI_KEY` is not the key that encrypted `/etc/defectdojo/compose.config`.

**`first-install can only be run on a fresh setup`.** The restored configuration is already initialized. That is expected: skip `first-install` and follow the steps above.

**`the instance of DefectDojo is not running` from `app restart`.** Use `app start`.

**The database restored, but DefectDojo sees an empty database.** A plain SQL restore without `-d` loaded the tables into the `postgres` database. Create `dojodb` and restore into it with `-d dojodb`.

**The initializer applies migrations during a restore.** The chart or configured version is newer than the version the backup came from. On Kubernetes, install the chart version from `helm get metadata`. On Compose, set it with `config set --version`.

**`tar: .: Cannot change mode ... Operation not permitted` while restoring media on Kubernetes.** The archive includes an entry for the media directory itself, which the application container cannot change. The files are still extracted. Archives made with `cd /app/media && tar -czf - *` do not have that entry.

## Questions or support

If a restore does not come up as expected, `dojo-compose-cli diagnostics collect` on Compose gathers a report bundle. Send it, or the output of the step that failed, to [support@defectdojo.com](mailto:support@defectdojo.com).
