---
title: "Migrating from Open Source to Self-Hosted DefectDojo Pro"
description: "Move your open source DefectDojo database and media files into a self-hosted DefectDojo Pro deployment"
draft: false
weight: 5
audience: pro
---

This page describes how to move the data from an open source DefectDojo instance into a self-hosted DefectDojo Pro deployment.

The examples use Amazon Web Services, with either Docker Compose on EC2 or Kubernetes on EKS, and the database on Amazon RDS for PostgreSQL. That is the combination this procedure was validated against. The same sequence applies to other providers that offer managed PostgreSQL and equivalent compute, and to on-premise hardware, with the provider-specific commands changed to suit.

Because you host the deployment, your data stays inside your own environment for the whole migration. You run the export and the restore, and DefectDojo support can assist at any step. If your DefectDojo Pro instance is cloud-hosted by DefectDojo rather than self-hosted, contact [support@defectdojo.com](mailto:support@defectdojo.com) instead, because the DefectDojo team performs the restore for you.

At a high level, you export the database and the media files from the open source instance, restore them into the database and the storage your Pro deployment uses, point Pro at the restored database, and then validate the result.

## Before you start

Confirm the following before you export anything.

Your database engine. DefectDojo supports PostgreSQL. MySQL support was deprecated and then [removed in 2.37.0](/releases/os_upgrading/2.37/), so an older instance still running on MySQL has to be converted to PostgreSQL before it can be migrated. Contact support if this applies to you.

Where your database runs. It may be a container from the default Docker Compose setup, or a separate service on the same host, on another VM, or on a managed service such as Amazon RDS or Cloud SQL. The export command differs depending on which of the two it is.

Your open source version. Find it in the UI footer, or from your deployment tags and image versions. All 2.x releases can be migrated with this procedure. If you are running 3.0.0, 3.0.1, 3.0.2, or 3.0.100, upgrade to [3.0.200](/releases/os_upgrading/3.0.200/) or later before you begin. Review the [upgrade notes](/releases/os_upgrading/upgrading_guide/) for every version between your current version and the version you upgrade to.

Version alignment. Your open source version should match, or be as close as possible to, the DefectDojo Pro version you are migrating to. On first start, Pro runs the database migrations that bring the schema up to its own version, so a large version gap increases the risk of a long or failed migration. Align the versions before you take the dump.

Your target database. Provision a currently supported PostgreSQL major version, 16 or newer, and never older than the version your open source instance runs, because a dump cannot be restored into an older major version. On AWS, place the RDS instance in the same VPC as your Pro compute and allow inbound traffic on port 5432 from the host you restore from.

Your restore host. You need a machine in the same network as the database, with the PostgreSQL client tools `pg_restore` and `psql` installed. On AWS, use an EC2 instance in the same VPC, ideally in the same Availability Zone as the RDS instance.

Free disk space. The source server needs room for the database dump and the compressed media archive before you move them.

## Step 1: Export your database

The default Docker Compose configuration uses `defectdojo` as both the database username and the database name. These can be overridden, so check the `DD_DATABASE_URL` value in your `docker-compose.yml` or `.env` file. The default connection string is:

```text
postgresql://defectdojo:defectdojo@postgres:5432/defectdojo
```

In the commands below, replace `<db_username>`, `<database_name>`, and `<postgres_container_name>` with your own values. Find the container name with `docker ps`.

A compressed custom-format dump is recommended. `pg_restore` can load it directly, and it avoids most of the ownership and role problems that come up during a restore into a managed database.

For a containerized PostgreSQL, which is the default Docker Compose setup:

```bash
docker exec <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

If the database requires a password, pass it in the environment:

```bash
docker exec -e PGPASSWORD='your_password' <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

For an external or remote PostgreSQL, such as a separate VM, Amazon RDS, or Cloud SQL:

```bash
pg_dump -h <remote_ip_or_hostname> -p 5432 \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

A plain text SQL dump, produced by omitting `-Fc`, also works. It tends to embed `CREATE ROLE`, `ALTER ROLE`, and `CREATE DATABASE` statements that a managed database will reject, so see the note in Step 4 if you use one.

## Step 2: Export your media files

DefectDojo stores uploaded artifacts such as screenshots, threat models, and risk acceptance documents in a media directory. Scan files used for import and reimport are not kept on disk by open source DefectDojo, since they are discarded once parsed, so the media directory holds only user-uploaded artifacts.

The location of the directory depends on how you deployed:

| Deployment method | Typical media path |
| --- | --- |
| Docker Compose | Named volume `defectdojo_media`, mounted at `/app/media` |
| Bare metal | `/opt/dojo/media`, or the path set in `DD_MEDIA_ROOT` |
| Kubernetes | Persistent volume mounted at `/app/media` |

Compress the directory into a single archive. From a named volume:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine tar czf /backup/defectdojo_media.tar.gz -C /media .
```

From a path on disk:

```bash
tar czf defectdojo_media.tar.gz -C /opt/dojo/media .
```

## Step 3: Name your files

Put your open source version in both filenames so the version in play is unambiguous during the restore. For an instance running 2.38.1:

| File | Renamed to |
| --- | --- |
| `defectdojo-backup.dump` | `defectdojo-v2.38.1-backup.dump` |
| `defectdojo_media.tar.gz` | `defectdojo-v2.38.1-media.tar.gz` |

Move both files to your restore host. You can copy them directly with a tool such as `scp`, or stage them in private object storage in your own account and pull them down to the restore host. On AWS that means a private S3 bucket and `aws s3 cp`. Either way the data stays inside your own environment.

## Step 4: Restore the database

Run the restore from your restore host, pointed at the database endpoint. Managed PostgreSQL services differ in what they support here. Amazon RDS has no one-step import of a dump file from a bucket, so a client-side `pg_restore` is the supported path.

1. Create the database and the application role. Connect as your master user and create the target database and the role the dump expects. The defaults are `defectdojo` for both, so use your own values if you overrode them.

```sql
CREATE ROLE defectdojo WITH LOGIN PASSWORD '<app_db_password>';
CREATE DATABASE defectdojo OWNER defectdojo;
```

2. Restore the dump. For a custom-format dump, use `--no-owner` and `--no-privileges` so the restore does not try to reassign ownership to roles that do not exist on the target. A managed database does not grant a true superuser, so a restore that tries to do this will fail.

```bash
pg_restore -v --no-owner --no-privileges \
  -h <db-endpoint> -U <master_user> -d defectdojo \
  -j 2 defectdojo-v<VERSION>-backup.dump
```

For a plain text SQL dump, first comment out or remove any `CREATE ROLE`, `ALTER ROLE`, `CREATE DATABASE`, and `ALTER DATABASE ... OWNER` statements, then load it:

```bash
gunzip -c defectdojo-v<VERSION>-backup.sql.gz | \
  psql -h <db-endpoint> -U <master_user> -d defectdojo
```

If the restore reports errors, capture the output and contact support before you strip anything further out of the dump. Removing too much can leave the database in an inconsistent state that is harder to diagnose than the original error.

## Step 5: Restore your media files

Put the contents of the media archive where your Pro deployment reads uploaded files from. The application looks for them at `/app/media`, which your deployment backs with either a bind mount or a persistent volume. Check the installation documentation supplied with your license for the host path or volume your deployment uses.

For a Docker Compose deployment backed by a named volume:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine sh -c "tar xzf /backup/defectdojo-v<VERSION>-media.tar.gz -C /media"
```

For a Kubernetes deployment, extract the archive locally and copy it into the Django pod, which writes to the persistent volume claim mounted at `/app/media`:

```bash
kubectl cp ./media-extracted/. <namespace>/<django-pod-name>:/app/media/
```

## Step 6: Point DefectDojo Pro at the restored database

Update the database connection so Pro uses the database you just restored, then start the application. On first start, Pro runs the database migrations that upgrade the schema from your open source version to the Pro version. Depending on the size of your database and the size of the version gap, this can take a while, and the application is not available until it finishes.

For Docker Compose deployments, set the database URL in your deployment configuration and restart the stack. The exact configuration key and command depend on the version of `dojo-compose-cli` you were supplied, so follow the installation documentation that came with your license. The connection string takes this form:

```text
postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

For Kubernetes deployments, set the database URL in your Helm values and redeploy:

```yaml
databaseUrl: postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

Which Pro capabilities are available to your deployment depends on your license and on how you deploy, since some of them are not applicable to a self-hosted install. DefectDojo confirms the set that applies to you during the migration.

## Step 7: Validate your data

Once the application is running against the restored database:

1. Log in to your DefectDojo Pro deployment.
2. Check that your Assets, Organizations, Engagements, Tests, and Findings are present. Assets and Organizations were called Products and Product Types in open source.
3. Download a representative uploaded file from the UI, for example an attachment on a Finding, Test, or Engagement, to confirm the media restore worked.
4. Check that user accounts and groups are intact. SSO and other authentication settings usually have to be reconfigured for the new deployment.
5. Report any discrepancies to your DefectDojo contact.

## Planning the cutover

The dump is a point-in-time snapshot, so anything created in the open source instance after you take it will not be in the Pro deployment. To avoid losing data, freeze the open source instance for the final dump and cutover, or run the migration during a quiet period.

A dry run is worth the time. Migrate a recent copy first, validate it, and then repeat the process for the real cutover. The second run is faster, and it tells you how long the schema migration in Step 6 is going to take.

## Migration checklist

- Database engine, database location, and open source version identified
- Open source version aligned with the target Pro version
- Target PostgreSQL provisioned, reachable from a restore host with the PostgreSQL client tools
- Database exported, with a custom-format dump if possible
- Media directory located and compressed
- Both files named with the open source version
- Database and application role created on the target
- Dump restored, with restore output reviewed for errors
- Media files restored to the path or volume your deployment uses
- Pro pointed at the restored database and started, with schema migrations complete
- Data validated in the new deployment

## Questions or support

DefectDojo supports this migration end to end. For help at any step, contact your account representative or [support@defectdojo.com](mailto:support@defectdojo.com).
