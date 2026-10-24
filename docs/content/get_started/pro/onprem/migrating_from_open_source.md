---
title: "Migrating from Open Source to Self-Hosted DefectDojo Pro"
description: "Move your open source DefectDojo data into a self-hosted DefectDojo Pro deployment, with a database dump or with the DefectDojo connector"
draft: false
weight: 3
audience: pro
---

This page describes two ways to move data from an open source DefectDojo instance into self-hosted DefectDojo Pro:

* **The database dump.** You export the database and the media files, and restore them into an empty Pro deployment. The result is an exact copy.
* **The DefectDojo connector.** DefectDojo Pro pulls the open source instance over its export API, from the Connectors UI. You run it as often as you need, until you cut over.

Because you host the deployment, your data stays inside your own environment for the whole migration. DefectDojo support can assist at any step. If DefectDojo hosts your Pro instance in the cloud, follow [Migrating from Open Source to DefectDojo Cloud](/get_started/pro/cloud/migrating_from_open_source/) instead. The DefectDojo team performs the restore for you there.

## Which path

| | Database dump | DefectDojo connector |
| --- | --- | --- |
| What moves | An exact copy of the database and the media files | Product Types, Products, engagements, tests, findings and their related data |
| Source version | Any 2.x release, or 3.0.200 and later | 3.4.300 and later |
| Target | An empty Pro deployment. The restore replaces what is there. | A Pro instance, with or without data in it |
| Who runs it | You, from a restore host with the PostgreSQL client tools | You, from the Connectors UI |
| How often | Once per cutover, in a scheduled window | As often as you need, until you cut over |
| Secrets, settings and history | Cross with the dump | Do not cross |
| Users | Cross, with passwords, groups and roles | Cross as inactive accounts, without passwords or roles. Users join no group, except the default group when their email matches its pattern. |
| The source during the move | Frozen with read-only mode from the final dump | Keeps running until the final Sync, then frozen with read-only mode |

Take the dump path if you want an exact copy, and you can schedule a window. Users, groups, settings and history come across as they are. The target must be empty.

Take the connector path to move Products over time, or into a Pro instance that already holds data. You set it up yourself in the Connectors UI, and you run it again until the cutover. The open source instance keeps running meanwhile. Secrets, instance settings and history do not cross with the connector. You set up SSO, notifications and tool credentials in DefectDojo Pro yourself.

## Path 1: The database dump

The examples use Amazon Web Services, with either Docker Compose on EC2 or Kubernetes on EKS, and the database on Amazon RDS for PostgreSQL. That is the combination this procedure was validated against. The same sequence applies to other providers that offer managed PostgreSQL and equivalent compute, and to on-premise hardware, with the provider-specific commands changed to suit.

You run the export and the restore, and DefectDojo support can assist at any step.

At a high level, you export the database and the media files from the open source instance, restore them into the database and the storage your Pro deployment uses, point Pro at the restored database, and then validate the result.

Running on Kubernetes? The [Kubernetes Migration Runbook & Troubleshooting](/get_started/pro/onprem/kubernetes/migration_runbook/) turns this into a validated, end-to-end Helm sequence, with an error-keyed troubleshooting index and a post-migration verification checklist.

### Before you start

Confirm the following before you export anything.

Your database engine. DefectDojo supports PostgreSQL. MySQL support was deprecated and then [removed in 2.37.0](/releases/os_upgrading/2.37/), so an older instance still running on MySQL has to be converted to PostgreSQL before it can be migrated. Contact support if this applies to you.

Where your database runs. It may be a container from the default Docker Compose setup, or a separate service on the same host, on another VM, or on a managed service such as Amazon RDS or Cloud SQL. The export command differs depending on which of the two it is.

Your open source version. Find it in the UI footer, or from your deployment tags and image versions. All 2.x releases can be migrated with this procedure. If you are running 3.0.0, 3.0.1, 3.0.2, or 3.0.100, upgrade to [3.0.200](/releases/os_upgrading/3.0.200/) or later before you begin. Review the [upgrade notes](/releases/os_upgrading/upgrading_guide/) for every version between your current version and the version you upgrade to.

Version alignment. Your open source version should match, or be as close as possible to, the DefectDojo Pro version you are migrating to. On first start, Pro runs the database migrations that bring the schema up to its own version, so a large version gap increases the risk of a long or failed migration. Align the versions before you take the dump.

Your target database. Provision a currently supported PostgreSQL major version, 16 or newer, and never older than the version your open source instance runs, because a dump cannot be restored into an older major version. On AWS, place the RDS instance in the same VPC as your Pro compute and allow inbound traffic on port 5432 from the host you restore from.

Your restore host. You need a machine in the same network as the database, with the PostgreSQL client tools `pg_restore` and `psql` installed. On AWS, use an EC2 instance in the same VPC, ideally in the same Availability Zone as the RDS instance.

Free disk space. The source server needs room for the database dump and the compressed media archive before you move them.

Your encryption keys. Record the `DD_CREDENTIAL_AES_256_KEY` and `DD_SECRET_KEY` values your open source instance runs with, and give Pro the same ones in Step 6. Tool Configuration credentials are encrypted with the credential key, and a Pro instance with a different key cannot read them.

### Step 1: Export your database

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

### Step 2: Export your media files

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

### Step 3: Name your files

Put your open source version in both filenames so the version in play is unambiguous during the restore. For an instance running 2.38.1:

| File | Renamed to |
| --- | --- |
| `defectdojo-backup.dump` | `defectdojo-v2.38.1-backup.dump` |
| `defectdojo_media.tar.gz` | `defectdojo-v2.38.1-media.tar.gz` |

Move both files to your restore host. You can copy them directly with a tool such as `scp`, or stage them in private object storage in your own account and pull them down to the restore host. On AWS that means a private S3 bucket and `aws s3 cp`. Either way the data stays inside your own environment.

### Step 4: Restore the database

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

3. Turn off read-only mode in the restored database. If you turned on read-only mode before the dump (see [Planning the cutover](#planning-the-cutover)), the restored copy is locked too. Clear the setting before you start DefectDojo Pro:

```bash
psql -h <db-endpoint> -U <master_user> -d defectdojo \
  -c "UPDATE dojo_system_settings SET read_only_mode = false;"
```

If the restore reports errors, capture the output and contact support before you strip anything further out of the dump. Removing too much can leave the database in an inconsistent state that is harder to diagnose than the original error.

### Step 5: Restore your media files

Put the contents of the media archive where your Pro deployment reads uploaded files from. The application looks for them at `/app/media`, which your deployment backs with either a bind mount or a persistent volume. Check the installation documentation supplied with your license for the host path or volume your deployment uses.

{{< tabs "migrate-media-restore" >}}
{{< tab "Kubernetes" >}}
Extract the archive locally and copy it into the Django pod, which writes to the persistent volume claim mounted at `/app/media`:

```bash
kubectl cp ./media-extracted/. <namespace>/<django-pod-name>:/app/media/
```
{{< /tab >}}
{{< tab "Compose" >}}
For a deployment backed by a named volume:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine sh -c "tar xzf /backup/defectdojo-v<VERSION>-media.tar.gz -C /media"
```
{{< /tab >}}
{{< /tabs >}}

### Step 6: Point DefectDojo Pro at the restored database

Update the database connection so Pro uses the database you just restored, then start the application. On first start, Pro runs the database migrations that upgrade the schema from your open source version to the Pro version. Depending on the size of your database and the size of the version gap, this can take a while, and the application is not available until it finishes.

{{< tabs "migrate-db-url" >}}
{{< tab "Kubernetes" >}}
Set the database connection and both keys in your Helm values and redeploy:

```yaml
database:
  host: <db-endpoint>
  port: "5432"
  name: defectdojo
  user: defectdojo
  password: <app_db_password>   # or database.existingSecret
dojo:
  secretKey: <DD_SECRET_KEY from open source>
  credentialAES256Key: <DD_CREDENTIAL_AES_256_KEY from open source>
```

The [Kubernetes Migration Runbook](/get_started/pro/onprem/kubernetes/migration_runbook/) covers this step in more detail.
{{< /tab >}}
{{< tab "Compose" >}}
Set the database URL and both keys in the CLI's configuration, then start the stack:

```bash
sudo -E dojo-compose-cli environment add -k DD_DATABASE_URL -v 'postgres://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo'
sudo -E dojo-compose-cli environment add -k DD_SECRET_KEY -v '<DD_SECRET_KEY from open source>'
sudo -E dojo-compose-cli environment add -k DD_CREDENTIAL_AES_256_KEY -v '<DD_CREDENTIAL_AES_256_KEY from open source>'
sudo -E dojo-compose-cli app start
```
{{< /tab >}}
{{< /tabs >}}

Which Pro capabilities are available to your deployment depends on your license and on how you deploy, since some of them are not applicable to a self-hosted install. DefectDojo confirms the set that applies to you during the migration.

### Step 7: Validate your data

Once the application is running against the restored database:

1. Log in to your DefectDojo Pro deployment.
2. Check that your Assets, Organizations, Engagements, Tests, and Findings are present. In older open source versions, Assets and Organizations were called Products and Product Types.
3. Download a representative uploaded file from the UI, for example an attachment on a Finding, Test, or Engagement, to confirm the media restore worked.
4. Check that user accounts and groups are intact. SSO and other authentication settings usually have to be reconfigured for the new deployment.
5. Report any discrepancies to your DefectDojo contact.

### Planning the cutover

The dump is a point-in-time snapshot, so anything created in the open source instance after you take it will not be in the Pro deployment. To avoid losing data, turn on read-only mode in the open source instance before the final dump. Read-only mode is available in DefectDojo 3.5.0 and later.

1. Go to **Configuration > System Settings**, select **Read-only mode**, and click **Submit**.
2. Wait until **Configuration > Celery Status** shows no queued tasks. Then run `celery --app=dojo inspect active` in the Celery worker container, and wait until it reports `empty` for every worker. Tasks that started before the lock still write until they finish.
3. Take the final dump. The dump keeps read-only mode turned on, so turn it off in the restored database (Step 4).

While read-only mode is on, DefectDojo rejects every change from the UI and the API, and pauses scheduled background jobs. Superusers can still sign in and change System Settings. To turn it off, clear **Read-only mode** and click **Submit**.

On a version without read-only mode, stop all writes by hand for the final dump: pause CI pipelines, scheduled imports, and anything else that pushes findings. Or run the migration during a quiet period.

A dry run is worth the time. Migrate a recent copy first, validate it, and then repeat the process for the real cutover. The second run is faster, and it tells you how long the schema migration in Step 6 is going to take.

### Migration checklist

- Database engine, database location, and open source version identified
- Open source version aligned with the target Pro version
- Target PostgreSQL provisioned, reachable from a restore host with the PostgreSQL client tools
- Read-only mode turned on in the open source instance, with no Celery task queued or running
- Database exported, with a custom-format dump if possible
- Media directory located and compressed
- Both files named with the open source version
- Database and application role created on the target
- Dump restored, with restore output reviewed for errors
- Read-only mode turned off in the restored database
- Media files restored to the path or volume your deployment uses
- Pro pointed at the restored database and started, with schema migrations complete
- Data validated in the new deployment

## Path 2: The DefectDojo connector

The DefectDojo connector pulls the open source instance into DefectDojo Pro over the source's [export API](/automation/api/product_export/). It runs from the Connectors UI, like every other [Upstream Connector](/connectors/upstream/about/), and its tile is **Source DefectDojo**. It reads the source and changes nothing on it. The [Source DefectDojo connector reference](/connectors/toolreference/defectdojo/) lists every option, what crosses and what does not.

The connector ships in a coming DefectDojo Pro release.

### Before you start

Confirm the following before you add the connector.

* **The open source version.** Upgrade the open source instance to 3.4.300 or later. That release added the export API. The connector refuses an older source.
* **HTTPS.** Serve the open source instance over HTTPS, on a URL your Pro deployment can reach. The connector refuses a plain `http://` URL.
* **A superuser API key.** Create a superuser on the source for the connector alone, and an API v2 key for it. The export API answers only a superuser. Revoke the key after the cutover.
* **What does not cross.** Secrets and settings stay on the source: SSO, JIRA, tool configurations, notifications, API tokens, passwords and system settings. So do history, JIRA issue links, groups and roles. Files over the size limit stay too. Duplicates stay, unless you ask for them. Plan to set up SSO, notifications and tool credentials in DefectDojo Pro yourself.
* **The owner fields.** The product manager, technical contact and team manager of a Product become members of the Product in DefectDojo Pro. The three fields stay empty.

### Step 1: Add the connector

1. In the Pro UI, open **Connect > Upstream**.
2. Click **Add Configuration** on the **Source DefectDojo** tile.
3. Enter the URL of the source in **Location URL** and the superuser API key in **API Token**.
4. Keep the other defaults, or change them. The [connector reference](/connectors/toolreference/defectdojo/#connector-mappings) explains each field.
5. Turn on **Enable Auto-Mapping**. Each source Product then gets a Product of the same name, under a Product Type of the same name. Do not skip this: mapping a Record by hand cannot create a Product.
6. Click **Submit**. DefectDojo Pro checks the key and the version of the source, and tells you if either check fails.

The [Add or Edit Upstream Connectors](/connectors/upstream/add_edit/) page covers the shared parts of the form: the schedule and the label.

### Step 2: Discover and map

Run [Discover](/connectors/upstream/manage_operations/#discover-operations). The connector creates one Record per Product on the source. With Auto-Mapping on, every Record is mapped at once. Without it, you can map a Record by hand only to a Product that already exists in DefectDojo Pro. Ignore a Record on the [Records page](/connectors/upstream/manage_records/) to leave that Product on the source.

Discover also fills the **Migration Preflight** card with the [preflight report](/connectors/toolreference/defectdojo/#the-preflight-report). The card opens folded. Click **View Details** to see the rest, and **Hide Details** to fold it again. Read it before the first Sync:

* **Warnings** lists the scan types that DefectDojo Pro has no parser for. Their findings go to a test of type `DefectDojo - Connectors Import`.
* **Counts** shows the totals. **View Details** adds the counts of each Product. Keep them to check the result of the Sync.
* **To Be Created** (after **View Details**) lists the users and the reference data that the Sync creates.
* **Not Migrated** (after **View Details**) lists the settings that you set up in DefectDojo Pro yourself.
* **Estimated Duration** tells you how long the first Sync takes.

### Step 3: Sync

Run [Sync](/connectors/upstream/manage_operations/#sync-operations). The first run imports every mapped Product: its engagements, its tests and its findings. The findings bring their notes, files, endpoints and metadata. Risk acceptances and finding groups come too. The run also creates the users and the reference data they refer to. A large estate takes a while. The [Operations page](/connectors/upstream/manage_operations/) shows each run.

The operation shows **Success** when the connector has sent the data. DefectDojo Pro then imports the findings in the background, which goes on for some minutes on a large Product. Before you validate, check the finding count of each Product against the preflight report. The [connector reference](/connectors/toolreference/defectdojo/#check-the-finding-count-after-a-sync) explains which findings it leaves out.

### Step 4: Validate your data

Compare the two instances once the first Sync ends:

1. Check that every Product Type and every Product you mapped is present, with its description and tags. The owners of each source Product are members of it, with the Maintainer role.
2. Open a Product and check its engagements and tests, with their names and dates.
3. Open one finding of each scan type. Check its fields, its notes, its files and its endpoints. A scan type that the preflight report listed as unknown is in a test of type `DefectDojo - Connectors Import`.
4. Check the risk acceptances and the finding groups of a Product that has them.
5. Check that the users are present. They arrive inactive, with no usable password, and none of them is a superuser. Activate the accounts you need, give them roles, and set up SSO. A migrated user does not use a license seat until it is activated or it logs in.
6. Report any discrepancies to your DefectDojo contact.

### Step 5: Repeat until you cut over

Run Sync on the schedule you set, or by hand. Each run updates what changed on the source. It makes no copies: a finding keeps its identity through its source id and its hash. A finding that the source deleted from a test closes in DefectDojo Pro: it is marked mitigated, not deleted. A run with no change on the source changes nothing in Pro.

On cutover day, turn on read-only mode in the open source instance before the final Sync. The connector only reads, so it keeps working while the source is read-only.

Read-only mode is available in DefectDojo 3.5.0 and later. On 3.4.300, stop all writes by hand before the final Sync: pause CI pipelines, scheduled imports, and anything else that pushes findings.

1. Go to **Configuration > System Settings**, select **Read-only mode**, and click **Submit**.
2. Wait until **Configuration > Celery Status** shows no queued tasks. Then run `celery --app=dojo inspect active` in the Celery worker container, and wait until it reports `empty` for every worker. Tasks that started before the lock still write until they finish.
3. Run one last Sync. Check the finding counts as in Step 3, and validate the result.
4. Point CI jobs, scripts, and integrations at your Pro deployment's `/api/v2/` API. Automate against `/api/v2/` only. Paths under `/api/vue/` belong to the Pro UI and reject API tokens.
5. Retire the open source instance. If you keep it running, revoke the superuser API key first. Read-only mode blocks that change, so turn it off, revoke the key, and turn it on again.

While read-only mode is on, DefectDojo rejects every change from the UI and the API, and pauses scheduled background jobs. Superusers can still sign in and change System Settings. To turn it off, clear **Read-only mode** and click **Submit**.

The open source instance keeps running until that day, so your team loses no working time.

### Connector checklist

- Open source instance on 3.4.300 or later, served over HTTPS
- Superuser created on the source for the connector, with an API v2 key
- Connector added in **Connect > Upstream**, with Auto-Mapping on
- Discover run, with every Record mapped or ignored
- Preflight report read: warnings, counts, what is created and what does not cross
- First Sync run, finding counts checked, and validated
- SSO, notifications and tool credentials set up in DefectDojo Pro
- Users activated and given roles
- Read-only mode turned on in the source, with no Celery task queued or running
- Final Sync run, finding counts checked, and validated
- Automation pointed at the Pro deployment, and the source retired or its key revoked

## Questions or support

DefectDojo supports both paths end to end. For help at any step, contact your account representative or [support@defectdojo.com](mailto:support@defectdojo.com).
