---
title: "Backing Up a Self-Hosted Deployment"
description: "The four things to capture, where each one lives for Compose and Kubernetes deployments, and how to confirm a backup can actually be restored"
draft: false
weight: 4
audience: pro
---

A deployment is more than its database. A backup that captures only the database restores into a system that runs but is missing uploaded files and cannot decrypt the connection credentials that are stored encrypted. This page covers what to capture, where each piece lives, and how to confirm the result is restorable.

## The four things to capture

The database holds your organizations, assets, engagements, tests, findings, users, and configuration.

Uploaded files live outside the database. Screenshots, threat models, risk acceptance documents, and similar attachments are on a filesystem, and the database only holds paths to them.

Deployment configuration is what makes the application come back up the same way, including your own customizations and TLS certificates.

The encryption keys are the piece most often missed. Connector credentials are encrypted with the secret key, and Tool Configuration credentials with the credential encryption key. Restore a database without the matching key and those credentials are intact but undecryptable, which means the affected integrations have to be re-entered by hand.

Not every integration credential is encrypted. Some are stored as entered, so treat a database backup as carrying secrets in its own right, whether or not you also hold the keys. Protect it accordingly, and rotate the credentials of any integration whose backup you cannot account for.

## The database

Most self-hosted deployments point at a managed PostgreSQL service, which is the chart's default and the recommended setup. In that case use the provider's own automated backups and point-in-time recovery rather than rolling your own. Two things are worth checking rather than assuming: that automated backups are actually enabled on the instance, since a managed database with backups switched off has none, and that the retention window matches what your organization requires.

There are two databases to capture. Alongside the main database (`dojodb` by default), the orchestrator keeps its state in a second one named after it with `-ddorch` appended, for example `dojodb-ddorch`. A managed service's instance-level backups cover both. A dump has to name each one.

Where you run PostgreSQL yourself, take a compressed custom-format dump of each:

{{< tabs "backup-db" >}}
{{< tab "Kubernetes" >}}
From any host that can reach the database server:

```bash
pg_dump -h <db_host> -U <db_user> -Fc dojodb > dojodb.dump
pg_dump -h <db_host> -U <db_user> -Fc dojodb-ddorch > dojodb-ddorch.dump
```

With the chart's bundled PostgreSQL, which is intended for development only, dump from its pod:

```bash
kubectl exec -n <namespace> dojopro-postgresql-0 -- pg_dump -U dojodbusr -Fc dojodb > dojodb.dump
kubectl exec -n <namespace> dojopro-postgresql-0 -- pg_dump -U dojodbusr -Fc dojodb-ddorch > dojodb-ddorch.dump
```
{{< /tab >}}
{{< tab "Compose" >}}
With the `containerized-db` deployment type, PostgreSQL runs in the `postgres` container:

```bash
sudo docker exec postgres pg_dump -U dbusr -Fc dojodb > dojodb.dump
sudo docker exec postgres pg_dump -U dbusr -Fc dojodb-ddorch > dojodb-ddorch.dump
```

`dbusr` and `dojodb` are that deployment type's defaults. With `separate-db`, dump from your database server using the user and database in `DD_DATABASE_URL`:

```bash
pg_dump -h <db_host> -U <db_user> -Fc dojodb > dojodb.dump
pg_dump -h <db_host> -U <db_user> -Fc dojodb-ddorch > dojodb-ddorch.dump
```

The `dojo-db-backup` tool dumps the main database only, so if you use it, dump the `-ddorch` database alongside it.
{{< /tab >}}
{{< /tabs >}}

Take the dumps on a schedule, store them off the machine that produced them, and keep enough generations to survive a problem you do not notice immediately. [Restoring a Self-Hosted Deployment](/get_started/pro/onprem/restoring/) covers putting them back.

## Uploaded files

{{< tabs "backup-media" >}}
{{< tab "Kubernetes" >}}
The media volume is provisioned according to the storage backend you configured, and where the data physically lives determines how you protect it:

| Storage backend | Where the data lives | How to protect it |
| --- | --- | --- |
| `efs` | An Amazon EFS filesystem | AWS Backup |
| `filestore` | A Google Filestore instance | Filestore backups |
| `gcsfuse` | A Cloud Storage bucket | Bucket versioning, or a scheduled copy to another bucket |
| `nfs` | Your NFS server | Whatever protects that server |
| `pvc` | A volume from your storage class | A CSI volume snapshot, if your driver supports them |
| `s3` | An Amazon S3 bucket, under the configured prefix | Bucket versioning, AWS Backup, or replication to another bucket |

The chart provisions the volume, it does not protect the contents. There is no snapshot schedule built into it, so the backup has to come from the platform or from your own tooling.

For a `pvc` volume without snapshot support, or as a second copy, stream the files out of the application container:

```bash
kubectl exec -n <namespace> deploy/dojopro-django -c uwsgi -- sh -c 'cd /app/media && tar -czf - *' > media.tar.gz
```

Archive the contents with `*` as shown rather than `.`. An archive that includes the directory itself makes the restore stop with a permissions error on the volume's root.
{{< /tab >}}
{{< tab "Compose" >}}
Uploaded files are in `/opt/dojo/media`, so the archive of `/opt/dojo` described under [Configuration and keys](#configuration-and-keys) includes them. If you have moved `media` onto separate storage, back up that filesystem as well, since an archive of the mount point does not capture it.
{{< /tab >}}
{{< /tabs >}}

## Configuration and keys

{{< tabs "backup-config" >}}
{{< tab "Kubernetes" >}}
Save the values the release was installed with, and note the chart version, since a restore should install that same version:

```bash
helm get values dojopro -n <namespace> -o yaml > values.yaml
helm get metadata dojopro -n <namespace>
```

If you set `dojo.secretKey` and `dojo.credentialAES256Key` inline, `values.yaml` contains both keys, so store it the way you store the keys.

Export the Secrets your release references that Helm does not create: the internal and ingress TLS certificates, any image pull secret, and every `existingSecret` you point the chart at, such as `dojo.existingSecret`, `license.existingSecret`, and `database.existingSecret`. `kubectl get secret -n <namespace>` lists them.

```bash
kubectl get secret -n <namespace> <secret-name> [<secret-name> ...] -o yaml > secrets.yaml
```

These can be applied as they are to a recreated namespace of the same name.
{{< /tab >}}
{{< tab "Compose" >}}
Two archives cover everything outside the database. The first is the deployment directory, which holds uploaded files, your `customizations`, and your `certs`:

```bash
sudo tar -czf opt-dojo.tar.gz -C / opt/dojo
```

The second is the CLI's configuration, the license, and the systemd unit:

```bash
sudo tar -czf etc-defectdojo.tar.gz -C / etc/defectdojo etc/systemd/system/defectdojo-compose.service
```

`/etc/defectdojo/compose.config` holds both encryption keys and the database connection string, encrypted with your `DOJO_CLI_KEY`. The systemd unit holds `DOJO_CLI_KEY` itself, in plain text. Between them, that second archive can decrypt every encrypted credential in the database, so store it the way you store the keys rather than next to the database dumps. Keep a separate record of `DOJO_CLI_KEY` as well. Without it the configuration cannot be read, and there is no way to recover it.

Check that the configuration pins a specific version, so a restore brings back the version that wrote the data:

```bash
sudo -E dojo-compose-cli config print -f version
```

If it reads `latest`, set the version you are running with `dojo-compose-cli config set --version <x.y.z>`.
{{< /tab >}}
{{< /tabs >}}

In both cases, keep the credential encryption key and the secret key somewhere durable and separate, in a secret manager rather than alongside the backup. Anyone holding both the database and those keys can read every stored credential that is encrypted, so they should not travel together. Keys and backup travelling separately narrows the exposure of a lost backup; it does not eliminate it, because the backup still holds the credentials that are not encrypted.

## What is not a backup

{{< tabs "backup-not-a-backup" >}}
{{< tab "Kubernetes" >}}
The chart annotates its persistent volume claims so they survive `helm uninstall`, which is on by default. That is a guard against an accidental uninstall, not a backup. It does nothing for corruption, for a deletion inside the application, or for an upgrade that goes badly, because in every one of those cases the volume survives and the damage is on it.
{{< /tab >}}
{{< tab "Compose" >}}
The `media` directory staying on the host after `dojo-compose-cli app stop` is not a backup either. Stopping the stack leaves the files in place, but corruption, a deletion inside the application, or an upgrade that goes badly all land on that same directory.
{{< /tab >}}
{{< /tabs >}}

Snapshots retained only in the same account or project as the deployment are similarly weaker than they look. Whatever can delete the deployment can usually delete those too.

## Confirming a backup is restorable

A backup nobody has restored is an assumption. Test it into a scratch environment rather than over the top of production, and check the following:

1. Log in, and confirm your organizations, assets, engagements, tests, and findings are present in the numbers you expect.
2. Open a finding with an attachment and download it. This is what proves the media restore worked, since the database alone would show the attachment listed but fail to serve it.
3. Open a configured connector and a configured Tool Configuration, and confirm the credentials on each are intact. Between them these cover both keys, and this is the check most likely to reveal a gap.
4. Confirm users and groups came across. Authentication settings such as SSO usually need reconfiguring for a different environment, so treat differences there as expected rather than as a failed restore.

Run this drill on a schedule rather than only when you need it. Doing a restore for the first time during an incident is where backup plans usually fail.

## Questions or support

For help planning backups for your deployment, or if a restore does not come up as expected, contact [support@defectdojo.com](mailto:support@defectdojo.com).
