---
title: "Backing Up a Self-Hosted Deployment"
description: "The four things to capture, where each one lives for Compose and Kubernetes deployments, and how to confirm a backup can actually be restored"
draft: false
weight: 11
audience: pro
---

A deployment is more than its database. A backup that captures only the database restores into a system that runs but is missing uploaded files and cannot decrypt the credentials it holds for your other tools. This page covers what to capture, where each piece lives, and how to confirm the result is restorable.

## The four things to capture

The database holds your organizations, assets, engagements, tests, findings, users, and configuration.

Uploaded files live outside the database. Screenshots, threat models, risk acceptance documents, and similar attachments are on a filesystem, and the database only holds paths to them.

Deployment configuration is what makes the application come back up the same way, including your own customizations and TLS certificates.

The encryption keys are the piece most often missed. The credential encryption key is what makes stored credentials for your connected tools readable. Restore a database without it and those credentials are intact but undecryptable, which means every integration has to be re-entered by hand.

## The database

Most self-hosted deployments point at a managed PostgreSQL service, which is the chart's default and the recommended setup. In that case use the provider's own automated backups and point-in-time recovery rather than rolling your own. Two things are worth checking rather than assuming: that automated backups are actually enabled on the instance, since a managed database with backups switched off has none, and that the retention window matches what your organization requires.

Where you run PostgreSQL yourself, take a compressed custom-format dump:

```bash
pg_dump -h <db_host> -U <db_user> -Fc <db_name> > defectdojo-$(date +%F).dump
```

Restore it with `pg_restore`, using `--no-owner` and `--no-privileges` if the target has different roles than the source:

```bash
pg_restore -v --no-owner --no-privileges -h <db_host> -U <db_user> -d <db_name> defectdojo-<date>.dump
```

Take the dump on a schedule, store it off the machine that produced it, and keep enough generations to survive a problem you do not notice immediately.

## Uploaded files

On a Docker Compose deployment, uploaded files are in the `media` directory inside your deployment directory on the host. Back that path up with your normal filesystem backup. If you have moved it onto separate storage, back up that filesystem rather than the mount point.

On Kubernetes, the media volume is provisioned according to the storage backend you configured, and where the data physically lives determines how you protect it:

| Storage backend | Where the data lives | How to protect it |
| --- | --- | --- |
| `efs` | An Amazon EFS filesystem | AWS Backup |
| `filestore` | A Google Filestore instance | Filestore backups |
| `gcsfuse` | A Cloud Storage bucket | Bucket versioning, or a scheduled copy to another bucket |
| `nfs` | Your NFS server | Whatever protects that server |
| `pvc` | A volume from your storage class | A CSI volume snapshot, if your driver supports them |

The chart provisions the volume, it does not protect the contents. There is no snapshot schedule built into it, so the backup has to come from the platform or from your own tooling.

## Configuration and keys

On Compose, capture your `customizations` directory, your `certs` directory, and the CLI's stored configuration and environment values. `config print` and `environment print` will show you what is set.

On Kubernetes, capture your values files and the contents of the secrets your release references.

In both cases, keep the credential encryption key and the secret key somewhere durable and separate, in a secret manager rather than alongside the backup. Anyone holding both the database and the credential key can read the credentials for every tool you have connected, so they should not travel together.

## What is not a backup

The chart annotates its persistent volume claims so they survive `helm uninstall`, which is on by default. That is a guard against an accidental uninstall, not a backup. It does nothing for corruption, for a deletion inside the application, or for an upgrade that goes badly, because in every one of those cases the volume survives and the damage is on it.

Snapshots retained only in the same account or project as the deployment are similarly weaker than they look. Whatever can delete the deployment can usually delete those too.

## Confirming a backup is restorable

A backup nobody has restored is an assumption. Test it into a scratch environment rather than over the top of production, and check the following:

1. Log in, and confirm your organizations, assets, engagements, tests, and findings are present in the numbers you expect.
2. Open a finding with an attachment and download it. This is what proves the media restore worked, since the database alone would show the attachment listed but fail to serve it.
3. Open a configured tool connection and confirm its credentials are intact. This is what proves you restored the credential encryption key correctly, and it is the check most likely to reveal a gap.
4. Confirm users and groups came across. Authentication settings such as SSO usually need reconfiguring for a different environment, so treat differences there as expected rather than as a failed restore.

Run this drill on a schedule rather than only when you need it. Doing a restore for the first time during an incident is where backup plans usually fail.

## Questions or support

For help planning backups for your deployment, or if a restore does not come up as expected, contact [support@defectdojo.com](mailto:support@defectdojo.com).
