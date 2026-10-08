---
title: "Sending Logs to Support (Docker Compose)"
description: "Collect a support bundle of container logs from the DefectDojo Pro UI and email it to DefectDojo support"
draft: false
weight: 6
audience: pro
---

When DefectDojo support asks for logs, a superuser can collect them from the DefectDojo Pro UI and email them to support, without signing in to the server. This works on a self-hosted deployment that runs on Docker Compose with `dojo-compose-cli`. It is not available on DefectDojo Cloud, where support can read the logs directly, or on a Kubernetes (Helm) deployment, where the page does not appear.

## What a support bundle contains

A support bundle is the same archive that `dojo-compose-cli diagnostics collect` builds on the server:

- the logs of every DefectDojo container for the selected period (see below), with timestamps
- the container list (`docker ps -a`), the image versions and Docker disk usage
- the status of the DefectDojo systemd service and its recent journal
- the deployment settings, with passwords, keys and tokens masked
- the `dojo-compose-cli` configuration and versions, and listings of the install directory

## Collecting and sending a bundle

1. Sign in as a superuser and open **Settings > License & Support > Support Bundle**.
2. Under **Logs From**, choose how far back to collect: **Last Hour**, **Last 24 Hours** (the default), **Last 7 Days** or **All Available**. Pick a period that covers when the problem happened.
3. Select **Collect Logs**. The bundle is listed as **Queued**, then **Collecting**, then **Ready**. Collection usually takes a minute or two; **All Available** on a busy server can take longer.
4. Open the menu on the bundle's row:
   - **Email to Support** sends the archive to `support@defectdojo.com` through this instance's email settings. Add a note describing the problem, or a ticket number. Support replies to the email address on your user account.
   - **Download** saves the archive (`.tar.gz`) so it can be attached to a ticket by hand.

### How much log a bundle holds

Container logs are kept newest first, up to 50 MB per container and 250 MB for all containers together. When a log is larger, its oldest lines are left out, and the bundle's row says how many logs were cut. A container that wrote nothing during the period contributes its last 200 lines instead. Each bundle includes `full-logs/MANIFEST.txt`, which lists what was collected from every container.

Before collecting, the server checks its free disk space. If space is short it collects less per container, and if there is not enough even for that, the bundle fails with a message saying how much space is free.

Bundles are emailed only when they are 15 MB or smaller, because larger attachments are often refused by mail servers. Download a larger bundle and send it another way.

### Setting up email

**Email to Support** sends through the same mail server DefectDojo uses for notifications, so if notification emails already arrive, there is nothing to set up. Otherwise the page says what is missing and links to it:

1. **A mail server.** Enter it under **Settings > System > Email** (host, port, user, password, and TLS or SSL), then select **Test Connection** there. If **Email Settings** is empty, DefectDojo falls back to the `DD_EMAIL_URL` environment variable (`dojo-compose-cli environment add --key DD_EMAIL_URL ...`, then `dojo-compose-cli app restart`).
2. **A sender address.** Set **Email From** under **Settings > System > System Settings**. Use an address the mail server is allowed to send as; many servers reject any other.

The **Delivery** panel on the Support Bundle page names the mail server in use and has its own **Test Connection** button, which signs in to that server without sending anything. If the server refuses, its reply is shown.

**Google Workspace and Gmail:** with 2-Step Verification on, Google refuses the account password over SMTP. Create an App Password at https://myaccount.google.com/apppasswords and use it as the Email Settings password, with host `smtp.gmail.com`, port `587` and TLS. Alternatively, a Workspace administrator can allow this server's IP address on `smtp-relay.gmail.com`. **Microsoft 365** needs SMTP AUTH enabled for the mailbox, or an app password when multi-factor authentication is on.

If this network does not allow outbound email, use **Download** and attach the bundle to a support ticket instead.

## How it works

The logs belong to Docker on the server, which no DefectDojo container can read. So collection runs on the server itself:

- `dojo-compose-cli` installs two systemd units, `dojo-support-bundle.path` and `dojo-support-bundle.service`, when DefectDojo is installed or started.
- Selecting **Collect Logs** writes a request file to `<install directory>/support-bundles/requests/` (by default `/opt/dojo/support-bundles`). That directory is mounted into the DefectDojo application containers and never into nginx, so a bundle is only served to a signed-in superuser.
- The path unit sees the request and runs `dojo-compose-cli diagnostics fulfil-requests`, which collects the bundle into `support-bundles/bundles/`.
- The server keeps the five most recent bundles and deletes older ones.

## Container log retention

Docker keeps container logs in its `json-file` format with no size limit by default, so they grow until the disk fills. When Docker uses that default, `dojo-compose-cli` limits each DefectDojo container to five log files of 100 MB, which it writes to `docker-compose.logging.yml` in the install directory and applies the next time DefectDojo starts. Your own `docker-compose.override.yml`, if you have one, is still applied.

The limit is not added when the Docker daemon uses a different log driver (for example `syslog` or `journald`), or when `/etc/docker/daemon.json` already sets `max-size`, because those settings already decide where logs go and how much is kept.

## Troubleshooting

**The page says the host collector is not installed.** The installed `dojo-compose-cli` predates this feature, or systemd is not available. Upgrade `dojo-compose-cli`, then restart DefectDojo (`sudo dojo-compose-cli app restart`), which installs the units. Until then, run `dojo-compose-cli diagnostics collect --since 24h` on the server and send the archive it writes. `--since` takes `1h`, `24h`, `7d` or `all`.

**A bundle stays Queued.** The path unit is not running. On the server, check it with:

```bash
systemctl status dojo-support-bundle.path
journalctl -u dojo-support-bundle.service
```

**A bundle failed.** The error from the server is shown under the bundle's status. The service journal above has the full output.

**A bundle failed for lack of disk space.** Free space on the disk that holds the install directory, then collect again.

**An email was not sent.** The error from the mail server is shown in the **Email to Support** column. Fix the mail server under **Settings > System > Email**, check it with **Test Connection** in the **Delivery** panel, then select **Email to Support** again. A message that the server refused the sign-in usually means the password is wrong or the provider needs an app password (see **Setting up email** above).
