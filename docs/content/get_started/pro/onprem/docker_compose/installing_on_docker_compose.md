---
title: "Installing on Docker Compose"
description: "Install self-hosted DefectDojo Pro on a single host using dojo-compose-cli, with PostgreSQL on a separate server"
draft: false
weight: 1
audience: pro
aliases:
  - /get_started/pro/onprem/installing_on_docker_compose/
---

This page covers installing DefectDojo Pro on Docker Compose, which is the simpler of the two self-hosted models and the right choice if you are not already running Kubernetes.

The result is two hosts. One runs the application and its supporting services under Docker Compose, and one runs PostgreSQL. You can point at a managed database instead of running your own, and for evaluation you can run the database in a container on the application host, though that is not what you want for production data.

Almost all of the work is done by `dojo-compose-cli`, which DefectDojo provides alongside your license. Its `first-install` command is an interactive wizard that configures the deployment, pulls the images, starts everything, and registers a systemd service.

## Before you start

Size the deployment first. The hardware sizing guidance in this section covers what to provision for both the application host and the database.

Ubuntu 24.04 LTS is the supported operating system for this installation. The installation runs commands as root, so you need `sudo` or a root shell on both hosts.

Update both hosts fully before you begin, and reboot if the update asks for it:

```bash
sudo apt update
sudo apt -y full-upgrade
[ -f /var/run/reboot-required ] && sudo reboot
```

You will need two files from DefectDojo, which arrive with your subscription: the `dojo-compose-cli` archive and your license file, usually named `dojopro.lic`. Contact your account representative or [support@defectdojo.com](mailto:support@defectdojo.com) if you do not have them.

## Set up the database

DefectDojo Pro requires PostgreSQL 16 or newer.

### Using a managed database

If you are using a managed PostgreSQL service, follow that provider's documentation to create the instance, then create the following:

- A database named `dojodb`
- A database user named `dojodbusr`, holding all privileges on `dojodb`, and set as its owner

Note the hostname, the port if it is not the default 5432, and the credentials. You need them during the install.

### Running PostgreSQL yourself

On Ubuntu 24.04, PostgreSQL 16 is in the default repositories:

```bash
sudo apt update
sudo apt -y install postgresql postgresql-contrib
```

Create the databases and the application user. DefectDojo uses a second database for its orchestration service, so create both. Open a `psql` session as the `postgres` superuser:

```bash
sudo -u postgres psql
```

Then run:

```sql
CREATE USER dojodbusr;
CREATE DATABASE dojodb;
CREATE DATABASE "dojodb-ddorch";
ALTER USER dojodbusr WITH ENCRYPTED PASSWORD '<strong-password>';
GRANT ALL PRIVILEGES ON DATABASE dojodb TO dojodbusr;
GRANT ALL PRIVILEGES ON DATABASE "dojodb-ddorch" TO dojodbusr;
ALTER DATABASE dojodb OWNER TO dojodbusr;
ALTER DATABASE "dojodb-ddorch" OWNER TO dojodbusr;
```

Use an alphanumeric password. Special characters have to be URL encoded later, when the password goes into a connection string, and that is an easy step to get wrong.

Then let the database listen for connections from the application host. In `/etc/postgresql/16/main/postgresql.conf`, set `listen_addresses` to the database server's own address, or to `*` if you would rather not pin it:

```bash
listen_addresses = '<db-server-address>'
```

And in `/etc/postgresql/16/main/pg_hba.conf`, add three lines authorizing the application host. Restricting to the application host's address is better than opening it to everything:

```text
host  dojodb         dojodbusr  <app-server-address>/32  scram-sha-256
host  dojodb-ddorch  dojodbusr  <app-server-address>/32  scram-sha-256
host  postgres       dojodbusr  <app-server-address>/32  scram-sha-256
```

Restart for both changes to take effect:

```bash
sudo systemctl restart postgresql
```

PostgreSQL's stock settings are sized for a small machine. Before you load real data, raise the memory and connection settings to match the host, following [Tuning the database](/get_started/pro/onprem/hardware_sizing/#tuning-the-database) on the Hardware Sizing page.

## Prepare the application host

### Outbound connectivity

In a restricted network, the application host needs outbound access to the following. All are HTTPS on port 443 unless noted.

| Destination | Purpose | Required |
| --- | --- | --- |
| `us-south1-docker.pkg.dev` | The DefectDojo Pro container registry | Yes |
| Your database host, usually port 5432 | Application to database | Yes |
| Your distribution's package repositories | Operating system dependencies during setup | Yes |
| `download.docker.com` | Docker Engine packages during setup | Yes |
| `api.first.org` | EPSS exploit prediction scores | Optional |
| `www.cisa.gov` | The KEV catalog of known exploited vulnerabilities | Optional |

Allowlist by hostname rather than by address. The registry sits behind a content delivery network, so its addresses vary by location and change over time.

If the host reaches the internet through an outbound proxy, see [Running DefectDojo Behind a Forward HTTPS Proxy](/get_started/pro/onprem/forward_proxy/). If it has no route to the internet at all, follow the air-gapped installation procedure in this section instead.

### Inbound access

Users only need to reach the application host on ports 80 and 443, which nginx serves. Allow those from your users' networks and nothing else.

The stack also publishes two internal ports on the host: `9142` for the MCP server and `9871` for the orchestration service. From release 3.3.300 they are bound to `127.0.0.1`, so other hosts cannot reach them. On earlier releases they are published on every interface of the host; unless you have a reason to reach them from elsewhere, block them from outside the host.

Do this at your network firewall or security group, or in the `DOCKER-USER` iptables chain on the host. A host firewall such as `ufw` is not enough on its own: Docker writes its own rules for published ports, and those rules take effect ahead of `ufw`, so a `ufw deny` does not close a port Docker has published. See Docker's [packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/) documentation for how to add rules to `DOCKER-USER`.

### Confirm the database is reachable

Install the client tools and connect before going any further. A database problem is much easier to diagnose now than in the middle of the install:

```bash
sudo apt update
sudo apt -y install postgresql-client-common postgresql-client-16
psql -h <db-host> -p 5432 -d dojodb -U dojodbusr -W
```

### Install Docker Engine

Follow the [Docker Engine installation instructions for Ubuntu](https://docs.docker.com/engine/install/ubuntu/). Use Docker's own documentation rather than a copy, since the steps change over time. Install the `docker-compose-plugin` package along with the engine, which those instructions include by default.

Then add your user to the `docker` group and pick up the new membership:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker info
```

## Install DefectDojo

Copy the CLI archive and your license file to the application host, into the same directory.

Check the archive before you extract it. Each CLI release comes with a `checksums.txt` file listing the SHA-256 of every archive. With both files in the same directory:

```bash
sha256sum --check --ignore-missing checksums.txt
```

The archive's line should end in `OK`. If you received the archive without `checksums.txt`, ask [support@defectdojo.com](mailto:support@defectdojo.com) for the expected checksum and compare it with the output of `sha256sum dojo-compose-cli_*.tar.gz`.

Then extract the CLI:

```bash
tar -xzvf dojo-compose-cli_*.tar.gz
```

Choose a `DOJO_CLI_KEY` before you start. It is the encryption key for the configuration the CLI stores on disk, and every later command needs it, so store it somewhere safe. Export it in your shell and run the installer with `sudo -E`, which passes the variable through `sudo`:

```bash
export DOJO_CLI_KEY="<your-key>"
sudo -E ./dojo-compose-cli first-install
```

If the variable is not set, the installer asks for the key instead.

The wizard prompts for the following.

| Prompt | What it is |
| --- | --- |
| DefectDojo Version | The release to install. The default is `latest`. Enter a specific release from the [DefectDojo Pro changelog](/releases/pro/changelog/) instead, so that you know exactly what you are running and upgrade on your own schedule. The deployment files follow this version automatically. |
| Deploy Type | `separate-db` for a database on its own host, or `containerized-db` to run PostgreSQL in a container. |
| Database Connection Type | Choose Single Line and supply the whole connection string. |
| Database URL | `postgres://<user>:<password>@<host>:5432/dojodb`. It must begin with `postgres://` rather than `postgresql://`. |
| `DD_ALLOWED_HOSTS` | Host headers the application will answer to. The default is `*`, which accepts any host name. Enter the host name users browse to instead. |
| `DD_SITE_URL` | The full URL where users reach DefectDojo, for example `https://defectdojo.internal.example.com`. The default is `http://localhost`, which only suits a test on the host itself, so replace it. |

Two things worth knowing at the prompts. Supply the database connection as a single line rather than value by value, since the per-value path does not currently ask for the username. And if the password contains characters like `!`, `@`, or `#`, URL encode them in the connection string.

The installer then pulls the images, starts the stack, creates a systemd service, and prints the generated admin credentials. **Save those credentials before you close the terminal. They are not shown again.** If the printed password does not let you log in, or you lose it, set a new one with `sudo -E dojo-compose-cli app change-password` (see [Reset the admin password](#reset-the-admin-password)).

Once it finishes, DefectDojo is available at the site URL you gave it.

The first start is the slow part. Before the application comes up, the `init` container creates the whole database schema. Allow about 30 minutes on the smallest Compose host in the [sizing table](/get_started/pro/onprem/hardware_sizing/#sizing-table); larger hosts may be faster. `dojo-compose-cli` 2.1.x can stop waiting before that and report a failure while the initializer is still working. If that happens, do not run `first-install` again. Follow [First install reports a failure while the initializer is still running](#first-install-reports-a-failure-while-the-initializer-is-still-running) instead.

## What the installation created

| Item | Location |
| --- | --- |
| CLI binary | `/usr/bin/dojo-compose-cli` |
| Application files, compose file, nginx config, media | `/opt/dojo/` |
| License file | `/etc/defectdojo/dojopro.lic` |
| Encrypted CLI configuration | `/etc/defectdojo/compose.config` |
| TLS certificates | `/opt/dojo/certs/` |
| Your customizations | `/opt/dojo/customizations/` |
| Systemd service | `/etc/systemd/system/defectdojo-compose.service` |

It also creates a `dojosrv` user and group, which own the application's files.

As of release 3.4.0, the running stack is these containers:

| Container | What it runs |
| --- | --- |
| `nginx` | The web server, on ports 80 and 443 |
| `dojo` | The Django application |
| `dojo-import-scan` | Scan imports, separate from the web application |
| `celeryworker`, `celerybeat` | The Celery worker and scheduler |
| `redis` | Valkey, for caching and queueing |
| `connectors`, `integrators` | The connectors and integrators services |
| `ddorch`, `ddorch-workers` | The orchestration service and its workers |
| `mcp-server` | The MCP server |
| `webhook-gateway` | Receives inbound webhooks |
| `sensei-engine` | The Sensei engine |
| `init` | Applies database migrations at each start, then exits |

With the `containerized-db` deployment type there is also a `postgres` container. `docker ps -a` lists them all, including `init` after it has exited.

Day to day, these are the commands you need:

```bash
systemctl status defectdojo-compose
sudo -E dojo-compose-cli app start
sudo -E dojo-compose-cli app stop
sudo -E dojo-compose-cli app restart
docker logs dojo
```

Use `app restart` after changing any configuration, since it recreates the containers so new values are picked up.

## Replace the TLS certificate

The installation ships a placeholder certificate so that nginx can start. It is issued for a different hostname than yours, so browsers will reject it until you replace it with a certificate for your own hostname. Do this before users start logging in.

Replace it by overwriting two files, keeping the names exactly as they are:

- `/opt/dojo/certs/dojo.crt`, your certificate followed by any intermediate certificates, in PEM format
- `/opt/dojo/certs/dojo.key`, the matching private key, in PEM format and without a passphrase

The nginx container runs as user ID 1002 with group 0 (`root`), not as `dojosrv`, so it reads the key through its group. Give the key group `root` and make it group-readable. A key owned by `dojosrv:dojosrv` with mode `0640` is unreadable to nginx, and nginx will not start:

```bash
sudo chown dojosrv:root /opt/dojo/certs/dojo.crt /opt/dojo/certs/dojo.key
sudo chmod 0644 /opt/dojo/certs/dojo.crt
sudo chmod 0640 /opt/dojo/certs/dojo.key
```

Then restart to pick them up, and confirm nginx came back:

```bash
sudo -E dojo-compose-cli app restart
docker ps --filter name=nginx
curl -sSI https://<your-hostname>/
```

`docker ps` should show the nginx container as `Up` rather than `Restarting`, and `curl` should complete the TLS handshake without a certificate error. If nginx is restarting, `docker logs nginx` usually names the file it could not read.

## Trusting an internal or private CA

If DefectDojo has to reach services whose TLS certificates are signed by an internal or private certificate authority (CA), the containers need to trust that CA first. This is common with a self-hosted Jira, an internal SSO or identity provider, SonarQube, or a security tool reached through a Connector. It is a separate concern from [replacing the server certificate](#replace-the-tls-certificate) above: that controls the certificate DefectDojo presents to browsers, whereas this controls which CAs DefectDojo trusts on its outbound calls.

You set the trust by placing PEM-encoded CA bundles in the `certs/private/` directory under the install directory, which is `/opt/dojo/certs/private/` in a default install. Two bundles cover the two sides of the application:

- `dojo-ca-bundle.crt` is for services the application calls directly, such as Jira and SSO providers. On startup the `dojo`, `celeryworker`, and `ddorch-workers` containers read it and set `REQUESTS_CA_BUNDLE` to it when it is present and not empty.
- `connectors-ca-bundle.crt` is for tools reached through Connectors, such as Burp or Semgrep. The connectors container appends it to `CA_BUNDLES` on startup.

Each file must be in PEM format (Base64-encoded X.509, starting with `-----BEGIN CERTIFICATE-----` and ending with `-----END CERTIFICATE-----`), and each may hold more than one certificate concatenated together. The file has to be readable by the container process, so set permissions accordingly (for example `chmod 644`).

To install a bundle for the application side:

```bash
# Create the directory if it does not already exist
sudo mkdir -p /opt/dojo/certs/private

# Copy your PEM bundle into place under the expected name
sudo cp my-internal-ca.crt /opt/dojo/certs/private/dojo-ca-bundle.crt
sudo chmod 644 /opt/dojo/certs/private/dojo-ca-bundle.crt

# Restart the application so the containers pick it up
sudo -E dojo-compose-cli app restart
```

On DefectDojo versions before 3.4.0 this file replaces the public root CAs instead of adding to them, so a file holding only your CA breaks calls to publicly signed services. Build it from the host's bundle plus yours:

```bash
cat /etc/ssl/certs/ca-certificates.crt my-internal-ca.crt | sudo tee /opt/dojo/certs/private/dojo-ca-bundle.crt >/dev/null
```

On RHEL-family hosts the host's bundle is `/etc/pki/tls/certs/ca-bundle.crt`. Use this instead of the `cp` command above, then set the file's permissions as above with `sudo chmod 644 /opt/dojo/certs/private/dojo-ca-bundle.crt` and run `sudo -E dojo-compose-cli app restart`.

Use the filename `connectors-ca-bundle.crt` instead when the CA is only needed for Connector tools, and install both files if you need both. Inside the containers these paths are `/app/certs/private/dojo-ca-bundle.crt` and `/app/certs/private/connectors-ca-bundle.crt`.

To confirm the bundle was loaded, look at the `dojo` container's startup logs (`docker logs dojo`). They should show a line starting `REQUESTS_CA_BUNDLE set to`. On DefectDojo 3.4.0 and later it names a merged file and mentions `system roots + /app/certs/private/dojo-ca-bundle.crt`. For example:

```text
REQUESTS_CA_BUNDLE set to /tmp/dojo-ca-bundle.merged.crt (system roots + /app/certs/private/dojo-ca-bundle.crt)
```

If the file is missing or empty the container logs `No CA bundle found ...` instead and starts normally, so a bundle you forgot to install fails as an untrusted-certificate error on the outbound call rather than as a startup error.

From the next `dojo-compose-cli` release after 2.1.5, `certs add-ca` writes both bundles for you and keeps the public root CAs in the application bundle, and `certs test` makes an HTTPS call from inside the container to confirm the CA is trusted. See [Checking a Deployment with doctor and certs](/get_started/pro/onprem/docker_compose/checking_a_deployment/#trust-an-internal-ca-with-certs-add-ca).

## Reset the admin password

If you lose the generated password, reset it from the application host. DefectDojo has to be running. The admin username is `admin`.

```bash
sudo -E dojo-compose-cli app change-password
```

## Upgrading

Upgrades are covered on their own page: see the [DefectDojo Pro Upgrade Guide (Docker Compose)](/get_started/pro/onprem/docker_compose/upgrading_on_docker_compose/) for the one-command `app upgrade`, the step-by-step path, air-gapped upgrades, and rollback.

## Command reference

`dojo-compose-cli --help` lists everything, and every subcommand takes `--help` as well. The commands you are most likely to need are below. `doctor`, `certs` and `bundle create` ship in the next `dojo-compose-cli` release after 2.1.5; see [Checking a Deployment with doctor and certs](/get_started/pro/onprem/docker_compose/checking_a_deployment/).

| Command | What it does |
| --- | --- |
| `first-install` | Interactive first-time install |
| `app start`, `app stop`, `app restart` | Control the stack |
| `app upgrade` | Upgrade to a newer version |
| `app pull-images`, `app purge-images` | Fetch or remove the configured images |
| `app change-password` | Reset the admin password, with the app running |
| `config print` | Show the current configuration |
| `config set` | Set the version, deploy version, deploy type, or air-gapped mode |
| `config rotate-secret` | Rotate the key encrypting stored configuration |
| `environment print`, `environment add`, `environment remove` | Manage environment variables |
| `deploy download` | Fetch deployment files for the configured version |
| `license print`, `license status`, `license update` | Inspect and update your license |
| `validate db-connection` | Check the database connection string |
| `validate deploy-version` | Check the deployment files match the configured version |
| `diagnostics collect` | Gather a diagnostics bundle for a support request |
| `doctor` | Check what would stop DefectDojo from starting or upgrading; `--fix` repairs `media/` ownership and the systemd unit |
| `certs status`, `certs add-ca`, `certs test` | Check the TLS certificates, trust an internal CA, and test an outbound HTTPS call from the containers |
| `bundle create` | Create an offline upgrade bundle for an air-gapped install |
| `register` | Authenticate to the container registry |
| `update-binary` | Update the CLI itself |

Most commands need `DOJO_CLI_KEY`, since the configuration is encrypted at rest. Export it for your session, then pass it through `sudo` with `sudo -E`:

```bash
export DOJO_CLI_KEY="your-key"
sudo -E dojo-compose-cli config print
```

Without it, the CLI asks for the key each time.

## Troubleshooting

### First install reports a failure while the initializer is still running

On a slower host, `first-install` from `dojo-compose-cli` 2.1.x can give up before the initializer has finished creating the database. It prints an error, but the `init` container keeps running in the background and usually completes. The failed run leaves three things undone:

- It prints no admin credentials.
- It does not create the systemd service.
- It does not mark the install as initialized.

The commands below need your `DOJO_CLI_KEY`. Export it once for the session before you start:

```bash
export DOJO_CLI_KEY="<your-key>"
```

`sudo -E dojo-compose-cli config print` then shows `Initialized` as `false`.

You do not need to reinstall. On an install that is not yet marked initialized, `app start` completes the first start: it creates the systemd service, sets the admin password, and marks the install initialized.

**1. Wait for the initializer to finish.** The initializer container is named `init`. Check its state and exit code:

```bash
docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' init
```

While it is working this prints `running 0`. To follow its progress, tail the log:

```bash
docker logs -f --tail 20 init
```

Wait until the state is `exited`. Do not run `app start` while it still says `running`: the start would wait on the same initializer and can time out the same way.

If `docker inspect` reports `No such object: init`, the failure came before the stack was created (for example during the image pull), and this recovery does not apply.

**2. Check the exit code.** `exited 0` means the database is ready, so go on to step 3. Any other code means the initializer stopped on an error, so do not continue yet:

- For the codes in [Reading the initializer's result](/get_started/pro/onprem/upgrading/#reading-the-initializers-result), that table says what each one means. Its advice about restoring a backup applies to upgrades only. On a first install there is no earlier database to go back to.
- A code that is not in that table, such as `137`, means the container was killed, often because the host ran out of memory. Check the kernel log and the host's memory before you retry, for example `sudo dmesg | grep -i -E 'killed process|out of memory'`. Ubuntu lets only root read the kernel log by default.

Fix the cause the log names, then run step 3. If it reports a failure while `init` is still running, go back to step 1. If the cause is not clear, run `sudo -E dojo-compose-cli diagnostics collect` and send the bundle to [support@defectdojo.com](mailto:support@defectdojo.com).

**3. Start DefectDojo.**

```bash
sudo -E dojo-compose-cli app start
```

Because the install is not marked initialized, this run brings the stack up (the initializer runs again, and finishes quickly because the schema is already in place), creates the systemd service, sets a new random admin password, prints the admin credentials, and marks the install as initialized. **Save the credentials it prints. They are not shown again.** `dojo-compose-cli` does not store the password, so if you miss it, follow [Reset the admin password](#reset-the-admin-password).

Do not run `app stop` while `init` is still running. The next paragraph applies only after step 2 shows `exited 0`.

If `app start` reports that DefectDojo is already running, the stack came up on its own. Run `sudo -E dojo-compose-cli app stop`, then `sudo -E dojo-compose-cli app start` again, so that the first-start steps run.

**4. Confirm the result.** `sudo -E dojo-compose-cli config print` now shows `Initialized` as `true`, and DefectDojo answers at your site URL. Check that the systemd service will start DefectDojo on boot:

```bash
systemctl is-enabled defectdojo-compose
```

If it does not print `enabled`, enable it:

```bash
sudo systemctl enable defectdojo-compose
```

### The systemd service keeps restarting

If `journalctl -u defectdojo-compose` shows the service failing with a message that DefectDojo is already running, over and over, the unit is trying to start a stack that is already up. The application itself keeps running. To stop the repeated restarts, disable the unit:

```bash
sudo systemctl disable defectdojo-compose
```

Do not run `systemctl stop defectdojo-compose` while the unit is active. Its stop action runs `app stop`, which takes the containers down. With the unit disabled, the stack still comes back after a reboot, because Docker restarts the containers on its own under their restart policy.

## Questions or support

If an install does not complete, `dojo-compose-cli diagnostics collect` gathers a report bundle that is the fastest way for us to help. Send it, along with what you were running when it failed, to [support@defectdojo.com](mailto:support@defectdojo.com).
