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

Ubuntu 24.04 LTS is the supported operating system for this installation. Update it fully before you begin. The installation runs commands as root, so you need `sudo` or a root shell on both hosts.

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
apt update
apt -y install postgresql postgresql-contrib
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
systemctl restart postgresql
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

### Confirm the database is reachable

Install the client tools and connect before going any further. A database problem is much easier to diagnose now than in the middle of the install:

```bash
apt update
apt -y install postgresql-client-common postgresql-client-16
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
| `DD_ALLOWED_HOSTS` | Host headers the application will answer to. |
| `DD_SITE_URL` | The full URL where users reach DefectDojo, for example `https://defectdojo.internal.example.com`. |

Two things worth knowing at the prompts. Supply the database connection as a single line rather than value by value, since the per-value path does not currently ask for the username. And if the password contains characters like `!`, `@`, or `#`, URL encode them in the connection string.

The installer then pulls the images, starts the stack, creates a systemd service, and prints the generated admin credentials. **Save those credentials before you close the terminal. They are not shown again.** If the printed password does not let you log in, or you lose it, set a new one with `sudo -E dojo-compose-cli app change-password` (see [Reset the admin password](#reset-the-admin-password)).

Once it finishes, DefectDojo is available at the site URL you gave it.

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

The running stack is the Django application, a separate container that handles scan imports, nginx, a Celery worker and scheduler, Valkey for caching and queueing, the connectors service, and the MCP server. `docker ps` lists them.

Day to day, these are the commands you need:

```bash
systemctl status defectdojo-compose
dojo-compose-cli app start
dojo-compose-cli app stop
dojo-compose-cli app restart
docker logs dojo
```

Use `app restart` after changing any configuration, since it recreates the containers so new values are picked up.

## Replace the TLS certificate

The installation ships a self-signed certificate so that the site works immediately. Replace it with your own by overwriting two files, keeping the names exactly as they are:

- `/opt/dojo/certs/dojo.crt`
- `/opt/dojo/certs/dojo.key`

Then `dojo-compose-cli app restart` to pick them up.

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
dojo-compose-cli app restart
```

Use the filename `connectors-ca-bundle.crt` instead when the CA is only needed for Connector tools, and install both files if you need both. Inside the containers these paths are `/app/certs/private/dojo-ca-bundle.crt` and `/app/certs/private/connectors-ca-bundle.crt`.

To confirm the bundle was loaded, look at the `dojo` container's startup logs for the confirmation line:

```text
REQUESTS_CA_BUNDLE set to /app/certs/private/dojo-ca-bundle.crt
```

If the file is missing or empty the container logs `No CA bundle found ...` instead and starts normally, so a bundle you forgot to install fails as an untrusted-certificate error on the outbound call rather than as a startup error.

## Reset the admin password

If you lose the generated password, reset it from the application host. DefectDojo has to be running:

```bash
sudo -E dojo-compose-cli app change-password
```

## Upgrading

Upgrades are covered on their own page: see the [DefectDojo Pro Upgrade Guide (Docker Compose)](/get_started/pro/onprem/docker_compose/upgrading_on_docker_compose/) for the one-command `app upgrade`, the step-by-step path, air-gapped upgrades, and rollback.

## Command reference

`dojo-compose-cli --help` lists everything, and every subcommand takes `--help` as well. The commands you are most likely to need:

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
| `register` | Authenticate to the container registry |
| `update-binary` | Update the CLI itself |

Most commands need `DOJO_CLI_KEY`, since the configuration is encrypted at rest. Export it for your session, then pass it through `sudo` with `sudo -E`:

```bash
export DOJO_CLI_KEY="your-key"
sudo -E dojo-compose-cli config print
```

Without it, the CLI asks for the key each time.

## Questions or support

If an install does not complete, `dojo-compose-cli diagnostics collect` gathers a report bundle that is the fastest way for us to help. Send it, along with what you were running when it failed, to [support@defectdojo.com](mailto:support@defectdojo.com).
