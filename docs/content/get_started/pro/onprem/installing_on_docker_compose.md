---
title: "Installing on Docker Compose"
description: "Install self-hosted DefectDojo Pro on a single host using dojo-compose-cli, with PostgreSQL on a separate server"
draft: false
weight: 15
audience: pro
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

Create the databases and the application user. DefectDojo uses a second database for its orchestration service, so create both:

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

If the host reaches the internet through an outbound proxy, see [Running DefectDojo Behind a Forward HTTPS Proxy](/onprem_deployment/forward_proxy/). If it has no route to the internet at all, follow the air-gapped installation procedure in this section instead.

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

Copy the CLI archive and your license file to the application host, into the same directory, and extract the CLI:

```bash
tar -xzvf dojo-compose-cli_*.tar.gz
```

Then run the installer from that directory:

```bash
sudo ./dojo-compose-cli first-install
```

The wizard prompts for the following.

| Prompt | What it is |
| --- | --- |
| `DOJO_CLI_KEY` | An encryption key for configuration the CLI stores on disk. Choose it now and keep it, since later commands need it. |
| DefectDojo Version | The release to install. |
| Deploy Version | The deployment files to use. Set it to the same value as the version. |
| Deploy Type | `separate-db` for a database on its own host, or `containerized-db` to run PostgreSQL in a container. |
| Database Connection Type | Choose Single Line and supply the whole connection string. |
| Database URL | `postgres://<user>:<password>@<host>:5432/dojodb`. It must begin with `postgres://` rather than `postgresql://`. |
| `DD_ALLOWED_HOSTS` | Host headers the application will answer to. |
| `DD_SITE_URL` | The full URL where users reach DefectDojo, for example `https://defectdojo.internal.example.com`. |

Two things worth knowing at the prompts. Supply the database connection as a single line rather than value by value, since the per-value path does not currently ask for the username. And if the password contains characters like `!`, `@`, or `#`, URL encode them in the connection string.

The installer then pulls the images, starts the stack, creates a systemd service, and prints the generated admin credentials. **Save those credentials before you close the terminal. They are not shown again.**

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

## Reset the admin password

If you lose the generated password, reset it from the application host. DefectDojo has to be running:

```bash
dojo-compose-cli app change-password
```

## Upgrading

Back up your database first, and read the release notes for every version between your current one and your target rather than only the target. See the [upgrade notes](/releases/os_upgrading/upgrading_guide/).

The CLI can do the whole upgrade, prompting for the version:

```bash
dojo-compose-cli app upgrade
```

If you would rather do it in steps, stop the application, set the new version, download the matching deployment files, then start again:

```bash
dojo-compose-cli app stop
dojo-compose-cli config set --version x.y.z --deploy-version x.y.z
dojo-compose-cli deploy download
dojo-compose-cli app start
```

The download step compares the incoming `docker-compose.yml`, nginx configuration, and `local_settings.py` against what you already have, and tells you when they differ so you can reconcile your changes. Adding `--overwrite` accepts the new versions of those files and discards local modifications to them, so use it deliberately.

Keep your own settings in `/opt/dojo/customizations/local_settings.py`. That file is yours and survives upgrades.

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

Most commands need `DOJO_CLI_KEY`, since the configuration is encrypted at rest. Export it for your session, or pass it through `sudo` with `sudo -E`:

```bash
export DOJO_CLI_KEY="your-key"
```

## Questions or support

If an install does not complete, `dojo-compose-cli diagnostics collect` gathers a report bundle that is the fastest way for us to help. Send it, along with what you were running when it failed, to [support@defectdojo.com](mailto:support@defectdojo.com).
