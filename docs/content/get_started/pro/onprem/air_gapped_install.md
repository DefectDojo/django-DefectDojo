---
title: "Installing DefectDojo Pro in an Air-Gapped Environment"
description: "Stage the DefectDojo Pro install artifacts on a host with internet access, then move them into an air-gapped network"
draft: false
weight: 8
audience: pro
---

This page is a supplement to the installation instructions supplied with your DefectDojo Pro license. It covers only what changes when the target host has no route to the internet. Everything else, including the host prerequisites and the PostgreSQL setup, follows the standard instructions.

The approach uses two hosts. A staging host with normal internet access downloads the deployment artifacts and container images. You then move those artifacts into the air-gapped network by whatever transfer process your environment allows, and complete the install on the target host with no network access to DefectDojo.

Plan for the staging host to be reachable again later. Upgrades repeat the same transfer, so it is worth keeping.

## What you need

On the staging host, a Linux host with internet access, Docker installed, and enough free disk space for the deployment directory plus the compressed container images. The images are the bulk of it and run to several hundred megabytes each.

On the air-gapped host, Docker installed and working, and a PostgreSQL server already provisioned and reachable, both per the standard installation instructions.

On both, a copy of the `dojo-compose-cli` archive and your license file, as supplied by DefectDojo. Use CLI version 2.1.0 or later. Earlier versions have no air-gapped mode, and without it the CLI tries to reach the container registry on every command and fails with name resolution errors instead of telling you what is wrong.

## Stage the artifacts

Run these steps on the staging host.

### 1. Register the CLI

Install Docker first if it is not already present. See the [Docker installation documentation](https://docs.docker.com/engine/install/) for instructions specific to your distribution.

Extract the CLI archive, then register it:

```bash
sudo ./dojo-compose-cli register
```

Registration installs the CLI to `/usr/bin`, creates the `dojosrv` group, adds your user to the `dojosrv` and `docker` groups, validates the license, and authenticates Docker against the DefectDojo container registry.

You are prompted for a `DOJO_CLI_KEY`, which encrypts the CLI's stored configuration on disk. Set it in the environment to avoid being prompted on every command:

```bash
export DOJO_CLI_KEY="your-key"
```

New group membership does not apply to your current shell. Either open a new session, or pick up the groups in place:

```bash
newgrp docker
```

Confirm with `id` that both `docker` and `dojosrv` are listed. Once your user is in the `docker` group, the remaining commands do not need `sudo`.

If the staging host reaches the internet through an outbound HTTPS proxy, configure the proxy variables before pulling anything. See [Running DefectDojo Behind a Forward HTTPS Proxy](/onprem_deployment/forward_proxy/).

### 2. Set the version

Set both the deployment version and the application version to the release you intend to install, replacing `x.y.z`:

```bash
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli config set --version x.y.z
```

Use the same version in both commands, and use it consistently for the rest of this procedure. Mixing versions between the deployment artifacts and the images produces a stack that either fails to start or starts on the wrong images.

### 3. Download the deployment artifacts and images

Download the deployment directory:

```bash
dojo-compose-cli deploy download
```

This populates `/opt/dojo` with the compose file, the nginx configuration, the issue tracker templates, the customizations directory, and a versioned subdirectory for the release you selected.

Then pull the container images:

```bash
dojo-compose-cli app pull-images
```

Confirm what arrived:

```bash
docker image ls
```

Note the repository prefix shared by the DefectDojo images in that output. You need it in the next step, and the set of images varies between releases, so read it from your own output rather than assuming a list.

### 4. Record the generated configuration

The standard install generates several configuration values on first run. In an air-gapped install you set them by hand on the target host, so capture them now:

```bash
dojo-compose-cli environment print | head -n 9
```

Keep the credential encryption key and the secret key. Both are generated 64 character random strings, and the credential key in particular must match the one used when credentials were encrypted, so record it accurately and store it as a secret. The uwsgi and celery values in the same output are useful as starting points for the target host.

Treat this output as sensitive. It contains the keys protecting stored credentials for your deployment.

### 5. Package everything

Create a directory for the transfer, using the version in its name so the contents are unambiguous later:

```bash
mkdir artifacts-x.y.z
cd artifacts-x.y.z
```

Archive the deployment directory, preserving permissions:

```bash
sudo tar -czvpf dojo-directory.tar.gz /opt/dojo
sudo chown "$USER:$USER" dojo-directory.tar.gz
```

Save the container images. This script takes the repository prefix you noted in step 3, saves each matching image, and compresses it:

```bash
#!/bin/bash
set -u

REPO_FILTER="${1:?usage: save-images.bash <image-repository-prefix>}"
BACKUP_DIR="./defectdojo-pro-images"
mkdir -p "$BACKUP_DIR"

images=$(docker image ls --format "{{.Repository}}:{{.Tag}}" \
  | grep -v "<none>" | grep "$REPO_FILTER")

if [ -z "$images" ]; then
    echo "No images matched '$REPO_FILTER'."
    exit 1
fi

for full_image in $images; do
    filename_part="${full_image##*/}"
    dest_path="$BACKUP_DIR/${filename_part//:/_}.tar.gz"

    echo "Saving $full_image to $dest_path"
    docker save "$full_image" | gzip > "$dest_path"

    if [[ ${PIPESTATUS[0]} -eq 0 ]] && [[ ${PIPESTATUS[1]} -eq 0 ]]; then
        du -h "$dest_path" | awk '{print "  ok, " $1}'
    else
        echo "  failed, removing partial file"
        rm -f "$dest_path"
    fi
done
```

Make it executable and run it with your prefix:

```bash
chmod u+x save-images.bash
./save-images.bash <image-repository-prefix>
```

Check that every image from step 3 produced a file, then bundle the directory:

```bash
cd ..
tar czvf artifacts-x.y.z.tar.gz artifacts-x.y.z
```

Move `artifacts-x.y.z.tar.gz` into the air-gapped network using your normal transfer process, along with the CLI archive and your license file if they are not already there.

## Install on the air-gapped host

### 6. Install the CLI and enable air-gapped mode

Extract the CLI archive, then place the license where the CLI expects it:

```bash
sudo mkdir /etc/defectdojo/
sudo cp dojopro.lic /etc/defectdojo/
```

Turn on air-gapped mode. This is the first CLI command you run on this host, and it installs the CLI to `/usr/bin`, validates the license from the file, and encrypts the stored configuration as it goes:

```bash
sudo ./dojo-compose-cli config set --air-gapped true
```

Confirm it took effect:

```bash
dojo-compose-cli config print
```

The output includes `Air Gapped Deploy` set to true. Set `DOJO_CLI_KEY` in the environment here as well, so later commands do not prompt for it.

Do not run `register` on this host. Registration exists to authenticate against the container registry, which is unreachable by definition, and in air-gapped mode the CLI declines it rather than attempting it. The same applies to the other commands that reach the registry:

| Command | Behavior in air-gapped mode |
| --- | --- |
| `register` | Declined. Registry authentication is not available. |
| `deploy download` | Declined. Run it on the staging host instead. |
| `app pull-images` | Declined. Run it on the staging host instead. |
| `app upgrade` | Declined. See the upgrade section below. |
| `app start`, `app stop`, `app restart` | Available. These do not contact the registry. |

Each declined command exits with a message naming air-gapped mode, so a refusal here is the CLI working as intended rather than a fault to diagnose.

Pick up your new group membership before continuing:

```bash
newgrp docker
```

### 7. Restore the deployment directory

Extract the transfer bundle, then move the deployment archive into place:

```bash
tar -xzvf artifacts-x.y.z.tar.gz
sudo cp artifacts-x.y.z/dojo-directory.tar.gz /opt/
```

Setting up the CLI may have created a nearly empty `/opt/dojo` holding only the license. If it is there, remove it first so the archive does not merge into it:

```bash
sudo ls -lah /opt/dojo
sudo rm -rf /opt/dojo
```

Extract the real deployment directory, then fix ownership and the media permissions:

```bash
cd /opt
sudo tar xzvf dojo-directory.tar.gz --strip-components 1
sudo chown -R dojosrv:dojosrv /opt/dojo
sudo chmod -R go+w /opt/dojo/media
```

### 8. Set the configuration by hand

An air-gapped install does not use the interactive first install, so set the values it would otherwise generate for you. Use the keys you captured in step 4:

```bash
dojo-compose-cli environment add --key "DD_CREDENTIAL_AES_256_KEY" --value "<64-character-key-from-step-4>"
dojo-compose-cli environment add --key "DD_SECRET_KEY" --value "<64-character-key-from-step-4>"
```

Set the version to match the artifacts you moved:

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
```

Set the site URL and allowed hosts. The site URL must be the address that resolves to this host inside your network:

```bash
dojo-compose-cli environment add --key "DD_SITE_URL" --value "https://defectdojo.internal.example.com"
dojo-compose-cli environment add --key "DD_ALLOWED_HOSTS" --value "*"
```

Set the database connection, using the PostgreSQL server you provisioned earlier:

```bash
dojo-compose-cli environment add --key "DD_DATABASE_URL" --value "postgres://<db_user>:<db_password>@<db_host>:5432/<db_name>"
```

### 9. Load the container images

This script loads every image file in the images directory:

```bash
#!/bin/bash
set -u

IMPORT_DIR="./defectdojo-pro-images"

if [ ! -d "$IMPORT_DIR" ]; then
    echo "Directory '$IMPORT_DIR' not found."
    exit 1
fi

files=$(ls "$IMPORT_DIR"/*.tar.gz 2>/dev/null)

if [ -z "$files" ]; then
    echo "No .tar.gz files found in $IMPORT_DIR."
    exit 1
fi

for file in $files; do
    echo "Loading $(basename "$file")"
    if docker load -i "$file"; then
        echo "  ok"
    else
        echo "  failed"
    fi
done
```

Run it from inside the extracted artifacts directory:

```bash
chmod u+x load-images.bash
./load-images.bash
```

Then confirm with `docker image ls` that every image loaded, at the version you expect.

### 10. Start the stack

Start the stack with the CLI. This works in air-gapped mode, since it reads the configuration you set and drives the local compose file without contacting the registry:

```bash
dojo-compose-cli app start
```

`app stop` and `app restart` are available the same way. Use `app restart` after changing any environment value, because it recreates the containers so the new values are picked up.

Two things to check if the stack does not come up. The command needs the deployment directory in place, so confirm `/opt/dojo/docker-compose.yml` exists from step 7. And the configured version selects the image tags, so it has to match the images you loaded in step 9.

DefectDojo is then available at the address you set as the site URL.

## Upgrading an air-gapped deployment

`app upgrade` downloads from the container registry, so it is one of the commands air-gapped mode declines. Upgrades follow the same route as the install rather than being driven by a single command.

On the staging host, set the new version and repeat steps 3 through 5 for it. Move the new bundle across, load the new images, then on the air-gapped host set the version to the new one and restart:

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli app restart
```

Two things catch people out. Restarting without changing the configured version brings the stack back on the images you already had, because the version selects the image tags. And the set of images can change between releases, so compare what you loaded against what the new version's pull produced rather than assuming the previous list still applies.

Your existing deployment directory does not pick up the new version's compose file or nginx configuration on its own, so restore the new `/opt/dojo` contents as you did in step 7, keeping your own customizations, certificates, and media.

Back up your database before any upgrade, and review the [upgrade notes](/releases/os_upgrading/upgrading_guide/) for every version between your current one and your target. If you are several releases behind, contact support before starting.

## Features that need outbound access

An air-gapped deployment runs without any outbound connectivity, but features that reach external services cannot work while it is disconnected. This applies to the connectors and integrators that pull from cloud-hosted tools, issue tracker integrations such as Jira, outbound notifications to services like Slack and Microsoft Teams, and vulnerability enrichment data that is normally fetched on a schedule.

These are configured per deployment rather than being on by default, so an air-gapped install is not broken by their absence. If you enable one, expect it to fail with name resolution or connection errors until the deployment has a route to that service. Where the outbound path exists but goes through a proxy, see [Running DefectDojo Behind a Forward HTTPS Proxy](/onprem_deployment/forward_proxy/).

### EPSS and KEV data from an internal mirror

EPSS and KEV enrichment is an exception worth setting up, because it does not require a route to the public internet. Both are configured in the Tuner under Finding Enrichment, and each has its own enable toggle and its own lookup URL. The URL fields ship pointing at the public sources, and you can repoint them at a copy hosted inside your own network.

The mirror has to serve the same files in the same format as the public sources. The lookups fetch a specific file from the URL you give them rather than discovering whatever is there, so a mirror that repackages or reorganizes the data will not work. Refresh your copies on a schedule that suits you, since the deployment only reads what your mirror serves.

## Questions or support

For help with an air-gapped install or upgrade, contact your account representative or [support@defectdojo.com](mailto:support@defectdojo.com).
