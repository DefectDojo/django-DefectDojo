---
title: "Installing DefectDojo Pro in an Air-Gapped Environment"
description: "Stage the DefectDojo Pro install artifacts on a host with internet access, then move them into an air-gapped network"
draft: false
weight: 3
audience: pro
aliases:
  - /get_started/pro/onprem/air_gapped_install/
---

This page is a supplement to the installation instructions supplied with your DefectDojo Pro license. It covers only what changes when the target host has no route to the internet. Everything else, including the host prerequisites and the PostgreSQL setup, follows the standard instructions.

The approach uses two hosts. A staging host with normal internet access downloads the deployment artifacts and container images. You then move those artifacts into the air-gapped network by whatever transfer process your environment allows, and complete the install on the target host with no network access to DefectDojo.

Plan for the staging host to be reachable again later. Every upgrade starts there, so it is worth keeping.

## What you need

On the staging host, a Linux host with internet access, Docker installed, and enough free disk space for the deployment directory plus the compressed container images. The images are the bulk of it and run to several hundred megabytes each.

On the air-gapped host, Docker installed and working, and a PostgreSQL server already provisioned and reachable, both per the standard installation instructions.

On both, a copy of the `dojo-compose-cli` archive and your license file, as supplied by DefectDojo. Use CLI version 2.1.0 or later. Earlier versions have no air-gapped mode, and without it the CLI tries to reach the container registry on every command and fails with name resolution errors instead of telling you what is wrong. To upgrade later with an offline bundle, as described in [Upgrading an air-gapped deployment](#upgrading-an-air-gapped-deployment), both hosts need the next `dojo-compose-cli` release after 2.1.5 or later.

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

If the staging host reaches the internet through an outbound HTTPS proxy, configure the proxy variables before pulling anything. See [Running DefectDojo Behind a Forward HTTPS Proxy](/get_started/pro/onprem/forward_proxy/).

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

Finally, fetch the Pro settings. They ship in their own image, which neither `deploy download` nor `app pull-images` retrieves, and the CLI cannot fetch them later on an air-gapped host. Copy them into the customizations directory so they travel inside the deployment archive:

```bash
SETTINGS_IMAGE="us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro/settings:x.y.z"
docker pull "$SETTINGS_IMAGE"
docker create --name settings_image "$SETTINGS_IMAGE"
sudo docker cp settings_image:/settings/. /opt/dojo/customizations/
docker rm settings_image
ls -l /opt/dojo/customizations/pro_settings.py
```

The last command must list `pro_settings.py`. Without that file the Pro features are not loaded, and nobody can sign in: the login page shows only the logo, and a sign-in attempt fails with `Sign in failed (HTTP 200)`.

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
| `app upgrade` | Declined, unless you give it an offline bundle with `--bundle`. See the upgrade section below. |
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

Confirm the Pro settings from step 3 arrived with it:

```bash
ls -l /opt/dojo/customizations/pro_settings.py
```

If DefectDojo will call services whose certificates are signed by an internal CA, such as a self-hosted GitLab or another SSO provider, Jira, or a tool reached through a Connector, install your CA bundle now. See [Trusting an internal or private CA](/get_started/pro/onprem/docker_compose/installing_on_docker_compose/#trusting-an-internal-or-private-ca). An air-gapped network almost always has an internal CA, and without the bundle those calls fail with `certificate verify failed`.

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

`app upgrade` normally downloads from the container registry. On an air-gapped host it needs an offline bundle instead: one file that holds the deployment files, the Pro settings, and every image of the target version. You create the bundle on the staging host with `bundle create`, carry the file across, and pass it to `app upgrade --bundle` on the air-gapped host.

Both commands ship in the next `dojo-compose-cli` release after 2.1.5. If `dojo-compose-cli --help` lists `bundle`, your CLI has them. With 2.1.5 or earlier, follow [Upgrade by hand with an older CLI](#upgrade-by-hand-with-an-older-cli) instead.

Before any upgrade, review the [upgrade notes](/releases/os_upgrading/upgrading_guide/) for every version between your current one and your target. If you are several releases behind, contact support before starting.

### 1. Update the CLI on both hosts

On the staging host:

```bash
sudo -E dojo-compose-cli update-binary
```

The air-gapped host cannot update itself, because `update-binary` reaches the registry. Carry the new CLI archive across, extract it, and run any command from the extracted binary as root:

```bash
sudo -E ./dojo-compose-cli config print
```

When the extracted binary is newer than the one in `/usr/bin`, it replaces it and prints `Upgraded dojo-compose CLI from version <old> to <new>`.

### 2. Create the bundle on the staging host

The staging host must be set up like the air-gapped one: the same license and the same deployment type. Check the deployment type with `dojo-compose-cli config print` on both hosts. A bundle made for another deployment type is refused on the air-gapped host. A license with a different subscription level only produces a warning, but the bundle then carries the settings for the wrong subscription.

Create the bundle for the version you are upgrading to, replacing `x.y.z`:

```bash
sudo -E dojo-compose-cli bundle create --defectdojo-version x.y.z
```

Without `--defectdojo-version` it bundles the newest release. The bundle holds the deployment files and Pro settings for that version, every image its compose file runs with your license, and the PostgreSQL client image the CLI uses for database checks and backups. It writes `defectdojo-x.y.z-<deployment-type>-bundle.tar.gz` in the current directory. Use `--output` (or `-o`) to choose another path. While it writes the bundle, the disk holding the output file needs room for the images twice: once as the saved images in a temporary directory beside the output, and once in the bundle itself.

`bundle create` does not change the install on the staging host. It renders the target version in a temporary directory next to the output file and removes it afterwards, so you do not need to set the version on the staging host first.

If the air-gapped database server runs a PostgreSQL version newer than 16, add a matching client image so the CLI can check and back up that database:

```bash
sudo -E dojo-compose-cli bundle create --defectdojo-version x.y.z --extra-image postgres:17-alpine
```

`--extra-image` can be given more than once.

When it finishes, the CLI prints the version, the deployment type, the number of images and the size, followed by the `app upgrade` command to run on the air-gapped host. Move the bundle file across using your normal transfer process.

### 3. Upgrade on the air-gapped host

Pass the bundle to `app upgrade`:

```bash
sudo -E dojo-compose-cli app upgrade --bundle /path/to/defectdojo-x.y.z-<deployment-type>-bundle.tar.gz
```

The version comes from the bundle, so do not add `--defectdojo-version`; the CLI refuses the combination. Before it changes anything, the CLI:

1. Extracts the bundle into a directory beside the install directory (under `/opt` in a default install), so that disk needs free space for the extracted bundle.
2. Refuses a bundle made for a different deployment type, and warns when it was made for a different subscription level.
3. Checks every file against the checksums recorded when the bundle was made.
4. Checks that Docker's data directory has room for the bundle's images, in addition to the space the extracted bundle already uses. The upgrade checks the space for its backup and the new install as well. If space is short, `--backup-dir` puts the pre-upgrade backup on another disk.
5. Loads the images and checks that every image the bundle lists is now present. It prints `Loaded N images from the bundle.`

The upgrade then runs as it does on a connected host. It takes a backup, installs the new deployment files and Pro settings from the bundle, carries over your customizations, `issue-trackers/`, your server certificate and key, the CA bundles in `certs/private/`, and `media/`, and starts the new version. The extracted files are removed when the upgrade finishes. The loaded images stay.

Afterwards, `sudo -E dojo-compose-cli doctor` checks the result, including the certificates and CA bundles. See [Checking a Deployment with doctor and certs](/get_started/pro/onprem/docker_compose/checking_a_deployment/).

### Upgrade by hand with an older CLI

With `dojo-compose-cli` 2.1.5 or earlier, `app upgrade` is declined in air-gapped mode and has no `--bundle` option. Upgrades follow the same route as the install.

As with the bundle, review the [upgrade notes](/releases/os_upgrading/upgrading_guide/) for every version between your current one and your target before you start.

On the staging host, set the new version and repeat steps 3 through 5 for it. Move the new archive across, load the new images, then on the air-gapped host set the version to the new one and restart:

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli app restart
```

Two things catch people out. Restarting without changing the configured version brings the stack back on the images you already had, because the version selects the image tags. And the set of images can change between releases, so compare what you loaded against what the new version's pull produced rather than assuming the previous list still applies.

Your existing deployment directory does not pick up the new version's files on its own, so restore the new `/opt/dojo` contents as you did in step 7. Some files must come from the new version and others must be carried over from your current install, and mixing them up is the most common cause of a broken air-gapped upgrade:

| Take from the new version | Carry over from your current install |
| --- | --- |
| `docker-compose.yml` and the nginx configuration | `customizations/local_settings.py`, if you changed it |
| `customizations/pro_settings.py` (an older copy will not start against the new release) | `certs/dojo.crt` and `certs/dojo.key`, your server certificate |
| The other files in `certs/`, which are internal service certificates | Everything in `certs/private/`, your CA bundles. The new version ships these files empty. |
| | `media/`, your uploaded files |

Before restarting, confirm that `customizations/pro_settings.py` is present, and that `certs/private/dojo-ca-bundle.crt` is not empty if you use an internal CA.

Back up your database before you start.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| The login page shows only the logo and footer, with no login form. A sign-in through `?force_login_form` fails with `Sign in failed (HTTP 200)`, and the browser's Network tab shows `/api/vue/auth/login/config/` redirecting to `/login?next=...`. | `customizations/pro_settings.py` is missing, so the Pro features are not loaded. | Fetch the settings on the staging host as in step 3, copy `pro_settings.py` into `/opt/dojo/customizations/`, then run `dojo-compose-cli app restart`. |
| Signing in through an SSO provider fails after you authenticate with the provider. The error contains `certificate verify failed`. A later DefectDojo release replaces it on the login form with a message that single sign-on could not verify the identity provider's certificate. | DefectDojo does not trust the CA that signed the provider's certificate, usually because `certs/private/dojo-ca-bundle.crt` is empty. Less often, the provider's certificate has expired or does not match its address. | Add your CA with `sudo -E dojo-compose-cli certs add-ca --restart <ca.pem>`, then run `sudo -E dojo-compose-cli certs test https://<idp-host>/`, which should print `OK`. See [Checking a Deployment with doctor and certs](/get_started/pro/onprem/docker_compose/checking_a_deployment/#trust-an-internal-ca-with-certs-add-ca). With a CLI that has no `certs` commands, add the bundle as described in [Trusting an internal or private CA](/get_started/pro/onprem/docker_compose/installing_on_docker_compose/#trusting-an-internal-or-private-ca). Either way, `docker logs dojo` should then show a line starting `REQUESTS_CA_BUNDLE set to`. On DefectDojo 3.4.0 and later it names a merged file and mentions `system roots + /app/certs/private/dojo-ca-bundle.crt`. |

## Features that need outbound access

An air-gapped deployment runs without any outbound connectivity, but features that reach external services cannot work while it is disconnected. This applies to the connectors and integrators that pull from cloud-hosted tools, issue tracker integrations such as Jira, outbound notifications to services like Slack and Microsoft Teams, and vulnerability enrichment data that is normally fetched on a schedule.

These are configured per deployment rather than being on by default, so an air-gapped install is not broken by their absence. If you enable one, expect it to fail with name resolution or connection errors until the deployment has a route to that service. Where the outbound path exists but goes through a proxy, see [Running DefectDojo Behind a Forward HTTPS Proxy](/get_started/pro/onprem/forward_proxy/).

### EPSS and KEV data from an internal mirror

EPSS and KEV enrichment is an exception worth setting up, because it does not require a route to the public internet. Both are configured in the Tuner under Finding Enrichment, and each has its own enable toggle and its own lookup URL. The URL fields ship pointing at the public sources, and you can repoint them at a copy hosted inside your own network.

The mirror has to serve the same files in the same format as the public sources. The lookups fetch a specific file from the URL you give them rather than discovering whatever is there, so a mirror that repackages or reorganizes the data will not work. Refresh your copies on a schedule that suits you, since the deployment only reads what your mirror serves.

## Questions or support

For help with an air-gapped install or upgrade, contact your account representative or [support@defectdojo.com](mailto:support@defectdojo.com).
