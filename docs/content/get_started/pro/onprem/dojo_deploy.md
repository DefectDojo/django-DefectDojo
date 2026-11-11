---
title: "Moving to dojo-deploy"
description: "dojo-deploy replaces dojo-compose-cli and dojo-helm-cli: what changes for an existing install, the legacy commands and their dojo-deploy equivalents, the support bundle, and what to do if a release has a problem"
draft: false
weight: 7
audience: pro
aliases:
  - /dojo-deploy/
  - /en/dojo-deploy/
---

`dojo-deploy` is one command line tool for installing and running self-hosted DefectDojo Pro. It replaces the two CLIs DefectDojo shipped before:

- `dojo-compose-cli`, for [Docker Compose installs](/get_started/pro/onprem/docker_compose/installing_on_docker_compose/)
- `dojo-helm-cli`, for [Kubernetes installs](/get_started/pro/onprem/kubernetes/installing_with_dojo_helm_cli/)

Both sets of commands now live in one binary. `dojo-deploy compose` runs the commands you know from `dojo-compose-cli`, and `dojo-deploy kubernetes` runs the ones from `dojo-helm-cli`.

**Existing installs keep working.** You don't need to reinstall, rename anything, or change scripts, cron jobs or the systemd unit. `dojo-compose-cli` and `dojo-helm-cli` are still released under their old names, from the same place as before, and `update-binary` keeps updating them. Under the old name, the binary has the same commands, options and help text as the old CLI.

## What you will see

### A note in your terminal

When you run `dojo-compose-cli` 2.2.0 or later, or `dojo-helm-cli` 4.1.0 or later, by hand in a terminal, the CLI prints a two-line note before running your command. The note has two forms.

When dojo-deploy is not installed:

```
dojo-compose-cli is now part of dojo-deploy. Install dojo-deploy (see https://docs.defectdojo.com/get_started/pro/onprem/dojo_deploy/),
then run "dojo-deploy compose <command>". Set DOJO_DEPLOY_NO_MIGRATION_NOTICE=1 to hide this note.
```

When dojo-deploy is already installed:

```
dojo-compose-cli is now part of dojo-deploy. Use dojo-deploy (see https://docs.defectdojo.com/get_started/pro/onprem/dojo_deploy/):
run "dojo-deploy compose <command>". Set DOJO_DEPLOY_NO_MIGRATION_NOTICE=1 to hide this note.
```

`dojo-helm-cli` prints the same notes, naming `dojo-helm-cli` and `dojo-deploy kubernetes <command>` instead. The `update-binary` run that brought you the release also installs `dojo-deploy` next to the old CLI (see [Getting dojo-deploy](#getting-dojo-deploy)), so you will usually see the second form. If you see the first, follow [Downloading dojo-deploy](#downloading-dojo-deploy).

If you have already installed `dojo-deploy` and run it under an old name (for example through the `/usr/bin/dojo-compose-cli` wrapper described [below](#getting-dojo-deploy)), the note reads:

```
dojo-compose-cli is now part of dojo-deploy. Run "dojo-deploy compose <command>" instead.
See https://docs.defectdojo.com/get_started/pro/onprem/dojo_deploy/ (set DOJO_DEPLOY_NO_MIGRATION_NOTICE=1 to hide this note).
```

The note goes to standard error. It never changes your command's output or its exit code, and it prints at most once per command, including when `app upgrade` restarts itself on an updated binary.

It does not appear:

- when standard error is not a terminal, so systemd units, cron jobs, CI and output piped or redirected to a file stay unchanged;
- for `--version`, or `-v` among the options before the command;
- for help: `--help`, `-h`, `help` or `h`;
- during shell completion;
- for JSON output (`--output json`, `-o json`, `--json`);
- with `--quiet` or `-q`, for example `app backup --quiet`;
- when you run `dojo-deploy compose` or `dojo-deploy kubernetes`;
- when `DOJO_DEPLOY_NO_MIGRATION_NOTICE` or `DOJO_CLI_UNATTENDED` is set to `1` or `true`.

### Hiding the note

Set the variable in your shell profile or script:

```bash
export DOJO_DEPLOY_NO_MIGRATION_NOTICE=1
```

`sudo` drops most environment variables by default (its `env_reset` setting), so a variable you export before running plain `sudo dojo-compose-cli ...` does not reach the CLI. Use one of these instead:

```bash
# Keep your environment, as the install guides already do with sudo -E
export DOJO_DEPLOY_NO_MIGRATION_NOTICE=1
sudo -E dojo-compose-cli app start

# Or put the variable on the sudo line
sudo DOJO_DEPLOY_NO_MIGRATION_NOTICE=1 dojo-compose-cli app start
```

`sudo -E` works only where the sudoers policy lets you keep your environment. To make `sudo` keep this one variable every time, add a drop-in with `sudo visudo -f /etc/sudoers.d/dojo-deploy`:

```
Defaults env_keep += "DOJO_DEPLOY_NO_MIGRATION_NOTICE"
```

Automation that runs the CLI on a terminal (`expect`, `script`, a pseudo-terminal in a test harness) sees the note in its captured output. Set `DOJO_DEPLOY_NO_MIGRATION_NOTICE=1` there. `DOJO_CLI_UNATTENDED=1`, which already tells the CLI never to prompt, hides it too.

### New doctor warnings on Docker Compose

After the update, `dojo-compose-cli doctor` can report two warnings it did not report before:

- **The systemd stop timeout is too short.** The unit lets `app stop` run for less than 4200 seconds. The next `app start`, `app restart` or `app upgrade` fixes it by writing a drop-in for the unit, or run `sudo -E dojo-compose-cli doctor --fix` now.
- **The internal CA is shared.** The install still uses the internal CA that the deployment files ship to every install. Run `sudo -E dojo-compose-cli certs rotate-internal` to give the install its own CA and internal certificates. It backs up the old ones under `certs/backup/`, and it refuses while DefectDojo is running unless you pass `--restart`.

Both are warnings, so plain `doctor` still exits 0. `doctor --strict` exits non-zero until they are fixed.

## Getting dojo-deploy

The first `dojo-deploy` release is **3.5.0**. A `dojo-deploy` release has the same version as the DefectDojo Pro release it ships with, so DefectDojo Pro 3.5.0 comes with `dojo-deploy` 3.5.0. A fix to `dojo-deploy` alone, between two DefectDojo Pro releases, adds a fourth number, such as 3.5.0.1.

### If you already run dojo-compose-cli or dojo-helm-cli

Update the CLI the way you always have:

```bash
# Docker Compose
sudo -E dojo-compose-cli update-binary

# Kubernetes
dojo-helm-cli update-binary
```

One run does two things. It installs the new release of the CLI you already use, built from `dojo-deploy`: `dojo-compose-cli` 2.2.0 or `dojo-helm-cli` 4.1.0. It also installs `dojo-deploy` next to the old CLI, with the same owner, group and mode:

- **Docker Compose:** next to `/usr/bin/dojo-compose-cli`, the copy on the `PATH` that the systemd unit runs, so `dojo-deploy` lands at `/usr/bin/dojo-deploy`, owned by root. It never goes into the install directory (`/opt/dojo`), even when the update runs from there.
- **Kubernetes:** in the same directory as `dojo-helm-cli`.

Starting from the releases out today (`dojo-compose-cli` 2.1.1 to 2.1.9, `dojo-helm-cli` 4.0.x), this one run is all you need. The old CLI exits as soon as its own update is done, and the new release then installs `dojo-deploy` in the background, giving up after 3 minutes. That first install prints nothing. If it fails, `dojo-compose-cli doctor` says so on its first line:

```
dojo-deploy is not installed; download it from https://cloud.defectdojo.com/tools (last install attempt <time>: <reason>)
```

The old-name CLI keeps its name, commands, options and version numbering, and prints the [note](#a-note-in-your-terminal) that links to this page. `dojo-compose-cli` also runs this update on its own before `app upgrade`, `app pull-images`, `deploy download` and `first-install`, as it did before.

From `dojo-compose-cli` 2.2.0 and `dojo-helm-cli` 4.1.0 on, `update-binary` installs or updates `dojo-deploy` itself and reports what it did in one line:

```
dojo-deploy 3.5.0 installed at /usr/bin/dojo-deploy
dojo-deploy 3.5.0 -> 3.5.0.1 at /usr/bin/dojo-deploy
dojo-deploy was not installed: <reason>. Download it from https://cloud.defectdojo.com/tools
```

The first line appears when `dojo-deploy` was not there before, and the second when an existing copy was updated. Nothing is printed when `dojo-deploy` is already current. The third line appears when `dojo-deploy` could not be installed, for example on a host that is offline or air-gapped, or when you lack permission to write to the directory. That does not fail the update: the CLI you already use is still updated and the command still exits successfully. Download `dojo-deploy` as described next.

### Downloading dojo-deploy

Most hosts don't need this, because `update-binary` installs `dojo-deploy` for you. Download it yourself on an air-gapped host, on a host that has neither old CLI, or when `update-binary` printed `dojo-deploy was not installed`.

`dojo-deploy` is listed with the other DefectDojo Pro tools at [cloud.defectdojo.com/tools](https://cloud.defectdojo.com/tools). It is published to `us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-deploy/executables`, in the same DefectDojo Pro registry that `dojo-compose-cli` and `dojo-helm-cli` come from. You log in with your license as you do for those CLIs, and the host needs the same HTTPS access to `us-south1-docker.pkg.dev`. Nothing new needs to be allowlisted. On an air-gapped host, download the binary from the tools page on a machine with internet access and copy it over.

Put the binary in a system directory on your `PATH`, such as `/usr/local/bin`, and check it:

```bash
dojo-deploy --version
dojo-deploy --help
```

`dojo-deploy --version` also names the DefectDojo Pro release it was tested with, for example `dojo-deploy version 3.5.0 (tested with DefectDojo Pro 3.5.0)`.

### Running dojo-deploy on a Docker Compose host

On a Docker Compose host, the systemd unit and your scripts run `/usr/bin/dojo-compose-cli`. The first time you run `dojo-deploy compose ...` as root, `dojo-deploy` replaces that file with a small wrapper script that runs `dojo-deploy` under the old name, so the unit and your scripts keep working. It keeps the previous file at `/usr/bin/dojo-compose-cli.pre-dojo-deploy`. To keep your own file at `/usr/bin/dojo-compose-cli`, set `DOJO_DEPLOY_SKIP_COMPOSE_LINK=true`. `dojo-deploy` only writes the wrapper when its own binary sits in `/usr/local/bin`, `/usr/bin`, `/usr/local/sbin` or `/usr/sbin`.

## Keeping the CLI up to date

How you update depends on which name you run.

| You run | Update with | What it installs |
| --- | --- | --- |
| `dojo-compose-cli` | `sudo -E dojo-compose-cli update-binary` | The newest `dojo-compose-cli` release, and `dojo-deploy` beside it |
| `dojo-helm-cli` | `dojo-helm-cli update-binary` | The newest `dojo-helm-cli` release, and `dojo-deploy` beside it |
| `dojo-deploy` | `dojo-deploy update-binary` | The newest `dojo-deploy` release |

`dojo-compose-cli` also updates itself before `app upgrade`, `app pull-images`, `deploy download` and `first-install`, then runs your command on the new binary. This is how it worked before. `dojo-helm-cli` only prints a one-line note when a newer release exists.

Under the `dojo-deploy` name, `dojo-deploy compose update-binary` and `dojo-deploy kubernetes update-binary` refuse to run, because they would overwrite `dojo-deploy` with an old-line release. Use `dojo-deploy update-binary`.

`update-binary` checks the downloaded binary and runs it before it replaces the current one. If anything fails, the current binary stays in place.

## Legacy commands

`dojo-compose-cli` and `dojo-helm-cli` are now legacy commands. They keep working, and every procedure on the [Docker Compose](/get_started/pro/onprem/docker_compose/installing_on_docker_compose/) and [dojo-helm-cli](/get_started/pro/onprem/kubernetes/installing_with_dojo_helm_cli/) pages still applies as written. For new scripts and runbooks, use `dojo-deploy`.

Every command keeps its name and options under `dojo-deploy`. Put `dojo-deploy compose` or `dojo-deploy kubernetes` where you used to type the old CLI's name. The exceptions are `update-binary` and `--version`, which become `dojo-deploy update-binary` and `dojo-deploy --version`. The tables below list each legacy command and its `dojo-deploy` equivalent.

### dojo-compose-cli

| dojo-compose-cli (legacy) | dojo-deploy |
| --- | --- |
| `dojo-compose-cli app start`, `stop`, `restart`, `upgrade` | `dojo-deploy compose app start`, `stop`, `restart`, `upgrade` |
| `dojo-compose-cli app pull-images`, `purge-images` | `dojo-deploy compose app pull-images`, `purge-images` |
| `dojo-compose-cli app backup`, `backups`, `restore` | `dojo-deploy compose app backup`, `backups`, `restore` |
| `dojo-compose-cli app change-password` | `dojo-deploy compose app change-password` |
| `dojo-compose-cli register` | `dojo-deploy compose register` |
| `dojo-compose-cli environment print`, `add`, `remove` | `dojo-deploy compose environment print`, `add`, `remove` |
| `dojo-compose-cli license print`, `set`, `status`, `update` | `dojo-deploy compose license print`, `set`, `status`, `update` |
| `dojo-compose-cli deploy download` | `dojo-deploy compose deploy download` |
| `dojo-compose-cli config print`, `set`, `rotate-secret`, `interactive` | `dojo-deploy compose config print`, `set`, `rotate-secret`, `interactive` |
| `dojo-compose-cli first-install` | `dojo-deploy compose first-install` |
| `dojo-compose-cli validate db-connection`, `deploy-version` | `dojo-deploy compose validate db-connection`, `deploy-version` |
| `dojo-compose-cli diagnostics collect` | `dojo-deploy compose diagnostics collect`, or `dojo-deploy support-bundle` ([below](#support-bundle)) |
| `dojo-compose-cli bundle create` | `dojo-deploy compose bundle create` |
| `dojo-compose-cli certs status`, `install`, `add-ca`, `self-signed`, `test`, `accept-bundles` | `dojo-deploy compose certs status`, `install`, `add-ca`, `self-signed`, `test`, `accept-bundles` |
| `dojo-compose-cli doctor` | `dojo-deploy compose doctor` |
| `dojo-compose-cli update-binary` | `dojo-deploy update-binary` |
| Global options `--verbose` (`-V`), `--version` (`-v`) | `dojo-deploy compose --verbose`, `dojo-deploy --version` |

One compose command is new: `certs rotate-internal` gives an install its own internal CA and service certificates. It is available as `dojo-compose-cli certs rotate-internal` and `dojo-deploy compose certs rotate-internal`.

### dojo-helm-cli

| dojo-helm-cli (legacy) | dojo-deploy |
| --- | --- |
| `dojo-helm-cli register` | `dojo-deploy kubernetes register` |
| `dojo-helm-cli license print` | `dojo-deploy kubernetes license print` |
| `dojo-helm-cli download-artifacts` | `dojo-deploy kubernetes download-artifacts` |
| `dojo-helm-cli preflight` | `dojo-deploy kubernetes preflight` |
| `dojo-helm-cli deploy` | `dojo-deploy kubernetes deploy` |
| `dojo-helm-cli deploy status`, `uninstall` | `dojo-deploy kubernetes deploy status`, `uninstall` |
| `dojo-helm-cli diag` | `dojo-deploy kubernetes diag`, or `dojo-deploy support-bundle` ([below](#support-bundle)) |
| `dojo-helm-cli update-binary` | `dojo-deploy update-binary` |
| Global options `--verbose` (`-V`), `--disable-update-check`, `--version` (`-v`) | `dojo-deploy kubernetes --verbose`, `--disable-update-check`, `dojo-deploy --version` |

### Commands only in dojo-deploy

`dojo-deploy` adds commands that work from an install file, a JSON description of the install, so an install or upgrade runs without prompts: `check`, `prereqs`, `install`, `upgrade`, `verify` and `support-bundle`. Run `dojo-deploy <command> --help` for each one.

## What changed since dojo-compose-cli 2.1.9 and dojo-helm-cli 4.0.1

Most changes are fixes. The ones you are most likely to notice after an update are below. The [dojo-deploy 3.5.0 release notes](/releases/pro/changelog/#dojo-deploy-350) in the DefectDojo Pro changelog have the full list.

**Both CLIs**

- **The note** described above, in a terminal only.
- **Revoked releases:** the CLIs read a signed list of DefectDojo Pro releases that have been withdrawn, from `https://intel.defectdojo.com/releases/revocations.json`. They refuse to install a revoked release, and "latest" skips it. If the list cannot be fetched, the CLI warns and carries on. Air-gapped Docker Compose installs do not fetch it. If your hosts reach the internet through an allowlist, add `intel.defectdojo.com`.

**dojo-compose-cli**

- **Shogun secret:** the CLI generates a `DD_SHOGUN_SHARED_SECRET` for each install, and replaces it when it holds a value DefectDojo ships. A value you set yourself is kept. With Shogun on, DefectDojo refuses to start on an unset, short or shipped value.
- **Stopping and systemd:** stopping the stack waits out the import service's stop grace period on releases that have one. `app start`, `app restart`, `app upgrade` and `doctor --fix` add a drop-in, `/etc/systemd/system/defectdojo-compose.service.d/50-dojo-compose-cli-stop-timeout.conf`, which sets `TimeoutStopSec=4200`. The unit file itself is not changed.
- **Upgrade refusals:** an install older than 2.58.0 must upgrade to 2.58.4 before 3.0.0 / 2.59.0 or later. `app upgrade` also refuses, before changing anything, when the installed or target version cannot be read (for example an install recorded as `latest`).
- **`doctor`:** it checks more things (the systemd stop timeout, a revoked running release, an internal CA shared by every install, SELinux labels, Docker user namespace remapping). Each is a warning, so plain `doctor` still exits 0, but `doctor --strict` exits non-zero until it is fixed.
- **TLS material:** a first install generates its own internal CA and service certificates. Existing installs keep theirs, and `doctor` warns about a shared CA. The new `certs rotate-internal` replaces it.
- **Restart:** `app restart` no longer fails when nginx or the `dojo` container restarts during startup and then stays up. The check lasts 30 seconds. It still fails when a container exits or is killed for running out of memory, or when it is still restarting, or starts again, in the last 15 seconds.
- **Configuration file:** on a new host, the first command run as root creates `/etc/defectdojo/compose.config` with mode 0660, owned by the service user and group. Before, every local user could read it until `first-install` ran. `doctor` now reports `/etc/defectdojo` as clean on a fresh host. The file is written in one step, so a crash cannot leave it half-written, and a symbolic link at that path is refused.
- **License file:** a license that is a symbolic link is refused instead of copied. `app upgrade` now carries the license copy beside the compose file (`/opt/dojo/dojopro.lic`) into the new install, owned by the service user.
- **Files:** `media/` belongs to the containers' user (uid 1001), and `customizations/` is created with mode 0755 whatever the umask.
- **SELinux hosts:** when Docker has SELinux enabled, the CLI loads `docker-compose.selinux.yml` from the deployment files so Docker labels the bind mounts. `doctor` reports unlabelled ones.
- **Rootless Docker:** the systemd unit keeps `DOCKER_HOST` and no longer starts the rootful Docker daemon at boot.
- **macOS:** the compose CLI is published for Linux only (amd64 and arm64). On macOS, `update-binary` fails, and once a newer release is published, `app upgrade`, image pulls, first install and deployment downloads refuse to run.

**dojo-helm-cli**

- **`deploy status`:** 4.0.1 printed `helm status -o json` as it came, including the release's values, which hold the license and passwords. It now prints a summary (name, namespace, status, revision, chart, app version, notes) with secrets removed. **Scripts that parsed the old JSON need `--output json`**, which prints those fields and never the values. Warnings go to standard error. If the release history cannot be read, the command warns and still exits 0. Each run also checks the revoked-release list and waits at most 2 seconds for it.
- **`diag`:** release secrets are no longer bundled. `--no-redact` keeps values as they are, but Secret data is still dropped.
- **New flags:** `deploy` takes `--kubeconfig` and `--context`. `deploy status` takes `--output` (`table` or `json`). `preflight` takes `--profile`. `download-artifacts` takes `--image-platform` and `--overwrite`. Without `--overwrite`, if a `dojopro/` chart directory in `--output-dir` differs from the pulled chart, the CLI asks on a terminal and stops when there is no terminal.

## Support bundle

`dojo-deploy support-bundle` writes one file for DefectDojo support, for a Docker Compose or a Kubernetes install. It is the recommended way to collect diagnostics. `dojo-compose-cli diagnostics collect` and `dojo-helm-cli diag` are unchanged and still work, under the old names and under `dojo-deploy compose` and `dojo-deploy kubernetes`.

Run it with no options and it finds the install by itself:

```bash
sudo -E dojo-deploy support-bundle
```

- **Docker Compose:** when the host has `/etc/defectdojo/compose.config`, it collects from the install that configuration points to. A Docker Compose install needs root and `DOJO_CLI_KEY` so it can read the CLI's configuration.
- **Kubernetes:** otherwise, or when you pass any of `--namespace`, `--release`, `--context` or `--kubeconfig`, it collects the Helm release `--release` in `--namespace`. Both default to `dojopro`, on the kubeconfig's current context. These are the same defaults as `dojo-helm-cli deploy status`. `--namespace` and `--release` must be Kubernetes names: lowercase letters, digits and `-`, at most 63 characters.

```bash
dojo-deploy support-bundle --namespace dojopro --release dojopro --context my-cluster
```

On a Docker Compose host that has lost `/etc/defectdojo/compose.config`, it falls back to Kubernetes. If no release answers, it tells you to pass `--config` or restore that file.

If you installed with `dojo-deploy install`, pass the install file instead: `dojo-deploy support-bundle --config install.json`. Without an install file, the `check` collector has nothing to read, and on Kubernetes neither does the `config` collector.

**What it collects.** On Docker Compose: instance details, install logs, the `check` results, the configuration, containers, container logs, certificates, an HTTPS probe and the systemd unit. On Kubernetes: instance details, install logs, the `check` results, the configuration, the Helm release, cluster resources, pod logs, certificates and an HTTPS probe. It keeps the last 2,000 lines of each log (`--tail` changes that). `--skip` leaves out named collectors. A collector that fails is recorded, and the others still run.

**What it redacts.** Every file is redacted as it is written: passwords, tokens, credentials inside URLs, the admin's email address, `Authorization` headers, webhook URLs, tokens in query strings, and every value the install file marks as secret, wherever it appears. A license, a private key and Kubernetes Secret data never go into a bundle. `meta/manifest.json` inside the bundle lists each redaction rule and how many times it matched. `--no-redact` turns off everything except those three, so the bundle then holds passwords. Don't use it for a bundle you send.

**Where it goes.** The bundle is a `.tar.gz` with mode `0600`, written to the current directory unless you pass `--output`. Nothing is uploaded. Look through it before you send it to support. `dojo-deploy support-bundle --validate <bundle.tar.gz>` checks that a bundle is valid.

## If a release has a problem

You don't need to pin a CLI version. If a `dojo-compose-cli`, `dojo-helm-cli` or `dojo-deploy` release turns out to be bad, DefectDojo withdraws it and publishes a fixed release. `update-binary`, or the automatic update `dojo-compose-cli` runs, then installs the fix.

### Emergency only: installing an earlier release

Use this only when support asks you to. `update-binary` does not keep the binary it replaces, so going back means installing an earlier release by version.

**dojo-compose-cli.** Pin the version, and allow the downgrade:

```bash
sudo -E dojo-compose-cli update-binary --version 2.1.9 --allow-downgrade
```

The pin lasts only until the next automatic update. `app upgrade`, `app pull-images`, `deploy download` and `first-install` update the CLI to the newest release first, and 2.1.9 does this too.

**dojo-helm-cli.**

```bash
dojo-helm-cli update-binary --version 4.0.1
```

**dojo-deploy.** `dojo-deploy update-binary --version <version>` installs an earlier `dojo-deploy` release.

If `dojo-deploy compose` replaced `/usr/bin/dojo-compose-cli` with its wrapper, put the previous file back and stop `dojo-deploy` from writing the wrapper again:

```bash
sudo install -m 0755 /usr/bin/dojo-compose-cli.pre-dojo-deploy /usr/bin/dojo-compose-cli
export DOJO_DEPLOY_SKIP_COMPOSE_LINK=true
```

## Questions or support

Contact [support@defectdojo.com](mailto:support@defectdojo.com). Include a support bundle, or the output of `diagnostics collect` or `diag`, if you can.
