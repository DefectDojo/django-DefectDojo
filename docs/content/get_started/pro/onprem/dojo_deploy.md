---
title: "Moving to dojo-deploy"
description: "dojo-deploy replaces dojo-compose-cli and dojo-helm-cli: what changes for an existing install, the command mapping, the support bundle, and what to do if a release has a problem"
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

When you run `dojo-compose-cli` or `dojo-helm-cli` by hand in a terminal, the CLI prints a two-line note before running your command:

```
dojo-compose-cli is now part of dojo-deploy. Install dojo-deploy (see https://docs.defectdojo.com/get_started/pro/onprem/dojo_deploy/),
then run "dojo-deploy compose <command>". Set DOJO_DEPLOY_NO_MIGRATION_NOTICE=1 to hide this note.
```

`dojo-helm-cli` prints the same note, naming `dojo-deploy kubernetes <command>` instead.

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

`sudo` drops most environment variables by default (its `env_reset` setting), so an exported variable does not reach `sudo dojo-compose-cli ...`. Pass it on the command line:

```bash
sudo DOJO_DEPLOY_NO_MIGRATION_NOTICE=1 dojo-compose-cli app start
```

Or let `sudo` keep it, with a drop-in file edited through `sudo visudo -f /etc/sudoers.d/dojo-deploy`:

```
Defaults env_keep += "DOJO_DEPLOY_NO_MIGRATION_NOTICE"
```

`sudo -E` keeps your environment only if the sudoers policy allows it.

Automation that runs the CLI on a terminal (`expect`, `script`, a pseudo-terminal in a test harness) sees the note in its captured output. Set `DOJO_DEPLOY_NO_MIGRATION_NOTICE=1` there. `DOJO_CLI_UNATTENDED=1`, which already tells the CLI never to prompt, hides it too.

## Getting dojo-deploy

`dojo-deploy` is published to `us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-deploy/executables`, in the same DefectDojo Pro registry that `dojo-compose-cli` and `dojo-helm-cli` come from. You log in with your license as you do for those CLIs, and the host needs the same HTTPS access to `us-south1-docker.pkg.dev`. Nothing new needs to be allowlisted.

> **TODO (owner, remove before merge):** add the exact download command and the first `dojo-deploy` version once the `dojo-deploy/executables` repository exists.

Put the binary in a system directory on your `PATH`, such as `/usr/local/bin`, and check it:

```bash
dojo-deploy --version
dojo-deploy --help
```

On a Docker Compose host, the systemd unit and your scripts run `/usr/bin/dojo-compose-cli`. The first time you run `dojo-deploy compose ...` as root, `dojo-deploy` replaces that file with a small wrapper script that runs `dojo-deploy` under the old name, so the unit and your scripts keep working. It keeps the previous file at `/usr/bin/dojo-compose-cli.pre-dojo-deploy`. To keep your own file at `/usr/bin/dojo-compose-cli`, set `DOJO_DEPLOY_SKIP_COMPOSE_LINK=true`. `dojo-deploy` only writes the wrapper when its own binary sits in `/usr/local/bin`, `/usr/bin`, `/usr/local/sbin` or `/usr/sbin`.

## Keeping the CLI up to date

How you update depends on which name you run.

| You run | Update with | What it installs |
| --- | --- | --- |
| `dojo-compose-cli` | `sudo -E dojo-compose-cli update-binary` | The newest `dojo-compose-cli` release |
| `dojo-helm-cli` | `dojo-helm-cli update-binary` | The newest `dojo-helm-cli` release |
| `dojo-deploy` | `dojo-deploy update-binary` | The newest `dojo-deploy` release |

`dojo-compose-cli` also updates itself before `app upgrade`, `app pull-images`, `deploy download` and `first-install`, then runs your command on the new binary. This is how it worked before. `dojo-helm-cli` only prints a one-line note when a newer release exists.

Under the `dojo-deploy` name, `dojo-deploy compose update-binary` and `dojo-deploy kubernetes update-binary` refuse to run, because they would overwrite `dojo-deploy` with an old-line release. Use `dojo-deploy update-binary`.

`update-binary` checks the downloaded binary and runs it before it replaces the current one. If anything fails, the current binary stays in place.

## Command mapping

Every command keeps its name, options and help text. Put `dojo-deploy compose` or `dojo-deploy kubernetes` where you used to type the old CLI's name.

### dojo-compose-cli

| dojo-compose-cli | dojo-deploy |
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

| dojo-helm-cli | dojo-deploy |
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

Most changes are fixes. The ones you can notice after an update:

- **The note** described above, in a terminal only.
- **systemd (Docker Compose):** `app start`, `app restart`, `app upgrade` and `doctor --fix` add a drop-in, `/etc/systemd/system/defectdojo-compose.service.d/50-dojo-compose-cli-stop-timeout.conf`, which gives the service time to stop cleanly. `doctor` warns when it is missing.
- **Upgrades:** the CLI refuses to install a DefectDojo release that has been withdrawn, and refuses upgrade paths that are not supported.
- **Files (Docker Compose):** the CLI sets file modes and ownership in the install directory, and writes its configuration file in one step, so a crash cannot leave it half-written.
- **SELinux hosts (Docker Compose):** when Docker has SELinux enabled, the CLI loads `docker-compose.selinux.yml` (shipped with DefectDojo Pro 3.4.202 and later) so Docker labels the bind mounts. `doctor` reports unlabelled ones.
- **`dojo-helm-cli deploy status`:** if the release history cannot be read, the command warns and carries on. Warnings go to standard error, so JSON output on standard output stays clean.
- **`dojo-helm-cli diag`:** redaction covers more secrets.
- **macOS:** `dojo-compose-cli` is no longer built for macOS. Docker Compose installs run on Linux.
- **Shogun secret (Docker Compose):** the CLI generates a `DD_SHOGUN_SHARED_SECRET` for each install, and replaces it when it holds a value DefectDojo ships. A value you set yourself is kept. With Shogun on, DefectDojo refuses to start on an unset, short or shipped value.

> **TODO (owner, remove before merge):** link the release notes once they are published, and check this list against them.

## Support bundle

`dojo-deploy support-bundle` writes one file for DefectDojo support, for a Docker Compose or a Kubernetes install. It is the recommended way to collect diagnostics. `dojo-compose-cli diagnostics collect` and `dojo-helm-cli diag` are unchanged and still work, under the old names and under `dojo-deploy compose` and `dojo-deploy kubernetes`.

```bash
sudo -E dojo-deploy support-bundle --config install.json
```

It reads the install file named by `--config`. A Docker Compose install needs root and `DOJO_CLI_KEY` so it can read the CLI's configuration.

An install made with `first-install` or `dojo-helm-cli deploy` has no install file. For those installs, use `diagnostics collect` or `diag`.

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
