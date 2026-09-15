---
title: "DefectDojo Pro Upgrade Guide (Docker Compose)"
description: "Upgrade a self-hosted DefectDojo Pro deployment that runs on Docker Compose with dojo-compose-cli"
draft: false
weight: 2
audience: pro
aliases:
  - /get_started/pro/onprem/upgrading_on_docker_compose/
---

This guide covers upgrading a self-hosted DefectDojo Pro deployment that runs on Docker Compose, managed with `dojo-compose-cli`. If you run on Kubernetes, see the [DefectDojo Pro Upgrade Guide](/get_started/pro/onprem/kubernetes/upgrading_on_kubernetes/) for the Helm chart instead.

Each DefectDojo Pro release is a set of container images, deployment files, and settings that are built and tested together. Upgrade them together, and do not change image tags on their own.

## Before you upgrade

Back up your database first, and read the release notes for every version between your current one and your target rather than only the target. See the [upgrade notes](/releases/os_upgrading/upgrading_guide/) and the [DefectDojo Pro Changelog](/releases/pro/changelog/).

Keep your own settings in `/opt/dojo/customizations/local_settings.py`. That file is yours and survives upgrades.

## Upgrade in one command

The CLI can do the whole upgrade, prompting for the version:

```bash
dojo-compose-cli app upgrade
```

## Upgrade step by step

If you would rather do it in steps, stop the application, set the new version, download the matching deployment files, then start again:

```bash
dojo-compose-cli app stop
dojo-compose-cli config set --version x.y.z --deploy-version x.y.z
dojo-compose-cli deploy download
dojo-compose-cli app start
```

The version you set selects the image tags, and `deploy download` fetches the deployment files that match it. The download step compares the incoming `docker-compose.yml`, nginx configuration, and `local_settings.py` against what you already have, and tells you when they differ so you can reconcile your changes. Adding `--overwrite` accepts the new versions of those files and discards local modifications to them, so use it deliberately.

## Air-gapped upgrades

In an air-gapped deployment, `app upgrade` is declined because it reaches the registry. Upgrade by repeating the staged image-transfer route you used to install: pull the new images on the staging host, move the bundle across, load it on the application host, then set the new `--version` and `--deploy-version` and restart. See [Installing DefectDojo Pro in an Air-Gapped Environment](/get_started/pro/onprem/docker_compose/air_gapped_install/) for the full procedure.

## Rollback

Docker Compose has no automatic rollback. To return to the previous release, set the prior version and re-download the matching deployment files:

```bash
dojo-compose-cli app stop
dojo-compose-cli config set --version x.y.z --deploy-version x.y.z
dojo-compose-cli deploy download
dojo-compose-cli app start
```

**Database migrations do not roll back.** Setting an older version restores the images and deployment files, but it does not reverse a schema migration the upgrade applied. If the upgrade migrated the database, restore from the backup you took before upgrading, or coordinate a manual migration reversal with DefectDojo support before you start the older version. If you are several releases behind, contact [support@defectdojo.com](mailto:support@defectdojo.com).

## Questions or support

If an upgrade does not complete, `dojo-compose-cli diagnostics collect` gathers a report bundle that is the fastest way for us to help. Send it, along with what you were running when it failed, to [support@defectdojo.com](mailto:support@defectdojo.com).
