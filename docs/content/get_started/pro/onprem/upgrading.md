---
title: "Upgrading DefectDojo Pro (On-Premise)"
description: "Supported upgrade procedure for self-hosted DefectDojo Pro, on both the Helm chart and Docker Compose"
draft: false
weight: 6
audience: pro
---

This page describes the supported upgrade procedure for self-hosted DefectDojo Pro. It applies to both deployment methods; the detailed, method-specific steps live on their own pages:

- **Kubernetes (Helm chart):** [DefectDojo Pro Upgrade Guide](/get_started/pro/onprem/kubernetes/upgrading_on_kubernetes/)
- **Docker Compose (`dojo-compose-cli`):** [DefectDojo Pro Upgrade Guide (Docker Compose)](/get_started/pro/onprem/docker_compose/upgrading_on_docker_compose/)

## Upgrade everything as one unit

Each DefectDojo Pro release consists of container image versions, deployment files (the Helm chart or the Docker Compose deployment files), and the Pro settings files. These are built and tested together and must be upgraded together as one unit.

Upgrading only the image tags is not supported and will break your deployment.

## Settings files and upgrades

DefectDojo Pro ships a `pro_settings.py` file with every release, and the file changes with nearly every version. Do not carry a copy of `pro_settings.py` forward across upgrades, and do not patch an older copy by hand. The application must always run the `pro_settings.py` that matches its version.

Put your own customizations in `local_settings.py`, never in `pro_settings.py`. Your `local_settings.py` is preserved across upgrades. Both deployment methods ship and mount the matching `pro_settings.py` and your `local_settings.py` automatically, so there is nothing to copy or migrate by hand.

## Supported upgrade procedure

1. Review the release notes for every version between your current version and your target version, not just the target itself. See the [DefectDojo Pro Changelog](/releases/pro/changelog/) and the version-specific [upgrade notes](/releases/os_upgrading/upgrading_guide/).
2. Back up your database, and the rest of what [Backing Up a Self-Hosted Deployment](/get_started/pro/onprem/backing_up/) lists. If an upgrade has to be undone, [Restoring a Self-Hosted Deployment](/get_started/pro/onprem/restoring/) covers bringing that backup back.
3. Follow the steps for your deployment method: [Kubernetes (Helm)](/get_started/pro/onprem/kubernetes/upgrading_on_kubernetes/) or [Docker Compose](/get_started/pro/onprem/docker_compose/upgrading_on_docker_compose/). Do not change image tags independently of the release.

## Reading the initializer's result

Every upgrade runs the initializer once before the application starts: the `init` container on Docker Compose, the initializer Job on Kubernetes. It applies the database migrations and then runs DefectDojo's system checks. Its exit code says how far it got:

| Exit code | Migrations | System checks | What to do |
| --- | --- | --- | --- |
| `0` | All applied | Passed | Nothing. The upgrade is complete. |
| `2` | All applied | At least one failed | Fix the configuration problem the log names, then start the initializer again. The database is already upgraded, so **do not restore your backup** to retry the upgrade. |
| `1` | Check the summary | Not run | Something other than a system check failed: a migration, or a step before or after the migrations (for example the cache or a data seed). The migration summary printed just before the exit shows whether every migration applied. Fix the cause the log names and start the initializer again. Restore your backup only when the summary shows unapplied migrations that cannot be completed. |

On a non-zero exit the initializer prints the migration state of each app before it stops, so the log shows whether the database was upgraded. Abridged example (the real output lists every app):

```
Migration state (manage.py showmigrations --skip-checks lists every migration):
  dojo: 301 of 301 applied
  pro: 250 of 251 applied (not applied: 0251_example)
```

To see the code after the fact:

- **Docker Compose:** `docker inspect --format '{{.State.ExitCode}}' init`
- **Kubernetes:** `kubectl get pod -n <namespace> -l app.kubernetes.io/component=initializer -o jsonpath='{.items[*].status.containerStatuses[*].state.terminated.exitCode}'`

When `DD_INITIALIZE=false` skips the migrations, exit code `2` still means a system check failed, and the database is unchanged.

If you have questions about upgrading your on-premise deployment, contact [support@defectdojo.com](mailto:support@defectdojo.com).
