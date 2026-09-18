---
title: "Upgrading DefectDojo Pro (On-Premise)"
description: "Supported upgrade procedure for self-hosted DefectDojo Pro, on both the Helm chart and Docker Compose"
draft: false
weight: 4
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
2. Back up your database.
3. Follow the steps for your deployment method: [Kubernetes (Helm)](/get_started/pro/onprem/kubernetes/upgrading_on_kubernetes/) or [Docker Compose](/get_started/pro/onprem/docker_compose/upgrading_on_docker_compose/). Do not change image tags independently of the release.

If you have questions about upgrading your on-premise deployment, contact [support@defectdojo.com](mailto:support@defectdojo.com).
