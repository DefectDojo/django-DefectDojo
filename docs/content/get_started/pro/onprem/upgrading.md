---
title: "Upgrading DefectDojo Pro (On-Premise)"
description: "Supported upgrade procedure for self-hosted DefectDojo Pro deployments using the Helm chart"
draft: false
weight: 5
audience: pro
---

This page describes the supported upgrade procedure for self-hosted DefectDojo Pro deployments that use the DefectDojo Pro Helm chart.

## Upgrade everything as one unit

Each DefectDojo Pro release consists of a Helm chart version, container image versions, and the Pro settings files. These are built and tested together and must be upgraded together as one unit.

Upgrading only the image tags is not supported and will break your deployment.

## Settings files and upgrades

DefectDojo Pro ships a `pro_settings.py` file with every release, and the file changes with nearly every version. Do not carry a copy of `pro_settings.py` forward across upgrades, and do not patch an older copy by hand. The application must always run the `pro_settings.py` that matches its version.

Put your own customizations in `local_settings.py`, never in `pro_settings.py`. Your `local_settings.py` is preserved across upgrades.

The Helm chart ships and mounts the matching `pro_settings.py` and your `local_settings.py` automatically. When you upgrade using the chart, there is nothing to copy or migrate by hand.

## Supported upgrade procedure

1. Review the release notes for every version between your current version and your target version, not just the target itself. See the [DefectDojo Pro Changelog](/releases/pro/changelog/) and the version-specific [upgrade notes](/releases/os_upgrading/upgrading_guide/).
2. Back up your database.
3. Upgrade to the Helm chart release that matches your target application version, reusing your existing values files. Do not change image tags independently of the chart version.

If you have questions about upgrading your on-premise deployment, contact [support@defectdojo.com](mailto:support@defectdojo.com).
