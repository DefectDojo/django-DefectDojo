---
title: "Feature Flags"
description: "Turn optional DefectDojo Pro features on and off from the DefectDojo UI"
weight: 1
audience: pro
---

Feature Flags let you turn optional DefectDojo Pro capabilities on and off for your own instance — features that previously could only be enabled by contacting DefectDojo Support can now be self-served from the UI.

The Feature Flags page is visible to **superusers** only. Other users, including Global Owners, do not see it.

## Opening the Feature Flags page

Go to **Settings > Feature Flags** in the left sidebar.

The page lists every optional feature with:

* **Name** — the feature, with a **BETA** tag when it is still in beta
* **Description** — what the feature does
* **Documentation link** — where documentation exists for that feature
* **Toggle** — whether the feature is currently on

Use the search box to filter the list by feature name or description.

## Turning a feature on or off

1. Find the feature in the list.
2. Click its toggle.
3. The change takes effect immediately. You do not need to restart anything, and other users pick the change up on their next page load.

Some features show a confirmation dialog before the change is applied. This happens when enabling a feature that carries a warning (for example one that requires a restart or may affect existing data), or one that cannot be turned back off.

Turning a feature off is normally just the reverse of turning it on. The exceptions are called out in the next section.

## When a toggle is locked

A feature you cannot change is shown with a lock badge explaining why:

| Badge | What it means | What to do |
| --- | --- | --- |
| **Managed by DefectDojo** | DefectDojo has set this feature centrally for your instance. Your setting cannot override it. | Contact [DefectDojo Support](mailto:support@defectdojo.com) if you need it changed. |
| **Unavailable on This Deployment** | The feature is not offered on your installation type. See [Feature availability](#feature-availability) below. | Nothing. The feature is not applicable to your instance. |
| **Cannot Be Disabled** | The feature is already on and is one way. There is no mechanism to reverse it. | Nothing. This is expected. |
| **Managed by deployment** | The feature is controlled by your deployment configuration rather than by this page. | See [DefectDojo Pro (On-Premise)](#defectdojo-pro-on-premise) below. |

## DefectDojo Pro (Cloud)

On [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), **Settings > Feature Flags** is the only place you need. Toggle a feature on and it is live.

Two things are handled by DefectDojo rather than by you:

* **Managed by DefectDojo** — the feature is pinned centrally. Contact [DefectDojo Support](mailto:support@defectdojo.com) to have it changed.
* **Managed by deployment** — the feature is part of how your instance is provisioned. Contact Support for these as well, since Cloud instances do not expose deployment configuration to customers.

Cloud instances also have access to features that are not offered on-premise. See [Feature availability](#feature-availability).

## DefectDojo Pro (On-Premise)

On [DefectDojo Pro (On-Premise)](/get_started/pro/onprem/), most features work exactly as they do on Cloud: open **Settings > Feature Flags** and toggle them.

A small number of features are read from your deployment configuration instead — they change how the application starts, so they cannot be flipped at runtime. These appear on the page as read-only, labeled **Managed by deployment**, and name the environment variable that controls them, for example `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`.

Because these features require a restart, and some of them cannot be reversed once enabled, check the feature's own documentation before changing one. Several are best enabled with help from [DefectDojo Support](mailto:support@defectdojo.com).

To change one of those features:

1. Set the environment variable on your DefectDojo deployment. The page tells you which variable to set.
2. Restart DefectDojo so the new value is read at startup.
3. Reload the Feature Flags page to confirm the new state.

Because these values are read at startup, changing them in the UI is not possible, and toggling them in your environment without a restart has no effect.

Features that are offered only on Cloud appear as **Unavailable on This Deployment** on an on-premise instance. This is expected and is not a licensing problem.

## Feature availability

Most features are available on both installation types. The exceptions are:

| Feature | Availability | How it is controlled |
| --- | --- | --- |
| Downstream Connections | [DefectDojo Pro (Cloud)](/get_started/pro/cloud/) only | Feature Flags page. Shown as **Unavailable on This Deployment** on-premise, which does not run the required infrastructure. See [Pro Integrations](/issue_tracking/pro_integration/integrations/). |
| Request a New Connector | [DefectDojo Pro (Cloud)](/get_started/pro/cloud/) only | Feature Flags page. Shown as **Unavailable on This Deployment** on-premise. |
| Locations | Both | Deployment configuration. Locations is in Beta and cannot be turned back off once enabled, so contact [DefectDojo Support](mailto:support@defectdojo.com) to have it enabled. See [Locations Overview](/asset_modelling/locations/pro__locations_overview/). |
| Organization / Asset Relabeling | Both | Deployment configuration: `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`. |

Every other optional feature is toggled directly on the Feature Flags page on both Cloud and On-Premise instances.

## Frequently asked questions

**A feature I want is not in the list.**
The list shows optional features only. Capabilities that are always on do not appear. If you expected a feature that is missing, confirm your license includes it, then contact [DefectDojo Support](mailto:support@defectdojo.com).

**I turned a feature on but I do not see it.**
Reload the page — menu entries and routes are evaluated when the page loads, so a newly enabled feature appears on the next load rather than instantly in the current view.

**Will upgrading change my settings?**
No. Upgrading preserves the features you have turned on and the ones you have turned off.
