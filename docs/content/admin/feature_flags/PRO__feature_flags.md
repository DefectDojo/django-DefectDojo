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

### Features that are not listed

The page lists the features you can choose to adopt. Two kinds of feature are absent from it.

**Always on.** Once a feature reaches general availability it is on for every instance and stops being listed, because there is no longer a decision to make:

* **Downstream Connectors** — see [Downstream Connectors](/connectors/downstream/about/)
* **Universal Parser** — see [Universal Parser](/import_data/pro/specialized_import/universal_parser/)
* **Asset Hierarchy** — see [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/)
* **Appearance** and **Feature Flags** — the two Settings pages of the same name

Nothing changes for your instance if you had one of these turned on. If you had one turned off, it is now on: these features are part of DefectDojo Pro rather than opt-in. Contact [DefectDojo Support](mailto:support@defectdojo.com) if that is a problem for your instance.

**Enabled by DefectDojo on request.** A few capabilities depend on infrastructure that is provisioned per instance, so they are switched on by DefectDojo rather than from this page:

* **Scheduling Service** — see [Scheduling Rules](/automation/rules_engine/scheduling/)

Contact [DefectDojo Support](mailto:support@defectdojo.com) to have one of these enabled. If it is already on for your instance, it stays on.

## Turning a feature on or off

1. Find the feature in the list.
2. Click its toggle.
3. The change takes effect immediately. Other users pick the change up on their next page load.

Some features show a confirmation dialog before the change is applied. This happens when enabling a feature that carries a warning (for example one that requires a restart or may affect existing data), or one that cannot be turned back off.

Turning a feature off is normally just the reverse of turning it on. The exceptions are called out in [When a toggle is locked](#when-a-toggle-is-locked).

### Restart Recommended

A few features carry a **Restart Recommended** tag next to their name (a stronger **Restart Required** variant also exists). The tag means that part of the feature is decided when DefectDojo starts: the Classic UI pages, and some `/api/v2` route wiring, read their configuration once at boot. A toggle reaches the Pro UI right away, but those start-time surfaces only pick it up after the serving process restarts. A **Restart Recommended** feature still works in the Pro UI without a restart; the restart only reconciles the remaining surfaces.

The tag is shown only while a restart is actually outstanding. Once the running server already reflects the flag's current value (because it has been restarted since you changed the flag), the tag disappears on your next page load. Turn a flag on and then back off without restarting and the tag clears too, because nothing is left to reconcile. There is nothing to dismiss: the tag tracks the real state of the running server, so a lingering tag means a restart is still pending, and its absence means the running server is already in sync.

### Organization / Asset Relabeling

**Organization / Asset Relabeling** renames "Product Type" to "Organization" and "Product" to "Asset". It is on by default and toggles from this page like any other feature, but it is worth knowing which parts of DefectDojo it governs:

* The **Pro UI** follows this toggle. The new labels appear on your next page load.
* The **Classic UI** pages, their URLs, and generated reports take their naming from the `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` deployment setting (also on by default), which is read when DefectDojo starts. This toggle does not change them, and restarting does not make it change them.

The stored toggle was seeded from that deployment setting, so the two agree until you change one of them. If you turn relabeling off here and you also use the Classic UI, set `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL=False` on your deployment and restart so both surfaces match. On [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), contact [DefectDojo Support](mailto:support@defectdojo.com) to have the deployment setting changed.

The feature carries a **Restart Recommended** tag on the Feature Flags page for this reason: the naming used outside the Pro UI is fixed when the process starts. The tag shows only while a restart is still outstanding, and clears once you have restarted or toggled the flag back (see [Restart Recommended](#restart-recommended)). Relabeling is cosmetic either way. Database models, field names, and API endpoints are unchanged, so existing automation keeps working. See [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/).

### Locations

**Locations** replaces the legacy Endpoints model: with it on, imports create Location records and the UI and API surface Locations; with it off, imports create Endpoints. It is off by default and is enabled from this page like any other feature, but a few things are worth knowing:

* The **Pro UI** and the **import pipeline** follow this toggle. After you enable Locations, new imports create Locations and the Locations pages appear on your next page load, without a restart.
* The **Classic UI** pages and the `/api/v2` endpoint/location route wiring are decided from the `DD_V3_FEATURE_LOCATIONS` deployment setting when DefectDojo starts. This toggle does not change them, and restarting does not make it change them. If you use the Classic UI or depend on the `/api/v2` endpoint routes, set `DD_V3_FEATURE_LOCATIONS` to match and restart so every surface agrees. The stored toggle is seeded from that deployment setting on upgrade, so an instance that already ran with `DD_V3_FEATURE_LOCATIONS=True` comes up with the toggle already on (and locked), and the database owns the value from then on.
* Enabling existing history is not automatic. Your existing data stays as it is until you run the **data-migration suite** that appears under this row once Locations is on: three backfills (endpoints, dependencies, and source-code locations) followed by an identity rehash that unlocks once all three finish. Each is superuser-run, shows progress, is safe to re-run, and can be cancelled while running (it stops at the next batch boundary and can be resumed). Each item can also be **marked complete**, automatically when a run here finishes or by hand for a migration you ran another way, so the page stops prompting you to run it. See [Migrating from Endpoints](/asset_modelling/locations/pro__migrating_from_endpoints/).

Enabling Locations is **self-service and one-way**: once it is on, the toggle locks (shown as **Cannot Be Disabled**), because turning it back off would require reversing the endpoint-to-location data migration, which is not yet supported. The feature carries a **Restart Recommended** tag for the Classic UI / API reason above; as with any such feature, the tag clears once the server has been restarted (see [Restart Recommended](#restart-recommended)).

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

A small number of features are read from your deployment configuration instead. They change how the application starts, so they cannot be flipped at runtime. These appear on the page as read-only, labeled **Managed by deployment**, and name the environment variable that controls them.

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
| Request a New Connector | [DefectDojo Pro (Cloud)](/get_started/pro/cloud/) only | Always on for Cloud instances, and not offered on-premise. No longer listed on the Feature Flags page. |
| Locations | Both | Feature Flags page for the Pro UI and import pipeline; the Classic UI and `/api/v2` route wiring follow the `DD_V3_FEATURE_LOCATIONS` deployment setting. Enabling is self-service and one-way — once on, it cannot be turned back off. See [above](#locations) and [Locations Overview](/asset_modelling/locations/pro__locations_overview/). |
| Organization / Asset Relabeling | Both | Feature Flags page for the Pro UI; the Classic UI, its URLs and generated reports follow the `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` deployment setting. See [above](#organization--asset-relabeling). |

Every other optional feature is toggled directly on the Feature Flags page on both Cloud and On-Premise instances.

## Reading feature flags outside the UI

You do not have to open the Feature Flags page to find out which features are enabled — flag state can also be read programmatically, which is useful when automation needs to check that a capability is available before depending on it.

```
GET /api/v2/defectdojo_information/feature_flags/
```

This returns a JSON array with one object per feature flag. Alongside the flag's `key`, `title` and `description`, each object reports the values automation usually wants: `effective` (whether the feature is actually on for this instance), `default`, `application_value` (the instance's own setting, or `null` if unset), `editable`, and `locked_reason` where a flag cannot be changed. Flags retired from the product are omitted.

Any **authenticated** user can read it — no superuser role is required. For the exact response schema on your version, see your instance's interactive API documentation at `/api/v2/oa3/swagger-ui/`, which is generated from the running build. See also the [API v2 documentation](/automation/api/api-v2-docs/).

The same read-only listing is also published on the instance's `/api/mcp/` surface, at `/api/mcp/defectdojo_information/feature_flags/`.

This endpoint is **read-only**. Turning a feature on or off is still done from the Feature Flags page, or — for the deployment-configured features noted above — in your deployment settings.

## Frequently asked questions

**A feature I want is not in the list.**
The list shows optional features only. Capabilities that are always on do not appear. A feature also leaves the list once it becomes standard — it is then on for every instance and there is nothing to switch. If you expected a feature that is missing, confirm your license includes it, then contact [DefectDojo Support](mailto:support@defectdojo.com).

**A feature I had turned off is on again after an upgrade.**
A feature that becomes standard is turned on everywhere, and the setting you had chosen for it while it was optional is cleared as part of that release — otherwise an instance that had opted out would stay off with no toggle left to change it back. This only happens to features that leave the list; everything still shown keeps your setting. If a standard feature causes you a problem, contact [DefectDojo Support](mailto:support@defectdojo.com), who can turn it off for your instance.

**I turned a feature on but I do not see it.**
Reload the page — menu entries and routes are evaluated when the page loads, so a newly enabled feature appears on the next load rather than instantly in the current view.

**Will upgrading change my settings?**
For every feature on this page, yes — upgrading preserves the ones you have turned on and the ones you have turned off. The exception is a feature that becomes standard in that release and leaves the page; see the question above.
