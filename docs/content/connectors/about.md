---
title: "About Connectors"
description: "The unified home for Upstream and Downstream Connectors in the Pro UI"
summary: ""
date: 2026-07-14T00:00:00+00:00
lastmod: 2026-07-14T00:00:00+00:00
draft: false
weight: 1
chapter: true
sidebar:
  collapsed: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
pro-feature: true
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Connectors are a DefectDojo Pro-only feature.</span>

**Connectors** is the single home in the DefectDojo Pro UI for every tool DefectDojo talks to, in either direction. It merges two features that were previously configured in separate places:

* **Upstream Connectors** (formerly **API Connectors**) pull findings and asset inventory *in* from your scanners and security tools.
* **Downstream Connectors** (formerly **Integrations**) push findings *out* to your issue trackers and ticketing systems.

If you think of DefectDojo as the hub of your security data, Upstream Connectors are how data arrives, and Downstream Connectors are how remediation work leaves.

## Where to find Connectors

In the Pro UI sidebar, open the **Connectors** group under the **Import** header:

* **Connectors > Upstream Connectors** — replaces the old **API Connectors** entry (previously under Import).
* **Connectors > Downstream Connectors** — replaces the old **Integrations** entry (previously under Settings). This direction is currently in **Beta**.

Old bookmarks and deep links keep working: the legacy **API Connectors** and **Integrations** URLs automatically redirect to the new **Upstream Connectors** and **Downstream Connectors** pages.

## Who can see what

* **Upstream Connectors** is visible to users with a Global Role of Reader or higher.
* **Downstream Connectors** is visible to superusers only, and is currently in **Beta** for Cloud-hosted DefectDojo Pro instances.

The **Connectors** group appears in the sidebar if at least one of the two pages is visible to you.

## The Connectors pages

Both directions share the same refreshed layout:

* Each tool is shown as a full-width **tile** — logo on the left, the tool name and a short description in the middle, and an action button on the right.
* Each section has a **search box** that filters tiles by tool name as you type.

On the **Upstream Connectors** page:

* **Configured Connectors** lists the connectors you have already set up. Each tile shows an operational health summary (health status, last operation, and total / mapped record counts) and a **Manage Configuration** menu with **Manage Records & Operations**, **Edit Configuration**, and **Delete Configuration** actions.
* **Available Connectors** lists the supported tools you have not yet configured, each with an **Add Configuration** button.
* A filter in the page header narrows both sections by connector type: **All**, **Asset** (or **Asset**, depending on your instance's vocabulary) for connectors that import asset inventory, and **Finding** for connectors that import vulnerability data.

On the **Downstream Connectors** page:

* **Available Integrations** lists every supported issue tracker. Tiles for integrations you have configured show a count of existing Integration Instances.

## Next Steps

* Read [About Upstream Connectors](/connectors/upstream/about/) and [add your first Upstream Connector](/connectors/upstream/add_edit/) to start importing findings automatically.
* Read the [Downstream Connectors guide](/connectors/downstream/about/) to push findings to your issue trackers.
