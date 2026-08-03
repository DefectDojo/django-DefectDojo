---
title: "Menu Badges"
description: "What the BETA, NEW, LEGACY and DEPRECATED tags in the DefectDojo Pro sidebar mean, and what each one asks you to do"
weight: 7
audience: pro
---

Entries in the DefectDojo Pro sidebar can carry a small coloured tag. Each one answers a different question about the feature it sits beside, and two of them are links.

| Badge | Colour | Means | What it asks of you |
| --- | --- | --- | --- |
| `NEW` | Green | Recently released | Nothing — it is there so you notice the feature |
| `BETA` | Orange | Working, still being finished; behaviour may change between releases | Try it, and expect rough edges |
| `LEGACY` | Red | Superseded by a newer feature, with no announced removal date | Prefer the replacement for new work |
| `DEPRECATED` | Red | Scheduled for removal in a named release | Migrate before that release |

![The LEGACY badge on the Jira menu entry](images/menu_badge_legacy.png)

## LEGACY and DEPRECATED are not the same thing

The distinction is deliberate, because the two states call for different responses.

**`DEPRECATED`** means a removal has been announced. Hovering the badge tells you the release it goes away in, and clicking it opens the deprecation notice:

> \<Feature\> is deprecated and will be removed by \<release\>. Click for the deprecation notice.

**`LEGACY`** means the feature has been superseded but no removal has been scheduled. There is deliberately no date in the hover text, because inventing one would be worse than saying nothing. Instead it names the replacement and links to its documentation:

> \<Feature\> is superseded by \<replacement\> and will not receive new development. Click for its documentation.

A `LEGACY` feature keeps working and keeps getting fixes. It just will not gain new capability, so anything you build now is better built on the replacement.

Both badges are links, because a tooltip closes the moment your pointer leaves it and so cannot hold a clickable link. Clicking either badge opens its notice in a new tab; it does not navigate the menu entry underneath.

## What currently carries a badge

**`LEGACY`**

* **Connect > Jira** — the original per-product Jira integration, superseded by the downstream connector for Jira. See [Pro Integrations](/issue_tracking/pro_integration/integrations/).

**`DEPRECATED`**

* **Settings > Configuration > Tool Types**
* **Settings > Configuration > Tool Configurations**

Both are removed in **3.5.0**, along with the API-based (pull) parsers they exist to configure. The [3.2 upgrade notes](/releases/os_upgrading/3.2/) explain what to migrate to and by when.

![DEPRECATED badges under Settings > Configuration](images/menu_badge_deprecated.png)

Where a label and its badge do not fit side by side in the sidebar, the badge wraps onto its own line beneath the label rather than being truncated.

## Related

* [3.2 upgrade notes](/releases/os_upgrading/3.2/) — the current deprecations and their removal release
* [Feature Flags](/admin/feature_flags/pro__feature_flags/) — turning optional features, including beta ones, on and off
