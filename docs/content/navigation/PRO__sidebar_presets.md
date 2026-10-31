---
title: "Sidebar Presets"
description: "Hide sidebar entries with named presets that can be shared, duplicated and set as the instance default"
draft: false
weight: 7
audience: pro
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Sidebar Presets are a DefectDojo Pro feature.</span>

A **sidebar preset** is a named list of sidebar entries to hide. A team that only triages findings can have a sidebar with the Connect section, the Sensei pages and most of Settings gone; a team that runs integrations can keep those and lose the rest. Presets are built on **Settings > UI Defaults > Sidebar Presets**, shared with everyone or kept to one person, duplicated like a dashboard or a page layout, and one shared preset can be the instance default. Each person picks the preset that shapes their own sidebar on their User Profile page.

A preset follows the user, not the browser: the pick is saved to the account, and the sidebar, the **Cmd+K** / **Ctrl+K** menu search, the [Default Landing Page](/navigation/pro__landing_page/) list, the All Settings directory and the walkthrough lightbulb all read the same preset, so they never disagree about what is there.

## Hidden, never denied

A preset only takes entries away from what a person can already see. It never adds an entry a role, a feature flag or the license hides, and it never removes access: a direct link, a bookmark, the menu search for a page name that is hidden, and the API all keep working. Roles decide who may open a page; a preset decides what the sidebar shows. To stop someone opening a page, change their role.

Because a preset is a list of hidden entries rather than a list of shown ones, the sidebar keeps up with the product on its own:

- An entry added in a later release appears for everyone, whatever preset they use, until someone hides it. The editor marks such entries **New Since Last Saved**, and the preset list shows how many a preset has not seen yet.
- An entry removed from the product disappears on its own. The editor lists it under **No Longer in the Sidebar** so it can be dropped on the next save.
- An entry a feature flag turns off is not in the sidebar, so a preset has nothing to say about it. Turning the flag on brings it back for everyone.

Two entries are always shown, whatever a preset says: **Home**, so every section a person can see has somewhere to go, and **All Settings**, so everyone keeps the way to their User Profile and their own preset choice.

## Building a preset

Open **Settings > UI Defaults > Sidebar Presets**. The page lists the presets you can see on the left (your own, the shared ones, and the instance default first) and opens the selected one in the editor on the right. **New Preset** starts an empty one; **Duplicate**, in a preset's menu, starts from a copy named `<name> (Copy)`.

The editor shows one card per sidebar section, with a row for each group and each entry and a switch on every row:

- Switching an entry off hides it. Switching a **group** off hides the group and every entry under it; those entries read **Hidden with <group>** and their own switches are off until the group is shown again.
- **Show All** on a section card shows or hides every row of that section at once. A section with nothing left to show leaves the sidebar.
- Entries you cannot open yourself are still listed, marked **Not visible to the current user**, so an administrator can build a preset for people with other roles.
- The search box filters the rows by name.

The **preview** beside the cards is the sidebar as it will look under the current switches: hidden rows are gone, and so is a section with nothing left. Clicking a section heading in the preview scrolls to that section's card.

A preset has a **Name**, an optional **Description**, and, for people who hold the Share permission, a **Shared** switch. **Submit** saves it. Saving also records which entries the sidebar had at that moment, which is what the **New Since Last Saved** marks are measured against.

## Sharing and the instance default

A **shared** preset appears in every user's list and in the **Sidebar Preset** field on every User Profile page. Sharing, unsharing, editing or deleting a shared preset, and choosing the instance default, all require the **Share Sidebar Preset** permission (under Additional Permissions in the role editor). A personal preset is edited and deleted by its owner with the Sidebar Preset Edit and Delete permissions, and anyone with Sidebar Preset Add can create one.

The **instance default** is the shared preset everyone gets who has not picked a preset of their own. Set it from a shared preset's menu (**Set as Instance Default**) or on **Settings > UI Defaults > Layout Defaults**, next to the dashboard, page layout and table defaults. Clearing it gives those users the full sidebar again. Deleting a preset that people had picked sends them back to the instance default.

While **Restrict Layout Customization** is on (also on the Layout Defaults page), everyone but superusers is pinned to the instance default: the **Sidebar Preset** field on User Profile reads **Set by an administrator**, and personal presets are kept but not applied until the switch is turned back off.

## Picking a preset

Each person picks their own preset in one of two places:

- **Use for Me** in a preset's menu on the Sidebar Presets page.
- The **Sidebar Preset** field on the **User Profile** page (select your username at the bottom of the sidebar, then **User Profile**, under **Navigation**). The first option is the instance default; the rest are your own presets and the shared ones. **Submit** saves it with the rest of the profile.

The sidebar, the menu search and the landing page list change at once, without a reload. If the chosen preset hides the page set as your [Default Landing Page](/navigation/pro__landing_page/), the profile page says so and sign-in opens Home instead.

## The permissions

| Permission | Lets a role |
| --- | --- |
| **Sidebar Preset View** | open the Sidebar Presets page and pick a preset on User Profile |
| **Sidebar Preset Add** | create presets and duplicate existing ones |
| **Sidebar Preset Edit** | edit the presets it owns |
| **Sidebar Preset Delete** | delete the presets it owns |
| **Share Sidebar Preset** | share and unshare presets, edit and delete shared ones, and set the instance default |

The four verbs sit in the Global Feature Permissions table of the role editor and the Share capability under Additional Permissions. They take effect through a global role: a preset is instance-wide, so a role held on one organization grants nothing here. By default Owner and Maintainer hold all five, Writer holds View, and Reader holds none. Picking a preset for yourself needs no permission at all.

## The API

Presets are managed at `/api/v2/sidebar_presets/` with the usual API token: list, create, update and delete, plus `clone`, `set_default` and `clear_default` for the caller's own pick, `set_shared_default` and `clear_shared_default` for the instance default, `shared` for the shared presets and `for_current_user` for the preset in effect. The entries a preset hides are **navigation ids**: a page's route suffix (`asset/all`, `settings/feature-flags`), `group:<name>` for a group, or `section:<name>` for a whole section. The editor shows a row's id when the pointer rests on it.

## Related

* [The Sidebar](/navigation/pro__sidebar/): the sections, pinned pages and the menu search
* [Default Landing Page](/navigation/pro__landing_page/): the page sign-in opens
* [Customizing Page Layouts](/navigation/pro__page_layouts/): the same sharing and default model for view pages
