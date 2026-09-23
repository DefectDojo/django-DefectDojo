---
title: "Editable Platform, Lifecycle and Origin Lists"
description: "Customize the Platform, Lifecycle and Origin dropdown options on your assets"
audience: pro
weight: 8
---

The **Platform**, **Lifecycle** and **Origin** fields on an asset used to be fixed lists that only
DefectDojo could change. They are now editable lookup tables, so an administrator can rename the
built-in options and add their own to match how the organization actually describes its assets. This
works the same way the **Environments** list has always worked.

## Managing the options

Open **Settings > Configuration** and pick **Platforms**, **Lifecycles** or **Origins**. Each page
lists the current options with:

- **Label** — the name shown in dropdowns and on the asset (for example, "API" or "Production"). This
  is the part you edit.
- **Value** — a fixed machine key stored on the asset and used by the API, imports and automation
  rules. It is set when an option is created and never changes afterward, so relabeling an option
  never breaks an integration.
- **Icon** and **Display order** — optional. The icon is a Font Awesome name; display order controls
  where the option appears in the dropdown.
- **Assets Using** — how many assets currently reference the option.

Use **New Platform** (or Lifecycle/Origin) to add an option, click an option's label to edit it, and
delete an option from its edit screen. An option that is still in use by an asset cannot be deleted;
reassign or clear those assets first.

## How your changes appear

New and renamed options show up immediately in the **Platform / Lifecycle / Origin** dropdowns on the
asset add and edit forms, and their labels are what appears on the asset detail page, in the asset
list, in reports and on dashboard tiles.

## What the API sees

Nothing about the API contract changes. These fields are still sent and returned as the option's
**value** string (for example `"web service"` or `"production"`), so existing integrations, imports
and exports keep working. When you add an option, its value must exist before an asset or an import
can use it; an unknown value is rejected, exactly as before.

## A note on Business Criticality

**Business Criticality** is intentionally **not** editable. Its values feed asset and finding
prioritization, so its list stays fixed. If you need a bespoke attribute that should not affect
prioritization, use [Custom Fields](../pro__custom_fields/) instead.
