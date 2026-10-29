---
title: "Location Map"
description: "See every Location an Asset has on one map, grouped by what the Locations share, with active finding counts on every node"
audience: pro
weight: 2
---

The **Location Map** opens an Asset's Locations page on a map instead of a table. Every URL, source file, dependency and cloud resource the Asset has is drawn as a set of trees, one dashed region per location type, and each node shows how many active findings sit on it or beneath it.

> The Location Map requires [Locations](/asset_modelling/locations/pro__locations_overview/). It is on wherever Locations is on, and there is nothing else to enable. While Locations is off, the Location Map is off too.

## Where the Map Appears

The map replaces the table on an Asset's Locations page, including the per-type views such as an Asset's URLs or Dependencies. A per-type view draws only that type's region.

Two pages keep the table:

- **All Locations**, which is not scoped to one Asset.
- A Finding's Locations.

## What the Map Shows

### Regions

Each dashed region holds one kind of location:

- URLs
- Source Code
- Dependencies
- Cloud Resources
- Container Images, when the **Container Image Locations** flag is also on. See [Container Image Locations](/asset_modelling/locations/pro__container_image_locations/).

Chips at the top of the page count the locations in each type, for example "11 URLs".

### Groups and Locations

Inside a region, locations are grouped by what they share: a host, a directory, a package, an account. A group node shows how many locations it holds. The leaves of each tree are the locations themselves.

Large groups are not drawn in full. A node with more beneath it has a **Load** button and a picker for how many children to load (5, 10, 25, 50 or 100).

### Finding Counts

Each node carries a bug icon with a count of **active findings**. On a location, that is the active findings recorded on it. On a group, it is the active findings beneath it. Counts are distinct, so a finding recorded on two locations under one group counts once for that group. A node with no active findings shows no count.

## Working with the Map

The page has three panels: actions on the left, the canvas in the middle, and details for the selected node on the right.

### Moving Around the Canvas

- Drag the canvas to pan, and scroll to zoom.
- The buttons on the canvas are **Zoom in**, **Zoom out** and **Fit the whole graph**.
- Under **Regions** in the left panel, click a region to jump to it. Each entry shows its location count.

### Selecting a Node

Click a node to select it. The right panel then shows:

- **Type** and **Value** of the node.
- For a single location: **Status Here** and its **Relationship** to the Asset. Users who can edit Locations on the Asset can change the relationship with **Set a Relationship** and **Save**, or remove it with **Clear**.
- For a group: how many **Locations** and **Children** it has.
- **Findings**: active findings by severity, split into **Direct** (on this node) and **Beneath** (on nodes under it), with a **Total**.

With no node selected, the right panel shows a short **Map Overview**. Click the empty canvas or use **Clear the selection** to deselect.

When a single location is selected, the left panel offers two actions:

- **View Findings** opens the active findings recorded on that location.
- **Copy Value** copies the full location value to the clipboard.

A group is drawn from several locations, so these actions apply only to a single location.

### Choosing What Nodes Show

Under **Show On Nodes**, tick the fields to show on each node:

- **Location Count** (on by default)
- **Findings** (on by default)
- **Status**
- **Child Count**

Under **Canvas**, **Type Boundaries** turns the dashed regions on or off. The **Legend** lists the color for each location type.

### Narrowing the Map with the List

**Choose Locations** opens the Asset's location list above the map, with its usual filters. Tick locations in the list and the map redraws around just those, marking them as selected. A chip shows how many are selected. **Hide Location List** collapses the list again.

### Adding Locations

**New Location** and **Add Existing** work as they do on the table page, and the map redraws to include what you added. See [Working with URLs](/asset_modelling/locations/pro__working_with_urls/) for the permissions each one needs.
