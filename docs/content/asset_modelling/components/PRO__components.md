---
title: "Components"
description: "Tracking third-party libraries and software components in DefectDojo Pro"
audience: pro
weight: 1
---

In DefectDojo, Components represent third-party libraries, software components, and modules that potentially have vulnerabilities.

## The Component Table

DefectDojo Pro includes a dedicated table view for Components. Imported Components remain on the table even if all of their associated Findings are Mitigated. When Findings are imported for a specific Component, the Component Table is updated to accurately reflect the new Finding totals.

The Component Table displays the following columns:

* **Component** — the name of the component, populated from scan data.
* **Version** — the component version, populated from scan data.
* **Active Findings** — count of Active Findings associated with the component.
* **Duplicate Findings** — count of Duplicate Findings associated with the component.
* **Total Findings** — total count of all Findings associated with the component.

The totals for Active Findings, Duplicate Findings, and Total Findings are calculated from the Findings on the instance.

Clicking on the Component Name or the values for Active Findings, Duplicate Findings, or Total Findings opens a filtered list of Findings for the respective field.

A **None** Component is displayed on the table, which shows all Findings that are not associated with any Component.

## Adding Components

Components can be added from a scan import or by manually editing a Finding. Once a Component Name is associated with a Finding, it is added to the Component Table. If the Component is already associated with other Findings on the instance, the totals for Active Findings, Duplicate Findings, and Total Findings are updated accordingly.

## Updating Components

To update a Component Name or Version, all Findings associated with the Component must have their Component Name or Component Version field updated.

## Removing Components

To remove a Component from the Component Table, all Findings associated with the Component must be updated to remove their Component Name and Component Version fields. Components are also removed if all of their associated Findings are deleted.

If all of a Component's Findings are Mitigated, the Component remains on the table but its Active Findings value is set to 0.
