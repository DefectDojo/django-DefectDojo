---
title: "Components"
description: "Tracking third-party libraries and software components in DefectDojo Pro"
audience: pro
weight: 1
---

In DefectDojo, Components represent third-party libraries, software components, and modules that potentially have vulnerabilities.


## Component Views

DefectDojo Pro includes a dedicated table view for Components, which can be found in the sidebar.  This view shows Active Findings, Duplicate Findings, and Total Findings for each Component.  These figures include all Assets on the DefectDojo instance.

An individual Asset's Components can be seen on the Asset view.

## The Component Table

The Component Table displays the following columns:

* **Component** — the name of the component, populated from scan data.
* **Version** — the component version, populated from scan data.
* **Active Findings** — count of Active Findings associated with the component.
* **Duplicate Findings** — count of Duplicate Findings associated with the component.
* **Total Findings** — total count of all Findings associated with the component.

Clicking on the Component Name or the values for Active Findings, Duplicate Findings, or Total Findings opens a filtered list of Findings for the respective field.

A **None** Component is displayed on the table, which shows all Findings that are not associated with any Component.

Imported Components remain on the table even if all of their associated Findings are Mitigated. When Findings are imported for a specific Component, the Component Table is updated to accurately reflect the new Finding totals.


### Example

A Component imported from a Dependency-Check scan against an application with a vulnerable `lodash` dependency might appear on the table as:

| Component | Version | Active Findings | Duplicate Findings | Total Findings |
| --- | --- | --- | --- | --- |
| npm:lodash | 4.17.15 | 3 | 1 | 5 |

Clicking `npm:lodash` opens the list of every Finding that references this Component. Clicking `3` opens the same list filtered to Active Findings only.

## Adding Components

Components can be parsed from a scan import or by manually editing a Finding. Once a Component Name is associated with a Finding, a corresponding entry will be added to the Component Table automatically. If the Component is already associated with other Findings in DefectDojo, the totals for Active Findings, Duplicate Findings, and Total Findings are updated accordingly.

### How Components are Parsed from Scan Data

When a scan is imported, parsers populate the **Component Name** and **Component Version** fields on each Finding from the scan output. The Component Table is then built from those values. The level of detail and the naming convention depend on the tool that produced the scan:

* **Software Composition Analysis (SCA) tools** typically report a package name and exact version. For example, OWASP Dependency-Check derives the Component from the [Package URL](https://github.com/package-url/purl-spec) in its identifier — a `pkg:npm/lodash@4.17.15` purl becomes `Component Name: npm:lodash`, `Component Version: 4.17.15`.
* **Container and OS package scanners** such as Trivy, Anchore Grype, and Anchore Engine report the affected OS or language package — for example, `Component Name: curl`, `Component Version: 7.68.0`.
* **Language-specific dependency scanners** such as npm Audit, pip-audit, bundler-audit, Retire.js, Govulncheck, and OSV-Scanner populate the offending package and version from their respective ecosystem manifests.

Scanners focused on configuration, infrastructure, or source-code logic (such as SAST and IaC tools) generally do not populate the Component fields, and their Findings appear under the **None** Component.

To add or change a Component manually, edit the Finding and set the **Component Name** and **Component Version** fields directly. The Component Table updates as soon as the Finding is saved.

## Updating Components

To update a Component Name or Version, all Findings associated with the Component must have their Component Name or Component Version field updated.

## Removing Components

To remove a Component from the Component Table, all Findings associated with the Component must be updated to remove their Component Name and Component Version fields. Components are also removed if all of their associated Findings are deleted.

If all of a Component's Findings are Mitigated, the Component remains on the table but its Active Findings value is set to 0.
