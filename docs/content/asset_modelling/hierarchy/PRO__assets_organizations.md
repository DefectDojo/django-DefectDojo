---
title: "Assets and Organization structure"
description: "DefectDojo Pro - Product Hierarchy Overhaul"
audience: pro
weight: 1
aliases:
  - /en/working_with_findings/organizing_engagements_tests/pro_assets_organizations
---
DefectDojo Pro is extending the Product/Product Type object classes to provide greater flexibility with the data model.

Currently, this feature is in Beta. Pro users who are interested in opting in can do so by emailing [support@defectdojo.com](mailto:support@defectdojo.com).

## Significant Changes

* **Product Types** have been renamed to "Organizations", and **Products** have been renamed to "Assets".  Currently, this name change is opt-in for existing DefectDojo Pro subscriptions.
* **Assets** can now have parent/child relationships with one another to further sub-categorize Organizational components. 

### Organizations

As with Product Types, **Organizations** should be understood as a top-level category.  You can use these to separate your business' core software applications, departments or business functions.

For example, you could create an Organization for many repository groupings: "Core Application", "Infrastructure", "DevOps", "Analytics", "SDK" could all contain multiple code repos.

Keep in mind that for reporting purposes, it’s easier to combine multiple Organizations into a single document than it is to subdivide a single Organization into separate documents. Therefore, we recommend setting up Organizations at as granular a level as makes sense for your team's reports. For example, there is no need to represent a large business division as an Organization if you're primarily going to be reporting on individual departments within that division.

### Assets

Assets are meant to represent subdivisions of your Organizations.  However, unlike Products, Assets can be nested, and have parent-child relationships with one another.

## Asset Nesting Examples

### Asset-Level Branch Representation

Development and feature branches can be represented in a variety of ways; separate Engagements or Tests are existing ways that you can represent the difference between your Production, Dev, and other feature branches.

You can also represent these using nested Assets.  Consider the following Asset tree:

```
Core Application [Organization]
└── webapp-frontend
    ├── webapp-frontend/prod
    └── webapp-frontend/dev
        ├── webapp-frontend/dev/feature-a
        └── webapp-frontend/dev/feature-b
```

In this environment, each branch (`prod`, `dev`, `feature a`, `feature b`) could have its own Engagements and Tests that are isolated from the other Assets, so that they don't deduplicate against each other.  This setup can also ease in navigation, as Asset names can directly correspond to the path on Git.

### Mono-Repo: Separate Components

If you use a single repository for all of your code, but have different teams contributing to directories within that repository, you can set up your Asset nesting to represent that structure.

```
Core Application [Organization]
├── webapp-frontend [Parent Asset]
│   ├── mobile-ios
│   ├── mobile-android
│   └── mobile-sdk
├── webapp-backend [Parent Asset]
│   ├── database
│   └── api
└── infra [Parent Asset]
    ├── docker
    ├── kubernetes
    └── nginx
```

In this diagram, every element under "Core Application" could be recorded as a separate Asset, with unique business criticality (see: [Priority & Risk](/asset_modelling/hierarchy/pro__priority_sla/#prioritization-engines/)), RBAC, and corresponding Engagements and Tests.  You could continue to test, and store results, on the parent Asset (for example, `webapp-backend`), but you could also run isolated testing on a particular child Asset (for example, `database`).

### Pen Tests: Isolated RBAC

If you want to store pen test results within a single asset, but you don't want testers to be able to look at asset data, you could create child assets for each testing group to upload their results.

```
Core Application [Organization]
└── webapp-frontend [Parent Asset]
    ├── Pen Test Group A
    └── Pen Test Group B
```

Crucially, giving a user RBAC access to a single Child Asset (e.g. `Pen Test Group A`) here does not allow them to see any Findings from other Child Assets (e.g. `Pen Test Group B`), nor does it allow them to see Findings in the Parent Asset (`webapp-frontend`).

The Parent Asset could contain Engagements representing CI/CD results, internal Testing, historical data, or other Finding data which you do not want 3rd parties to be able to discover.  Creating a Child Asset for specific Test results allows your internal team to report on those results in combination with the state of the parent Asset.

## Visualizing Assets - Hierarchy

You can visualize the structure of Assets in DefectDojo, and change relationships using the Asset Hierarchy option in the menu.

![image](images/asset_hierarchy.png)

Opening Asset Hierarchy will display a table of all of your Assets which can be filtered.  Selecting one or more Assets from this table will render a hierarchy diagram.

![image](images/asset_hierarchy_diagram.png)

### Diagram navigation

The icons at the top left of the hierarchy diagram allow you to zoom in and out.  Clicking and dragging in this diagram allows you to scroll through the diagram.

Each Asset is rendered as a single node in this diagram, which can be moved around for display purposes.

Assets are connected together using labelled paths, which represent the kind of relationship each note has to one another.  Currently, `parent` is the only label supported.

### Exploring Asset nodes

Each Asset node can be interacted with by clicking on the blue buttons.  These buttons appear only when an Asset node is selected (by clicking on the node).

![image](images/asset_hierarchy_node.png)

* 👁️ (eyeball icon) will take you directly to the corresponding Asset View (formerly known as the Product View).
* ✏️ (pencil icon) will open a modal with the Edit Asset form (formerly known as the Edit Product form)
* ➕ (plus icon) will allow you to add a new Child Asset to this Asset.  The Asset does not need to be currently visible in the diagram, but must be part of the same Organization.
* ✥ (four-arrows icon) allows you to change the Parent Asset of the currently selected Asset.
* 🗑️ (trash can icon) allows you to remove an Asset's parent relationship. This icon only appears if an Asset already has a Parent.

If your diagram displays an Asset with un-selected Parent Assets, you can click the Load More button to populate the diagram with the Parent Asset (as well as that Parent Asset's children).

![image](images/assets_loadmore.png)

## Notes

* Note that deduplication scopes have not changed; Assets only deduplicate Findings within themselves, and do not consider Findings in other Assets, regardless of Parent/Child relationships.
* RBAC scopes have not changed within this system; each Asset is still considered an individual object for the purposes of assigning permissions.  No new RBAC inheritance has been created.
  * Giving a user access to an entire Organization will still give that user access to all Assets contained within that Organization (as with Product Types).
  * Giving a user access to a single Asset does not give that user access to any related Parent or Child Assets, nor access to the Organization.
* There is no limit to the number of Parent/Child relationships that can be created. Theoretically, you could represent a repository's entire directory structure with separate Assets if you wished.
* Cyclical relationships are not allowed: Parent Assets cannot be Children of their Child Assets.