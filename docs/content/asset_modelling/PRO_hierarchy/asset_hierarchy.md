---
title: "Asset Hierarchy"
description: "DefectDojo Pro - Asset Hierarchy Overhaul"
audience: pro
weight: 1
aliases:
  - /en/working_with_findings/organizing_engagements_tests/pro_assets_organizations
  - /asset_modelling/pro_hierarchy/assets_organizations
---
DefectDojo Pro is extending the Product/Product Type object classes to provide greater flexibility with the data model.

## Enabling the Hierarchy Feature

The two pieces below are separate, and are controlled by different means.

### Asset Hierarchy

**Asset Hierarchy** enables parent/child relationships between Assets. The hierarchy is viewed and managed from the **Product** tab in the navigation.

Asset Hierarchy is generally available and on for every instance, Cloud and On-Premise. There is nothing to enable, and it is no longer listed on the Feature Flags page.

### Label Changes (optional)

**Label Changes** renames "Product Type" to "Organization" and "Product" to "Asset" throughout the UI. This is a separate step from enabling the hierarchy and can be done at the same time or later.

Label changes are on by default as of 3.0. There are two controls, covering different parts of the application:

* **Pro UI** (the default UI): a superuser toggles "Organization / Asset Relabeling" at **Settings > Feature Flags**, on both Cloud and On-Premise instances. The new labels appear on the next page load. See [Feature Flags](/admin/feature_flags/pro__feature_flags/).
* **Classic UI pages and generated reports**: their labels and URLs come from the `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` deployment setting, which is read when DefectDojo starts. On-premise, set it and restart DefectDojo. On [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), email [support@defectdojo.com](mailto:support@defectdojo.com) with your instance URL.

Both default to on, and the Feature Flags value was seeded from the deployment setting, so the two agree unless you change one of them. Keep them in sync if you use the Classic UI as well as the Pro UI.

Note that label changes are cosmetic only: API endpoints and field names remain unchanged, so existing automation will continue to work.

## Significant Changes

* **Product Types** have been renamed to "Organizations", and **Products** have been renamed to "Assets".  As of 3.0 this name change is on by default. See [Label Changes](#label-changes-optional) for the controls that turn it off.
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

In this diagram, every element under "Core Application" could be recorded as a separate Asset, with unique business criticality (see: [Priority & Risk](/asset_modelling/pro_hierarchy/priority_sla/#prioritization-engines)), RBAC, and corresponding Engagements and Tests.  You could continue to test, and store results, on the parent Asset (for example, `webapp-backend`), but you could also run isolated testing on a particular child Asset (for example, `database`).

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

The page has three parts: a list of your Assets across the top, the diagram below it, and a panel on either side of the diagram. Selecting one or more Assets in the list draws them, and each Asset you select becomes a starting point that the diagram builds around. The list can be filtered, and once you have the Assets you want you can collapse it with the **Hide Asset List** button to give the diagram the whole page.

![image](images/asset_hierarchy_diagram.png)

### Diagram navigation

The buttons at the bottom left of the diagram zoom in and out, and fit the whole diagram in view. Clicking and dragging the background moves the diagram, and each Asset can be dragged for display purposes.

Assets are connected by labelled arrows, which represent the kind of relationship each node has to the other.

Three relationship types ship by default:

| Label | Meaning | Rolls up? |
| --- | --- | --- |
| `parent` | The tree relationship you build from the Asset Hierarchy screen. An Asset has at most one parent. | Yes |
| `contains` | Composition — the source Asset is made up of the target. Unlike `parent`, the same Asset can be contained by several others. | Yes |
| `derived_from` | Lineage — the source Asset was built from the target, as a container image is built from a base image. | **No** |

"Rolls up" is what decides whether a relationship aggregates upward: it controls both the
indirect counts described below and the **Include child assets** option on metrics. `derived_from`
deliberately does not roll up. A base image's Findings are not the derived Asset's own exposure,
and attributing them to every Asset built from it multiplies the same Finding across your whole
estate.

Each node is coloured by where it came from: one colour for the Assets you selected in the list, another for Assets the diagram loaded because they are related to your selection. The **Legend** in the left panel names both.

The left panel also chooses what the nodes display. **Asset ID**, **Organization ID**, **Organization Name**, **Child Count** and **Vulnerabilities** can each be turned on or off.

### Direct and indirect vulnerabilities

Each node shows two counts:

* **direct** — Findings on that Asset itself.
* **indirect** — Findings on the Assets below it, reached over relationships that roll up.

So an Asset that contains a library shows the library's Findings as indirect, while an Asset
built from a base image does **not** show the base image's Findings at all.

A Finding reachable by more than one path is counted once. The counts are always calculated from
the graph as it currently stands — nothing is stored, so re-parenting an Asset changes them
immediately, and no Finding is ever copied onto another Asset. Assets you do not have permission
to view contribute nothing, and show no counts at all rather than a zero.

The same split appears under the Findings count on the Asset page. There, **direct** matches the
total in that page's Open Finding Severity breakdown: both exclude duplicates, false positives
and out-of-scope Findings.

### Acting on an Asset

Clicking an Asset's node selects it, which fills both panels: the left panel lists what you can do with that Asset, and the right panel describes it, including its Organization, its relationship to its parent, how many children it has, and links to its metrics.

![image](images/asset_hierarchy_node.png)

* **Open Asset** takes you to the corresponding Asset View (formerly known as the Product View).
* **Edit Asset** opens the Edit Asset form (formerly known as the Edit Product form).
* **Add Child** nests another Asset under this one. You can choose an Asset that is not currently in the diagram, or create a new one, but either way it must be part of the same Organization.
* **Change Parent** moves the selected Asset underneath a different parent.
* **Remove From Hierarchy** detaches the Asset from its parent, and asks whether that Asset's own children should be left without a parent or moved up to the parent you are detaching from. It is only available when the Asset has a parent.

Each of these opens in the right panel, so the diagram stays visible while you work on it. An action you cannot use is shown greyed out, and hovering it explains why: changing relationships needs edit permission on the Asset itself as well as permission to edit the hierarchy.

### Loading more of the hierarchy

The diagram loads part of the hierarchy at a time, so a large one stays readable.

Where an Asset's parent has not been loaded, a **Load Parents** button appears above it, which adds that parent along with the parent's other children.

![image](images/assets_loadmore.png)

Where an Asset has more children than the diagram is currently showing, a **Load** button appears below it, together with a choice of how many to add at a time.

## Notes

* Note that deduplication scopes have not changed; Assets only deduplicate Findings within themselves, and do not consider Findings in other Assets, regardless of Parent/Child relationships.
* RBAC scopes have not changed within this system; each Asset is still considered an individual object for the purposes of assigning permissions.  No new RBAC inheritance has been created.
  * Giving a user access to an entire Organization will still give that user access to all Assets contained within that Organization (as with Product Types).
  * Giving a user access to a single Asset does not give that user access to any related Parent or Child Assets, nor access to the Organization.
* There is no limit to the number of Parent/Child relationships that can be created. Theoretically, you could represent a repository's entire directory structure with separate Assets if you wished.
* Cyclical relationships are not allowed: Parent Assets cannot be Children of their Child Assets. This is enforced per relationship type and in the database itself, so it holds no matter how the edge was created.
* Indirect counts are calculated on read and never stored. Attributing a Finding to an Asset that did not report it would multiply that Finding across every Asset below it, so DefectDojo shows the number and leaves the Finding where it was found.