---
title: "Google Cloud SCC"
description: "How to set up the Google Cloud SCC Upstream Connector for DefectDojo"
weight: 67
audience: pro
---
The Google Cloud SCC connector uses the Security Command Center v2 REST API to import active security findings from your Google Cloud organization, folder, or project. DefectDojo creates a Record for each Google Cloud **project** that has open findings.

#### Prerequisites

Security Command Center must be **activated** on your organization (the Standard tier is free). You will then need a service account that can list findings, and a JSON key for it:

1. In Google Cloud, create a service account — a dedicated one for DefectDojo is recommended.
2. Grant it the **Security Center Findings Viewer** role (`roles/securitycenter.findingsViewer`) at the scope you want to import (organization, folder, or project).
3. Create a **JSON key** for the service account and download it.

#### Connector Mappings

1. Leave the **Location** field at the default `https://securitycenter.googleapis.com` unless you use a non-standard endpoint.
2. In the **Parent Resource** field, enter the scope to import from: `organizations/{id}`, `folders/{id}`, or `projects/{id}`.
3. Paste the full contents of the service-account **JSON key** file into the **Service Account Key** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Only `ACTIVE`, un-muted findings are imported, so findings you deactivate or mute in SCC are automatically mitigated in DefectDojo on the next sync. Each finding's affected GCP project becomes its Record.

#### Asset Grouping (optional)

By default the connector creates one Record, and so one asset, per Google Cloud project (plus one for the configured parent, for findings that do not belong to a project). The **Asset Grouping** field, under **Import Filters** on the connector form, can split findings more finely:

| Asset Grouping | Records | Findings are imported on |
|---|---|---|
| **Project** (default) | one per project | the project Records |
| **Resource Type** | additionally, one per resource type (`google.compute.Instance`, ...) under each project | the resource type Records |
| **Resource** | additionally, one per resource, under its resource type | the resource Records |

With **Resource**, Artifact Registry image digests are grouped under their image, because a digest is a version of the image.

Resource Records are named `<resource> (<type>, <project>)`, for example `web-1 (compute.Instance, shop-prod / 123456789)`. The project number is always part of the name because project display names are not unique.

With a finer grouping:

* The project Records keep the same identity and become **parent assets** with no findings of their own. When the Asset Hierarchy feature is enabled, DefectDojo relates each resource type asset to its project asset, and each resource asset to its resource type asset, with a `parent` relationship. Relationships created by the connector never overwrite relationships you created by hand.
* Each finding is imported once, on the asset of the resource it is about. The total number of findings is the same under every grouping.
* Resources are discovered from findings, so only resources with at least one active, unmuted finding at or above the minimum severity become Records. A resource whose last finding becomes inactive keeps its Record for 14 days so that the next Syncs close its findings, after which the Record is marked MISSING.
* Artifact Registry image Records carry the image's registry address, so the same image repository reported by another connector can be recognized as the same asset.
* Security Command Center findings do not include resource labels, so this connector does not sync asset tags.
* The connector makes one Security Command Center request per Record on each Sync, paced below the API's read quota, instead of loading every finding of the parent into memory at once.

**Switching an existing connection to a finer grouping:** the field can be changed at any time. On the next discovery, the new Records appear for mapping; enable **Auto Map** on the connection when you change the grouping so findings move without a gap. On the next Sync, the project assets stop receiving findings and their previously imported findings are closed (the same findings are imported again on the new assets). Switching back reverses this, and the finer Records close their findings and are then marked MISSING. Closing the findings of the parent assets needs DefectDojo and the connectors service from the same release or later.

#### Organization Placement (optional)

New assets from a Google Cloud SCC connection are placed in the connector's default organization. The **Organization Placement** field can instead use:

* **One per Project:** an organization per project, named after the project's display name.
* **One per Folder:** an organization per nearest folder of the project, falling back to the project's display name for projects directly under the organization.

Organizations are created when they do not exist yet, and reused when they do. The field only affects assets created after it is set: assets that already exist are never moved. No extra permission is needed: the folder comes from the findings themselves.
