---
title: "Google Cloud"
description: "How to set up the Google Cloud Upstream Connector for DefectDojo"
weight: 67
audience: pro
---
The Google Cloud connector is an **Asset Connector**: it reads your Google Cloud resource hierarchy and creates a DefectDojo Asset for each **project**, grouped into Organizations by the folder the project sits in. Each folder becomes an Asset too, so your organization, folders and projects appear in DefectDojo as the same tree you see in the Cloud console. No findings are imported.

**Please note:** this connector imports your project **inventory** only. To import Security Command Center findings, use the separate [Google Cloud SCC](/connectors/toolreference/google_cloud_scc/) connector. The two are independent and are designed to run together: a project this connector creates is the same Asset that SCC findings land on, so running both does not duplicate anything.

#### Prerequisites

The connector authenticates with a Google **service account** and reads only hierarchy metadata: folder and project names, ids, lifecycle state and labels. It reads no resource contents and no findings.

1. In Google Cloud, create a service account — a dedicated one for DefectDojo is recommended.
2. Grant it the **Browser** role (`roles/browser`) at the organization or folder you want to import. The hierarchy walk needs `resourcemanager.folders.list` and `resourcemanager.projects.list`. A custom role must also carry `resourcemanager.folders.get` and `resourcemanager.organizations.get`, or the top-level Asset is named after its resource id instead of its display name.
3. Grant the role at the **top** of the scope you configure. The connector walks the whole subtree, and a folder it cannot read fails the sync rather than silently importing a partial inventory.
4. Create a **JSON key** for the service account and download it.
5. Enable the **Cloud Resource Manager API** (`cloudresourcemanager.googleapis.com`) on the project that owns the service account.

#### Connector Mappings

1. Leave the **Location** field at the default `https://cloudresourcemanager.googleapis.com` unless you use a non-standard endpoint.
2. In the **Parent Resource** field, enter the root of the hierarchy to import: `organizations/{id}` or `folders/{id}`. A single project is not a hierarchy, so `projects/{id}` is not accepted here — use the Google Cloud SCC connector for a single-project scope.
3. Paste the full contents of the service-account **JSON key** file into the **Service Account Key** field.

Every `ACTIVE` folder and project beneath the parent becomes a Record. Each project's Record is named after its **project ID**, and its Organization in DefectDojo is the folder it sits in (or your Google Cloud organization, for a project that sits directly under it).

A project you delete in Google Cloud moves to the `DELETE_REQUESTED` state and drops out of the import, so its mapped Record is flagged `MISSING` on the next Sync rather than removed — DefectDojo never silently deletes an Asset. The same applies to a folder you delete.

Once a Record is mapped, this connector never refreshes its metadata. If you rename a folder or move a project to a different folder in Google Cloud, DefectDojo keeps showing the old name or the old folder.

#### Working alongside the Google Cloud SCC connector

Both connectors identify a project the same way, and both name its Asset after the project ID. So if you run this connector first, SCC findings land on the Assets it created; if SCC ran first, this connector adopts those Assets and adds the folder hierarchy around them. You do not need to map anything twice.

The Organization follows the same rule: when this connector creates the Asset, it sets the Organization to the project's folder. When the Google Cloud SCC connector creates the Asset first, that Asset keeps its existing Organization, and this connector only adds the folder hierarchy around it.
