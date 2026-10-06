---
title: "DefectDojo (Open Source)"
description: "How to set up the DefectDojo source Connector to copy an open source DefectDojo into DefectDojo Pro"
weight: 47
audience: pro
---
The DefectDojo connector copies data from an open source DefectDojo instance into DefectDojo Pro. Each Product on the source becomes a Record. A Sync copies the Product's Engagements, Tests and Findings into a matching Asset. Notes, files, Finding Groups and Risk Acceptances travel with them too. You can run a Sync as often as you like before cutover. If the source does not change, a second Sync changes nothing.

#### Prerequisites

* DefectDojo Pro must reach the source over HTTPS. A cloud-hosted Pro instance connects from your region's published outbound IP addresses. Allow those addresses on the source.
* An API v2 key for a superuser on the source. Find it on the source, under your user menu, **API v2 Key**.
* The source must run release 3.5.0 or later for a full copy. If an older source does not have Locations enabled, it still works in compatibility mode. If Locations is enabled, the source must first upgrade to a release with the export API. See Compat mode below.

#### Connector Mappings

1. Enter the source URL, for example `https://dojo.example.com`, in the **Location** field.
2. Enter the superuser's API v2 key in the **Secret** field.

Run **Discover**. Every source Product becomes a Record. Discover shows each Record's Organization, tags, business criticality and owners. Turn on auto-mapping to create a new Asset and Organization for each Record. The new Asset and Organization use the source's names. You can also map Records to existing Assets yourself.

#### What the preflight report shows

After Discover, the connector tile shows a **Migration preflight** card. The card shows:

* the source version, the read mode (export API or compatibility mode) and the endpoint mode;
* how many Findings DefectDojo Pro will copy, and how many users it will create;
* test types this DefectDojo Pro does not know (their Findings go to the Record's connector test);
* files too large to copy, over 10 MiB;
* settings that stay behind, and an estimated duration.

#### What crosses, and what does not

| Crosses | Stays behind |
|---------|--------------|
| Engagements and Tests, with their fields, tags and notes | API tokens |
| Every non-duplicate Finding, with its fields, tags, vulnerability ids, CWEs, endpoints with their status, raw requests and responses, notes, files and custom fields | SSO settings |
| Finding Groups and Risk Acceptances, with their members and proof files | JIRA instances and credentials |
| Every user that the source data references, in mapped and unmapped Products alike, created as an inactive user with no password | Tool configurations and credentials, notification settings and system settings |
| | API scan configurations, threat model files and locations that are not URLs |
| | Engagement presets, report types and requesters |
| | A Finding's history |

A copied Finding keeps its original scan type and field values. DefectDojo Pro computes the same hash code the source used. Later scans then deduplicate against the copied Findings. DefectDojo Pro does not copy duplicate Findings from the source. DefectDojo Pro finds duplicates again on its own, with its own rules.

#### Compat mode

A source without the export API works in compat mode. Compat mode needs a source with Locations turned off. A source with Locations turned on must first upgrade to a release with the export API.

Compat mode cannot tell which users the copied data references. It creates every source user as an inactive user in DefectDojo Pro. The preflight report shows this count before you run Sync.

Compat mode also leaves out:

* files;
* custom fields on Findings;
* found-by test types.

#### Things to know

* An existing Asset keeps its name, description and other fields when you map a Record onto it. The connector only adds tags, source regulations and metadata to it.
* Until you finish migration, each Sync updates the Engagement and Test fields from the source. A field you changed in Pro, for example the lead, reverts on the next Sync.
* If a Finding disappears from the source, the next complete Sync closes its copy in DefectDojo Pro. In compat mode, the copies of a source Product that loses its last Finding stay open. The connector never deletes a Finding.
* The connector creates an inactive DefectDojo Pro user for every user that the source data references. This covers mapped and unmapped Products alike. These users count toward your license's user limit. Activate the ones who need to sign in to DefectDojo Pro.
* Like any connector, each Sync counts every copied Finding toward your weekly Finding usage.
* If you point the connector at a different source, its old Records turn Missing. The connector never writes one source's data into another source's Assets.
* Keep the source URL the same while Records stay mapped. The Record ids come from the URL, so a new URL makes Discover create new Records. An upgrade from compat mode to the export API keeps the same Records.
