---
title: "Prowler"
description: "How to set up the Prowler Upstream Connector for DefectDojo"
weight: 108
audience: pro
---
The Prowler connector uses the **Prowler App** REST API to import cloud security posture (CSPM) findings from a self-hosted Prowler App instance. DefectDojo discovers each Prowler **provider** (cloud account) as a Record and imports the **FAIL** findings of that provider's latest completed scan.

#### Prerequisites

You will need a running, self-hosted **Prowler App** instance and either a user email + password (for JWT authentication) or a Prowler App **API key**. Findings only appear once you have connected a cloud account (AWS, GCP, Azure, Kubernetes, ...) in Prowler App and run a scan.

#### Connector Mappings

1. Enter your Prowler App URL in the **Location** field (for example `https://prowler.your-company.com`).
2. For JWT authentication, enter the Prowler App user **Email** and **Password**. Alternatively, leave those blank and enter a Prowler App **API Key**. If both are provided, the email/password (JWT) is used.
3. Optionally set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity are not imported.

DefectDojo creates a Record for each Prowler provider and imports the FAIL findings of its latest completed scan, mapping Prowler severities to DefectDojo severities, the affected cloud resource (ARN/resource id) as the component, and the check's remediation and risk into the finding. Muted findings are skipped. Cloud account, region, and service are attached as tags.

For more information, see the **[Prowler App API documentation](https://api.prowler.com/api/v1/docs)**.

#### Asset Grouping (optional)

By default the connector creates one Record, and so one asset, per Prowler provider (cloud account). The **Asset Grouping** field, under **Import Filters** on the connector form, can split findings more finely:

| Asset Grouping | Records | Findings are imported on |
|---|---|---|
| **Provider** (default) | one per provider | the provider Records |
| **Service** | additionally, one per service (ec2, s3, iam, ...) under each provider | the service Records |
| **Resource** | additionally, one per resource, under its service | the resource Records |

Resource Records are named `<resource> (<service>, <region>, <provider>)`, for example `web-1 (ec2, us-east-1, prod / aws:111111111111)`. The provider's account identifier is always part of the name because provider aliases are not unique.

With a finer grouping:

* The provider Records keep the same identity and become **parent assets** with no findings of their own. When the Asset Hierarchy feature is enabled, DefectDojo relates each service asset to its provider asset, and each resource asset to its service asset, with a `parent` relationship. Relationships created by the connector never overwrite relationships you created by hand.
* Each finding is imported once, on the asset of the first resource it names. The total number of findings is the same under every grouping.
* Resources are discovered from the latest completed scan, so only resources with at least one FAIL finding that is not muted and is at or above the minimum severity become Records. A resource whose last failed check now passes keeps its Record for 14 days so that the next Syncs close its findings, after which the Record is marked MISSING.
* Resource tags reach resource assets as asset tags, prefixed `prowler:` (for example `prowler:team:payments`). Tags you add yourself are never touched.
* ECR repository resources carry the repository's registry address, so the same repository reported by another connector can be recognized as the same asset.
* The connector makes one Prowler App request per Record on each Sync (plus one scan lookup per provider), paced to avoid overloading your Prowler App instance, so a Sync with thousands of resource Records takes longer than a provider Sync. Memory use stays low because findings are processed one page at a time.

**Switching an existing connection to a finer grouping:** the field can be changed at any time. On the next discovery, the new Records appear for mapping; enable **Auto Map** on the connection when you change the grouping so findings move without a gap. On the next Sync, the provider assets stop receiving findings and their previously imported findings are closed (the same findings are imported again on the new assets). Switching back reverses this, and the finer Records close their findings and are then marked MISSING. Closing the findings of the parent assets needs DefectDojo and the connectors service from the same release or later.

#### Organization Placement (optional)

New assets from a Prowler connection are placed in the connector's default organization. The **Organization Placement** field can instead use:

* **One per provider:** an organization per provider, named after its alias (or `<type>:<account>` without one).
* **One per cloud type:** an organization per cloud, for example `AWS`, `Azure` or `Google Cloud`.

Organizations are created when they do not exist yet, and reused when they do. The field only affects assets created after it is set: assets that already exist are never moved.
