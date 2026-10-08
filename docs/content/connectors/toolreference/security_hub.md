---
title: "Security Hub"
description: "How to set up the Security Hub Upstream Connector for DefectDojo"
weight: 117
audience: pro
---
The AWS Security Hub connector uses an AWS access key to interact with the Security Hub APIs.

#### Prerequisites

Rather than use the AWS access key from a team member, we recommend creating an IAM User in your AWS account specifically for DefectDojo, with that user's permissions limited to those necessary for interacting with Security Hub.

AWS's "**[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)**policy" provides the required level of access for a connector. If you would like to write a custom policy for a Connector, you will need to include the following permissions:

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

A working policy definition might look like the following:

```
{  
    "Version": "2012-10-17",  
    "Statement": [  
        {  
            "Sid": "AWSSecurityHubConnectorPerms",  
            "Effect": "Allow",  
            "Action": [  
                "securityhub:DescribeHub",  
                "securityhub:GetFindingAggregator",  
                "securityhub:GetFindings",  
                "securityhub:ListFindingAggregators"  
            ],  
            "Resource": "*"  
        }  
    ]  
}
```

**Please note:** we may need to use additional API actions in the future to provide the best possible experience, which will require updates to this policy.

Once you have created your IAM user and assigned it the necessary permissions using an appropriate policy/role, you will need to generate an access key, which you can then use to create a Connector.

#### Connector Mappings

1. Enter the appropriate [AWS API Endpoint for your region](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region) in the **Location** field**:**  for example, to retrieve results from the `us-east-1` region, you would supply

`https://securityhub.us-east-1.amazonaws.com`
2. Enter a valid **AWS Access Key** in the **Access Key** field.
3. Enter a matching **Secret Key** in the **Secret Key** field.

DefectDojo can pull Findings from more than one region using Security Hub's **cross\-region aggregation** feature. If [cross\-region aggregation](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html) is enabled, you should supply the API endpoint for your "**Aggregation Region**". Additional linked regions will have ProductRecords created for them in DefectDojo based on your AWS account ID and the region name.

#### Asset Grouping (optional)

By default the connector creates one Record, and so one asset, per AWS account and region, named `Account <account id> (<region>)`. Every finding in that account and region lands on that one asset, whatever resource it is about. The **Asset Grouping** field, under **Import Filters** on the connector form, can split findings more finely:

| Asset Grouping | Records | Findings are imported on |
|---|---|---|
| **Account and Region** (default) | one per AWS account and region | the account and region Records |
| **Resource Type** | additionally, one per resource type (EC2, ECR, Lambda, S3, ...) under each account and region | the resource type Records |
| **Resource** | additionally, one per resource, under its resource type | the resource Records |

With **Resource**, a container image is not a resource of its own: every image of an ECR repository is grouped under that repository, along with the repository's own findings, because an image digest is a version of the repository. Lambda function versions are likewise grouped under the function.

Resource Records are named `<resource> (<type>, <account>, <region>)`, for example `team/api (ECR, prod / 111111111111, us-east-1)` or `web-1 [i-0abc] (EC2, prod / 111111111111, us-east-1)`. The account ID is always part of the name; the account name is added when DefectDojo can read it (see *Optional permissions* below).

With a finer grouping:

* The account and region Records keep the same identity and become **parent assets**. They carry no findings themselves. When the Asset Hierarchy feature is enabled, DefectDojo relates each resource type asset to its account and region asset, and each resource asset to its resource type asset, with a `parent` relationship. Findings then roll up the hierarchy. Relationships created by the connector never overwrite relationships you created by hand.
* Each finding is imported once, on the asset of the first resource it names (Security Hub lists the affected resource first). The total number of findings is the same under every grouping.
* Resources are discovered from findings, so only resources with at least one finding that the connector would import (active, at or above the minimum severity, from an AWS service) become Records. A resource whose last finding is fixed keeps its Record for 14 days so that the next Syncs close its findings in DefectDojo, after which the Record is marked MISSING.
* AWS resource tags reach resource assets as asset tags, prefixed `aws:` (for example `aws:team:payments`). Tags you add yourself are never touched; tags that start with `aws:` on resource assets are managed by the connector.
* The connector makes one Security Hub request per Record on each Sync, paced below the Security Hub API rate limit, so a Sync with thousands of resource Records takes longer than an account and region Sync. Memory use stays low because findings are processed one page at a time.

Under every grouping, including the default, findings are sent to DefectDojo one Security Hub page at a time as they arrive, so the connectors service holds about one upload chunk in memory rather than every finding of an account and region.

**Switching an existing connection to a finer grouping:** the field can be changed at any time. On the next discovery, the new Records appear for mapping; enable **Auto Map** on the connection when you change the grouping so findings move without a gap. On the next Sync, the account and region assets stop receiving findings and their previously imported findings are closed (the same findings are imported again on the new assets, with fresh status). Notes and history on the old findings stay on the account and region assets. Switching back reverses this: the account and region Records carry findings again (previously closed findings re-open as they re-match), and the finer Records close their findings and are then marked MISSING. Their assets are kept, so you can archive them at your convenience.

#### Account Parent Assets (optional)

Turn on **Parent Asset per AWS Account** to add one asset per AWS account above that account's assets. Its name is `<account name> / <account id>` when DefectDojo can read the account name (see *Optional permissions* below), otherwise `AWS account <account id>`. The account ID stays in the name because AWS account names are not unique. The account asset carries no findings; it exists so the hierarchy reads by account. With the Asset Hierarchy feature enabled, DefectDojo relates every account and region asset to its account asset with a `parent` relationship:

| Asset Grouping | Hierarchy with Parent Asset per AWS Account |
|---|---|
| **Account and Region** | account > account and region |
| **Resource Type** | account > account and region > resource type |
| **Resource** | account > account and region > resource type > resource |

Existing account and region assets keep their names and identities, so existing mappings, findings and history are unchanged; they gain the parent on the next discovery. The account asset is placed in the same organization as the account's other assets (see *Organization Placement*). Turning the toggle off stops creating account assets; relationships already drawn stay until you remove them.

#### Organization Placement (optional)

New assets from a Security Hub connection are placed in the organization named **Security Hub Connector**. The **Organization Placement** field can instead place each AWS account's assets in an organization of its own:

* **One per AWS Account, Named by Account ID:** organizations named `AWS <account id>`.
* **One per AWS Account, Named by Account Name:** organizations named after the AWS account name, falling back to `AWS <account id>` when the name cannot be read.
* **One per AWS Organizations OU, Nested Along the OU Path:** each account's assets go to an organization for the organizational unit (OU) the account sits in. The full OU path becomes nested organizations: an account in the OU `Prod` under the OU `Workloads` lands in the organization `Workloads / Prod`, nested under the organization `Workloads`. Each nested organization is named by its whole path so that two OUs with the same name under different parents stay apart.
* **Named by an AWS Account Tag:** each account's assets go to an organization named after the value of an AWS account tag. Enter the tag key, for example `team`, in **AWS Account Tag Key**. A key that differs only in case also matches.

Organizations are created when they do not exist yet, and reused when they do. Nesting is only added to an organization that has no parent and the same organization type as its parent; DefectDojo never moves an organization you nested yourself. An account that sits directly under the organization root, an account without the tag, and every account when the optional permissions are missing, keep the default **Security Hub Connector** placement.

The field decides where new assets are created. Assets that already exist stay where they are until you re-place them (see *Re-placing existing assets*). After you change the field, run a discovery: it records each account's placement on its Records, which the re-place action reads.

#### Re-placing existing assets

A connection that mapped its assets before you chose an **Organization Placement** has them all in the **Security Hub Connector** organization. The **Re-place Existing Assets** panel at the bottom of the connection's edit page moves them:

1. Save the connection with the placement you want, then run a discovery (or wait for the scheduled one).
2. Click **Preview**. Nothing changes yet. The preview lists every asset that will move, from which organization to which, how many descendants move along with their parents, how many parent relationships are removed because they would cross organizations, how many organizations will be created, and how many assets are skipped and why.
3. Click **Start Re-placement** and confirm. The moves run in the background in batches, and DefectDojo notifies you when they finish. The panel shows the outcome of the last run.

Only assets that are still in the connector's default organization move. An asset you (or a rule) already placed in another organization is never touched. An asset is also skipped when its account has no placement (no OU, no tag), when the placement on its Record was computed under a different setting (run a discovery first), when you cannot edit it, or when you may not add assets to its destination organization or create the organizations it needs.

Moves follow the same rules as any other organization move in DefectDojo: an asset's descendants move with it unless you turn off **Move Children Along**, a parent relationship left crossing organizations is removed and its owners are notified, and priority is recalculated for every affected organization. After the moves, the connector's parent relationships that could not be drawn while parent and child sat in different organizations are drawn.

The same action is available to automation with an API token, for a user who can manage connectors:

* `POST /api/v2/connector_configs/{id}/replace_assets/` with `{"dry_run": true}` (the default) returns the preview as JSON and changes nothing.
* `POST /api/v2/connector_configs/{id}/replace_assets/` with `{"dry_run": false}` starts the moves and answers `202` with the run's status, or `409` when a run for the connection is already in progress.
* `GET /api/v2/connector_configs/{id}/replace_assets/` returns the latest run's status: `idle`, `queued`, `running`, `done` (with counts of moved assets and refused batches) or `failed`.

Both `POST` forms accept `"move_children": false`. A preview looks like this (shortened):

```
{
    "placement": "account_tag:team",
    "default_organization": {"id": 3, "name": "Security Hub Connector"},
    "moves": [
        {
            "asset": {"id": 41, "name": "Account 012345678901 (us-east-1)"},
            "record": "securityhub-012345678901-us-east-1",
            "from_organization": {"id": 3, "name": "Security Hub Connector"},
            "to_organization": {"id": null, "name": "payments", "path": ["payments"]},
            "descendants": []
        }
    ],
    "organizations": [{"name": "payments", "id": null, "parent": null, "create": true}],
    "links_removed": [],
    "skipped": [{"asset": {"id": 57, "name": "Account 333333333333 (us-east-1)"}, "record": "securityhub-333333333333-us-east-1", "reason": "no_placement"}],
    "summary": {"moves": 1, "descendants_moved": 0, "parent_links_removed": 0, "organizations_created": 1, "skipped": {"no_placement": 1}}
}
```

#### Optional permissions: AWS Organizations

Account names and the OU and account tag placements read from AWS Organizations. Only the AWS Organizations management account or a delegated administrator account can grant these permissions. Each is used only when a setting needs it, at most once per account and OU on each discovery, and without it the connector silently falls back: account IDs instead of names, and the default organization instead of an OU or tag placement.

| Permission | Used for |
|---|---|
| `organizations:ListAccounts` | account names in Record and organization names: a grouping finer than the default, **Organization Placement** by account name, or **Parent Asset per AWS Account** |
| `organizations:ListParents` | **Organization Placement** by OU: the OU path of each account |
| `organizations:DescribeOrganizationalUnit` | **Organization Placement** by OU: the name of each OU |
| `organizations:ListTagsForResource` | **Organization Placement** by account tag: the tags of each account |

```
{
    "Sid": "AWSSecurityHubConnectorOrganizations",
    "Effect": "Allow",
    "Action": [
        "organizations:ListAccounts",
        "organizations:ListParents",
        "organizations:DescribeOrganizationalUnit",
        "organizations:ListTagsForResource"
    ],
    "Resource": "*"
}
```

Placement by OU or account tag makes one or two AWS Organizations requests per account on each discovery, paced to stay under the AWS Organizations rate limit, so a discovery across thousands of accounts takes several minutes longer.

#### Compliance Tags

Each Finding is tagged with the compliance requirements Security Hub relates its control to, for
example `nist.800-53.r5:ac-2(1)` or `pci_dss_v4.0.1/2.2.4`. DefectDojo Pro reads these tags to map
the Finding to NIST 800-53 and PCI DSS controls (see
[Control Coverage](/federal_compliance/control_coverage/)). The same requirements are still listed
under **Compliance details** in the Finding's description.
