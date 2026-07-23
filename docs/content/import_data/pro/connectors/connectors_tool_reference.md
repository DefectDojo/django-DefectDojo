---
title: "Tool-Specific Connector Setup"
description: "Our list of supported Connector tools, and how to set them up with DefectDojo"
aliases:
  - /en/connecting_your_tools/connectors/connectors_tool_reference
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Connectors are a DefectDojo Pro-only feature.</span>

When setting up a Connector for a supported tool, you'll need to give DefectDojo specific information related to the tool's API. At a base level, you'll need:

* **Location** \-a field whichgenerallyrefers to your tool's URL in your network,
* **Secret** \- generally an API key.

Some tools will require additional API\-related fields beyond **Location** and **Secret**. They may also require you to make changes on their side to accommodate an incoming Connector from DefectDojo.

![image](images/connectors_tool_reference.png)

Each tool has a different API configuration, and this guide is intended to help you set up the tool's API so that DefectDojo can connect.

Whenever possible, we recommend creating a new 'DefectDojo Bot' account within your Security Tool which will only be used by the Connector. This will help you better differentiate between actions manually taken by your team, and automated actions taken by the Connector.

# **Asset Connectors**

Most Connectors import **findings** from a security tool. **Asset Connectors** work differently: they import your **asset inventory** instead. An Asset Connector enumerates the assets that exist in an external platform (for example, the repositories in a GitLab group) and automatically creates and maintains the matching **Products** (Assets) and **Product Types** (Organizations) in DefectDojo. No findings are imported by an Asset Connector.

* **Discover** and **Sync** both reconcile the asset list. New assets appear as `NEW` Records; once mapped (automatically, if auto-mapping is enabled), DefectDojo creates the Product and groups it under a Product Type derived from the tool — for example, the GitLab namespace or the Azure DevOps project.
* If an asset is later removed upstream (for example, a repository is deleted), its mapped Record is flagged `MISSING` on the next Sync so your team can triage it. DefectDojo never silently deletes a Product.

Azure DevOps, Bitbucket, GitHub, GitLab, and Jira Service Management Assets are Asset Connectors. All other Connectors listed below import findings.

# **Supported Connectors**

## **Akamai API Security**

The Akamai API Security connector uses an API key to pull security findings from the Akamai API. DefectDojo will discover your Akamai environment and create separate Records for each **Application** and **Host** configured in your account.

#### Prerequisites

You will need an API key with access to the Akamai API. We recommend creating a dedicated service account for DefectDojo to clearly distinguish automated activity from manual team actions.

#### Connector Mappings

1. Enter your Akamai API base URL in the **Location** field. This URL is specific to your Akamai instance: for example
2. Enter a valid **API Key** in the **Secret** field.

DefectDojo will map **Applications** and **Hosts** as separate Records. Each Application will appear as `{name} (application)` and each Host as `{name} (host)` in your Records list.

## **Anchore**

The Anchore connector uses a user's API token to pull data from Anchore Enterprise.  Products will be mapped and discovered based on "Applications", which are composed of multiple Images in Anchore - see [Anchore Enterprise Documentation](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) for more information.

#### Connector Mappings

1. The Anchore URL in the **Location** field: this is the URL where you access the Anchore.
2. Enter a valid API Key in the Secret field. This is the API key associated with your Burp Service account.

See the official [Anchore documentation](https://docs.anchore.com/current/docs/) for more information on creating a token for Anchore.

## **AWS Security Hub**

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

## **Azure DevOps**

The Azure DevOps connector is an **Asset Connector**: it enumerates the git repositories in every project of your Azure DevOps organization and creates a DefectDojo Asset for each repository, grouped into Organizations by Azure DevOps project. No findings are imported.

#### Prerequisites

You will need a Personal Access Token (PAT) for the organization. We recommend creating the token from a dedicated service account. Only read scopes are required:

1. In Azure DevOps, open **User settings \> Personal access tokens \> New Token**.
2. Click **Show all scopes**, then select **Code: Read** and **Project and Team: Read**.

Only Azure DevOps Services (dev.azure.com) is supported; on-premise Azure DevOps Server is not supported at this time.

#### Connector Mappings

1. Enter your organization URL in the **Location** field: `https://dev.azure.com/{your-organization}`. Legacy `https://{your-organization}.visualstudio.com` URLs are also accepted, and any extra path segments (for example, a link to a specific project) are ignored.
2. Enter the PAT in the **Secret** field.

Each repository becomes a Record named after the repository, grouped by its Azure DevOps **project**. Disabled repositories are skipped, so disabling or deleting a repository flags its Record as `MISSING` on the next Sync.

## **Backstage**

The Backstage connector is an **asset connector**: instead of importing Findings, it pulls your [Backstage](https://backstage.io) Software Catalog into DefectDojo and keeps your Product hierarchy and team ownership in sync with it. It is designed for organizations that maintain their service inventory and org structure in Backstage and want DefectDojo to mirror that structure instead of maintaining it by hand.

#### What gets mapped

| Backstage | DefectDojo |
|---|---|
| **System** | Product Type (Components with no System are grouped under a configurable "Backstage / Uncategorized" Product Type) |
| **Component** | Product — named from the entity `title` (falling back to `name`), with the catalog description |
| **Owning Group** (`ownedBy` relation) | A DefectDojo Group linked to the Product (default role: Maintainer, configurable) |
| **Owner email** (Group profile email, or a User owner's email) | A Product Member, when a DefectDojo user with that email already exists (users are never created) |
| `metadata.tags`, `spec.type`, `spec.lifecycle`, namespace, domain | Product tags under a `backstage:` prefix |
| `metadata.annotations` | Stored on the Record (bounded); selected annotations can be promoted to first-class attributes or tags via **Annotation Mappings** |

Records are keyed by the entity's server\-assigned `metadata.uid`, so renames in Backstage update the mapped Product **in place** on the next sync — no duplicates. The Product name always tracks the catalog: to rename a Product managed by this connector, rename the Component in Backstage (a DefectDojo\-side rename, or a custom name given during manual mapping, is reconciled back to the catalog name on the next sync unless it would collide with another Product). Ownership changes move the Product's group assignment. Components that disappear from the catalog (or are flagged with the `backstage.io/orphan` annotation) are marked **MISSING** — DefectDojo never deletes a Product on its own. Domain and Group hierarchy (parent teams) are recorded as tags/metadata only; they do not create extra hierarchy levels.

#### Prerequisites

The connector authenticates with a **static external access token** against the Backstage backend. In your Backstage app config, define a token and (recommended) restrict it to the catalog plugin:

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

Generate a strong random token (for example `openssl rand -hex 32`) and store it in your Backstage deployment's environment. See the [Backstage service-to-service auth documentation](https://backstage.io/docs/auth/service-to-service-auth) for details.

#### Connector Mappings

1. Enter your **Backstage backend root URL** in the **Location** field: for example `https://backstage.example.com` (the connector appends `/api/catalog`). This must be the **backend** URL, not the frontend web UI.
2. Enter the static external access token in the **Secret** field.

Optional fields (leave blank for the defaults):

* **Namespaces** — comma\-separated catalog namespaces to import; blank imports every namespace.
* **Component Types** — comma\-separated `spec.type` values (e.g. `service,website`); blank imports every type.
* **Page Size** — catalog query page size (1\-500, default 250).
* **TLS Verification** — set to `false` only if Backstage serves a certificate DefectDojo cannot verify (internal CA); not recommended.
* **Uncategorized Product Type** — the Product Type used for Components with no System (default `Backstage / Uncategorized`).
* **Owner Group Role** — the role granted to the owning team on mapped Products (default `Maintainer`).
* **Annotation Mappings** — a JSON object mapping annotation keys to Record attribute names, or to `"tag"` to import an annotation as a Product tag, e.g. `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`.

With **Auto\-Map** enabled, a single Discover \+ Sync builds the complete Product Type / Product / ownership structure with no manual steps. With Auto\-Map disabled, discovered Components appear as Records awaiting your mapping decision.

#### Limitations (v1)

* Backstage **Group membership is not synchronized**: the connector creates/links the owning team as a DefectDojo Group, but populating that group's users is left to your identity provider or admins.
* Only Components become Products; APIs, Resources, and Domains are not imported as assets (domains surface as tags).
* Tags and annotations are normalized and bounded to fit DefectDojo field limits (oversized values are truncated).

**A note on the reverse direction:** displaying DefectDojo findings and grades *inside* Backstage (on entity pages) is a natural follow\-on that would be built as a Backstage frontend plugin consuming the DefectDojo REST API — it is deliberately out of scope for this connector, which only pulls catalog data into DefectDojo.

## **Bitbucket**

The Bitbucket connector is an **Asset Connector**: it enumerates the repositories in the Bitbucket Cloud workspaces you name and creates a DefectDojo Asset for each repository, grouped into Organizations by Bitbucket project. No findings are imported.

#### Prerequisites

Bitbucket Cloud requires a **scoped** Atlassian API token — classic (unscoped) Atlassian API tokens are rejected by Bitbucket with an "API Token provided has no Bitbucket scopes" error.

1. Go to [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) and choose **Create API token with scopes**.
2. Select the **Bitbucket** app, then grant the read scopes: `read:account:bitbucket`, `read:workspace:bitbucket`, `read:repository:bitbucket`, and `read:project:bitbucket`.

Only Bitbucket Cloud (bitbucket.org) is supported. Bitbucket Server reached end of life in 2024, and Bitbucket Data Center is not supported.

#### Connector Mappings

1. Enter `https://bitbucket.org` in the **Location** field.
2. Enter the Atlassian account email the token belongs to in the **Email** field.
3. Enter the scoped API token in the **Secret** field.
4. Enter one or more workspace slugs (comma-separated) in the **Workspace Slugs** field. This field is required: Bitbucket's scoped API tokens cannot list workspaces automatically, so DefectDojo needs to be told which workspaces to read.

Each repository becomes a Record named after the repository, grouped by its Bitbucket **project**.

## **BurpSuite**

DefectDojo’s Burp connector calls Burp’s GraphQL API to fetch data. 

#### Prerequisites

Before you can set up this connector, you will need an API key from a Burp Service Account. Burp user accounts don’t have API keys by default, so you may need to create a new user specifically for this purpose. 

See [Burp Documentation](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user) for a guide on setting up a Service Account user with an API key.

#### Connector Mappings

1. Enter Burp’s root URL in the **Location** field: this is the URL where you access the Burp tool.
2. Enter a valid API Key in the Secret field. This is the API key associated with your Burp Service account.

See the official [Burp documentation](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html) for more information on the Burp API.

## **Censys**

The Censys connector reads host assets from the Censys Platform and imports each host's exposed services as findings. It uses the Censys Platform global search API to enumerate the hosts you scope it to.

#### Prerequisites

You will need a Censys **Platform** account with API access:

* A **Personal Access Token**, created in the Censys Platform Console under Personal Access Tokens.
* Your **Organization ID**, shown on the same settings page under "Current Organization". API access to the search endpoint requires an organization, so a Starter tier or higher is needed. Free\-tier tokens have no organization ID and cannot use the search API.

Per\-host CVE and risk data is available only on Censys Core (enterprise) tiers, so on lower tiers findings represent exposed services rather than vulnerabilities.

See the [Censys Platform API documentation](https://docs.censys.com/reference/get-started) for more information.

#### Connector Mappings

1. Enter `https://api.platform.censys.io` in the **Location** field.
2. Enter your Personal Access Token in the **API Key** field.
3. Enter your **Organization ID**.
4. Enter a **Search Query** that scopes the import to your own assets, for example `host.autonomous_system.asn: <your ASN>` or `host.ip: 203.0.113.0/24`.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo creates a Record for each host and imports its exposed services as findings.

## **Checkmarx ONE**

DefectDojo's Checkmarx ONE connector calls the Checkmarx API to fetch data.

#### **Connector Mappings**

1. Enter your **Tenant Name** in the **Checkmarx Tenant** field. This name should be visible on the Checkmarx ONE login page in the top\-right hand corner:   
" Tenant: \<**your tenant name**\> "  
​
![image](images/connectors_tool_reference_2.png)

2. Enter a valid API key. You may need to generate a new one: see [Checkmarx API Documentation](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08) for details.
3. Enter your tenant location in the **Location** field. This URL is formatted as follows:  
​`https://<your-region>.ast.checkmarx.net/` . Your Region can be found at the beginning of your Checkmarx URL when using the Checkmarx app. **<https://ast.checkmarx.net>** is the primary US server (which has no region prefix).

## **Cloudflare**

The Cloudflare connector imports **Security Center insights** — security posture issues Cloudflare surfaces about your account and zones, such as a missing DMARC record, DNSSEC not being enabled, or a certificate problem. DefectDojo creates a Record for each zone (domain) that has open insights, plus an account-level Record for insights that are not tied to a specific zone.

#### Prerequisites

You will need a Cloudflare **API token** (not the legacy Global API Key). Create one under **My Profile > API Tokens > Create Token** in the Cloudflare dashboard. The quickest option is the **"Read all resources"** template; for a least-privilege token, grant **Zone > Zone > Read** (all zones) plus account-level read access for Security Center.

#### Connector Mappings

1. Enter `https://api.cloudflare.com/client/v4` in the **Location** field.
2. Enter the API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo auto-discovers the accounts and zones the token can access — no account ID is required. Only open (active, non-dismissed) insights are imported, so insights you resolve or dismiss in Cloudflare are automatically mitigated in DefectDojo on the next sync.

## **Cobalt.io**

The Cobalt.io connector uses the Cobalt.io API (v2) to pull pentest findings from your Cobalt.io organization. DefectDojo discovers every organization your API token can access and creates a separate Record for each **asset** (the unit Cobalt pentests).

#### Prerequisites

You will need a Cobalt.io **personal API token**. We recommend creating a dedicated service account for DefectDojo to clearly distinguish automated activity from manual team actions. Generate a token from **Settings \> API Tokens** in the Cobalt.io UI. Organization tokens are discovered automatically \- you do not need to supply them.

#### Connector Mappings

1. Enter the Cobalt.io API base URL in the **Location** field: `https://api.cobalt.io` (or your regional host, for example `https://api.us.cobalt.io`).
2. Enter your **personal API token** in the **Secret** field.
3. Optionally, enter an **Organization Token** to pin the sync to a single organization. When left blank, DefectDojo syncs every organization the personal API token can access.

DefectDojo maps each Cobalt.io **asset** as a separate Record. Findings are imported for each mapped asset, with their Cobalt.io state (for example `valid_fix`, `wont_fix`, `invalid`) driving the finding status in DefectDojo.

## **Contrast**

The Contrast connector uses the Contrast Assess REST API to import application vulnerabilities. DefectDojo discovers the applications in your Contrast organization and creates a Record for each one.

#### Prerequisites

You will need four values from Contrast. We recommend creating a dedicated service account so automated activity is easy to distinguish from your team's manual actions. In the Contrast UI, under **User Settings > Profile > Your Keys**, you can find:

* Your organization **API Key**.
* Your personal **Service Key**.
* The **username** the credentials belong to (the account's login email).
* Your **Organization ID** — the UUID of the organization to import from, also shown under **Organization Settings**.

#### Connector Mappings

1. Enter the base URL you use to access Contrast in the **Location** field — for the hosted product this is typically `https://app.contrastsecurity.com` (or your regional / self-hosted Team Server URL).
2. Enter the account login email in the **Username** field.
3. Enter the organization **API Key** in the **API Key** field.
4. Enter the personal **Service Key** in the **Service Key** field.
5. Enter the **Organization ID** (UUID) in the **Organization ID** field.
6. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Contrast application becomes a Record, and its vulnerabilities are imported as findings.

## **CrowdStrike Falcon**

The CrowdStrike Falcon connector imports **Spotlight vulnerabilities** and **EDR detections** from the Falcon platform, as two separate finding types (`CrowdStrike:Spotlight` and `CrowdStrike:Detections`). DefectDojo creates a Record for each Falcon **host**.

#### Prerequisites

A Falcon **API client** (Client ID and secret), created in the Falcon console under **Support \> API Clients and Keys**. Grant it the scopes for the data you want to import: **Hosts: Read** (required, for host discovery), **Vulnerabilities (Spotlight): Read** (for Spotlight findings), and **Alerts: Read** (for EDR detections). The two finding types are independent — if the client lacks a scope, that finding type is skipped rather than failing the sync, so a client without **Alerts: Read** still imports Spotlight vulnerabilities.

#### Connector Mappings

1. Enter your Falcon cloud's API base URL in the **Location** field, matching your console region — for example `https://api.crowdstrike.com` (US\-1), `https://api.us-2.crowdstrike.com` (US\-2), `https://api.eu-1.crowdstrike.com` (EU\-1), or `https://api.laggar.gcw.crowdstrike.com` (US\-GOV\-1).
2. Enter the API client's Client ID in the **Client ID** field.
3. Enter the API client's secret in the **Client Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Falcon host becomes a Record, named for its hostname, OS, and type. Only **open** and **reopened** Spotlight vulnerabilities are imported, so reimport closes remediated findings.

## Dependency\-Track

This connector fetches data from a on\-premise Dependency\-Track instance, via REST API.

​**Connector Mappings**

1. Enter your local Dependency\-Track server URL in the **Location** field.
2. Enter a valid API key in the **Secret** field.

To generate a Dependency\-Track API key:

1. **Access Management**: Navigate to Administration \> Access Management \> Teams in the Dependency\-Track interface.
2. **Teams Setup**: You can either create a new team or select an existing one. Teams allow you to manage API access based on group membership.
3. **Generate API Key**: In the selected team's details page, find the "API Keys" section. Click the \+ button to generate a new API key.
4. **Assign Permissions**: In the "Permissions" section of the team's page, click the \+ button to open the permissions selector. Choose **VIEW\_PORTFOLIO** and **VIEW\_VULNERABILITY** permissions to enable API access to project portfolios and vulnerability details.
5. Click "**Select**" to confirm and save these permissions.

For more information, see **[Dependency\-Track Documentation](https://docs.dependencytrack.org/integrations/rest-api/)**.

## **Docker Scout**

The Docker Scout connector uses the Docker Scout metrics exporter API to report the vulnerability posture of your organization's images. DefectDojo discovers each Docker Scout stream (your runtime environments) and imports a summary of the vulnerabilities and policy compliance for each.

#### Prerequisites

You will need a Docker personal access token created by an **owner** of a Docker organization that is **enrolled in Docker Scout**. The metrics exporter is an organization-level feature, so a personal account, or an organization that is not enrolled in Docker Scout, will not return data.

Create the token from your Docker account settings under **Personal access tokens**, and note your Docker **organization namespace**, which you will also need.

#### Connector Mappings

1. Enter `https://api.scout.docker.com` in the **Location** field.
2. Enter your Docker personal access token in the **Secret** field.
3. Enter your Docker **Organization** namespace.
4. Optionally, set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity will not be imported.

DefectDojo creates a separate Record for each Docker Scout stream, and imports one finding per severity for the vulnerabilities Docker Scout counts in that stream, plus a finding for each image that fails your Docker Scout policy. Docker Scout's metrics API reports aggregate counts rather than individual CVEs, so these findings summarize the posture of a stream. Open the stream in Docker Scout for per-image and per-CVE detail.

See the [Docker Scout documentation](https://docs.docker.com/scout/) for more information.

## **Endor Labs**

The Endor Labs connector uses the Endor Labs REST API to sync an entire Endor Labs **namespace**. DefectDojo discovers each Endor **project** as a Record and imports that project's findings, carrying Endor's **reachability** verdict so you can prioritize vulnerabilities whose affected code is actually reachable.

#### Prerequisites

You will need an Endor Labs **API key** (a key identifier plus its secret) and the **namespace** you want to sync. Create the key in the Endor Labs platform under **Settings \> Access \> API Keys**; the key needs read access to the projects and findings in that namespace.

The connector authenticates by exchanging the API key and secret for a short-lived bearer token — the secret is used only for that exchange and is never stored in cleartext.

#### Connector Mappings

1. Enter `https://api.endorlabs.com` in the **Location** field. If your tenant is hosted in a different region, use that region's API base URL instead.
2. Enter the Endor Labs **Namespace** to sync (for example `your-org` or `your-org.team`).
3. Enter the **API Key** identifier.
4. Enter the **API Secret** paired with the key.
5. Optionally set **Traverse Child Namespaces** to `true` to also import findings from child namespaces of the configured namespace.
6. Optionally set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity are not imported.

DefectDojo creates a Record for each Endor Labs project in the namespace and imports its findings, mapping Endor severity levels to DefectDojo severities, the CVE/GHSA identifiers and CVSS score of each vulnerability, and Endor's reachability tags. The reachability verdict (for example *Reachable — vulnerable function is called* or *Unreachable*) is surfaced as the finding's Impact and as a tag.

For more information, see the **[Endor Labs REST API documentation](https://docs.endorlabs.com/rest-api/)**.

## **Edgescan**

The Edgescan connector uses the Edgescan REST API to import open vulnerabilities across your whole Edgescan account. DefectDojo enumerates every Edgescan **asset** and creates a Record for each one, then imports that asset's open vulnerabilities as findings — there is no per\-asset configuration.

#### Prerequisites

You will need an Edgescan API token. Create one from your Edgescan account under **Account settings \> API tokens**: enter a label, click **Create**, and copy the generated token (it is shown only once). We recommend a dedicated account for the Connector so automated activity is easy to distinguish.

#### Connector Mappings

1. Enter your Edgescan URL in the **Location** field — `https://live.edgescan.com` for the standard hosted platform, or your tenant's host if different.
2. Enter your Edgescan API token in the **Secret** field. It is sent as the `X-API-TOKEN` header.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Edgescan asset becomes a Record, and each open vulnerability on that asset is imported as a finding. Severity is mapped from Edgescan's numeric scale (1–5) to DefectDojo's Info–Critical, and CVE references, the CWE, and a CVSS v3 vector are included where Edgescan provides them.

## **GitGuardian**

The GitGuardian connector uses the GitGuardian REST API to import **secret incidents** — exposed credentials GitGuardian has detected across your monitored sources. DefectDojo creates a Record for each monitored source (repository or perimeter) that currently has open incidents, and imports each open incident as a finding.

For your security, the connector imports only incident **metadata** — the detector, severity, validity, status, and a link back to GitGuardian. The exposed secret value itself is never retrieved or stored by DefectDojo; follow the link in each finding to review the affected locations in GitGuardian.

#### Prerequisites

You will need a GitGuardian API key. We recommend a **Service Account token** (rather than a personal access token) so automated activity is easy to distinguish. Create it under **API** in the GitGuardian dashboard and grant these read scopes:

* `incidents:read`
* `sources:read`

#### Connector Mappings

1. Enter your GitGuardian API URL in the **Location** field: `https://api.gitguardian.com` for the SaaS platform, or your self-hosted instance's API URL.
2. Enter the API key in the **Secret** field.

Only **open** incidents (status `TRIGGERED` or `ASSIGNED`) are imported; incidents you resolve or ignore in GitGuardian are automatically mitigated in DefectDojo on the next sync. A confirmed-live secret (validity *valid*) is imported as a verified finding.

## **GitHub Advanced Security**

The GitHub Advanced Security connector imports **code scanning**, **Dependabot**, and **secret scanning** alerts from GitHub, as three separate finding types (`GitHub:CodeScanning`, `GitHub:Dependabot`, and `GitHub:SecretScanning`). DefectDojo discovers every non\-archived repository in the configured organization and creates a Record for each one.

#### Prerequisites

GitHub Advanced Security features must be enabled for the repositories you want to import. The connector authenticates with a GitHub **personal access token**:

1. In GitHub, open **Settings \> Developer settings \> Personal access tokens** and create a token owned by (or with access to) the target organization.
2. Grant it read access to the security alerts: a *fine\-grained* token needs **Read\-only** access to **Code scanning alerts**, **Dependabot alerts**, and **Secret scanning alerts** on the organization's repositories; a *classic* token needs the **`repo`** and **`security_events`** scopes.
3. Confirm the token's owner can see the repositories you intend to import — the connector only sees repositories the token can access.

#### Connector Mappings

1. Enter `https://api.github.com` in the **Location** field. For GitHub Enterprise Server, use `https://<your-host>/api/v3`.
2. Enter the organization login in the **Organization** field.
3. Enter the personal access token in the **Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each non\-archived repository becomes a Record, queried across the three alert families for open alerts. An alert family that is not enabled for a repository is skipped rather than reported as resolved, so disabled features do not cause false closures.

## **GitLab**

The GitLab connector is an **Asset Connector**: it enumerates every project (repository) your token can access and creates a DefectDojo Asset for each one, grouped into Organizations by GitLab namespace (group or user). No findings are imported.

#### Prerequisites

You will need a Personal Access Token with the **read_api** scope. We recommend creating the token from a dedicated service account; the connector lists the projects that account is a member of.

#### Connector Mappings

1. Enter your GitLab URL in the **Location** field: `https://gitlab.com`, or the base URL of your self-hosted instance.
2. Enter the Personal Access Token in the **Secret** field.

Each project becomes a Record named after the project, grouped by its **namespace**. Projects that are pending deletion in GitLab (deleted by a user, but not yet purged by GitLab's background job) are excluded automatically, so deleting a project flags its Record as `MISSING` on the next Sync instead of leaving behind a renamed ghost asset.

## **Google Cloud Security Command Center**

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

## **Group-IB ASM**

The Group-IB ASM (Attack Surface Management) connector uses the Group-IB ASM REST API to pull external attack-surface **issues** (findings) into DefectDojo. DefectDojo discovers each Group-IB **company/tenant** as a separate Record and imports that company's issues on a scheduled, incremental basis. The asset each issue relates to (a domain, IP, or URL) is attached to the resulting finding as an **Endpoint**.

#### Prerequisites

You will need your Group-IB ASM login and an API key. We recommend creating a dedicated service account for DefectDojo so that automated activity can be distinguished from manual team actions.

To generate an API key:

1. Open Group-IB Attack Surface Management, click **Help** in the lower-left corner, and select **API**.
2. Click **Generate API Key** (top-right, under your username).
3. Enter your SSO password and click **Next**, then click **Copy token**.
4. Store the key in a secret manager and plan for regular rotation.

#### Connector Mappings

Group-IB ASM authenticates with HTTP Basic Auth, where the username is your ASM login and the password is your API key. **Both values are required** — the API key alone is not sufficient.

1. Enter `https://asm.group-ib.com` in the **Location** field. This is the same for all Group-IB ASM tenants.
2. Enter your ASM login (usually an email address) in the **Username** field.
3. Enter your API key in the **API Key** (Secret) field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity are not imported.

DefectDojo maps each Group-IB **company** as a separate Record, using the company ID as the identifier. On the first Sync, DefectDojo backfills recent issue history; subsequent Syncs are incremental, pulling only issues changed since the last Sync (tracked by each issue's most recent `lastSeen` timestamp).

#### Scoping to a single company (optional)

By default, the connector automatically discovers the companies available to your API credentials (via the ASM `clients` endpoint) and creates one Record per company. This is the recommended setup and requires no extra configuration.

If the `clients` endpoint is not available for your tenant — for example, when it is restricted to partner/MSP accounts — the connector can be scoped to one company by supplying its **company ID** as a `company_id` tool-specific field on the connector configuration. When `company_id` is set, DefectDojo uses that company directly instead of enumerating companies. Leave it unset to use automatic discovery.

See the Group-IB ASM REST API manual (available in-product via **Help → API**) for more information.

## **HackerOne**

The HackerOne connector uses the HackerOne REST API to import reports from your bug bounty or vulnerability disclosure program. DefectDojo creates a Record for each program the token can access and imports its reports as findings.

#### Prerequisites

The connector uses HackerOne's **customer** API, which requires an **organization API token** — a personal token from your user settings only works against the hacker API and will not authenticate here.

1. In HackerOne, go to **Organization Settings > API Tokens**.
2. Create a token and note both the **identifier** and the **token** value. Read access to the program is sufficient.

#### Connector Mappings

1. Enter `https://api.hackerone.com` in the **Location** field.
2. Enter the token **identifier** in the **API Token Identifier** field.
3. Enter the token value in the **API Token** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each program becomes a Record, and its reports are imported as findings with the HackerOne severity rating preserved.

## **Have I Been Pwned**

The Have I Been Pwned (HIBP) connector uses the HIBP REST API to report which accounts on your organization's own domains have appeared in known data breaches. DefectDojo discovers each domain you have verified with HIBP and imports one finding per breach affecting that domain.

#### Prerequisites

You will need a Have I Been Pwned API key with domain search, which requires a **Core** subscription tier or higher. You can obtain a key from your [Have I Been Pwned account](https://haveibeenpwned.com/API/Key).

You must also **verify at least one domain** on your HIBP account before any breach data is available. HIBP lets you verify a domain by DNS TXT record, meta tag, file upload, or email, under **Domain search** in your account. Until a domain is verified, the connector discovers no domains and imports no findings.

#### Connector Mappings

1. Enter `https://haveibeenpwned.com` in the **Location** field.
2. Enter your API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity will not be imported.

DefectDojo creates a separate Record for each domain you have verified with HIBP, and imports one finding per breach affecting accounts on that domain. Each finding's severity reflects the kind of data the breach exposed, and its description lists the affected accounts on your domain so your team can act on them.

See the [Have I Been Pwned API documentation](https://haveibeenpwned.com/API/v3) for more information.

## **Intruder**

The Intruder connector uses the [Intruder REST API](https://developers.intruder.io/) to pull your whole account's posture into DefectDojo. Each Intruder **target** is discovered as a Record (Product); each **occurrence** of an issue on a target becomes a Finding.

#### Connector Mappings

1. Leave the **Location** field as `https://api.intruder.io/` (the default Intruder API server).
2. Enter an Intruder **API access token** in the **Secret** field.

Generate an access token in Intruder under **My account > API Access Tokens** (you'll need your account password to create it, and the token is shown only once). See the [Intruder API documentation](https://developers.intruder.io/docs/creating-an-access-token) for details.

Findings are derived per occurrence: severity comes from the issue severity, CVEs and CVSS from the occurrence, the location from the target/port, and a snoozed occurrence is imported as an inactive (false-positive or risk-accepted) finding.

## **IriusRisk**

The IriusRisk connector uses an API token to pull threat modeling data from your IriusRisk instance.

#### Prerequisites

You will need an API token from your IriusRisk account. We recommend creating a dedicated service account for DefectDojo to clearly distinguish automated activity from manual team actions.

To generate an API token in IriusRisk:

1. Log in to your IriusRisk instance.
2. Navigate to your **User Profile** in the top-right menu.
3. Select **API Token** and generate a new token.

See the [IriusRisk API documentation](https://support.iriusrisk.com/hc/en-us/categories/360001148511) for more information.

#### Connector Mappings

1. Enter your IriusRisk instance URL in the **Location URL** field. For cloud-hosted instances this is typically `https://{your-subdomain}.iriusrisk.com`. For on-premise installations, use your instance's base URL.
2. Enter your **API Token** in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity will not be imported.

## **JFrog Xray**

The JFrog Xray connector uses the JFrog Xray REST API to fetch vulnerability data from your Artifactory repositories. DefectDojo will discover all repositories in your JFrog instance and generate vulnerability reports via Xray, importing findings on a scheduled basis.

#### Prerequisites

You will need an API token with access to both Artifactory and Xray APIs. We recommend creating a dedicated service account for DefectDojo. The account requires:

* Read access to Artifactory repositories
* Permission to generate and view Xray vulnerability reports (`Apply on Watches` permission in Xray, or equivalent)

#### Connector Mappings

1. Enter your JFrog instance base URL in the **Location** field. This should be the root URL of your JFrog instance, for example `https://your-instance.jfrog.io`. Do not include a trailing path — DefectDojo will construct the appropriate API paths automatically.
2. Enter a valid **Reference Token** in the **Secret** field. Tokens can be generated under **User Management \> Access Tokens** in the JFrog Platform UI.
You'll need to generate a **Reference Token** and use that value.

Required token scopes for JFrog Xray:

- **All Services**, as DefectDojo needs access to both access to both XRay and Artifactory services
- **Manage Reports + Manage Resources** at a minimum.

DefectDojo maps each Artifactory **repository** as a separate Record. On first Sync, DefectDojo generates a full historical vulnerability report; subsequent Syncs generate incremental (delta) reports covering new findings since the last Sync.

See the [JFrog Xray REST API documentation](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis) for more information.

## **Jira Service Management Assets**

The JSM Assets connector is an **Asset Connector**: it enumerates the objects in your Jira Service Management Assets (formerly Insight) workspace and creates a DefectDojo Asset for each object, grouped into Organizations by object schema. No findings are imported.

#### Prerequisites

* Assets requires a **Jira Service Management Premium or Enterprise** plan. On Free or Standard plans the Assets API responds with `403 "Access to Assets API was denied"`, even though the rest of the site works.
* The Atlassian account used must have **Jira Service Management product access** (an agent seat) on the site — site access alone is not enough.
* Create a classic Atlassian API token at [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens). We recommend a dedicated service account.

#### Connector Mappings

1. Enter your Atlassian site URL in the **Location** field: `https://{your-site}.atlassian.net`.
2. Enter the Atlassian account email the token belongs to in the **Email** field.
3. Enter the API token in the **Secret** field.

Each Assets object becomes a Record named after the object's label, grouped by its **object schema**.

## **Kubescape**

The Kubescape connector reads Kubernetes posture (misconfiguration) results produced by the [Kubescape operator](https://kubescape.io/docs/install-operator/) directly from the cluster's Kubernetes API — no ARMO SaaS account is required. It reads the `WorkloadConfigurationScan` objects served by the operator's in-cluster storage aggregated API (`spdx.softwarecomposition.kubescape.io/v1beta1`). Each Kubernetes **namespace** that has posture results is mapped to a Record (Product); each failed control on a workload becomes a Finding.

#### Prerequisites

- The Kubescape operator must be installed in the target cluster with configuration scanning enabled (see [Installing in your cluster](https://kubescape.io/docs/install-operator/)). Confirm results exist with `kubectl get workloadconfigurationscans -A`.
- A **kubeconfig** granting read access to the `spdx.softwarecomposition.kubescape.io` API group (list/get on `workloadconfigurationscans`) for the target cluster.

#### Connector Mappings

1. Enter the cluster's API server URL (or a friendly cluster identifier) in the **Location** field.
2. Paste the **kubeconfig** for the target cluster in the `kubeconfig` field. Optionally set `kube_context` to select a context within it, and `cluster_name` to label the discovered Products.
3. Each namespace with posture results is discovered as a Record; map the ones you want to import to DefectDojo Products.

Findings are derived per failed control: the control name and workload identify the Finding, severity comes from the control's score factor, the control ID becomes the vulnerability ID, and each Finding links to its control reference at `https://hub.armosec.io/docs/`.

## **Microsoft Defender**

The Microsoft Defender connector imports device vulnerability findings from **Microsoft Defender Vulnerability Management (MDVM)** — one finding per device / software version / CVE combination, including severity, CVSS score, exploitability level and recommended security updates. DefectDojo will discover your Defender **device groups** and create a Record for each one; devices that aren't assigned to any device group are collected under a synthetic **Unassigned** group.

**Please note:** this Connector is distinct from the file\-based **"MSDefender Parser"** scan type, which imports manually exported Defender files. Choose one import path per Product to avoid duplicate findings.

#### Prerequisites

Your Microsoft tenant needs an active license that includes the Defender vulnerability export APIs: **Defender for Endpoint Plan 2**, **Microsoft Defender Vulnerability Management Standalone**, or MDE P1/P2 with the MDVM add\-on. (The MDVM *Add\-on* SKU on its own is not sufficient — it requires Defender for Endpoint Plan 2 underneath.)

The connector authenticates as a Microsoft Entra ID **app registration** using the client credentials flow. To create one:

1. In the [Azure portal](https://portal.azure.com), open **App registrations \> New registration**. Name it (for example `defectdojo-connector`), leave the defaults, and select **Register**.
2. On the app's **Overview** page, note the **Application (client) ID** and **Directory (tenant) ID**.
3. Open **API permissions \> Add a permission \> APIs my organization uses** and search for **WindowsDefenderATP**. If it doesn't appear, your tenant's Defender backend hasn't been provisioned yet: ensure the license is active, open [security.microsoft.com](https://security.microsoft.com) once, and retry after a few minutes.
4. Choose **Application permissions** (*not* Delegated — Delegated permissions never appear in the connector's service token), expand **Vulnerability**, check **Vulnerability.Read.All**, and select **Add permissions**.
5. Select **Grant admin consent** and confirm. The Status column must show a green check — without this step every API call returns a 403 error.
6. Open **Certificates & secrets \> New client secret**, set an expiry, and copy the secret **Value** immediately (it is only shown once). The Connector stops working when the secret expires, so note the date.

#### Connector Mappings

1. Enter `https://api.security.microsoft.com` in the **Location** field.
2. Enter the **Directory (tenant) ID** in the **Tenant ID** field.
3. Enter the **Application (client) ID** in the **Client ID** field.
4. Enter the client secret value in the **Client Secret** field.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Defender device group becomes a Record. Microsoft regenerates the vulnerability snapshot the connector reads roughly every 6 hours, and newly onboarded devices can take up to \~24 hours to produce their first vulnerability data — a brand\-new tenant will legitimately Sync zero findings until devices are onboarded and assessed. License activation itself can also take \~20 minutes or more to reach the API ("No active license found" errors during that window resolve on their own).

## **Microsoft Defender for Cloud**

The Microsoft Defender for Cloud connector imports vulnerability findings from **Microsoft Defender Vulnerability Management (MDVM)** as surfaced by Defender for Cloud — both **server** findings (Azure VM operating\-system and installed\-software CVEs) and **container\-registry** findings (container image CVEs), including severity, CVSS score, the affected package or image, and remediation. DefectDojo discovers the Azure **subscriptions** your service principal can read and creates a Record for each enabled subscription.

**Please note:** this Connector is distinct from the **Microsoft Defender** connector, which imports device findings from the Defender for Endpoint API. Defender for Cloud is an Azure product with a different API surface (Azure Resource Manager / Resource Graph) and permission model (Azure RBAC). Run whichever matches where your findings live — or both, if you use both products.

#### Prerequisites

You need one or more **Azure subscriptions with Microsoft Defender for Cloud enabled**, with the relevant Defender plans turned on for the resources you want scanned (under **Microsoft Defender for Cloud \> Environment settings**, then select your subscription):

* **Defender for Servers (Plan 2)** — Azure VM operating\-system and software CVE findings (agentless vulnerability scanning).
* **Defender for Containers** — container\-registry image CVE findings.

SQL vulnerability\-assessment and configuration/posture findings are intentionally **not** imported — this connector imports CVE vulnerabilities only.

The connector authenticates as a Microsoft Entra ID **app registration** using the client credentials flow:

1. In the [Azure portal](https://portal.azure.com), open **App registrations \> New registration**. Name it (for example `defectdojo-connector`), leave the defaults, and select **Register**.
2. On the app's **Overview** page, note the **Application (client) ID** and **Directory (tenant) ID**.
3. Open **Certificates & secrets \> New client secret**, set an expiry, and copy the secret **Value** immediately (it is shown only once). The Connector stops working when the secret expires, so note the date.
4. Grant the app read access to each subscription you want to import: open **Subscriptions**, select your subscription, then **Access control (IAM) \> Add \> Add role assignment**. Select the **Security Reader** role (or **Reader**), and on the **Members** tab assign it to the app you created — search for it by the app's **name** or **object ID**, as the picker does not match the client ID. Repeat for every subscription.

Unlike the device\-based Microsoft Defender connector, no API permissions or admin consent are required: Defender for Cloud access is governed entirely by the Azure RBAC role assignment above.

#### Connector Mappings

1. Enter `https://management.azure.com` in the **Location** field. (For sovereign clouds, use the matching ARM endpoint, for example `https://management.usgovcloudapi.net`.)
2. Enter the **Directory (tenant) ID** in the **Tenant ID** field.
3. Enter the **Application (client) ID** in the **Client ID** field.
4. Enter the client secret value in the **Client Secret** field.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each enabled Azure subscription becomes a Record. Findings are read through Azure Resource Graph, so they surface promptly once Defender for Cloud has scanned your resources — but the scans themselves run on Microsoft's schedule: container\-registry images are usually scanned within an hour of being pushed, while a VM's first agentless vulnerability scan can take several hours. A newly enabled subscription will legitimately Sync zero findings until its resources have been scanned.

## **Nuclei (ProjectDiscovery Cloud)**

The Nuclei connector uses the ProjectDiscovery Cloud Platform (PDCP) REST API to pull [nuclei](https://github.com/projectdiscovery/nuclei) scan results from your PDCP account. DefectDojo discovers every scan in the account and creates a separate Record for each **scan**.

#### Prerequisites

You will need a ProjectDiscovery Cloud **API key**. We recommend creating a dedicated service account for DefectDojo to clearly distinguish automated activity from manual team actions. Generate a key from **Settings \> API Key** in the ProjectDiscovery Cloud UI ([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)). Results reach PDCP either from hosted scans or from the nuclei CLI run with `-dashboard`.

#### Connector Mappings

1. Enter the PDCP API base URL in the **Location** field: `https://api.projectdiscovery.io`.
2. Enter your **API key** in the **Secret** field.
3. Optionally, enter a **Team ID** to scope the sync to a team workspace (found under **Settings \> Team**). When left blank, DefectDojo syncs your personal workspace.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each PDCP **scan** as a separate Record and imports that scan's findings across every severity, including informational.

## **OpenVAS / Greenbone**

The OpenVAS / Greenbone connector imports **network vulnerability findings** from a Greenbone (Greenbone Community Edition or Greenbone Enterprise) instance. It talks to `gvmd` over **GMP (Greenbone Management Protocol)** — an XML protocol over a TLS socket, not HTTP — and syncs the whole instance: it enumerates scan **tasks** and creates a DefectDojo product for each, importing the results of each task's latest report.

#### Prerequisites

A Greenbone **GMP user** (username + password) and network access to gvmd's GMP TLS port (default **9390**). The Greenbone Community Edition compose stack fronts gvmd via a unix socket, so to reach it from a networked connector you either run the connector where it can reach the socket or expose the GMP TLS port (for example a `socat` TLS bridge to `gvmd.sock`).

#### Connector Mappings

1. Enter the gvmd host in the **Location** field (host or `host:port`).
2. Enter the GMP **Username** and **Password**.
3. Optionally set the **GMP Port** (defaults to 9390).
4. For gvmd's default self\-signed certificate, either provide a **CA Certificate (PEM)** to verify against, or set **Skip TLS Verification** to `true`.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Greenbone task becomes a Record. Findings come from the task's latest finished report — one per `<result>`. Severity is taken from the result's threat level (Greenbone's `Log`/`Debug` informational levels map to Info), with the numeric CVSS score recorded; CVE references become vulnerability ids, the NVT solution becomes the mitigation, and each result's host/port becomes an endpoint.

## Probely

This connector uses the Probely REST API to fetch data.

​**Connector Mappings**

1. Enter the appropriate API server address in the **Location** field. (either <https://api.us.probely.com/> or <https://api.eu.probely.com/> )
2. Enter a valid API key in the **Secret** field.

You can find an API key under the User \> API Keys menu in Probely.  
See [Probely documentation](https://help.probely.com/en/articles/8592281-how-to-generate-an-api-key) for more info.

## Prowler

The Prowler connector uses the **Prowler App** REST API to import cloud security posture (CSPM) findings from a self-hosted Prowler App instance. DefectDojo discovers each Prowler **provider** (cloud account) as a Record and imports the **FAIL** findings of that provider's latest completed scan.

#### Prerequisites

You will need a running, self-hosted **Prowler App** instance and either a user email + password (for JWT authentication) or a Prowler App **API key**. Findings only appear once you have connected a cloud account (AWS, GCP, Azure, Kubernetes, ...) in Prowler App and run a scan.

#### Connector Mappings

1. Enter your Prowler App URL in the **Location** field (for example `https://prowler.your-company.com`).
2. For JWT authentication, enter the Prowler App user **Email** and **Password**. Alternatively, leave those blank and enter a Prowler App **API Key**. If both are provided, the email/password (JWT) is used.
3. Optionally set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity are not imported.

DefectDojo creates a Record for each Prowler provider and imports the FAIL findings of its latest completed scan, mapping Prowler severities to DefectDojo severities, the affected cloud resource (ARN/resource id) as the component, and the check's remediation and risk into the finding. Muted findings are skipped. Cloud account, region, and service are attached as tags.

For more information, see the **[Prowler App API documentation](https://api.prowler.com/api/v1/docs)**.

## Qualys

The Qualys connector imports **VMDR host vulnerability detections** — each joined with its Qualys KnowledgeBase (QID) metadata — from the Qualys Cloud Platform. DefectDojo creates a Record for each Qualys **host** in your subscription.

#### Prerequisites

A Qualys user account with **VMDR API access**, and your subscription's **API server (platform) URL** — this differs per subscription. Find it in the Qualys UI under **Help \> About**, or on the Qualys [Platform Identification](https://www.qualys.com/platform-identification/) page (for example `https://qualysapi.qualys.com` for US Platform 1, or `https://qualysapi.qg2.apps.qualys.com` for US Platform 2).

#### Connector Mappings

1. Enter your Qualys API server URL in the **Location** field (for example `https://qualysapi.qualys.com`).
2. Enter the Qualys API username in the **Username** field.
3. Enter the Qualys API password in the **Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Qualys host becomes a Record. Detections Qualys has marked **Fixed** are excluded, so reimport closes remediated findings.

## **Rapid7 InsightAppSec**

The Rapid7 InsightAppSec connector imports **DAST vulnerability findings** from the InsightAppSec cloud platform, enriched with attack\-module metadata (for example *SQL Injection*), CVSS scores, and the evidence collected by the scan. DefectDojo creates a Record for each InsightAppSec **app**.

**Please note:** this Connector is distinct from the **Rapid7 InsightVM** connector below — InsightAppSec is Rapid7's cloud DAST product on the Insight platform, while InsightVM findings come from your own Security Console.

#### Prerequisites

An Insight platform account with InsightAppSec, and a platform **API key**: in the [Rapid7 Insight platform](https://insight.rapid7.com), open the settings (gear) menu \> **API Keys** and generate a **User Key** (any role) or an **Organization Key** (platform admins). Copy the key when it is shown — it is displayed only once.

You also need your platform **region**, visible in your Insight URL (for example `us`, `us2`, `us3`, `eu`, `ca`, `au`, or `ap`).

#### Connector Mappings

1. Enter your regional API endpoint in the **Location** field — for example `https://us.api.insight.rapid7.com` (replace `us` with your region).
2. Enter the Insight platform API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each InsightAppSec app becomes a Record. Only **open** vulnerabilities (Unreviewed or Verified) are imported — findings Rapid7 has marked Remediated, a False Positive, Ignored, or Duplicate are excluded, so reimport closes them in DefectDojo. Severities map directly (`SAFE` and `INFORMATIONAL` import as Info).

## **Rapid7 InsightVM**

The Rapid7 InsightVM connector imports asset vulnerability findings from your InsightVM **Security Console** (API v3), enriched with the console's global vulnerability catalog. DefectDojo creates a Record for each InsightVM **site**.

#### Prerequisites

Network access from DefectDojo to your Security Console, and a console **user account** — its login is used for HTTP Basic authentication. The console API is served on port **3780** by default.

#### Connector Mappings

1. Enter your Security Console URL, including the port, in the **Location** field — for example `https://console.example.com:3780`.
2. Enter the console username in the **Username** field.
3. Enter the console password in the **Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each InsightVM site becomes a Record; the connector walks the site's assets and imports their vulnerable findings.

## **Semgrep**

This connector uses the Semgrep REST API to fetch data.

#### Connector Mappings

Enter `https://semgrep.dev/api/v1/` in the **Location** field.

1. Enter a valid API key in the **Secret** field. You can find this on the Tokens page:   
​  
"Settings" in the left navbar \> Tokens \> Create new token ([https://semgrep.dev/orgs/\-/settings/tokens](https://semgrep.dev/orgs/-/settings/tokens))

See [Semgrep documentation](https://semgrep.dev/docs/semgrep-cloud-platform/semgrep-api/#tag__badge-list) for more info.

## **Shodan**

The Shodan connector uses the Shodan REST API to import the vulnerabilities (CVEs) Shodan has observed on your internet-exposed hosts. You provide a Shodan search query that scopes the import to your own assets; DefectDojo creates a Record for each matching host and imports its CVEs as findings.

#### Prerequisites

You will need a Shodan API key, found on your Shodan **Account** page. Host search with vulnerability data requires a Shodan membership or a paid API plan — the free tier cannot page through search results.

#### Connector Mappings

1. Enter `https://api.shodan.io` in the **Location** field.
2. Enter your Shodan API key in the **API Key** field.
3. In the **Search Query** field, enter a Shodan query that scopes the import to your organization's assets — for example `hostname:example.com`, `net:203.0.113.0/24`, or `org:"Example Inc"`. Only hosts matching this query are imported, so keep it scoped to infrastructure you own.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each matching host becomes a Record, and each CVE Shodan detected on that host's exposed services is imported as a finding — severity is derived from the CVSS score, with EPSS and CISA KEV context included where available. Each page of search results consumes one Shodan query credit.

## SonarQube

The SonarQube Connector can fetch data from either a SonarCloud account or from a local SonarQube instance.

**For SonarCloud users:**

1. Enter https://sonarcloud.io/ in the Location field.
2. Enter a valid **API key** in the Secret field.

**For SonarQube (on\-premise) users:**

1. Enter the base url of your SonarQube instance in the Location field: for example `https://my.sonarqube.com/`
2. Enter a valid **API key** in the Secret field. This will need to be a **[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)** [API Token Type](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

The token will need to have access to Projects, Vulnerabilities and Hotspots within Sonar.

API tokens can be found and generated via **My Account \-\> Security \-\> Generate Token** in the SonarQube app. For more information, [see SonarQube documentation](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

## **Snyk**

The Snyk connector uses the Snyk REST API to fetch data.

#### Connector Mappings

1. Enter **[https://api.snyk.io/rest](https://api.snyk.io/v1)** or **[https://api.eu.snyk.io/rest](https://api.eu.snyk.io/v1)** (for a regional EU deployment) in the **Location** field.
2. Enter a valid API key in the **Secret** field. API Tokens are found on a user's **[Account Settings](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)** [page](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token) in Snyk.

See the [Snyk API documentation](https://docs.snyk.io/snyk-api) for more info.

## **Sonatype IQ**

The Sonatype IQ connector uses the Sonatype IQ Server (Nexus Lifecycle) REST API to import open\-source component vulnerabilities. It enumerates every application in your IQ organization and, for each one, imports the component vulnerabilities from that application's latest report at the lifecycle stage you configure. DefectDojo creates a Record for each application automatically — there is no per\-application configuration.

#### Prerequisites

You will need a Sonatype IQ user account with the **View IQ Elements** permission on the applications you want to import. Sonatype recommends authenticating with a **user token** (generated under **My Profile > User Token** in IQ Server) rather than a password; the token's two parts map to the Username and User Token fields below. The connector works with both self\-hosted IQ Server and Sonatype\-hosted (SaaS) instances.

#### Connector Mappings

1. In the **Location** field, enter your IQ Server base URL — for a self\-hosted server, `https://iq.example.com`; for a Sonatype\-hosted instance, `https://<tenant>.sonatype.app/platform`.
2. Enter the IQ user (or the user\-code part of your user token) in the **Username** field.
3. Enter the IQ user token (or password) in the **User Token** field.
4. Optionally, set a **Stage** to choose which lifecycle stage's report is imported per application (`build`, `stage-release`, `release`, and so on). Leave it blank to use `build`.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each application becomes a Record, and each security issue in that application's latest report for the selected stage is imported as a finding. Severity is derived from the issue's numeric score, and CVE references, CWE, the CVSS vector, and the affected component's package URL (PURL) are included where available.

## Tenable

The Tenable connector uses the **Tenable.io** REST API to fetch data.  Scans are pulled from the Tenable VM `/scans` endpoint.

On\-premise Tenable Connectors are not available at this time.

#### **Connector Mappings**

1. Enter <https://cloud.tenable.com> in the Location field.
2. Enter a valid **API key** in the Secret field.

See [Tenable's API Documentation](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm) for more info.

## **Veracode**

The Veracode connector imports application findings from the Veracode platform, split by scan type into **SAST**, **DAST**, **SCA**, and **Manual** finding types. DefectDojo creates a Record for each Veracode **application**.

#### Prerequisites

Generate a Veracode **API credential** for an account that can see the applications you want to import: in the Veracode Platform, open your account menu \> **API Credentials** and select **Generate API Credentials** (see [Managing Veracode API credentials](https://docs.veracode.com/r/c_api_credentials3)). Copy both the **API ID** and the **API Secret Key** — the secret is shown only once.

#### Connector Mappings

1. Enter the Veracode API base URL in the **Location** field: `https://api.veracode.com` (commercial region), `https://api.veracode.eu` (European region), or `https://api.veracode.us` (US federal region).
2. Enter the API ID in the **API ID** field.
3. Enter the API secret key in the **Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Veracode application becomes a Record. Only **open** findings are imported, so reimport closes findings Veracode reports as resolved.

## **Wazuh**

The Wazuh connector uses the Wazuh Indexer (OpenSearch) to fetch vulnerability findings. Wazuh 4.8 and later store detected CVEs in the Indexer rather than the Wazuh server API, so this connector reads them directly from the `wazuh-states-vulnerabilities-*` index.

DefectDojo creates a Record for each Wazuh agent (endpoint) and imports that agent's detected CVEs as findings on a scheduled basis.

#### Prerequisites

You will need:

* The base URL of your Wazuh Indexer, including the port (the Indexer listens on port 9200 by default). DefectDojo connects to the Indexer directly, so this endpoint must be reachable from DefectDojo. For self\-managed deployments this is the host running the Wazuh Indexer. For Wazuh Cloud, use the Indexer endpoint shown in your Wazuh Cloud console, which is separate from the Wazuh dashboard URL.
* An Indexer user and password with read access to the `wazuh-states-vulnerabilities-*` index. We recommend creating a dedicated user for DefectDojo.

Vulnerability detection must be enabled in Wazuh so that the vulnerability\-state index is populated. See the [Wazuh vulnerability detection documentation](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html) for more information.

#### Connector Mappings

1. Enter your Wazuh Indexer base URL in the **Location** field, including the scheme and port, for example `https://your-indexer.example.com:9200`. Do not include a trailing path. DefectDojo constructs the search paths automatically.
2. Enter the Indexer username in the **Username** field.
3. Enter the Indexer password in the **Password** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity will not be imported.

## Wiz

Using the Wiz connector requires you to create a service account: see the [Wiz documentation](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) for more info.  You will need a Wiz account to access the documentation.

#### **Connector Mappings**

1. Enter your Wiz Client ID in the Client ID field.
2. Enter the Wiz Client Secret in the Secret field.
