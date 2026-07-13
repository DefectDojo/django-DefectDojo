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

## Probely

This connector uses the Probely REST API to fetch data.

​**Connector Mappings**

1. Enter the appropriate API server address in the **Location** field. (either <https://api.us.probely.com/> or <https://api.eu.probely.com/> )
2. Enter a valid API key in the **Secret** field.

You can find an API key under the User \> API Keys menu in Probely.  
See [Probely documentation](https://help.probely.com/en/articles/8592281-how-to-generate-an-api-key) for more info.

## **Semgrep**

This connector uses the Semgrep REST API to fetch data.

#### Connector Mappings

Enter `https://semgrep.dev/api/v1/` in the **Location** field.

1. Enter a valid API key in the **Secret** field. You can find this on the Tokens page:   
​  
"Settings" in the left navbar \> Tokens \> Create new token ([https://semgrep.dev/orgs/\-/settings/tokens](https://semgrep.dev/orgs/-/settings/tokens))

See [Semgrep documentation](https://semgrep.dev/docs/semgrep-cloud-platform/semgrep-api/#tag__badge-list) for more info.

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

## Tenable

The Tenable connector uses the **Tenable.io** REST API to fetch data.  Scans are pulled from the Tenable VM `/scans` endpoint.

On\-premise Tenable Connectors are not available at this time.

#### **Connector Mappings**

1. Enter <https://cloud.tenable.com> in the Location field.
2. Enter a valid **API key** in the Secret field.

See [Tenable's API Documentation](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm) for more info.

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
