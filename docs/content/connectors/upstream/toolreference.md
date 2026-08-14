---
title: "Upstream Connectors Tool Reference"
description: "Our list of supported Connector tools, and how to set them up with DefectDojo"
aliases:
  - /import_data/pro/connectors/connectors_tool_reference/
  - /en/connecting_your_tools/connectors/connectors_tool_reference
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Upstream Connectors are a DefectDojo Pro-only feature.</span>

When setting up a Connector for a supported tool, you'll need to give DefectDojo specific information related to the tool's API. At a base level, you'll need:

* **Location** \-a field whichgenerallyrefers to your tool's URL in your network,
* **Secret** \- generally an API key.

Some tools will require additional API\-related fields beyond **Location** and **Secret**. They may also require you to make changes on their side to accommodate an incoming Connector from DefectDojo.

![image](images/connectors_tool_reference.png)

Each tool has a different API configuration, and this guide is intended to help you set up the tool's API so that DefectDojo can connect.

Whenever possible, we recommend creating a new 'DefectDojo Bot' account within your Security Tool which will only be used by the Connector. This will help you better differentiate between actions manually taken by your team, and automated actions taken by the Connector.

# **Asset Connectors**

Most Connectors import **findings** from a security tool. **Asset Connectors** work differently: they import your **asset inventory** instead. An Asset Connector enumerates the assets that exist in an external platform (for example, the repositories in a GitLab group) and automatically creates and maintains the matching **Assets** and **Organizations** in DefectDojo. No findings are imported by an Asset Connector.

* **Discover** and **Sync** both reconcile the asset list. New assets appear as `NEW` Records; once mapped (automatically, if auto-mapping is enabled), DefectDojo creates the Asset and groups it under an Organization derived from the tool — for example, the GitLab namespace or the Azure DevOps project.
* If an asset is later removed upstream (for example, a repository is deleted), its mapped Record is flagged `MISSING` on the next Sync so your team can triage it. DefectDojo never silently deletes an Asset.

Azure DevOps, Backstage, Bitbucket, GitHub, GitLab, JSM Assets, and ServiceNow CMDB are Asset Connectors. runZero is primarily an Asset Connector but can optionally import vulnerabilities as findings. All other Connectors listed below import findings.

# **Supported Connectors**

## **AccuKnox**

The AccuKnox connector imports **cloud security posture (CSPM) findings** across your whole AccuKnox tenant. DefectDojo creates a Record for each **connected cloud account**, plus a tenant\-level catch\-all Record — findings that match no specific account land there, so nothing is silently dropped.

#### Prerequisites

An AccuKnox **access key**. An access key inherits the permissions of the user who created it, and the **Viewer** role is sufficient.

**Access keys expire.** When one does, the Sync fails with an authentication error rather than degrading quietly — so an authentication failure on a previously working connector usually means the key needs replacing, not that the connection is misconfigured.

#### Connector Mappings

1. Enter your AccuKnox CSPM host in the **Location** field.
2. Enter the access key in the **Secret** field.
3. Optionally, enter your AccuKnox **Tenant ID** (workspace ID). It is sent with every read request.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each connected cloud account becomes a Record, with AccuKnox's own four severity levels (Critical, High, Medium, Low) carried through.

## **Action1**

The Action1 connector imports **endpoint vulnerability findings** from Action1. DefectDojo creates a Record for each **endpoint (host)**.

#### Prerequisites

An Action1 **API key and secret** pair. The key acts as the OAuth client ID and the secret is never logged.

#### Connector Mappings

1. Enter `https://app.action1.com/api/3.0` in the **Location** field.
2. Enter the API key in the **API Key (Client ID)** field.
3. Enter the API secret in the **API Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

**One finding is created per endpoint-and-vulnerability pair**, so a single CVE present on fifty hosts produces fifty findings, each attached to its own host's Record. This is what makes per\-host remediation tracking possible, but it does mean finding counts scale with fleet size rather than with the number of distinct CVEs.

## **Acunetix 360**

The Acunetix 360 connector imports **DAST vulnerability findings** from the Acunetix 360 cloud platform (the Invicti platform). DefectDojo discovers your account's scanned websites and creates a Record for each **website**; the findings for a website come from its latest completed scan.

**Please note:** this connector is for **Acunetix 360** (the cloud product at `online.acunetix360.com`). It is not for the on\-premises Acunetix Standard/Premium scanner, which has a different API.

#### Prerequisites

An Acunetix 360 account and an **API credential**: in Acunetix 360, open your account menu \> **API Settings**, and note the **API User ID** and generate an **API Token**. The connector authenticates with these as HTTP Basic credentials, so a dedicated service account is recommended to distinguish automated activity from manual team actions.

#### Connector Mappings

1. Enter your Acunetix 360 URL in the **Location** field: `https://online.acunetix360.com`.
2. Enter the API User ID in the **API User ID** field.
3. Enter the API Token in the **API Token** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each scanned website becomes a Record. Findings come from the website's latest completed scan; vulnerabilities Acunetix 360 has marked **Accepted Risk** or **False Positive** are still imported but flagged inactive (risk\-accepted or false\-positive) so the DefectDojo product reflects the vendor's triage.

## **Akamai**

The Akamai API Security connector uses an API key to pull security findings from the Akamai API. DefectDojo will discover your Akamai environment and create separate Records for each **Application** and **Host** configured in your account.

#### Prerequisites

You will need an API key with access to the Akamai API. We recommend creating a dedicated service account for DefectDojo to clearly distinguish automated activity from manual team actions.

#### Connector Mappings

1. Enter your Akamai API base URL in the **Location** field. This URL is specific to your Akamai instance: for example
2. Enter a valid **API Key** in the **Secret** field.

DefectDojo will map **Applications** and **Hosts** as separate Records. Each Application will appear as `{name} (application)` and each Host as `{name} (host)` in your Records list.

## **Akto**

The Akto connector imports **API security testing findings** from Akto. DefectDojo creates a Record for each Akto **API collection**.

#### Prerequisites

An Akto **API key**, created under **Settings \> Integrations \> Akto APIs** in the Akto dashboard. It is sent as the `X-API-KEY` header and is never logged.

#### Connector Mappings

1. Enter `https://app.akto.io` in the **Location** field for Akto's SaaS platform. If you run Akto self\-hosted, enter your own dashboard URL instead.
2. Enter your Akto API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each API collection becomes a Record. Only **open** issues are imported, so issues you resolve in Akto are reflected in DefectDojo on the next Sync. Both Akto SaaS and self\-hosted deployments use this connector — the only difference is the **Location** you supply.

## **Alert Logic**

The Alert Logic connector imports **vulnerability exposures** from your Alert Logic account. DefectDojo creates a Record for each Alert Logic **deployment**, with no per\-deployment configuration required.

#### Prerequisites

An Alert Logic **access key ID and secret key**, created under **Configure \> API Keys**. DefectDojo exchanges them for a short\-lived session token on each Sync; neither the secret nor the token is ever logged.

#### Connector Mappings

1. Enter your region's API URL in the **Location** field — `https://api.cloudinsight.alertlogic.com` (US) or `https://api.cloudinsight.alertlogic.co.uk` (UK). Alert Logic is region\-partitioned, so this must match the region your account lives in.
2. Enter the access key ID in the **Access Key ID** field.
3. Enter the secret in the **Secret Key** field.
4. Optionally, enter an **Account ID** to override the account the credentials authenticate into. This is intended for managed\-service parent accounts operating on a child account.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

This connector imports **vulnerability exposures only** — MDR incidents are deliberately out of scope.

## **Anchore Enterprise**

The Anchore connector uses a user's API token to pull data from Anchore Enterprise.  Assets will be mapped and discovered based on "Applications", which are composed of multiple Images in Anchore - see [Anchore Enterprise Documentation](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) for more information.

#### Connector Mappings

1. The Anchore URL in the **Location** field: this is the URL where you access the Anchore.
2. Enter a valid API Key in the Secret field. This is the API key associated with your Burp Service account.

See the official [Anchore documentation](https://docs.anchore.com/current/docs/) for more information on creating a token for Anchore.

## **AppCheck**

The AppCheck connector imports **DAST vulnerability findings** from the AppCheck NG platform. DefectDojo discovers every scan on your account and creates a Record for each **scan** — there is no per\-scan configuration.

#### Prerequisites

An AppCheck **API key**, from the **API** section of your AppCheck account.

**Treat this key like a password.** AppCheck sends it as part of the request path rather than in a header, so it forms part of the URL. DefectDojo registers the key for redaction and never logs a full request URL, but apply the same care wherever else you store it.

#### Connector Mappings

1. Enter `https://api.appcheck-ng.com` in the **Location** field.
2. Enter your AppCheck API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each scan becomes a Record, and its findings come from that scan's most recent **completed** run — so a scan that is still in flight never truncates the finding set. AppCheck fans a scan out across several engines (its own scanner, **Nmap**, and **OpenVAS**) and normalizes the output, so each finding carries the engine that reported it.

## **Aqua Security**

The Aqua Security connector imports **container image and workload vulnerability findings** across your whole Aqua tenant. DefectDojo creates a Record for each scanned **registry/repository**.

#### Prerequisites

An **admin-generated** Aqua **API key and secret**, created under **Account Management \> API Keys**. The secret is shown only once when the key is generated, so capture it at that point. Neither value is ever logged.

#### Connector Mappings

1. Enter your Aqua tenant URL in the **Location** field — `https://<your-tenant>.cloud.aquasec.com`. DefectDojo appends the API path itself.
2. Enter the API key in the **API Key** field.
3. Enter the API secret in the **API Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each scanned registry/repository becomes a Record, and its image and workload vulnerabilities are imported as findings.

## **Automox**

The Automox connector imports **missing patches** from Automox. DefectDojo creates a Record for each Automox **device group**.

**A finding here is a missing patch**, not a scanner result — this connector reports patches Automox is waiting to apply, so use it to track patch coverage rather than as a vulnerability scanner.

#### Prerequisites

An Automox **API key**, from **Settings \> API** in the Automox console. It is sent as a bearer token and never logged.

#### Connector Mappings

1. Enter `https://console.automox.com/api` in the **Location** field.
2. Enter your Automox API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each device group becomes a Record, carrying the patches awaiting installation on the devices in that group.

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

The Backstage connector is an **asset connector**: instead of importing Findings, it pulls your [Backstage](https://backstage.io) Software Catalog into DefectDojo and keeps your Asset hierarchy and team ownership in sync with it. It is designed for organizations that maintain their service inventory and org structure in Backstage and want DefectDojo to mirror that structure instead of maintaining it by hand.

#### What gets mapped

| Backstage | DefectDojo |
|---|---|
| **System** | Organization (Components with no System are grouped under a configurable "Backstage / Uncategorized" Organization) |
| **Component** | Asset — named from the entity `title` (falling back to `name`), with the catalog description |
| **Owning Group** (`ownedBy` relation) | A DefectDojo Group linked to the Asset (default role: Maintainer, configurable) |
| **Owner email** (Group profile email, or a User owner's email) | An Asset Member, when a DefectDojo user with that email already exists (users are never created) |
| `metadata.tags`, `spec.type`, `spec.lifecycle`, namespace, domain | Asset tags under a `backstage:` prefix |
| `metadata.annotations` | Stored on the Record (bounded); selected annotations can be promoted to first-class attributes or tags via **Annotation Mappings** |

Records are keyed by the entity's server\-assigned `metadata.uid`, so renames in Backstage update the mapped Asset **in place** on the next sync — no duplicates. The Asset name always tracks the catalog: to rename an Asset managed by this connector, rename the Component in Backstage (a DefectDojo\-side rename, or a custom name given during manual mapping, is reconciled back to the catalog name on the next sync unless it would collide with another Asset). Ownership changes move the Asset's group assignment. Components that disappear from the catalog (or are flagged with the `backstage.io/orphan` annotation) are marked **MISSING** — DefectDojo never deletes an Asset on its own. Domain and Group hierarchy (parent teams) are recorded as tags/metadata only; they do not create extra hierarchy levels.

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
* **Uncategorized Organization** — the Organization used for Components with no System (default `Backstage / Uncategorized`).
* **Owner Group Role** — the role granted to the owning team on mapped Assets (default `Maintainer`).
* **Annotation Mappings** — a JSON object mapping annotation keys to Record attribute names, or to `"tag"` to import an annotation as an Asset tag, e.g. `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`.

With **Auto\-Map** enabled, a single Discover \+ Sync builds the complete Organization / Asset / ownership structure with no manual steps. With Auto\-Map disabled, discovered Components appear as Records awaiting your mapping decision.

#### Limitations (v1)

* Backstage **Group membership is not synchronized**: the connector creates/links the owning team as a DefectDojo Group, but populating that group's users is left to your identity provider or admins.
* Only Components become Assets; APIs, Resources, and Domains are not imported as assets (domains surface as tags).
* Tags and annotations are normalized and bounded to fit DefectDojo field limits (oversized values are truncated).

**A note on the reverse direction:** displaying DefectDojo findings and grades *inside* Backstage (on entity pages) is a natural follow\-on that would be built as a Backstage frontend plugin consuming the DefectDojo REST API — it is deliberately out of scope for this connector, which only pulls catalog data into DefectDojo.

## **Beagle Security**

The Beagle Security connector imports **DAST findings** from Beagle Security. DefectDojo creates a Record for each **verified** application in your Beagle project tree — applications that have not been verified are not imported.

#### Prerequisites

A Beagle Security **personal access token**, sent as a bearer token.

**Beagle access tokens expire.** When one does, Beagle returns an HTML error page rather than a JSON error, so an expired token can present as an unclear Sync failure. If a previously working connector starts failing, check the token first.

#### Connector Mappings

1. Enter your Beagle API URL in the **Location** field — `https://api.beaglesecurity.com/rest/v2`.
2. Enter the personal access token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each verified application becomes a Record, and its findings come from that application's most recently **finished** test session — so a test still in progress does not replace your existing results.

## **BigID**

The BigID connector imports **data security posture (DSPM) findings** — exposed sensitive data, over-permissive access, and unprotected PII stores — from BigID's actionable insights. DefectDojo creates a Record for each BigID **data source**.

> **Your sensitive data is never copied into DefectDojo.** Findings carry only identifiers, classifications, and affected-object **counts**. No sample or preview of the underlying sensitive data is read or written into a finding — which is what makes it safe to surface DSPM results alongside your other findings.

#### Prerequisites

A BigID **user token**, from **Administration \> Access Management**. DefectDojo exchanges it for a short\-lived system token on each Sync; the user token is never logged.

#### Connector Mappings

1. Enter your BigID instance URL in the **Location** field.
2. Enter the user token in the **User Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each BigID data source becomes a Record, carrying the actionable-insight cases raised against it.

## **Black Duck**

The Black Duck connector imports **software composition analysis (SCA)** findings from a Black Duck (Synopsys / Black Duck) Hub instance. DefectDojo discovers every project in the instance and creates a Record for each **project**; the findings for a project come from the vulnerable BOM components of its selected version.

#### Prerequisites

A Black Duck **API token** for a user that can see the projects you want to import. In Black Duck, open your user menu \> **My Access Tokens** \> **Create New Token**, grant it (at least) read access, and copy the token when it is shown — it is displayed only once. The connector exchanges this token for a short\-lived bearer on each sync; it is never stored in cleartext beyond the connector's secret field.

#### Connector Mappings

1. Enter your Black Duck hub URL in the **Location** field — for example `https://your-company.app.blackduck.com`.
2. Enter the API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Black Duck project becomes a Record. By default the connector imports the project's **released** version (falling back to its first version); each vulnerable BOM component of that version becomes a finding, titled `{vulnerability} in {component}:{version}`.

This connector is distinct from the file-based Black Duck parsers — its findings use the dedicated **Black Duck - Connectors Import** scan type.

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

## **Black Duck Continuous Dynamic**

The Black Duck Continuous Dynamic connector imports **DAST findings** from the Continuous Dynamic platform. DefectDojo creates a Record for each **site** on your account, with no per\-site configuration.

**Please note:** findings from this connector use the **WhiteHat Sentinel** scan type. Continuous Dynamic was sold as WhiteHat Sentinel Dynamic before the acquisition, and DefectDojo reuses that established mapping — so this is expected, not a misconfiguration.

#### Prerequisites

A Continuous Dynamic **API key**, from **Account \> API Keys**. Black Duck treats this key as equivalent to a username and password, so store it accordingly.

#### Connector Mappings

1. Enter `https://sentinel.whitehatsec.com` in the **Location** field.
2. Enter the API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each site becomes a Record. DefectDojo requests attack vectors, risk scores and descriptions from the API so that findings arrive complete — the same detail the file\-based WhiteHat Sentinel parser expects.

## **Bugcrowd**

The Bugcrowd connector uses the Bugcrowd REST API to import submissions from your bug bounty and vulnerability disclosure programs. DefectDojo discovers the programs your API token can access and creates a Record for each one, importing that program's submissions as findings.

#### Prerequisites

You will need a Bugcrowd **API token** with access to the programs you want to import. We recommend creating a dedicated service account for DefectDojo so automated activity is easy to distinguish from manual team actions. Generate the token in Bugcrowd under **Organization settings \> API credentials**; read access to submissions, programs, and targets is sufficient.

#### Connector Mappings

1. Enter `https://api.bugcrowd.com` in the **Location** field.
2. Enter your Bugcrowd API token in the **Secret** field. It is sent as an `Authorization: Token` header.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Bugcrowd **program** becomes a Record, and its submissions are imported as findings with the Bugcrowd severity preserved. Duplicate submissions are excluded, so reimport does not create repeated findings for the same issue.

## **Bright Security**

The Bright Security connector uses the [Bright](https://brightsec.com) (formerly NeuraLegion) API to import **DAST findings**. DefectDojo discovers every scan the token can access and creates a Record for each completed scan, then imports that scan's issues as findings.

#### Prerequisites

You will need a Bright **API key**, created in the Bright app under **User settings → API keys** (an `Org` or personal key). The key is sent in the `Authorization: Api-Key` header and is never logged.

#### Connector Mappings

1. Leave the **Location** field blank to use `https://app.brightsec.com`, or enter your Bright host explicitly.
2. Enter the Bright API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each completed **scan** to a Record and each **issue** to a finding: the severity comes from Bright's own rating (Critical/High/Medium/Low), the CVSS score, CWE and remediation are carried over, the affected entry point becomes the endpoint, and the request/response evidence is included in the description. Findings are recorded as dynamic findings and de-duplicated on Bright's issue id.

See the [Bright API documentation](https://docs.brightsec.com/) for more information.

## **Burp Suite Enterprise**

DefectDojo’s Burp connector calls Burp’s GraphQL API to fetch data. 

#### Prerequisites

Before you can set up this connector, you will need an API key from a Burp Service Account. Burp user accounts don’t have API keys by default, so you may need to create a new user specifically for this purpose. 

See [Burp Documentation](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user) for a guide on setting up a Service Account user with an API key.

#### Connector Mappings

1. Enter Burp’s root URL in the **Location** field: this is the URL where you access the Burp tool.
2. Enter a valid API Key in the Secret field. This is the API key associated with your Burp Service account.

See the official [Burp documentation](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html) for more information on the Burp API.

## **Calico Cloud**

The Calico Cloud connector imports **container image vulnerability findings** from Calico Cloud Image Assurance. DefectDojo creates a Record for each scanned **image repository**.

#### Prerequisites

An Image Assurance **API token**, from **Image Assurance \> Access Settings** in the Calico Cloud UI. This is the same token the `tigera-scanner` CLI uses, and it is never logged.

#### Connector Mappings

1. Enter your Image Assurance API URL in the **Location** field — the same value you would pass to `tigera-scanner` as `--apiurl`.
2. Enter the token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each scanned image repository becomes a Record, carrying the CVE results of its images.

**Images whose scan results are not ready yet are skipped, not reported as clean.** Calico's registry scanner runs asynchronously, so an image can be absent from a Sync simply because its scan is still in progress — it will appear once results exist. This is worth knowing before reading a short finding list as a coverage gap.

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

## **Checkmarx One**

DefectDojo's Checkmarx One connector calls the Checkmarx API to fetch data.

#### **Connector Mappings**

1. Enter your **Tenant Name** in the **Checkmarx Tenant** field. This name should be visible on the Checkmarx One login page in the top\-right hand corner:   
" Tenant: \<**your tenant name**\> "  
​
![image](images/connectors_tool_reference_2.png)

2. Enter a valid API key. You may need to generate a new one: see [Checkmarx API Documentation](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08) for details.
3. Enter your tenant location in the **Location** field. This URL is formatted as follows:  
​`https://<your-region>.ast.checkmarx.net/` . Your Region can be found at the beginning of your Checkmarx URL when using the Checkmarx app. **<https://ast.checkmarx.net>** is the primary US server (which has no region prefix).

#### **Branch handling**

By default, each sync imports the findings of a project's **single most recent completed scan, regardless of branch**. If your CI scans many branches, whichever branch happened to scan last "wins" that sync: findings that only exist on other branches are not imported, and the sync's close-old reconciliation can churn findings open and closed as different branches take turns being the latest scan.

Two optional fields control this behavior:

- **Branch**: pins every project to one branch name — only scans of that branch are imported. This is a single global value for the whole connector, so it fits fleets where every project uses the same long-lived branch (e.g. `main`).
    - A **`*` wildcard** is supported. A Branch value containing `*` selects across *every* matching branch rather than a single one — for example `release/*` imports each release branch, and `*` matches every branch. Combined with **Track Scanned Branches**, this is the way to track a family of branches without tracking all of them.
    - If a wildcard matches **no** branch within the scan window, that sync is **skipped** rather than treated as "the branch has no findings" — so a pattern that temporarily matches nothing cannot close every finding on the asset.
- **Track Scanned Branches**: when enabled, each sync finds every branch with a completed scan in the project's recent scan history and imports **the latest completed scan of each branch**, one reimport per branch. Each branch's findings live in their own engagement on the mapped asset, named "\<default engagement\> \- \<branch\>", so closing stale findings is scoped per branch: a fix merged to one branch can never close another branch's findings. The project's primary branch (as reported by Checkmarx) is imported first, so re-occurrences of the same finding on other branches deduplicate against the primary branch's original.

Notes on **Track Scanned Branches**:

- **Check which default applies to you.** Branch tracking is **on by default for new installations**. Installations that predate the change keep their previous behavior, so the toggle is off for them until someone turns it on.
- When both fields are set, only the pinned **Branch** is tracked — including when that Branch value is a wildcard pattern, in which case every branch matching the pattern is tracked.
- A branch that stops being scanned (merged or deleted) stops receiving updates: its engagement remains visible with its last-known findings, which you can review and close in bulk.
- Turning the toggle off later is safe: per-branch engagements simply stop receiving imports and the default engagement resumes on the next sync.
- Connectors reconcile state on the sync schedule. Branch tracking makes each sync complete across branches; it does not make data real-time between syncs.

## **Chef Automate**

The Chef Automate connector imports **InSpec compliance findings**. DefectDojo groups the nodes Chef Automate reports on by their **environment**, and creates a Record for each environment.

#### Prerequisites

A Chef Automate **API token**. It is never logged.

#### Connector Mappings

1. Enter your Chef Automate server URL in the **Location** field.
2. Enter the API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each environment becomes a Record, carrying the **failed** InSpec controls from each of its nodes' **latest** compliance runs. Passing and skipped controls are not imported, so the finding list is your outstanding compliance work rather than a full control inventory.

## **CI Fuzz**

The CI Fuzz connector imports **fuzzing findings** from Code Intelligence CI Fuzz. DefectDojo creates a Record for each CI Fuzz **project**.

#### Prerequisites

A CI Fuzz **API token**, sent as a bearer token and never logged.

#### Connector Mappings

1. Enter `https://app.code-intelligence.com` in the **Location** field.
2. Enter the API token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each CI Fuzz project becomes a Record, carrying that project's fuzzing findings.

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

## **Codacy**

The Codacy connector imports **code quality and security findings** from Codacy. DefectDojo enumerates every organization your token can see and creates a Record for each **repository that carries security issues** — repositories with none are not mapped.

#### Prerequisites

You need a Codacy **account** API token.

> **A repository ("project") token will not work.** Codacy's repository tokens are valid only against its older API version, and this connector uses the current one. Pasting a project token produces authentication failures that look like an invalid key. Make sure you generate an **account** token.

#### Connector Mappings

1. Enter `https://app.codacy.com/api/v3` in the **Location** field.
2. Enter your Codacy **account** API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each repository with security issues becomes a Record. Only **open** Security and Risk Management items are imported, so items you resolve in Codacy are reflected on the next Sync.

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

## **Coverity**

The Coverity connector imports findings from a **Coverity Connect** server. DefectDojo creates a Record for each Coverity **project**.

#### Connector Mappings

1. Enter your Coverity Connect server URL in the **Location** field.
2. Enter the Coverity Connect **username** in the **Username** field.
3. Enter the user's password or authentication key in the **Secret** field.
4. Optionally, set a **View Name** to select which saved issues view the connector reads. Leave blank to use the default, **Outstanding Issues**.
5. Optionally, set **Import All Issue Kinds** to `true` to widen the import beyond the default Security and Quality (`RESOURCE_LEAK`) issue filter.

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

## **CyberArk Certificate Manager**

The CyberArk Certificate Manager connector imports **PKI/certificate posture findings**. DefectDojo creates a Record for each certificate's **owning application** (SaaS) or **policy folder** (self\-hosted).

**These findings are DefectDojo's own analysis, not a vendor vulnerability list.** The connector enumerates your certificates and evaluates four posture rules against each one — **expiry**, **weak key**, **SHA\-1 signature**, and **self\-signed** — then raises findings from the results. If you go looking for a matching "vulnerabilities" list inside Certificate Manager, there isn't one.

Both editions are supported, and the connector normalizes them so the same rules apply to each:

* **`cloud`** — Certificate Manager SaaS, formerly TLS Protect Cloud.
* **`tpp`** — Certificate Manager Self\-Hosted, formerly Trust Protection Platform.

#### Prerequisites

* **Cloud:** a SaaS **API key**.
* **Self-hosted:** an **OAuth client ID** registered on the server, plus a **service account username and password**.

#### Connector Mappings

1. Enter your Certificate Manager URL in the **Location** field — `https://api.venafi.cloud` (or your region's host) for cloud, or your Trust Protection Platform host for self\-hosted.
2. Set **Edition** to `cloud` or `tpp`. It defaults to `cloud`.
3. For the **cloud** edition, enter the SaaS API key in **API Key (cloud)** and leave the `tpp` fields blank.
4. For the **tpp** edition, enter the **Client ID (tpp)**, **Username (tpp)** and **Password (tpp)**, and leave the cloud API key blank.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Because the credential fields are shared between editions, only the ones matching your chosen **Edition** are required — the others should be left empty.

## **Cyberwatch**

The Cyberwatch connector imports **CVEs and security (compliance) issues** from a Cyberwatch appliance — both kinds in a single Sync. DefectDojo creates a Record for each asset, or "server", the appliance knows about.

#### Prerequisites

A Cyberwatch **API key ID and secret key**, created in the appliance under **Profile \> API keys**. The secret is never logged.

#### Connector Mappings

1. Enter your Cyberwatch appliance URL in the **Location** field.
2. Enter the API key ID in the **API Key** field.
3. Enter the secret in the **Secret Key** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset becomes a Record, carrying both its CVEs and its compliance findings.

## **CyCognito**

The CyCognito connector imports **external attack surface (EASM) findings** from the CyCognito platform. By default DefectDojo creates a Record for each **discovered asset**, across every asset type CyCognito tracks — IPs, domains, certificates, web apps and IP ranges.

There is deliberately no per\-asset configuration: the point of an EASM source is that it finds assets nobody enumerated in advance, so newly discovered assets appear as Records without anyone editing a configuration.

#### Prerequisites

A CyCognito **API key**, created under **Settings \> API** in CyCognito. It is sent as the value of the `Authorization` header.

#### Connector Mappings

1. Enter `https://api.platform.cycognito.com` in the **Location** field.
2. Enter your CyCognito API key in the **API Key** field.
3. Optionally, set **Asset Grouping** to `organization` to create one Record per CyCognito **organization** instead of one per asset. Leave it blank for the default, one Record per asset.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Under **organization** grouping, assets that belong to no organization are collected into a Record named **Unattributed Assets**.

## **Datadog**

The Datadog connector imports **Cloud Security findings** — misconfigurations, identity risks and vulnerabilities — from the Datadog security findings API. DefectDojo creates a Record for each **cloud account** the findings belong to, so no per\-resource configuration is needed.

#### Prerequisites

You will need two credentials from Datadog:

* An **API key**, from **Organization Settings \> API Keys**.
* An **application key**, from **Organization Settings \> Application Keys**, which must carry the **`security_monitoring_findings_read`** scope.

Neither key is ever logged by DefectDojo.

#### Connector Mappings

1. Enter your organization's Datadog **site** in the **Location** field — for example `https://api.datadoghq.com`. Organizations on the EU, US3, US5 or AP1 sites must use their own site hostname.
2. Enter the API key in the **API Key** field.
3. Enter the application key in the **Application Key** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each cloud account that has findings becomes a Record. DefectDojo respects Datadog's rate limits, backing off and retrying rather than failing the Sync.

## **Deepfence ThreatMapper**

The Deepfence ThreatMapper connector uses the [ThreatMapper](https://github.com/deepfence/ThreatMapper) management-console REST API to import **vulnerability scan** results. DefectDojo discovers every node ThreatMapper has scanned — a container image, host, or container — and creates a Record for each, then imports that node's most recent completed scan as findings.

#### Prerequisites

You will need a ThreatMapper **API token**, found in the console under **Settings → User Management** (your user's API key). The connector exchanges it for a short-lived access token on each sync; the API token is never logged.

#### Connector Mappings

1. Enter your ThreatMapper console URL in the **Location** field (for example `https://threatmapper.example.com`).
2. In the **Secret** field, enter the ThreatMapper API token.
3. If your console uses a self-signed certificate, set **Skip TLS Verification** to `true`.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each scanned **node** to a Record and each **CVE** in its latest completed vulnerability scan to a finding. The severity comes from ThreatMapper's own rating, and the affected package, CVSS score, fix version (as mitigation), reference links, and a details block are carried over. Findings are recorded as dynamic findings and de-duplicated on the node, CVE, package and package path.

See the [ThreatMapper documentation](https://community.deepfence.io/threatmapper/docs/v2.5/) for more information.

## **DeepSource**

The DeepSource connector imports **static analysis findings** from DeepSource. DefectDojo enumerates every account your token can see and creates a Record for each **activated** repository.

#### Prerequisites

A DeepSource **personal access token**, sent as a bearer token.

#### Connector Mappings

1. Enter your DeepSource GraphQL API URL in the **Location** field — `https://api.deepsource.com/graphql/` for the cloud platform, or your own host's GraphQL path if self\-hosted.
2. Enter the personal access token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each activated repository becomes a Record. DeepSource reports the currently-open set of issue occurrences rather than a per\-finding status, so each Sync reflects what is open at that moment.

## **Dependency\-Track**

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

## **Detectify**

The Detectify connector imports **vulnerability findings** covering Application Scanning, Surface Monitoring and API Scanning in one connector. DefectDojo creates a Record for each **asset** in your account.

#### Prerequisites

A Detectify **API key**, from **Team settings \> API keys**. It is sent as the `X-Detectify-Key` header and never logged.

Optionally, you can also supply the **base64 secret** paired with that key to have DefectDojo HMAC\-sign its requests. This is a **Professional plan** feature; without it, DefectDojo uses key\-only authentication, which works on all plans.

#### Connector Mappings

1. Enter `https://api.detectify.com/rest` in the **Location** field.
2. Enter your Detectify API key in the **API Key** field.
3. Optionally, enter the base64 secret in the **API Secret** field to enable request signing. Leave it blank for key\-only authentication.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset becomes a Record, carrying its vulnerabilities from all three Detectify scanning products.

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

## **Dragos**

The Dragos connector imports **OT/ICS vulnerability findings** from a Dragos SiteStore deployment. DefectDojo creates a Record for each **OT zone** — one SiteStore deployment represents one site, so the zone is the meaningful grouping within it.

#### Prerequisites

A Dragos **API key ID and secret**, created under **Admin \> Users \> Add New API Key**. The key needs these read privileges:

* `asset:read`
* `detection:read`
* `vulnerability:read`

The secret is shown only once when the key is generated, so capture it then. It is never logged.

#### Connector Mappings

1. Enter your Dragos **SiteStore** host in the **Location** field.
2. Enter the API key ID in the **API Key ID** field.
3. Enter the secret in the **API Key Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each OT zone becomes a Record, carrying the vulnerabilities detected on the assets in that zone.

## **Elastic Security**

The Elastic Security connector imports **cloud vulnerability, posture and detection findings** from an Elasticsearch cluster, as three separate finding types. DefectDojo creates a Record for each **cloud account**.

Not every Elastic finding carries a cloud account, so DefectDojo falls back in order: the **Kubernetes cluster** (for KSPM findings with no cloud account), then the **host**. Anything identifying none of those lands in a single catch\-all Record rather than being dropped.

#### Prerequisites

An Elasticsearch **API key**, supplied as the base64 `id:api_key` value.

**Prefer an API key over a username and password**, because a key can be scoped read\-only to just the security indices. A username and password are supported as a fallback for clusters that do not have API keys enabled.

#### Connector Mappings

1. Enter your Elasticsearch cluster URL in the **Location** field.
2. Enter the base64 API key in the **API Key** field. Leave it blank if you are using a username and password instead.
3. If you are not using an API key, enter the **Username** and password for HTTP Basic authentication. These are only used when no API key is supplied.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

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

## **Escape**

The Escape connector uses the [Escape](https://escape.tech) API to import **API\-security (DAST) findings**. DefectDojo enumerates every organization the token can access and every application within each, creates a Record for each application that has a scan, and imports that application's latest scan issues as findings — there is no per\-application configuration.

#### Prerequisites

You will need an Escape **API key**, created in the Escape app under **Settings → API keys**. The key is sent in the `Authorization: Key` header and is never logged.

#### Connector Mappings

1. Leave the **Location** field blank to use `https://public.escape.tech/v2`, or enter your Escape API host explicitly.
2. Enter the Escape API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each **application** to a Record and each scan **issue** to a finding: the severity comes from Escape's rating (Critical/High/Medium/Low), the CWE is carried over, the OWASP category and HTTP method become tags, the affected URL becomes the endpoint, and the remediation guidance is included. Findings are recorded as dynamic findings and de\-duplicated on Escape's issue id.

See the [Escape API documentation](https://docs.escape.tech/) for more information.

## **Fairwinds Insights**

The Fairwinds Insights connector uses the [Fairwinds Insights](https://insights.fairwinds.com) REST API to import **Kubernetes security findings** across your whole organization. DefectDojo enumerates every active **cluster** and creates a Record for each one, then imports that cluster's Security **action items** \(from Polaris, Trivy, Kube\-bench, OPA and the other Insights reports\) as findings — there is no per\-cluster configuration.

#### Prerequisites

You will need a Fairwinds Insights **organization** name and an **API token**. Create the token in the Insights app under **Organization Settings \> Tokens**; a `read_only` token is sufficient. The token is org\-scoped and is sent as a bearer token; it is never logged.

#### Connector Mappings

1. Leave the **Location** field blank to use `https://insights.fairwinds.com`, or enter your Insights host explicitly.
2. Enter your Insights **Organization** name (the slug shown in your dashboard URL).
3. Enter the Insights API token in the **Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each active **cluster** to a Record and each Security **action item** to a finding: severity comes from Fairwinds' numeric score \(mapped to DefectDojo's Info–Critical\), the Fairwinds report that produced the item \(`polaris`, `trivy`, `kube-bench`, ...\) becomes a tool tag, the affected Kubernetes resource and container image are included, and any CVE identifiers are extracted. Findings are recorded as static findings and de\-duplicated on the Fairwinds action\-item id.

See the [Fairwinds Insights API documentation](https://insights.docs.fairwinds.com/technical-details/api/) for more information.

## **Finite State**

The Finite State connector imports **firmware and embedded-device findings** from Finite State. DefectDojo creates a Record for each **Asset**, which in Finite State is a **product line** rather than an individual firmware build.

This matters for how your data is organized: a product line's findings are the union of its builds' findings, with the build recorded on each finding as a tag and in the description. One Record therefore accumulates the history of a firmware line, instead of fragmenting into a separate Record per release.

#### Prerequisites

A Finite State **API token**. It is sent in the `X-Authorization` header — not `Authorization` — which the connector handles for you.

#### Connector Mappings

1. Enter your Finite State subdomain in the **Location** field — for example `https://acme.finitestate.io`. DefectDojo appends the API path itself.
2. Enter the API token in the **API Token** field.
3. Optionally, set **Import Every Firmware Build** to `true` to import findings from **every** build of each asset. Leave it blank to import only the **newest** build, which is what most teams want.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Merged duplicates and deleted findings are excluded automatically, so they never reach DefectDojo.

## **Fleet**

The Fleet connector imports **software vulnerabilities** and **failing compliance policies** from Fleet, as two separate finding types. DefectDojo creates a Record for each Fleet **team**.

Hosts that belong to no team still carry real vulnerabilities, so they are mapped to a synthetic **"No team"** Record rather than being dropped.

> **Teams are a Fleet Premium feature.** On a free Fleet deployment the team list is unavailable, so **every host** lands in the single synthetic Record. That is expected, not a mapping failure.

#### Prerequisites

A Fleet **API token**, from **Account Settings \> Get API token**. The connector needs **read access only** — on Fleet Premium you can issue a scoped API\-only user for it.

#### Connector Mappings

1. Enter your Fleet server URL in the **Location** field.
2. Enter the API token in the **API Token** field.
3. Optionally, enable **Skip software vulnerabilities** to leave out CVEs found on installed software. Leave it off to import them.
4. Optionally, enable **Skip compliance policies** to leave out failing osquery policy checks. Leave it off to import them under their own scan type.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Both imports are on by default — the two toggles exist to turn each off if you only want one kind of finding in DefectDojo.

## **Fortify**

The Fortify connector imports SAST/DAST results from Fortify (OpenText/Micro Focus), covering both editions that share the platform: **SSC** (Software Security Center, self-hosted) and **Fortify on Demand (FoD)** (SaaS). It syncs the whole account: DefectDojo discovers every application (SSC project version / FoD release) and creates a Record for each, then imports that application's issues as findings.

#### Prerequisites

- **SSC**: a **FortifyToken** — create one in the SSC UI under **Administration → Token Management** (a CIToken/UnifiedLoginToken).
- **FoD**: an **OAuth2 API key** — a Client ID and Client Secret from **Settings → API** (with the `api-tenant` scope).

The token and OAuth secret are never logged.

#### Connector Mappings

1. Enter the Fortify base URL in the **Location** field: for SSC your server host (the connector adds `/ssc/api/v1`); for FoD the API host for your region, e.g. `https://api.ams.fortify.com`.
2. Set **Edition** to `SSC` or `FoD`.
3. For **FoD**, enter the OAuth **Client ID**; leave it blank for SSC.
4. In **Token / Client Secret**, enter the SSC FortifyToken or the FoD OAuth client secret.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each Fortify **application** to a Record and each **issue** to a finding: the severity comes from Fortify's own **friority** rating (Critical/High/Medium/Low), the title combines the issue category with its file and line, and the file path, line, kingdom, analyzer and engine type are carried over. Issues from static-analysis engines (SCA) are recorded as static findings and WebInspect (DAST) issues as dynamic findings; suppressed, removed and hidden issues are skipped, issues audited "Not an Issue" are marked false positive, and "Exploitable"/reviewed issues are marked verified.

See the [Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/) and [Fortify on Demand](https://api.ams.fortify.com/swagger/ui) API documentation for more information.

## **FOSSA**

The FOSSA connector imports both **security vulnerabilities** and **license-policy violations** from FOSSA. DefectDojo creates a Record for each FOSSA **project**.

#### Prerequisites

A FOSSA **Full** API token.

> **A Push-Only token will not work.** FOSSA's Push-Only tokens cannot read the APIs this connector uses, so the Sync fails to retrieve anything. This is the most common misconfiguration for this connector — make sure the token is a **Full** token.

#### Connector Mappings

1. Enter `https://app.fossa.com/api` in the **Location** field.
2. Enter your FOSSA Full API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each FOSSA project becomes a Record. Only your organization's **active** issues are imported, covering both vulnerability and license-policy findings — so this connector can drive licence compliance work as well as security remediation.

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

## **GitHub**

The GitHub connector is an **Asset Connector**: it enumerates the repositories your token can access and creates a DefectDojo Asset for each one, grouped into Organizations by GitHub owner (organization or user). No findings are imported.

**Please note:** this connector imports your repository **inventory** only. To import GitHub security alerts — code scanning, Dependabot, and secret scanning — as findings, use the separate **GitHub Advanced Security** connector below. The two are independent and can be run together.

#### Prerequisites

The connector authenticates with a GitHub **personal access token** and reads only repository **metadata** (name, description, URL, and owner) — it does not access your code, issues, or security alerts. It imports every repository the token's account owns, collaborates on, or is an organization member of, so confirm the token's account can see the repositories you want to mirror. We recommend a dedicated service account.

The token only needs read-only access to repository metadata:

- A *fine-grained* token needs **Repository permissions → Metadata: Read-only**, granted to the repositories (or the whole organization) you want to import.
- A *classic* token needs the **`repo`** scope to include private repositories (use **`public_repo`** if you only need public ones), plus **`read:org`** so organization-owned repositories resolve.

Only GitHub.com (including GitHub Enterprise Cloud) is supported. GitHub Enterprise **Server** is not supported by this connector at this time.

#### Connector Mappings

1. Enter `https://api.github.com` in the **Location** field.
2. Enter the personal access token in the **Secret** field.

No organization or repository list needs to be entered — DefectDojo imports every repository the token can see. Each repository becomes a Record named after the repository, grouped by its GitHub **owner** (organization or user). If a repository is later deleted, or the token loses access to it, its mapped Record is flagged `MISSING` on the next Sync rather than removed — DefectDojo never silently deletes an Asset.

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

## **Google Artifact Analysis**

The Google Artifact Analysis connector imports **container image vulnerability findings** from Google Cloud. DefectDojo creates a Record for each **active** GCP project the service account can list — no per\-image or per\-repository configuration is needed.

#### Prerequisites

A Google **service account** with the **Container Analysis Occurrences Viewer** role, and a **JSON key** for it. Neither the key nor the token derived from it is ever logged.

#### Connector Mappings

1. Leave the **Location** field at the default unless you use a non\-standard endpoint.
2. Paste the **entire contents** of the service account JSON key file into the **Service Account Key** field.
3. Optionally, set **Parent** to narrow the sync to `organizations/{id}`, `folders/{id}` or `projects/{id}`. Leave it blank to sync every project the service account can list.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each active GCP project becomes a Record, carrying the vulnerability occurrences Artifact Analysis has recorded against its images.

## **Google Cloud SCC**

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

## **Halo Security**

The Halo Security connector imports **attack surface findings** from Halo Security. DefectDojo creates a Record for each **monitored target**.

#### Prerequisites

A Halo Security **API key**. This connector uses a single key — there is no secret, key pair, or OAuth flow to configure.

#### Connector Mappings

1. Enter `https://api.halosecurity.com/api/v1` in the **Location** field.
2. Enter your Halo Security API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each monitored target becomes a Record, carrying the account's **active** issues that affect it, enriched from Halo's issue catalogue.

A finding's identity combines the issue **and** the target it was found on. Halo's issue IDs are catalogue identifiers shared across targets, so the same issue affecting two targets is correctly tracked as two findings rather than collapsing into one.

## **Harbor**

The Harbor connector uses the Harbor v2.0 REST API to import container image vulnerabilities across your whole registry. DefectDojo enumerates every Harbor **project** and creates a Record for each one, then walks the project's repositories and artifacts and imports the vulnerabilities from each **scanned** artifact — carrying the image (repository + tag/digest) as finding context. There is no per\-image configuration.

#### Prerequisites

You will need a Harbor account (or a **robot account**) with pull/read access to the projects you want to import. We recommend a dedicated robot account: in Harbor, open a project (or **Administration \> Robot Accounts** for a system robot), create a robot with the **pull** permission on repositories and artifacts, and copy its full name and secret. Robot names start with `robot$` by default, but the prefix is configurable per Harbor instance (some use `robot_`) — copy the name exactly as Harbor displays it. A regular username/password also works.

#### Connector Mappings

1. Enter your Harbor URL in the **Location** field — for example `https://harbor.example.com`. DefectDojo appends the `/api/v2.0` API path automatically.
2. Enter the Harbor username, or a robot account name exactly as Harbor shows it (`robot$<name>` by default), in the **Username** field.
3. Enter the password or robot account secret in the **Secret** field. It is sent using HTTP Basic authentication.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Harbor project becomes a Record. For every artifact that has a completed scan, its vulnerabilities are imported as findings; the affected package/version, a CVSS\-derived severity, the CVE, the CWE, and a remediation (fixed version) are included where Harbor provides them. Only scanned artifacts are imported — trigger a scan in Harbor for images that have not been scanned yet.

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

## **HCL AppScan**

The HCL AppScan connector uses the AppScan v4 REST API to import issues from **AppScan on Cloud (ASoC)** or a self-hosted **AppScan 360°** (both share the API). It syncs the whole account: DefectDojo discovers every application and creates a Record for each, then imports that application's issues (DAST, SAST and IAST) as findings.

#### Prerequisites

You will need an AppScan **API key** — a Key ID and Key Secret generated under your AppScan account settings (API Key). The connector exchanges them for a short-lived session token on each run; the Key ID, Key Secret and token are never logged.

#### Connector Mappings

1. Enter the AppScan console URL in the **Location** field: for ASoC use `https://cloud.appscan.com` (or `https://eu.cloud.appscan.com` for the EU region); for AppScan 360° use your instance host.
2. Set **Provider** to `ASOC` for AppScan on Cloud, or `A360` for a self-hosted AppScan 360°.
3. Enter the **API Key ID** and **API Key Secret**.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each AppScan **application** to a Record (VEP) and each **issue** to a finding: the title is the issue type with its domain / entity / cause-id / URL / path appended; the severity maps Informational → Info (Low/Medium/High/Critical pass through); the CWE, a labeled description, the remediation and advisory, and the host/port endpoint are carried over. Issues from static analysis are recorded as static findings and dynamic/interactive issues as dynamic findings; open issues are active and fixed/passed issues are mitigated.

See the [AppScan REST API documentation](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html) for more information.

## **HiddenLayer**

The HiddenLayer connector imports **AI/ML model scan findings** from HiddenLayer's Model Scanner. DefectDojo creates a Record for each **scanned model**.

#### Prerequisites

A HiddenLayer API **client ID and client secret**, created under **Model Scanner \> API Access**. DefectDojo exchanges them for a short\-lived bearer token on each Sync; the secret is never logged.

#### Connector Mappings

1. Enter your tenant's regional API URL in the **Location** field — `https://api.us.hiddenlayer.ai` or `https://api.eu.hiddenlayer.ai`.
2. Enter the client ID in the **Client ID** field.
3. Enter the client secret in the **Client Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

HiddenLayer returns model scan results as **SARIF** logs, and DefectDojo maps them the same way it maps an uploaded SARIF report — so these findings behave like SARIF imports elsewhere in the Asset.

## **Holm Security**

The Holm Security connector imports findings across **both** of Holm's asset classes — network/infrastructure scanning and web application scanning — through one connector. DefectDojo creates a Record for each **asset**.

#### Prerequisites

A Holm Security **API token**, from **Security Center \> API**. It is never logged.

#### Connector Mappings

1. Enter your **region's** API host in the **Location** field — for example `https://se-api.holmsecurity.com` for the Swedish region. Holm Security's API host is region\-specific, so this must match the region your account is in.
2. Enter the API token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset becomes a Record, whether it was found by a network scan or a web scan.

## **ImmuniWeb**

The ImmuniWeb connector imports **web application security findings** from ImmuniWeb. DefectDojo creates a Record for each **tested asset** (website) on the account.

#### Prerequisites

An ImmuniWeb **premium API key**.

> **A premium key is required, even though ImmuniWeb treats its API key as optional.** Without one, ImmuniWeb **truncates the vulnerability list** it returns. DefectDojo requires the key rather than importing a silently incomplete set of findings — an import that under\-reports is worse than one that will not start.

#### Connector Mappings

1. Enter your ImmuniWeb API URL in the **Location** field.
2. Enter your premium API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each tested asset becomes a Record, carrying that asset's detected vulnerabilities.

## **InsightCloudSec**

The InsightCloudSec connector imports **cloud security posture findings** from Rapid7 InsightCloudSec. DefectDojo creates a Record for each **onboarded cloud account**.

**Please note:** InsightCloudSec (formerly DivvyCloud) is a **distinct Rapid7 product** from InsightVM and InsightAppSec, each of which has its own connector in this list. Make sure you are configuring the one that matches your Asset.

#### Prerequisites

An InsightCloudSec **API key**, from the **API Keys** page in your user profile. It is never logged.

#### Connector Mappings

1. Enter `https://cloudsec.insight.rapid7.com` in the **Location** field. Self\-hosted InsightCloudSec deployments use their own host.
2. Enter the API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

One finding is created per **insight and failing resource** pair, so a single policy failing across many resources produces a finding for each — grouped under the cloud account the resource belongs to.

## **Intigriti**

The Intigriti connector uses the Intigriti external company API to pull bug-bounty / pentest **submissions** into DefectDojo. It syncs the whole company account: DefectDojo discovers every program the token can access and creates a Record for each, then imports that program's submissions as findings.

#### Prerequisites

You will need an Intigriti **company API token**. In the Intigriti company portal, under **Company Settings > API** (the `company_external_api` scope), generate an access token with read access to your programs and submissions. A dedicated token for DefectDojo is recommended. The token is sent as a Bearer token and is never logged.

#### Connector Mappings

1. Enter the Intigriti external company API base URL in the **Location** field: `https://api.intigriti.com/external/company`. The URL must be HTTPS.
2. Enter the company API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each Intigriti **program** to a Record and each **submission** to a finding, keyed by the submission code. The finding severity follows Intigriti's rating (Exceptional/Critical → Critical, then High/Medium/Low, otherwise Informational), and the submission's lifecycle state maps to the finding's status: open/triage submissions are active, accepted submissions are verified, and closed submissions become mitigated, a duplicate, out-of-scope, false-positive or risk-accepted according to their close reason. The finding description carries the report's vulnerability type, affected asset, proof of concept and the researcher's answers.

See the [Intigriti API documentation](https://kb.intigriti.com/en/articles/6117846-intigriti-api) for more information.

## **Intruder**

The Intruder connector uses the [Intruder REST API](https://developers.intruder.io/) to pull your whole account's posture into DefectDojo. Each Intruder **target** is discovered as a Record (Asset); each **occurrence** of an issue on a target becomes a Finding.

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

## **JFrog XRay**

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

By default, DefectDojo maps each Artifactory **repository** as a separate Record. Each Sync generates a complete vulnerability report per repository via Xray, so finding statuses in DefectDojo always reflect the current state of the repository.

#### Repository Filter (optional)

By default the connector discovers **every** repository in your JFrog instance. On instances with a large number of repositories — many of which may not be relevant to security review — discovery can be narrowed with the optional **Repository Filter** field, under **Import Filters** on the connector form.

The filter is applied during discovery, **before any per\-repository work is done**. A repository outside the filter costs nothing: no Xray report is generated for it and, in artifact mode, none of its first\-level artifacts are enumerated. This makes it the most effective way to cut both Sync time and the load DefectDojo places on your JFrog instance — more so than any setting applied later in the Sync. It is especially recommended alongside **Artifact\-Level Records** on large instances.

**Syntax:** a comma\-separated list of repository keys. Each entry may use `*` wildcards:

* An entry containing `*` is matched as a pattern — `releases-*` matches every repository key beginning `releases-`, and `*docker-pr-local*` matches any key containing `docker-pr-local`. A `*` matches any run of characters, including `/`.
* An entry with no `*` must match a repository key **exactly**.
* A repository is discovered if it matches **any** entry in the list. Spaces around commas are ignored.

```
releases-*, snapshots
```

The example above discovers every repository whose key starts with `releases-`, plus the single repository named exactly `snapshots`.

Notes:

* The filter is an **allow\-list** — a match selects a repository. There is no exclusion or negation syntax, so you cannot express "everything except X" directly.
* Matching is **case\-sensitive**, for both exact entries and wildcards. `*` is the only wildcard character; `?` and character ranges are not supported.
* **Leave it blank to discover every repository.** A value that is only spaces or commas is treated as blank.
* A filter that matches nothing simply discovers nothing — there is no error. If a Sync unexpectedly finds no repositories, check the connector log for the `repository filter scoped discovery` entry, which reports how many of the total repositories matched.
* The field can be changed after the connection is created.

**Changing the filter later:** repositories that a newly narrowed filter now excludes are no longer discovered, and their existing Records follow the normal lifecycle for Assets the tool no longer reports — **mapped** Records are flagged `MISSING` on the next Sync, and unmapped `NEW` Records are removed. Findings already imported into DefectDojo are not deleted; the filter governs discovery only.

#### Artifact-Level Records

The **Artifact-Level Records** toggle changes discovery to one level below the repository: every first-level entry under a repository root (for Docker repositories, each image; for generic repositories, each top-level file or folder) becomes its own Record. Each Sync still generates a single Xray report per repository — DefectDojo attributes each vulnerability to the artifacts it impacts, so the load on your JFrog instance does not increase.

> **Check which mode you are in before your first Sync.** Artifact\-Level Records is **on by default for new installations**. Installations that predate the feature keep their existing repository\-level layout, so the toggle is off for them until someone turns it on. In both cases the toggle can be changed at any time — see *Switching an existing connection* below.

With Artifact-Level Records enabled:

* Repositories remain as Records and become **parent assets**: they carry no findings themselves, but when the Asset Hierarchy feature is enabled, DefectDojo automatically relates each artifact asset to its repository asset with a `parent` relationship. Assets can then be filtered by parent/child, and findings roll up the hierarchy.
* A vulnerability that impacts several artifacts is imported into each affected artifact's asset, so every asset shows the complete set of findings that affect it.
* Findings are scoped to each artifact's **latest build**, so an artifact's findings describe its current build rather than accumulating results from every build Xray has ever scanned.
* Hierarchy relationships created by the connector never overwrite relationships you created by hand. If an asset already has a parent you assigned, the connector leaves it alone.
* The token additionally needs read access to the Artifactory storage API (included in the scopes above).

**Switching an existing connection to Artifact-Level Records:** the toggle can be changed at any time. On the first Sync afterward, new artifact Records appear for mapping — enable **Auto Map** on the connection when flipping the toggle so findings move without a gap. The repository-level assets stop receiving findings and their previously imported findings are closed on their next Sync (the same findings are re-imported under the new artifact assets, with fresh status); notes and history on the old repository-level findings stay on the repository asset. Switching back reverses this: repository Records resume carrying findings (previously closed findings re-open as they re-match), and artifact Records are marked MISSING — their assets and findings are kept but stop updating, so you can archive them at your convenience.

See the [JFrog Xray REST API documentation](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis) for more information.

## **JSM Assets**

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

## **Klocwork**

The Klocwork connector imports **static analysis (SAST) findings** from a Perforce Klocwork server. DefectDojo enumerates the server's projects and creates a Record for each **project**.

#### Prerequisites

A Klocwork **username** and its **login token (`ltoken`)** — the token generated by `kwauth` and stored in the ltoken file. The token is never logged.

#### Connector Mappings

1. Enter your Klocwork server URL in the **Location** field.
2. Enter the Klocwork username the token belongs to in the **Username** field.
3. Enter the login token in the **Login Token (ltoken)** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Klocwork project becomes a Record. Only issues Klocwork classes as **actionable** are imported, and only from each project's **latest build** — so the findings describe the current state of the project rather than accumulating across builds.

## **Kubescape**

The Kubescape connector reads Kubernetes posture (misconfiguration) results produced by the [Kubescape operator](https://kubescape.io/docs/install-operator/) directly from the cluster's Kubernetes API — no ARMO SaaS account is required. It reads the `WorkloadConfigurationScan` objects served by the operator's in-cluster storage aggregated API (`spdx.softwarecomposition.kubescape.io/v1beta1`). Each Kubernetes **namespace** that has posture results is mapped to a Record (Asset); each failed control on a workload becomes a Finding.

#### Prerequisites

- The Kubescape operator must be installed in the target cluster with configuration scanning enabled (see [Installing in your cluster](https://kubescape.io/docs/install-operator/)). Confirm results exist with `kubectl get workloadconfigurationscans -A`.
- A **kubeconfig** granting read access to the `spdx.softwarecomposition.kubescape.io` API group (list/get on `workloadconfigurationscans`) for the target cluster.

#### Connector Mappings

1. Enter the cluster's API server URL (or a friendly cluster identifier) in the **Location** field.
2. Paste the **kubeconfig** for the target cluster in the `kubeconfig` field. Optionally set `kube_context` to select a context within it, and `cluster_name` to label the discovered Assets.
3. Each namespace with posture results is discovered as a Record; map the ones you want to import to DefectDojo Assets.

Findings are derived per failed control: the control name and workload identify the Finding, severity comes from the control's score factor, the control ID becomes the vulnerability ID, and each Finding links to its control reference at `https://hub.armosec.io/docs/`.

## **Mend**

The Mend connector (formerly **WhiteSource**) uses the Mend API to import security findings from your Mend organization. DefectDojo creates a Record for each Mend **project**.

#### Prerequisites

You will need a Mend (service) user with a **User Key** (a personal access token) and your Mend **Organization UUID**. We recommend a dedicated service account so automated activity is easy to distinguish from manual team actions. Find the Organization UUID in the Mend App under **Administration > Organization UUID**.

#### Connector Mappings

1. Enter your Mend API URL in the **Location** field. This URL is **region-specific** — use the API base URL for the region your Mend organization is hosted in.
2. Enter the login email of the Mend user in the **Email** field.
3. Enter your Mend **Organization UUID** in the **Organization UUID** field.
4. Enter the Mend **User Key** in the **User Key** field.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

## **Lacework / FortiCNAPP**

The Lacework / FortiCNAPP connector uses the Lacework v2 API to import **host and container vulnerabilities** for your whole Lacework account.

#### Prerequisites

You will need a Lacework **API key** — an API key id and secret, created in the Lacework console under **Settings → API keys**. The connector exchanges these for a short-lived access token on each sync; the key id, secret and token are never logged.

#### Connector Mappings

1. Enter your Lacework account URL in the **Location** field — for example `https://YOUR-ACCOUNT.lacework.net` (a bare account name is also accepted).
2. Enter the **API Key ID** and **API Secret**.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps the Lacework **account** to a Record (the whole-account scope). Each **container** and **host** vulnerability becomes a finding: the severity comes from Lacework's own rating, the affected package and version become the component, the fix version becomes the mitigation, and the affected image/host is recorded as tags. Container vulnerabilities are recorded as static findings (image scans) and host vulnerabilities as dynamic findings (running-host scans).

See the [Lacework API documentation](https://docs.lacework.net/api/v2/docs) for more information.

## **Microsoft Defender**

The Microsoft Defender connector imports device vulnerability findings from **Microsoft Defender Vulnerability Management (MDVM)** — one finding per device / software version / CVE combination, including severity, CVSS score, exploitability level and recommended security updates. DefectDojo will discover your Defender **device groups** and create a Record for each one; devices that aren't assigned to any device group are collected under a synthetic **Unassigned** group.

**Please note:** this Connector is distinct from the file\-based **"MSDefender Parser"** scan type, which imports manually exported Defender files. Choose one import path per Asset to avoid duplicate findings.

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

**Please note:** this Connector is distinct from the **Microsoft Defender** connector, which imports device findings from the Defender for Endpoint API. Defender for Cloud is an Azure Asset with a different API surface (Azure Resource Manager / Resource Graph) and permission model (Azure RBAC). Run whichever matches where your findings live — or both, if you use both Assets.

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

## **MobSF**

The MobSF connector uses the [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) REST API to import mobile application (APK/IPA) static-analysis results. DefectDojo discovers every app that has been scanned on your MobSF instance and creates a Record for each one, then imports that app's static-analysis findings.

#### Prerequisites

You will need your MobSF **REST API key**. Find it on the MobSF home page under **API** (also shown in the MobSF docs as the `Authorization` value). The key is sent on every request and is never logged.

#### Connector Mappings

1. Enter your MobSF base URL in the **Location** field (for example `https://mobsf.example.com`).
2. In the **Secret** field, enter the MobSF REST API key.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each scanned **app** to a Record and imports its findings from the MobSF JSON report across several sections — application permissions, code analysis, the signing certificate, the Android manifest, Android API usage and binary analysis. Each finding is tagged with **CWE 919** (mobile), and its severity comes from MobSF's own rating (high, warning, info, secure/good) — a *dangerous* permission is treated as High. Findings are recorded as static findings and de-duplicated on the scan, section, title, severity and file path.

See the [MobSF REST API documentation](https://mobsf.github.io/docs/#/rest_api) for more information.

## **NetRise**

The NetRise connector imports **firmware vulnerability findings** from NetRise. DefectDojo enumerates every firmware artifact in your tenant and creates a Record for each **product line** — the vendor and Asset pair — so a product line accumulates the findings of its artifacts.

#### Prerequisites

A NetRise API **client ID and secret**, plus the **organization ID** they belong to. The secret is never logged.

#### Connector Mappings

1. Enter your NetRise API URL in the **Location** field.
2. Enter the client ID in the **Client ID** field.
3. Enter the client secret in the **Client Secret** field.
4. Enter your **Organization ID**.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each product line becomes a Record, carrying the CVEs found in its firmware artifacts.

## **NeuVector**

The NeuVector connector uses the [NeuVector](https://github.com/neuvector/neuvector) controller REST API to import container **image vulnerability scans**. DefectDojo discovers every image NeuVector has scanned and creates a Record for each, then imports that image's scan report as findings.

#### Prerequisites

You will need a NeuVector **username and password** for a controller account with permission to read scan results. The connector logs in with these credentials to obtain a session token; the password and token are never logged.

#### Connector Mappings

1. Enter your NeuVector controller URL in the **Location** field, including the REST API port — for example `https://neuvector.example.com:10443`.
2. Enter the controller **Username** and **Password**.
3. If your controller uses a self-signed certificate, set **Skip TLS Verification** to `true`.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each scanned **image** to a Record and each **CVE** in its scan report to a finding. The severity comes from NeuVector's own rating, and the affected package and version, CVSSv3 score and vector, fix version (as mitigation) and reference link are carried over. Findings are de-duplicated on the image, CVE, package, version and severity.

See the [NeuVector API documentation](https://open-docs.neuvector.com/automation/automation) for more information.

## **Nightfall AI**

The Nightfall AI connector imports **data loss prevention (DLP) violations** — sensitive data Nightfall has detected across your connected SaaS tools. DefectDojo creates a Record for each **connected integration** that has violations.

The integration is the natural grouping here, because Nightfall's asset is the data source itself: Slack, Google Drive, GitHub, Jira, Confluence, Salesforce, Zendesk, Notion, Teams, OneDrive, the browser extension, and inline email.

#### Prerequisites

A Nightfall **API key**, sent as a bearer token and never logged.

#### Connector Mappings

1. Enter `https://api.nightfall.ai/dlp/v1` in the **Location** field.
2. Enter your Nightfall API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each integration with violations becomes a Record. Integrations with no violations are not mapped.

## **NowSecure**

The NowSecure connector imports **mobile application security findings**, covering both mobile SAST and DAST. DefectDojo creates a Record for each **mobile app** on the account.

#### Prerequisites

A NowSecure **Platform API token**, from **Profile \> Tokens \> Generate Token**. It is sent as a bearer token and never logged.

#### Connector Mappings

1. Enter `https://lab-api.nowsecure.com` in the **Location** field.
2. Enter the API token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each mobile app becomes a Record, carrying the findings from that app's **latest assessment** — so results describe the current build rather than accumulating across assessments.

## **Nozomi Networks**

The Nozomi Networks connector imports **OT/ICS vulnerability findings** from Nozomi Vantage. DefectDojo creates a Record for each **network zone**, so one Record represents one zone of your operational network.

#### Prerequisites

A Vantage **access key name** and **key token**, created under **Administration \> Security \> Access Keys**. DefectDojo exchanges them for a short\-lived session token on each Sync; the key token is never logged.

#### Connector Mappings

1. Enter `https://api.vantage.nozominetworks.io` in the **Location** field.
2. Enter the access key name in the **Key Name** field.
3. Enter the key token in the **Key Token** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

This connector imports **vulnerabilities only** — it does not import alert-log events — and only those Vantage still reports as **unresolved**, so vulnerabilities you resolve in Vantage are reflected in DefectDojo on the next Sync.

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

## **Orca Security**

The Orca Security connector imports **open alerts** from Orca — vulnerabilities, misconfigurations, malware and secrets alike. DefectDojo creates a Record for each **connected cloud account**.

#### Prerequisites

An Orca **API token**.

**Orca tokens are region-scoped**, so the token and the API host must belong to the same region. If a Sync fails to authenticate with a token you know is valid, check that the **Location** matches the token's region.

#### Connector Mappings

1. Enter your **region-matched** Orca API host in the **Location** field.
2. Enter your Orca API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each connected cloud account becomes a Record. Only **open** alerts are imported, so alerts you close in Orca are reflected in DefectDojo on the next Sync.

## **Ostorlab**

The Ostorlab connector imports **mobile, web and attack-surface findings** — all three of Ostorlab's asset classes through one connector. DefectDojo creates a Record for each **scanned asset**, which may be an app bundle ID, a domain, or a host.

#### Prerequisites

An Ostorlab **API key**, created under **Settings \> API Keys**. It is sent as the `X-Api-Key` header and is never logged.

#### Connector Mappings

1. Enter `https://api.ostorlab.co` in the **Location** field. DefectDojo appends the GraphQL API path itself.
2. Enter your Ostorlab API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each scanned asset becomes a Record, and the vulnerabilities from every scan of that asset are imported against it.

## **Parasoft DTP**

The Parasoft DTP connector imports **static analysis violations** from a Parasoft DTP server. DefectDojo creates a Record for each DTP **report filter**.

#### Prerequisites

A Parasoft DTP **username and password**, used over HTTP Basic authentication. The password is never logged.

#### Connector Mappings

1. Enter your Parasoft DTP server URL in the **Location** field, including its port if it uses a non\-standard one.
2. Enter the DTP username in the **Username** field.
3. Enter the password in the **Password** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each report filter becomes a Record, carrying that filter's static analysis violations **from the latest build** — so findings describe the current state of the code rather than accumulating across builds.

## **Picus Security**

The Picus Security connector imports **breach and attack simulation (BAS) results** from the Picus platform — whether your existing security controls prevented, logged and alerted on each simulated attack. DefectDojo creates a Record for each **agent group**, so one Record represents one environment under test.

#### Prerequisites

You need a Picus **REST API refresh token**, generated by hand at **app.picussecurity.com \> Settings \> Rest API Token**. It is valid for **six months**, and DefectDojo exchanges it for short\-lived access tokens automatically.

> **Paste the refresh token, not an access token.** Picus also issues a two\-hour **access token** from the same area. An access token pasted into the connector will authenticate at first and then stop working the same afternoon. The connector needs the six\-month refresh token.

Because the refresh token expires after six months, plan to rotate it — the connector cannot renew it for you.

#### Connector Mappings

1. Enter `https://api.picussecurity.com` in the **Location** field.
2. Enter the six\-month REST API refresh token in the **Refresh Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each agent group becomes a Record, and its findings come from the **most recent run of every simulation** bound to that group.

## **PingCastle**

The PingCastle connector imports **Active Directory security posture findings** from a PingCastle Enterprise reporting server. DefectDojo creates a Record for each **Active Directory domain** the reporting server monitors, and that domain's **latest HealthCheck report** supplies its findings.

This is a different category from most connectors in this list — identity and Active Directory posture, rather than application, cloud or container scanning.

#### Prerequisites

The PingCastle Enterprise **API key** — the same key your PingCastle agents use when they submit reports (the `--api-key` value passed alongside `--api-endpoint`). It is sent as the `X-API-Key` header.

#### Connector Mappings

1. Enter your **PingCastle Enterprise reporting server** URL in the **Location** field — the same address your agents submit to via `--api-endpoint`.
2. Enter the PingCastle Enterprise API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each monitored domain becomes a Record. DefectDojo reads the same HealthCheck risk rules that the file-based PingCastle parser reads from a local XML export, so findings are consistent whichever route you use.

## Probely

This connector uses the Probely REST API to fetch data.

​**Connector Mappings**

1. Enter the appropriate API server address in the **Location** field. (either <https://api.us.probely.com/> or <https://api.eu.probely.com/> )
2. Enter a valid API key in the **Secret** field.

You can find an API key under the User \> API Keys menu in Probely.  
See [Probely documentation](https://help.probely.com/en/articles/8592281-how-to-generate-an-api-key) for more info.

## **Promptfoo**

The Promptfoo connector imports **LLM red-teaming and evaluation findings** from Promptfoo Cloud. DefectDojo creates a Record for each **target application** (provider) that Promptfoo probed.

#### Prerequisites

A Promptfoo Cloud **API token**, sent as a bearer token and never logged.

#### Connector Mappings

1. Enter `https://api.promptfoo.app` in the **Location** field.
2. Enter your Promptfoo API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo reads every stored evaluation the token can see and works out which targets were probed. A target's findings are its **failing** probes across all evaluations, aggregated **per weakness** rather than one finding per probe run — so repeated evaluations of the same weakness stay a single finding.

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
4. Optionally, restrict discovery to part of your subscription with **Host Tags** (see below).
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Qualys host becomes a Record. Detections Qualys has marked **Fixed** are excluded, so reimport closes remediated findings.

#### Host Tags (optional)

By default the connector discovers **every** host in your Qualys subscription. On a large estate that produces a Record list far bigger than most teams want. It also makes every Sync download the detections of every host.

The optional **Host Tags** field, under **Import Filters** on the connector form, restricts the connector to hosts carrying the Qualys asset tags you name. The restriction travels to Qualys as part of the request, so out-of-scope hosts are never returned. It applies to **both** the host listing and the detection download. Narrowing the scope therefore cuts Sync time and transfer volume, not just the length of the Record list.

**Syntax:** a comma-separated list of Qualys asset tag **names**, exactly as they appear in the Qualys UI under **Asset Management \> Tags**.

```
Prod, Business Unit: Finance
```

The example above discovers every host tagged `Prod` plus every host tagged `Business Unit: Finance`.

Notes:

* Tag names are matched **exactly**, and **wildcards are not supported**. Qualys offers no pattern matching on tag names, so `Prod-*` matches a tag literally named `Prod-*` and nothing else. This differs from the JFrog Xray **Repository Filter** described above, which does accept `*`.
* A host is discovered if it carries **any** tag in the list, not all of them.
* Spaces **around** the commas are ignored. Spaces **inside** a tag name are kept, so `Business Unit: Finance` works as written.
* A tag name that itself contains a comma cannot be used here, because the comma separates entries.
* The filter is an **allow-list**. There is no exclusion or negation syntax, so you cannot express "everything except X".
* **Leave it blank to discover every host.** A value that is only spaces or commas is treated as blank.
* If the tag names match no host, nothing is discovered. Check the spelling against the Qualys UI, and check the visible-host count reported on the connection.
* The field can be changed after the connection is created.

**Testing the connection** ignores this field on purpose, so it still confirms your username and password even when the tag names are wrong.

**Changing the filter later:** hosts that a newly narrowed filter excludes are no longer discovered. Their existing Records then follow the normal lifecycle for assets the tool stops reporting: **mapped** Records are flagged `MISSING` on the next Sync, and unmapped `NEW` Records are removed. Findings already imported into DefectDojo are not deleted. The filter governs discovery only.

## **Quay**

The Quay connector uses the Project Quay REST API to discover container repositories and import the vulnerability reports produced by Quay's built-in **Clair** scanner. DefectDojo creates a Record for each Quay **repository** and, on each Sync, reads the Clair security report of every active tag's image manifest.

#### Prerequisites

Security scanning (Clair) must be enabled on your Quay instance, and you will need a Quay **OAuth 2 access token**:

* In Quay, create (or open) an Organization, go to **Applications**, create an OAuth application, then **Generate Token** with at least the **Read repositories** scope. A dedicated application for DefectDojo is recommended.
* The token is sent as a Bearer token on every request and is never logged.

#### Connector Mappings

1. Enter your Quay base URL in the **Location** field, for example `https://quay.io` or your self-hosted `https://quay.example.com`. The URL must be HTTPS; do not include a trailing API path — DefectDojo constructs the API paths automatically.
2. Enter the OAuth access token in the **Secret** field.
3. Optionally, set a **Namespace** to restrict discovery to a single Quay organization or user. Leave blank to discover every repository the token can read.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each Quay **repository** to a Record. For each repository it lists the active tags, deduplicates them to their unique image manifests (a manifest shared by multiple tags is scanned once), and reads each manifest's Clair report. Manifests Clair has not finished scanning (for example a multi-architecture manifest list, or an image still queued) are skipped until a later Sync. Each Clair vulnerability becomes a finding — the affected package is the component, the fixed version becomes the mitigation, and Clair's **Negligible**/**Unknown** severities are recorded as **Informational**.

See the [Project Quay API documentation](https://docs.projectquay.io/api_quay.html) and the [Clair documentation](https://quay.github.io/clair/) for more information.

## **Qwiet AI**

The Qwiet AI connector imports **SAST, SCA and secret findings** from Qwiet AI (formerly ShiftLeft), and carries Qwiet's **reachability signal** — an indication of whether vulnerable code is actually reachable — which DefectDojo has no other source for. DefectDojo creates a Record for each **application** in your organization.

#### Prerequisites

A Qwiet AI **preZero access token**, sent as a bearer token and never logged. Your organization is read from the token itself, so you do not normally need to supply it.

#### Connector Mappings

1. Enter `https://app.shiftleft.io` in the **Location** field — the host is still the legacy ShiftLeft domain. DefectDojo appends the API path itself.
2. Enter the access token in the **Access Token** field.
3. Optionally, enter an **Organization ID** to override the organization. Leave it blank to use the organization encoded in the access token.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each application becomes a Record, carrying its SAST, SCA and secret findings together.

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

## **Red Hat Satellite**

The Red Hat Satellite connector imports **errata** from your Satellite inventory as findings. DefectDojo enumerates every host and folds the fleet into Records along one Katello dimension of your choosing.

**This is broader than "vulnerabilities."** Every applicable erratum on every host becomes a finding — that includes RHSA security advisories **and** bugfix and enhancement advisories. Use a **Minimum Severity** if you only want the security ones.

#### Prerequisites

A Satellite login with the **`view_hosts`** and **`view_content_views`** permissions. Satellite has no token endpoint, so the credentials are sent with every request over HTTP Basic authentication, and the password is never logged.

#### Connector Mappings

1. Enter your Satellite server URL in the **Location** field — for example `https://satellite.example.com`.
2. Enter the Satellite username in the **Username** field.
3. Enter the password in the **Password** field.
4. Optionally, set **Asset Grouping** to choose how hosts are folded into Records: `host-collection`, `lifecycle-environment`, `content-view`, or `host` for one Record per host. Leave it blank for `host-collection`.
5. Optionally, set **Skip TLS Verification** to `true` if your Satellite server uses the self\-signed certificate a default Satellite or Foreman install generates for itself. Leave it blank to verify certificates.
6. Optionally, set a **Minimum Severity** to limit which findings are imported.

Hosts that share a grouping value share a Record, and a new host joins the right Record automatically on the next Discover — so the mapping keeps up with your fleet without per\-host configuration.

## **runZero**

The runZero connector uses the runZero Export API to sync your whole organization's asset inventory into DefectDojo. It is primarily an **asset** connector: DefectDojo discovers every asset and creates a Record for each, grouped into an Organization by its runZero **site**. It can optionally also import runZero's vulnerabilities as findings.

#### Prerequisites

You will need an organization **Export Token** from runZero (Account → API), which is prefixed `XT`. The token is organization-scoped (the organization is encoded in the token), read-only, and is sent as a Bearer token — it is never logged. A community/starter tier is available.

#### Connector Mappings

1. Enter your runZero console URL in the **Location** field, for example `https://console.runzero.com`. The URL must be HTTPS.
2. Enter the Export Token in the **Secret** field.
3. Optionally set **Import Vulnerabilities** to `true` to also import runZero vulnerabilities as findings; leave it blank to sync assets only.
4. Optionally, set a **Minimum Severity** to limit which vulnerability findings are imported (applies only when vulnerabilities are imported).

DefectDojo maps each runZero **asset** to a Record (VEP): the display name comes from the asset's name or address, and its site, type, OS, addresses and tags are attached as attributes; the asset's **site** becomes its Organization. Assets are synced with a full export that DefectDojo reconciles (adds/removes). When **Import Vulnerabilities** is enabled, each runZero vulnerability becomes a finding on its asset — mapping the severity, CVSS score, CVE, affected service (`protocol://address:port`) endpoint and the remediation.

See the [runZero API documentation](https://help.runzero.com/) for more information.

## **Scantist**

The Scantist connector imports **SCA and SAST findings** from Scantist. DefectDojo creates a Record for each **project** on the account.

#### Prerequisites

A Scantist **API token**, generated in the Scantist UI under your account settings.

#### Connector Mappings

1. Enter `https://api.scantist.io` in the **Location** field.
2. Enter the API token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each project becomes a Record, and its findings come from that project's **most recent completed scan**.

## **Security Hub**

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

## **Semgrep**

This connector uses the Semgrep REST API to fetch data.

#### Connector Mappings

Enter `https://semgrep.dev/api/v1/` in the **Location** field.

1. Enter a valid API key in the **Secret** field. You can find this on the Tokens page:   
​  
"Settings" in the left navbar \> Tokens \> Create new token ([https://semgrep.dev/orgs/\-/settings/tokens 389 )

See [Semgrep documentation](https://semgrep.dev/docs/semgrep-cloud-platform/semgrep-api/#tag__badge-list) for more info.

## **ServiceNow CMDB**

The ServiceNow CMDB connector is an **Asset Connector**: instead of importing findings, it reads Configuration Items (CIs) from your ServiceNow Configuration Management Database and creates a DefectDojo Asset for each CI, grouped into Organizations by CI class. No findings are imported.

#### Prerequisites

You will need a ServiceNow instance and an account that can read the CMDB tables over the ServiceNow Table API. We recommend a dedicated, read-only service account for DefectDojo. The account needs read access to the `cmdb_ci` tables you want to import.

#### Connector Mappings

1. Enter your ServiceNow instance URL in the **Location** field: `https://{your-instance}.service-now.com`.
2. Select or create a ServiceNow **Tool Configuration** holding the instance credentials (the ServiceNow username and password).

Each Configuration Item becomes a Record named after the CI, grouped by its **CI class** (for example, application, server, or business service). Discovery and Sync reconcile the CI list: new CIs appear as `NEW` Records, and a CI removed from the CMDB is flagged `MISSING` on the next Sync so your team can triage it. DefectDojo never silently deletes an Asset.

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

1. Enter **[https://api.snyk.io/rest 394 ** or **[https://api.eu.snyk.io/rest 395 ** (for a regional EU deployment) in the **Location** field.
2. Enter a valid API key in the **Secret** field. API Tokens are found on a user's **[Account Settings](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)** [page](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token) in Snyk.

See the [Snyk API documentation](https://docs.snyk.io/snyk-api) for more info.

## **Socket**

The Socket connector uses the [Socket.dev](https://socket.dev) API to import **software supply-chain findings** — Socket's alerts on your dependencies (malware, typosquats, install scripts, known vulnerabilities and 70+ other categories). DefectDojo discovers every repository across the organizations your token can access and creates a Record for each, then imports the alerts from that repository's latest full scan.

#### Prerequisites

You will need a Socket **API token** — an organization token created in the Socket dashboard under **Settings → API Tokens** (with the `repo:list` and full-scan read scopes). The token is sent as a bearer token and is never logged.

#### Connector Mappings

1. Leave the **Location** field blank to use `https://api.socket.dev/v0`, or enter it explicitly.
2. Enter the Socket API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each **repository** to a Record and imports the alerts from its most recent full scan. Each alert becomes a finding: the severity comes from Socket's own rating (low, medium, high, critical), the affected package becomes the component and a PURL, the alert category (supply-chain risk, quality, maintenance, vulnerability, license) is recorded as tags, and the alert details are carried into the description. Findings are recorded as static findings and de-duplicated on Socket's alert key.

See the [Socket API documentation](https://docs.socket.dev/reference) for more information.

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
## **SOOS**

The SOOS connector imports **SCA findings** from SOOS. DefectDojo creates a Record for each **project** on the account.

#### Prerequisites

**Two credentials — neither works on its own:**

* Your **Client ID**, which forms part of every request path.
* Your **API Key**, sent as a request header.

Both are found under **SOOS \> Integrations**.

#### Connector Mappings

1. Enter `https://api.soos.io/api/` in the **Location** field.
2. Enter your SOOS **Client ID**.
3. Enter your SOOS **API Key**.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each project becomes a Record, carrying its scanned dependencies' vulnerabilities.

## **Sysdig Secure**

The Sysdig Secure connector imports **container / CNAPP vulnerability findings** from Sysdig Secure's vulnerability management API. It syncs the whole account across the configured scope(s) and creates a DefectDojo product for each scanned asset grouping.

#### Prerequisites

A Sysdig Secure **API token**: in Sysdig Secure, go to **Settings \> Sysdig Secure API Token** and copy the token. You also need your Sysdig **region URL** (for example `https://us2.app.sysdig.com`, `https://eu1.app.sysdig.com`, or your on\-premises host).

#### Connector Mappings

1. Enter your Sysdig region/base URL in the **Location** field.
2. Enter the API token in the **Secret** field.
3. Optionally set **Scopes** — a comma\-separated list of `runtime`, `registry`, and/or `pipeline` (leave blank for `runtime`, the deployed\-workload scope).
4. Optionally set **Runtime Asset Grouping** — how runtime results map to Assets: `cluster`, `namespace`, `workload`, or `image` (leave blank for `namespace`). Registry and pipeline results always group by image repository.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset grouping becomes a Record. For each scan result the connector imports every vulnerable package as a finding. **Runtime** findings (deployed workloads) are recorded as dynamic findings and tagged with their Kubernetes cluster / namespace / workload / container context; **registry** and **pipeline** findings are recorded as static image\-scan findings. Sysdig's `NEGLIGIBLE` severity maps to Info.

## **Tenable.io**

The Tenable connector uses the **Tenable.io** REST API to fetch data.  Scans are pulled from the Tenable VM `/scans` endpoint.

On\-premise Tenable Connectors are not available at this time.

#### **Connector Mappings**

1. Enter <https://cloud.tenable.com> in the Location field.
2. Enter a valid **API key** in the Secret field.

See [Tenable's API Documentation](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm) for more info.

## **Tenable Web App Scanning**

The Tenable Web App Scanning connector imports **web application (DAST) findings** from Tenable Web App Scanning. It is a separate connector from Tenable (Vulnerability Management): the two Assets cover different assets and are configured independently, so you can use either or both.

DefectDojo creates a Record for each **scanned web application**. Applications are discovered from your Web App Scanning scan configurations; a configuration that has never run does not produce a Record until its first scan completes. When more than one configuration scans the same application, they share a single Record.

#### Prerequisites

Tenable **API keys** (an access key and a secret key) for a user with Web App Scanning permissions. In Tenable, go to **My Account \> API Keys** to generate them, and confirm the user can view the scans you want to import — keys limited to Vulnerability Management cannot read Web App Scanning data.

On\-premise Tenable connectors are not available at this time.

#### Connector Mappings

1. Enter <https://cloud.tenable.com> in the **Location** field.
2. Enter your **Access Key** and **Secret Key**.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Findings are imported with the severity Tenable reports for your account, including any severity your team has recast. Each finding carries the affected URL as an endpoint, the request parameter and payload that triggered it, and Tenable's proof and output as steps to reproduce, along with CWE, CVE, CVSS and EPSS values where the detecting plugin supplies them.

Only findings that are currently open or reopened are imported. A finding Tenable has marked fixed is closed in DefectDojo on the next sync.

## **TruffleHog**

The TruffleHog connector imports **secret detections** from TruffleHog Enterprise. DefectDojo creates a Record for each configured **scan source** — a repository, bucket or registry — and that source's detections become its findings. No per\-source configuration is required.

**Secret handling.** Findings carry only the **redacted** secret as TruffleHog reports it. Raw secret material is read solely to compute the deduplication digest, and never reaches a finding field, a log line, or an error message. Response bodies are never logged, even with debug logging enabled, so a debug session cannot leak secret material.

**Not to be confused with `trufflehog3`.** The separate `trufflehog3` parser in the supported tools list is a different tool with a different report format — it is not this connector's file equivalent.

#### Prerequisites

A TruffleHog **Enterprise** API token, sent as a bearer token.

#### Connector Mappings

1. Enter your TruffleHog Enterprise API host in the **Location** field.
2. Enter the Enterprise API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each configured scan source becomes a Record.

## **Trustwave Fusion**

The Trustwave Fusion connector imports findings from the Trustwave Fusion platform. DefectDojo creates a Record for each **asset**, derived from the findings themselves.

#### Prerequisites

A Trustwave Fusion **API token** for the tenant whose findings you want to import.

#### Connector Mappings

1. Enter your Trustwave Fusion API URL in the **Location** field.
2. Enter the API token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset referenced by your findings becomes a Record, grouped by the asset the finding was reported against.

## **Uptycs**

The Uptycs connector imports **vulnerability findings** from your Uptycs tenant. DefectDojo creates a Record for each **asset group**.

#### Prerequisites

Three values from Uptycs:

* Your **customer ID**, shown in the API key file.
* An **API key ID**, from **Configuration \> User \> API Keys**.
* The matching **API secret**, which DefectDojo uses to sign a per\-request token. It is never logged.

#### Connector Mappings

1. Enter your Uptycs stack URL in the **Location** field — for example `https://your-stack.uptycs.io`.
2. Enter the customer ID in the **Customer ID** field.
3. Enter the API key ID in the **Key** field.
4. Enter the API secret in the **Secret** field.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset group becomes a Record. Uptycs vulnerabilities are read through its osquery-style query engine, so the imported finding set is whatever that query returns for your tenant.

## **Vanta**

The Vanta connector imports **failing compliance tests** from Vanta. DefectDojo creates a Record for each Vanta **integration**, plus an organization\-wide catch\-all for tests that belong to none.

#### Prerequisites

An OAuth **client ID and secret** from Vanta. Create them under **Settings \> Developer Console** as a **"Manage Vanta"** app — other app types will not have the access this connector needs.

#### Connector Mappings

1. Enter your Vanta API URL in the **Location** field.
2. Enter the OAuth client ID in the **Client ID** field.
3. Enter the client secret in the **Client Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each **failing resource of a failing test** becomes a finding, grouped under the integration the test belongs to — so a single failing control across many resources produces a finding per resource.

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

## **Vulnerability Manager Plus**

The Vulnerability Manager Plus connector imports **endpoint vulnerability findings** from ManageEngine Vulnerability Manager Plus. DefectDojo creates a Record for each **host**.

#### Prerequisites

A Vulnerability Manager Plus **API token**, from **Admin \> API key generation**. It is never logged.

#### Connector Mappings

1. Enter your Vulnerability Manager Plus server URL in the **Location** field.
2. Enter the API token in the **Auth Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each host becomes a Record, carrying the vulnerabilities detected on it.

## **Wallarm**

The Wallarm connector imports **API security findings** from Wallarm. DefectDojo creates a Record for each **affected domain**.

#### Prerequisites

A Wallarm **API token**, from **Console \> Settings \> API tokens**. A **Read Only** role is sufficient, and the token is never logged.

#### Connector Mappings

1. Enter your Wallarm cloud URL in the **Location** field — `https://api.wallarm.com` for the EU cloud or `https://us1.api.wallarm.com` for the US cloud.
2. Enter the API token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each affected domain becomes a Record, carrying the account's API security vulnerabilities that affect it.

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

## **WebInspect Enterprise**

The WebInspect Enterprise connector imports **DAST findings** from a WebInspect Enterprise (WIE) server. DefectDojo creates a Record for each **application** the token can see.

#### Prerequisites

A WebInspect Enterprise **API token**. WIE accepts a Fortify\-style API token, and it is never logged.

#### Connector Mappings

1. Enter your WebInspect Enterprise server URL in the **Location** field.
2. Enter the API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each application becomes a Record, and its findings come from that application's **most recent completed scan**.

## Wiz

Using the Wiz connector requires you to create a service account: see the [Wiz documentation](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) for more info.  You will need a Wiz account to access the documentation.

The service account must meet all of the following requirements. A service account that misses one of them can still authenticate successfully but will import nothing:

* **Type**: Custom Integration (GraphQL API).
* **API scopes**: at minimum `read:projects`, `read:issues`, and `read:vulnerabilities`.
* **Project visibility**: the service account must be scoped to every Wiz Project you want imported (or to all Projects). The connector discovers your Wiz Projects first and then pulls each Project's findings — an account that can read issues but has no Project visibility discovers zero Projects, so there is nothing to import and no error is reported by either side.

#### **Connector Mappings**

1. Enter your Wiz Client ID in the Client ID field.
2. Enter the Wiz Client Secret in the Secret field.

## **YesWeHack**

The YesWeHack connector uses the YesWeHack REST API to import reports from your bug bounty and vulnerability disclosure programs. DefectDojo creates a Record for each program your token can access and imports its reports as findings.

#### Prerequisites

You will need a YesWeHack **Personal Access Token (PAT)**. Read access to your programs is sufficient. Some accounts require TOTP/MFA when creating a token; once created, the token value itself is what the connector uses.

1. In YesWeHack, open your account settings and go to **API / Personal Access Tokens**.
2. Create a token and copy its value. It is only shown once.

#### Connector Mappings

1. Enter `https://api.yeswehack.com/` in the **Location** field.
2. Enter your Personal Access Token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity will not be imported.

DefectDojo creates a separate Record for each program your token can access, and imports each report as a finding. The finding's severity is taken from the report's CVSS rating (falling back to the triage priority), and its status reflects the report's workflow state — for example, resolved reports are imported as mitigated, and reports marked invalid or out of scope are imported as inactive.

## **Zimperium**

The Zimperium connector imports **mobile application security findings** from Zimperium zScan. DefectDojo creates a Record for each zScan **mobile app**.

#### Prerequisites

A zScan **client ID and secret**, issued from **zConsole \> Account Management \> Authorizations** (the `ZSCAN_CLIENT_ID` and `ZSCAN_CLIENT_SECRET` values). DefectDojo exchanges them for a bearer token on each Sync; the secret is never logged.

#### Connector Mappings

1. Enter your **zConsole** host in the **Location** field.
2. Enter the client ID in the **Client ID** field.
3. Enter the client secret in the **Client Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each zScan mobile app becomes a Record, carrying the findings of that app's **latest completed assessment**.

## **Zora**

The Zora connector imports **Kubernetes cluster findings** from Zora. DefectDojo creates a Record for each **scanned cluster**.

Zora is a multi\-cluster manager, so DefectDojo reads the Zora resources in your **management cluster** and maps each cluster Zora scans to its own Record.

#### Prerequisites

A **kubeconfig** granting read access to the **management cluster** where the Zora Operator writes its results.

Unlike most connectors, this one does not use an API token — Zora exposes no REST API, and its results live only as Kubernetes resources, so DefectDojo reads them directly from the cluster.

#### Connector Mappings

1. Provide the kubeconfig for the management cluster.
2. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each scanned cluster becomes a Record, carrying the issues and vulnerability reports Zora recorded for it.
