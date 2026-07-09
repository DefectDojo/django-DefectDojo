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

## **BurpSuite**

DefectDojo’s Burp connector calls Burp’s GraphQL API to fetch data. 

#### Prerequisites

Before you can set up this connector, you will need an API key from a Burp Service Account. Burp user accounts don’t have API keys by default, so you may need to create a new user specifically for this purpose. 

See [Burp Documentation](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user) for a guide on setting up a Service Account user with an API key.

#### Connector Mappings

1. Enter Burp’s root URL in the **Location** field: this is the URL where you access the Burp tool.
2. Enter a valid API Key in the Secret field. This is the API key associated with your Burp Service account.

See the official [Burp documentation](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html) for more information on the Burp API.

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

## Tenable

The Tenable connector uses the **Tenable.io** REST API to fetch data.  Scans are pulled from the Tenable VM `/scans` endpoint.

On\-premise Tenable Connectors are not available at this time.

#### **Connector Mappings**

1. Enter <https://cloud.tenable.com> in the Location field.
2. Enter a valid **API key** in the Secret field.

See [Tenable's API Documentation](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm) for more info.

## Wiz

Using the Wiz connector requires you to create a service account: see the [Wiz documentation](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) for more info.  You will need a Wiz account to access the documentation.

#### **Connector Mappings**

1. Enter your Wiz Client ID in the Client ID field.
2. Enter the Wiz Client Secret in the Secret field.
