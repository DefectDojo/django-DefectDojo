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

## **GitLab**

The GitLab connector is an **Asset Connector**: it enumerates every project (repository) your token can access and creates a DefectDojo Asset for each one, grouped into Organizations by GitLab namespace (group or user). No findings are imported.

#### Prerequisites

You will need a Personal Access Token with the **read_api** scope. We recommend creating the token from a dedicated service account; the connector lists the projects that account is a member of.

#### Connector Mappings

1. Enter your GitLab URL in the **Location** field: `https://gitlab.com`, or the base URL of your self-hosted instance.
2. Enter the Personal Access Token in the **Secret** field.

Each project becomes a Record named after the project, grouped by its **namespace**. Projects that are pending deletion in GitLab (deleted by a user, but not yet purged by GitLab's background job) are excluded automatically, so deleting a project flags its Record as `MISSING` on the next Sync instead of leaving behind a renamed ghost asset.

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

## Wiz

Using the Wiz connector requires you to create a service account: see the [Wiz documentation](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) for more info.  You will need a Wiz account to access the documentation.

#### **Connector Mappings**

1. Enter your Wiz Client ID in the Client ID field.
2. Enter the Wiz Client Secret in the Secret field.
