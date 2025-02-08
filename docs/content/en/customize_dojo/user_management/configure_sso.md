---
title: "SSO Configuration (OAuth, SAML)"
description: "Sign in to DefectDojo using OAuth or SAML login options"
pro-feature: true
---

Users can connect to DefectDojo with a Username and Password, but if you prefer, you can allow users to authenticate using a Single Sign\-On or SSO method. You can set up DefectDojo to work with your own SAML Identity Provider, but we also support many OAuth methods for authentication:

* **[Auth0](./#auth0-setup)**
* **[Azure Active Directory (Azure AD)](./#azure-active-directory-setup)**
* **[GitHub Enterprise](./#github-enterprise)**
* **[GitLab](./#gitlab)**
* **[Google](./#google-auth)**
* **[KeyCloak](./#keycloak)**
* **[Okta](./#okta)**

All of these methods can only be configured by a Superuser in DefectDojo.  DefectDojo Pro users can quickly set up SSO through their system settings, while Open Source users will need to configure these settings on the back-end via the local_settings.py file.  This article covers both methods of configuration.

## Disable username / password use
You may wish to disable traditional username/password login on your instance.  

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users can uncheck the "Allow Login via Username and Password" box on the Login Settings form: **Enterprise Settings > Login Settings**.

[image](images/pro_login_settings.png)

Open-Source users can set environment variables in local_settings.py to disable the Login form:

```yaml
DD_SOCIAL_LOGIN_AUTO_REDIRECT: "true"
DD_SOCIAL_AUTH_SHOW_LOGIN_FORM: "false"
```

### ⚠️ Login Fallback
In case your OAuth or SAML integration stops working, you can always return to the standard login method by adding the following to your DefectDojo URL:

- `your-instance.cloud.defectdojo.com` + `/login?force_login_form`

We recommend having at least one DefectDojo admin set up with a username and password as a fallback.
​
## Auth0 Setup

Both <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> and Open-Source users will need to complete these steps to create an integration:

1.  Inside your Auth0 dashboard, create a new application (Applications /
    Create Application / Single Page Web Application).

2.  On the new application set the following fields:

    -   Name: "Defectdojo"
    -   Allowed Callback URLs:
        `https://your-instance.cloud.defectdojo.com/complete/auth0/`

3.  Copy the following info from the application:
    -   Domain
    -   Client ID
    -   Client Secret

### Pro Configuration

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users can set up this integration from the OAuth Settings page, which is nested under **Enterprise Settings**.

1. In DefectDojo's OAuth Settings page, select Auth0, and use these values from Auth0 to complete the form:
    - **Auth0 OAuth Key**: enter your **Client ID**
    - **Auth0 OAuth Secret**: enter your **Client Secret**
    - **Auth0 Domain**: enter your **Domain**.

2. Check the box for 'Enable Auth0 OAuth' to add the "Login With Auth0" button to the DefectDojo login page.

### Open-Source

Open-Source users will need to map these variables in the local_settings.py file. (see [Configuration](../../os_getting_started/configuration)).

1. Fill out the variables as follows:
    {{< highlight python >}}
    DD_SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED=True
    DD_SOCIAL_AUTH_AUTH0_KEY=(str, '**YOUR_CLIENT_ID_FROM_STEP_ABOVE**'),
    DD_SOCIAL_AUTH_AUTH0_SECRET=(str,'**YOUR_CLIENT_SECRET_FROM_STEP_ABOVE**'),
    DD_SOCIAL_AUTH_AUTH0_DOMAIN=(str, '**YOUR_AUTH0_DOMAIN_FROM_STEP_ABOVE**'),
    {{< /highlight >}}

2.  Restart DefectDojo, and you should now see a **Login with Auth0**
    button on the login page.

## Azure Active Directory Setup

Users can log in to DefectDojo via Azure AD.  DefectDojo can leverage Azure AD Groups to automatically import User Group membership.

Both <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> and Open-Source users will need to complete these steps to create an integration:

1.  Navigate to the following address and follow instructions to create
    a new app registration

    -   <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app>

2.  Once you register an app, take note of the following information:

    -   **Application (client) ID**
    -   **Directory (tenant) ID**
    -   Under Certificates & Secrets, create a new **Client Secret**
    -   **Application ID URI**

3.  Under Authentication > Redirect URIs, add a *WEB* type of uri where
    the redirect points to:
    `https://your-instance.cloud.defectdojo.com/complete/azuread-tenant-oauth2/`

### Pro Configuration

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users can set up this integration from the OAuth Settings page, which is nested under **Enterprise Settings**.

1. In DefectDojo's OAuth Settings page, select Azure AD, and use these values from Azure to complete the form:
    - **Azure AD OAuth Key**: enter your **Application (client) ID**
    - **Azure AD OAuth Secret**: enter the **Client Secret** which was created in step 2
    - **Azure AD Resource**: **by default this should be set to `https://graph.microsoft.com/`**.  This should be set a the URI which DefectDojo can use to pull additional info (such as Azure AD Group names) from the [web API](https://docs.azure.cn/en-us/entra/identity-platform/security-best-practices-for-app-registration#application-id-uri).  This field only needs to be changed if your Group Names are stored on a different API resource from the Microsoft Graph Web API.
    - **Azure AD Tenant ID**: enter the **Directory (tenant) ID**
    - **Azure AD Groups Filter**: here, you can enter a regex string to restrict the User Groups you wish to import.

2. Check the **Enable Azure AD OAuth** box.  Submit the form, and `Login With Azure AD` will be added as an option to the Login menu.

#### Pro Azure Group Mapping

Group synchronization allows you to import [User Group](../create_user_group/) membership from Azure AD.  DefectDojo's User Groups govern the Products and Product Types a given user can access via [RBAC](../set_user_permissions/).

To import groups from Azure AD users, you can check the **Enable Azure AD OAuth Grouping** box on the form.  All User Groups found in Azure will be matched with an existing User Group in DefectDojo.  If an imported Azure User Group is missing from DefectDojo, a new User Group will be created automatically.

If you only want to import a subset of Groups from Azure, you can use regex in the Azure AD Groups Filter field.  For example, `'^team-.*'` and `'teamA|teamB|groupC'` are regex strings that can be used to restrict the Groups that will be imported to DefectDojo.  Regex is used to filter out Group Names.

##### Sending Groups from Azure AD

The Azure AD token need to be configured to include Group IDs. Without this step, the token will not contain any notion of a Group, so users will not be mapped correctly in DefectDojo.

To update the format of the token, add a [Group Claim](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims) that applies to whatever Group type you are using.
If unsure of what type that is, select `All Groups`. Do not activate `Emit groups as role claims` within the Azure AD "Token configuration" page.

Application API permissions need to be updated with the `Group.Read.All` permission so that groups can be read on behalf of the user that has successfully signed in.

##### Group Cleaning

If **Enable Azure AD OAuth Group Cleaning** is enabled, groups created by Azure AD in DefectDojo will be automatically removed if they contain no users. Otherwise, Azure-created Groups will be left as-is, even without assigned Users.

When a user is removed from a given group in Azure AD, they will also be removed from the corresponding group in DefectDojo.

### Open-Source

Open-Source users will need to map these variables in the local_settings.py file. (see [Configuration](../../os_getting_started/configuration)).

1.  Add the following information to the settings file:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY=(str, 'YOUR_APPLICATION_ID_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET=(str, 'YOUR_CLIENT_SECRET_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID=(str, 'YOUR_DIRECTORY_ID_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_ENABLED = True
    {{< /highlight >}}

2.  Restart DefectDojo, and you should now see a **Login with Azure AD** button on the login page.

#### Open-Source Azure Group Mapping
To import groups from Azure AD users, the following environment variable needs to be set:  

    {{< highlight python >}}
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GET_GROUPS=True
    {{< /highlight >}}

This will ensure the user is added to all the groups found in the Azure AD Token. Any missing groups will be created in DefectDojo (unless filtered). This group synchronization allows for product access via groups to limit the products a user can interact with.

The Azure AD token returned by Azure will also need to be configured to include group IDs. Without this step, the token will not contain any notion of a group, and the mapping process will report that the current user is not a member of any groups. To update the format of the token, add a group claim that applies to whatever group type you are using.

If unsure of what type that is, select `All Groups`. Do not activate `Emit groups as role claims` within the Azure AD "Token configuration" page.

Application API permissions need to be updated with the `Group.Read.All` permission so that groups can be read on behalf of the user that has successfully signed in.

To limit the amount of groups imported from Azure AD, a regular expression can be used as the following:
    
    {{< highlight python >}}
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GROUPS_FILTER='^team-.*' # or 'teamA|teamB|groupC'
    {{< /highlight >}}

##### Automatic Cleanup of User-Groups

To prevent authorization creep, old Azure AD groups a user is not having anymore can be deleted with the following environment parameter:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS=True
    {{< /highlight >}}

When a user is removed from a given group in Azure AD, they will also be removed from the corresponding group in DefectDojo.
If there is a group in DefectDojo, that no longer has any members, it will be left as is for record purposes.

## GitHub Enterprise

Both <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> and Open-Source users will need to complete these steps to create an integration:

1.  Navigate to your GitHub Enterprise Server and follow instructions to create a new OAuth App [https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app](https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app)

2. Choose a name for your application, e.g. "DefectDojo".

3. For the Redirect URI, enter the DefectDojo URL with the following
    format
    -   `https://the_hostname_you_have_dojo_deployed:your_server_port/complete/github-enterprise/`

### Pro Configuration

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users can set up this integration from the OAuth Settings page, which is nested under **Enterprise Settings**.

1. In DefectDojo's OAuth Settings page, select GitHub Enterprise, and use these values from GitHub to complete the form:

    - **GitHub Enterprise OAuth Key**: enter your GitHub Enterprise OAuth App Client ID
    - **GitHub Enterprise OAuth Secret**: enter your GitHub Enterprise Client Secret
    - **GitHub Enterprise URL**: enter the GitHub URL for your organization, likely `https://github.<your_company>.com/`
    - **GitHub Enterprise API URL**: enter the URL for your organization's GitHub API (e.g. `https://github.<your_company>.com/api/v3/`)
    
2. Check off the box for 'Enable GitHub Enterprise OAuth'.  Submit the form, and 'Login With GitHub' should now be visible on the login page.

### Open-Source

Open-Source users will need to map these variables in the local_settings.py file. (see [Configuration](../../os_getting_started/configuration)).

1. Add the following variables to your `local_settings.py` file:
    {{< highlight python >}}  
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_KEY=(str, 'GitHub Enterprise OAuth App Client ID'),  
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_SECRET=(str, 'GitHub Enterprise OAuth App Client Secret'),  
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_URL=(str, 'https://github.<your_company>.com/'),  
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_API_URL=(str, 'https://github.<your_company>.com/api/v3/'),  
    DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_OAUTH2_ENABLED = True,  
    {{< /highlight >}}

2. Restart DefectDojo, and you should now see a **Login with GitHub Enterprise**
    button on the login page.  

## GitLab

In a similar fashion to that of Google and Okta, using GitLab as a
OAuth2 provider carries the same attributes and a similar procedure.
Follow along below.

1. Navigate to your GitLab settings page and got to the Applications
    section

    -   <https://gitlab.com/profile/applications>
    -   **OR**
    -   **https://the_hostname_you_have_gitlab_deployed:your_gitlab_port/profile/applications**

2. Choose a name for your application, "DefectDojo" for example.

3. For the Redirect URI, enter your DefectDojo URL as follows:
    -   **https://your-dojo-instance.cloud.defectdojo.com/complete/gitlab/**

### Pro Configuration

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users can set up this integration from the OAuth Settings page, which is nested under **Enterprise Settings**.

1. In DefectDojo's OAuth Settings page, select GitLab, and use these values from GitLab to complete the form:

    - **GitLab OAuth Key**: enter your Application ID from GitLab
    - **GitLab OAuth Secret**: enter the Secret from GitLab
    - **GitLab API URL**: enter the URL for your GitLab deployment (e.g. `https://gitlab.com`)

2. Check the 'Enable GitLab OAuth' box, and submit the form. `Login With GitLab` will be added as an option to the Login menu.

### Open-Source

Open-Source users will need to map these variables in the local_settings.py file. (see [Configuration](../../os_getting_started/configuration)).

1. Add the following variables to your `local_settings.py` file:
    {{< highlight python >}}
    DD_SOCIAL_AUTH_GITLAB_KEY=(str, 'YOUR_APPLICATION_ID_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_GITLAB_SECRET=(str, 'YOUR_SECRET_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_GITLAB_API_URL=(str, 'https://gitlab.com'),
    DD_SOCIAL_AUTH_GITLAB_OAUTH2_ENABLED = True
    {{< /highlight >}}

    Additionally, if you want to import your Gitlab projects as DefectDojo
    products, add the following line to your settings:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GITLAB_PROJECT_AUTO_IMPORT = True
    {{< /highlight >}}

    **Important:** if you enable this setting on already working instance with a GitLab integrations, it will require new grant "read_repository" by user
 
2. Restart DefectDojo, and you should now see a **Login with Gitlab** button on the login page.

## Google Auth

Google accounts can be used for user creation and login.

Upon login with a Google account, a new user will be created if one does not already exist.  Existing DefectDojo users will be matched to Google accounts based on their Google username (the name prior to the @ symbol on their Google Account).

In order to use Google Authentication, a Google Authentication Server will need to be set up.  Both <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> and Open-Source users will need to complete these steps to create an integration:

1.  Navigate to the following address and either create a new account,
    or login with an existing one: [Google Developers
    Console](https://console.developers.google.com)

2.  Once logged in, find the key shaped button labeled **Credentials**
    on the left side of the screen. Click **Create Credentials**, and
    choose **OAuth Client ID**:

    ![image](images/google_1.png)

3.  Select **Web Applications**, and provide a descriptive name for the
    client (such as "DefectDojo").

4.  Enter `https://your-instance.cloud.defectdojo.com/complete/google-oauth2/` in the **Authorized Redirect URLs** section.

5. Now with the authentication client created, note the **Client ID** and
   **Client Secret Key**.

### Pro Configuration

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users can set up this integration from the OAuth Settings page, which is nested under **Enterprise Settings**.

1. In DefectDojo's OAuth Settings page, select Google, and use these values to complete the form:
    - **Google OAuth Key** should be set to your **Client ID**.
    - **Google OAuth Secret** should be set to your **Client Secret Key**.
    - **Whitelisted Domains** can be set to the domain name used by your organization.  However, this will allow login from any user with this domain name in their Google email address.
    - Alternatively, if you only want to allow specific Google email addresses to log in to DefectDojo, you can enter those in the **Whitelisted E-mail Addresses** section of the form. `(appsecuser1@xyz.com,appsecuser2@xyz.com)`, etc.

2. Check the **Enable Azure AD OAuth** box.  Submit the form, and `Login With Google` will be added as an option to the Login menu.

### Open-Source

Open-Source users will need to map these variables in the local_settings.py file. (see [Configuration](../../os_getting_started/configuration)).

1. Add the following variables to your `local_settings.py` file:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_ENABLED=True,
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_KEY=(str, '**YOUR_CLIENT_ID_FROM_STEP_ABOVE**'),
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET=(str, '**YOUR_CLIENT_SECRET_FROM_STEP_ABOVE**'),
    {{< /highlight >}}

   To authorize users you will need to set the following:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS = ['example.com', 'example.org']
    {{< /highlight >}}

    As an environment variable: 

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS = example.com,example.org
    {{< /highlight >}}

    or

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS = ['<email@example.com>']
    {{< /highlight >}}

    As an environment variable: 

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS = email@example.com,email2@example.com
    {{< /highlight >}}

2. Restart DefectDojo, and `Login With Google` will be added as an option to the Login menu.

## KeyCloak

Both <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> and Open-Source users will need to complete these steps to create an integration:

This guide assumes you already have a KeyCloak Realm set up.  If not, you will need to create one: see [KeyCloak Documentation](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_admin/topics/realms/create.html).

1. Navigate to your keycloak realm and add a new client of type openid-connect. Choose a name for the client id.

2. In the client settings:
   * Set `access type` to `confidential`
   * Under `valid Redirect URIs`, add the URI to your DefectDojo installation, e.g.`https://yourorganization.cloud.defectdojo.com` or `https://<YOUR_DD_HOST>/*`
   * Under `web origins`, add the same (or '+')
   * Under `Fine grained openID connect configuration` -> `user info signed response algorithm`: set to `RS256`
   * Under `Fine grained openID connect configuration` -> `request object signature algorithm`: set to `RS256`
   * -> save these settings in keycloak (hit save button)

3. Under `Scope` -> `Full Scope Allowed` set to `off`.

4. Under `mappers` -> add a custom mapper here: 
   * Name: `aud`
   * Mapper type: `audience`
   * Included audience: select your client/client-id here
   * Add ID to token: `off`
   * Add access to token: `on`

5. Under `credentials`: copy the value of the secret.

6. In your realm settings -> keys: copy the "Public Key" (signing key).

7. In your realm settings -> general -> endpoints: look into openId endpoint configuration and copy the values of your Authorization and Token endpoints.

### Pro Configuration

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users can set up this integration from the OAuth Settings page, which is nested under **Enterprise Settings**.

1. In DefectDojo's OAuth Settings page, select KeyCloak, and use these values to complete the form:
    - **KeyCloak OAuth Key**: Enter your client name (from step 1)
    - **KeyCloak OAuth Secret**: Enter the your client credentials secret (from step 5)
    - **KeyCloak Public Key**: Enter the Public Key from your realm settings (from step 6)
    - **KeyCloak Resource**: Enter the Authorization Endpoint URL (from step 7)
    - **KeyCloak Group Limiter**: Enter the Token Endpoint URL (from step 7)
    - **KeyCloak OAuth Login Button Text** Choose the text you want to use for the DefectDojo login button.

2. Check the 'Enable KeyCloak OAuth' button, and submit the form.  A login button should now be visible on the login page with the text you have set.

### Open-Source

Edit the local_settings.py file (see [Configuration](../../os_getting_started/configuration)) with the following information:

1.    {{< highlight python >}}
   DD_SESSION_COOKIE_SECURE=True,
   DD_CSRF_COOKIE_SECURE=True,
   DD_SECURE_SSL_REDIRECT=True,
   DD_SOCIAL_AUTH_KEYCLOAK_OAUTH2_ENABLED=True,
   DD_SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY=(str, '<your realm public key>'),
   DD_SOCIAL_AUTH_KEYCLOAK_KEY=(str, '<your client id>'), 
   DD_SOCIAL_AUTH_KEYCLOAK_SECRET=(str, '<your keycloak client credentials secret>'), 
   DD_SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL=(str, '<your authorization endpoint>'),
   DD_SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL=(str, '<your token endpoint>')         
   {{< /highlight >}}
 
or, alternatively, for helm configuration, add this to the `extraConfig` section: 

```yaml
DD_SESSION_COOKIE_SECURE: 'True'
DD_CSRF_COOKIE_SECURE: 'True'
DD_SECURE_SSL_REDIRECT: 'True'
DD_SOCIAL_AUTH_KEYCLOAK_OAUTH2_ENABLED: 'True'
DD_SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY: '<your realm public key>'
DD_SOCIAL_AUTH_KEYCLOAK_KEY: '<your client id>'
DD_SOCIAL_AUTH_KEYCLOAK_SECRET: '<your keycloak client credentials secret>'
DD_SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL: '<your authorization endpoint>'
DD_SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL: '<your token endpoint>'
```

Optionally, you *can* set `DD_SOCIAL_AUTH_KEYCLOAK_LOGIN_BUTTON_TEXT` in order to customize the login button's text caption. 

2. Restart DefectDojo, and `Login With ____` (your login button text) will be added as an option to the Login menu.

## Okta

In a similar fashion to that of Google, using Okta as a OAuth2 provider
carries the same attributes and a similar procedure.

Both <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> and Open-Source users will need to complete these steps to create an integration:

1.  Navigate to the following address and either create a new account,
    or login with an existing one: [Okta Account
    Creation](https://www.okta.com/developer/signup/)
    
2.  Once logged in, enter the **Applications** and click **Add
    Application**:

    ![image](images/okta_1.png)

3.  Select **Web Applications**.

    ![image](images/okta_2.png)

4.  Add the pictured URLs in the **Login Redirect URLs** section. This
    part is very important. If there are any mistakes here, the
    authentication client will not authorize the request, and deny
    access. Check the **Implicit** box as well.

    ![image](images/okta_3.png)

5.  Once all URLs are added, finish by clicking **Done**.

6.  Return to the **Dashboard** to find the **Org-URL**. Note this value
    as it will be important when configuring DefectDojo.

    ![image](images/okta_4.png)

7.  Now, with the authentication client created, the **Client ID** and
    **Client Secret** Key need to be copied over to the settings.
    Click the newly created client and copy the values:

    ![image](images/okta_5.png)

### Pro Configuration

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users can set up this integration from the OAuth Settings page, which is nested under **Enterprise Settings**.

1. In DefectDojo's OAuth Settings page, select Okta, and use these values to complete the form:
    - **Okta OAuth Key**: set this to your Client ID from step 7 above.
    - **Okta OAuth Secret**: set this to your Client Secret from step 7 above.
    - **Okta Tenant ID**: set this to your Okta Org-URL: `https://{your-org-url}/oauth2` for example
    -

2. Check the 'Enable Okta OAuth' button, and submit the form.  A 'Login With Okta' button should now be visible on the DefectDojo login screen.

### Open-Source

1. Edit the local_settings.py file (see [Configuration](../../os_getting_started/configuration)) with the following:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_OKTA_OAUTH2_ENABLED=True,
    DD_SOCIAL_AUTH_OKTA_OAUTH2_KEY=(str, '**YOUR_CLIENT_ID_FROM_STEP_ABOVE**'),
    DD_SOCIAL_AUTH_OKTA_OAUTH2_SECRET=(str, '**YOUR_CLIENT_SECRET_FROM_STEP_ABOVE**'),
    DD_SOCIAL_AUTH_OKTA_OAUTH2_API_URL=(str, 'https://{your-org-url}/oauth2'),
    {{< /highlight >}}

If during the login process you get the following error: *The
'redirect_uri' parameter must be an absolute URI that is whitelisted
in the client app settings.* and the `redirect_uri` HTTP
GET parameter starts with `http://` instead of
`https://` you need to add
`SOCIAL_AUTH_REDIRECT_IS_HTTPS = True` in your local_settings.py file.

2. Restart DefectDojo, and 'Login With Okta' should appear on the login screen.

## SAML Configuration

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users can follow this guide to set up a SAML configuration using the DefectDojo UI. Open-Source users can set up SAML via environment variables, using the following [guide](./#open-source-saml).

1. Open the SAML Settings page to view the SAML form.  This page is located under the **Enterprise Settings** option on the sidebar.

![image](images/sso_betaui_1.png)

2. Complete the SAML form. Start by setting an **Entity ID** \- this is either a label or a URL which your SAML Identity Provider can point to, and use to identify DefectDojo. This is a required field.  
​
3. If you wish, set **Login Button Text** in DefectDojo. This text will appear on the button or link users click to initiate the login process.  
​
4. You can also set a **Logout URL** to redirect your users to once they have logged out of DefectDojo.  
​
5. The **Name ID Format** has four options: Persistent, Transient, Entity and Encrypted.  
​   
    - If you would prefer that users have a different SAML ID each time they access   
    DefectDojo, choose **Transient**.   
    - If you want your users to be consistently identified by SAML, use **Persistent.**   
    - If you’re ok with all of your users sharing a SAML NameID, you can select **Entity.**   
    - If you would like to encrypt each user’s NameID, you can use **Encrypted** as your NameID format.
​
6. **Required Attributes** are the attributes that DefectDojo requires from the SAML response.  
​
7. **Attribute Mapping** contains a formula for how you want these attributes to be matched to a user. For example, if your SAML response returns an email, you can associate it with a DefectDojo user with the formula **email=email**.  
​  
The left side of the ‘=’ sign represents the attribute you want to map from the SAML response. The right side is a user’s field in DefectDojo, which you want this attribute to map to.
​
8. **Remote SAML Metadata** is the URL where your SAML Identity Provider is located.  
​
9. Finally, check the **Enable SAML** checkbox at the bottom of this form to confirm that you want to use SAML to log in. Once this is enabled, you will see the **Login With SAML** button on the DefectDojo Login Page.

![image](images/sso_saml_login.png)

#### Additional SAML Options

* **Create Unknown User** allows you to decide whether or not to automatically create a new user in DefectDojo if they aren’t found in the SAML response.

* **Allow Unknown Attributes** allows you to authorize users who have attributes which are not found in the **Attribute Mapping** field.

* **Sign Assertions/Responses** will require any incoming SAML responses to be signed.

* **Sign Logout Requests** forces DefectDojo to sign any logout requests.

* **Force Authentication** determines whether you want to force your users to authenticate using your Identity Provider each time, regardless of existing sessions.

* **Enable SAML Debugging** will log more detailed SAML output for debugging purposes.

### Open-Source SAML

1.  Navigate to your SAML IdP and find your metadata.
2.  Edit the local_settings.py file (see [Configuration](../../os_getting_started/configuration)) with the following information:

    {{< highlight python >}}
    DD_SAML2_ENABLED=(bool, **True**),
    # SAML Login Button Text
    DD_SAML2_LOGIN_BUTTON_TEXT=(str, 'Login with SAML'),
    # If the metadata can be accessed from a url, try the
    DD_SAML2_METADATA_AUTO_CONF_URL=(str, '<https://your_IdP.com/metadata.xml>'),
    # Otherwise, downlaod a copy of the metadata into an xml file, and
    # list the path in DD_SAML2_METADATA_LOCAL_FILE_PATH
    DD_SAML2_METADATA_LOCAL_FILE_PATH=(str, '/path/to/your/metadata.xml'),
    # Fill in DD_SAML2_ATTRIBUTES_MAP to corresponding SAML2 userprofile attributes provided by your IdP
    DD_SAML2_ATTRIBUTES_MAP=(dict, {
        # format: SAML attrib:django_user_model
        'Email': 'email',
        'UserName': 'username',
        'Firstname': 'first_name',
        'Lastname': 'last_name'
    }),
    # May configure the optional fields
    {{< /highlight >}}

NOTE: *DD_SAML2_ATTRIBUTES_MAP* in k8s can be referenced as extraConfig (e.g. `DD_SAML2_ATTRIBUTES_MAP: 'Email'='email', 'Username'='username'...`)

NOTE: *DD_SITE_URL* might also need to be set depending on the choices you make with the metadata.xml provider. (File versus URL).

4.  Checkout the SAML section in dojo/`dojo/settings/settings.dist.py` and verfiy if it fits your requirement. If you need help, take a look at the [plugin
documentation](https://djangosaml2.readthedocs.io/contents/setup.html#configuration).

5.  Restart DefectDojo, and you should now see a **Login with SAML** button (default setting of DD_SAML2_LOGIN_BUTTON_TEXT) on the login page.

NOTE: In the case when IDP is configured to use self signed (private) certificate,
than CA needs to be specified by define environments variable
REQUESTS_CA_BUNDLE that points to the path of private CA certificate.

#### Advanced Configuration
The [https://github.com/IdentityPython/djangosaml2](djangosaml2) plugin has a lot of options. For details take a look at the [plugin documentation](https://djangosaml2.readthedocs.io/contents/setup.html#configuration).

All default options in DefectDojo can overwritten in the local_settings.py file. If you want to change the organization name, you can add the following lines:

{{< highlight python >}}
if SAML2_ENABLED:
    SAML_CONFIG['contact_person'] = [{
        'given_name': 'Extra',
        'sur_name': 'Example',
        'company': 'DefectDojo',
        'email_address': 'dummy@defectdojo.com',
        'contact_type': 'technical'
    }]
    SAML_CONFIG['organization'] = {
        'name': [('DefectDojo', 'en')],
        'display_name': [('DefectDojo', 'en')],
    },
{{< /highlight >}}

![image](images/sso_oauth_beta_ui.png)

#### Migration from django-saml2-auth
Up to relase 1.15.0 the SAML integration was based on [https://github.com/fangli/django-saml2-auth](django-saml2-auth). Which the switch to djangosaml2 some parameters has changed:

* DD_SAML2_ASSERTION_URL: not necessary any more - automatically generated
* DD_SAML2_DEFAULT_NEXT_URL: not necessary any more - default forwarding from defectdojo is used
* DD_SAML2_NEW_USER_PROFILE: not possible any more - default profile is used, see User Permissions
* DD_SAML2_ATTRIBUTES_MAP: Syntax has changed
* DD_SAML2_CREATE_USER: Default value changed to False, to avoid security breaches

## Other Open-Source Options

### RemoteUser

This implementation is suitable if the DefectDojo instance is placed behind HTTP Authentication Proxy.
Dojo expects that the proxy will perform authentication and pass HTTP requests to the Dojo instance with filled HTTP headers.
The proxy should check if an attacker is not trying to add a malicious HTTP header and bypass authentication.

Values which need to be set:

* `DD_AUTH_REMOTEUSER_ENABLED` - Needs to be set to `True`
* `DD_AUTH_REMOTEUSER_USERNAME_HEADER` - Name of the header which contains the username
* `DD_AUTH_REMOTEUSER_EMAIL_HEADER`(optional) - Name of the header which contains the email
* `DD_AUTH_REMOTEUSER_FIRSTNAME_HEADER`(optional) - Name of the header which contains the first name
* `DD_AUTH_REMOTEUSER_LASTNAME_HEADER`(optional) - Name of the header which contains the last name
* `DD_AUTH_REMOTEUSER_GROUPS_HEADER`(optional) - Name of the header which contains the comma-separated list of groups; user will be assigned to these groups (missing groups will be created)
* `DD_AUTH_REMOTEUSER_GROUPS_CLEANUP`(optional) - Same as [#automatic-import-of-user-groups](AzureAD implementation)
* `DD_AUTH_REMOTEUSER_TRUSTED_PROXY` - Comma separated list of proxies; Simple IP and CIDR formats are supported
* `DD_AUTH_REMOTEUSER_LOGIN_ONLY`(optional) - Check [Django documentation](https://docs.djangoproject.com/en/3.2/howto/auth-remote-user/#using-remote-user-on-login-pages-only)

*WARNING:* There is possible spoofing of headers (for all `DD_AUTH_REMOTEUSER_xxx_HEADER` values). Read Warning in [Django documentation](https://docs.djangoproject.com/en/3.2/howto/auth-remote-user/#configuration)

### User Permissions

When a new user is created via the social-auth, only the default permissions are active. This means that the newly created user does not have access to add, edit, nor delete anything within DefectDojo. There are two parameters in the System Settings to influence the permissions for newly created users:

#### Default group

When both the parameters `Default group` and `Default group role` are set, the new user will be a member of the given group with the given role, which will give him the respective permissions.

#### Groups from Identity Providers

Some Identity Providers are able to send list of groups to which should user belongs. This functionality is implemented only for Identity Providers mentioned below. For all others, we will be more than happy for contribution (hint: functions `assign_user_to_groups` and `cleanup_old_groups_for_user` from [`dojo/pipeline.py`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/pipeline.py) might be useful).

- [Azure](#automatic-import-of-user-groups): Check `DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_GET_GROUPS` and `DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS`
- [RemoteUser](#remoteuser): Check `DD_AUTH_REMOTEUSER_GROUPS_HEADER` and `DD_AUTH_REMOTEUSER_GROUPS_CLEANUP`

### Other Providers

In an effort to accommodate as much generality as possible, it was
decided to implement OAuth2 with the
[social-auth](https://github.com/python-social-auth/social-core/tree/master/social_core/backends)
ecosystem as it has a library of compatible providers with documentation
of implementation. Conveniently, each provider has an identical
procedure of managing the authenticated responses and authorizing access
within a given application. The only difficulty is creating a new
authentication client with a given OAuth2 provider.