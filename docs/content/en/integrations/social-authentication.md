---
title: "Authentication via OAuth2"
description: "OAuth2 let users authenticate against enterprise directories."
draft: false
weight: 3
---

## Auth0

In the same way as with other identity providers, it's now possible to
leverage Auth0 to authenticate users on DefectDojo.

1.  Inside your Auth0 dashboard create a new application (Applications /
    Create Application / Single Page Web Application).
2.  On the new application set the following fields:
    -   Name: "Defectdojo"
    -   Allowed Callback URLs:
        [https://the_hostname_you_have_dojo_deployed:your_server_port/complete/auth0/](https://the_hostname_you_have_dojo_deployed:your_server_port/complete/auth0/)
3.  Copy the following info from the application:
    -   Domain
    -   Client ID
    -   Client Secret
4.  Now, edit the `dojo/settings/settings.dist.py` file and edit/replace the following
    information:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED=True
    DD_SOCIAL_AUTH_AUTH0_KEY=(str, '**YOUR_CLIENT_ID_FROM_STEP_ABOVE**'),
    DD_SOCIAL_AUTH_AUTH0_SECRET=(str,'**YOUR_CLIENT_SECRET_FROM_STEP_ABOVE**'),
    DD_SOCIAL_AUTH_AUTH0_DOMAIN=(str, '**YOUR_AUTH0_DOMAIN_FROM_STEP_ABOVE**'),
    {{< /highlight >}}

5.  Restart DefectDojo, and you should now see a **Login with Auth0**
    button on the login page.

## Google

New to DefectDojo, a Google account can now be used for Authentication,
Authorization, and a DefectDojo user. Upon login with a Google account,
a new user will be created if one does not already exist. The criteria
for determining whether a user exists is based on the users username. In
the event a new user is created, the username is that of the Google
address without the domain. Once created, the user creation process will
not happen again as the user is recalled by its username, and logged in.
In order to make the magic happen, a Google authentication server needs
to be created. Closely follow the steps below to guarantee success.

1.  Navigate to the following address and either create a new account,
    or login with an existing one: [Google Developers
    Console](https://console.developers.google.com)
2.  Once logged in, find the key shaped button labeled **Credentials**
    on the left side of the screen. Click **Create Credentials**, and
    choose **OAuth Client ID**:

![image](../../images/google_1.png)

3.  Select **Web Applications**, and provide a descriptive name for the
    client.

![image](../../images/google_2.png)

4.  Add the pictured URLs in the **Authorized Redirect URLs** section.
    This part is very important. If there are any mistakes here, the
    authentication client will not authorize the request, and deny
    access.
5.  Once all URLs are added, finish by clicking **Create**

Now with the authentication client created, the **Client ID** and
**Client Secret Key** need to be copied over to `dojo/settings/settings.dist.py` in the
project. Click the newly created client and copy the values:

![image](../../images/google_3.png)

In the **Environment** section at the top of `dojo/settings/settings.dist.py`, enter the
values as shown below:

![image](../../images/google_4.png)

In the **Authentication** section of `dojo/settings/settings.dist.py`, set
**DD_GOOGLE_OAUTH_ENABLED** to **True** to redirect away from this
README and actually authorize.

![image](../../images/google_5.png)

To authorize users you will need to set the following:

{{< highlight python >}}
SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS = ['example.com', 'example.org']
{{< /highlight >}}

or

{{< highlight python >}}
SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS = ['<email@example.com>']
{{< /highlight >}}

OKTA
----

In a similar fashion to that of Google, using OKTA as a OAuth2 provider
carries the same attributes and a similar procedure. Follow along below.

1.  Navigate to the following address and either create a new account,
    or login with an existing one: [OKTA Account
    Creation](https://www.okta.com/developer/signup/)
2.  Once logged in, enter the **Applications** and click **Add
    Application**:

![image](../../images/okta_1.png)

3.  Select **Web Applications**.

![image](../../images/okta_2.png)

4.  Add the pictured URLs in the **Login Redirect URLs** section. This
    part is very important. If there are any mistakes here, the
    authentication client will not authorize the request, and deny
    access. Check the **Implicit** box as well.

![image](../../images/okta_3.png)

5.  Once all URLs are added, finish by clicking **Done**.
6.  Return to the **Dashboard** to find the **Org-URL**. Note this value
    as it will be important in the settings file.

![image](../../images/okta_4.png)

Now, with the authentication client created, the **Client ID** and
**Client Secret** Key need to be copied over to `dojo/settings/settings.dist.py` in the
project. Click the newly created client and copy the values:

![image](../../images/okta_5.png)

In the **Environment** section at the top of `dojo/settings/settings.dist.py`, enter the
values as shown below:

![image](../../images/okta_6.png)

In the **Authentication** section of `dojo/settings/settings.dist.py`, set
**DD_OKTA_OAUTH_ENABLED** to **True** to redirect away from this
README and actually authorize.

![image](../../images/okta_7.png)

If during the login process you get the following error: *The
'redirect_uri' parameter must be an absolute URI that is whitelisted
in the client app settings.* and the `redirect_uri` HTTP
GET parameter starts with `http://` instead of
`https://` you need to add
**SOCIAL_AUTH_REDIRECT_IS_HTTPS = True** in the **Authentication**
section of `dojo/settings/settings.dist.py`.

## Azure Active Directory

You can now use your corporate Azure Active Directory to authenticate
users to Defect Dojo. Users will be using your corporate Azure AD
account (A.K.A. Office 365 identity) to authenticate via OAuth, and all
the conditional access rules and benefits from Azure Active Directory
will also apply to the Defect Dojo Authentication. Once the user signs
in, it will try to match the UPN of the user to an existing e-mail from
a user in Defect Dojo, and if no match is found, a new user will be
created in Defect Dojo, associated with the unique id/value of the user
provided by your Azure AD tenant. Then, you can assign roles to this
user, such as 'staff' or 'superuser'

1.  Navigate to the following address and follow instructions to create
    a new app registration

    -   <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app>

2.  Once you register an app, take note of the following information:

    -   **Application (client) ID**
    -   **Directory (tenant) ID**
    -   Under Certificates & Secrets, create a new **Client Secret**

3.  Under Authentication > Redirect URIs, add a *WEB* type of uri where
    the redirect points to

    -   <http://localhost:8080/complete/azuread-tenant-oauth2/>
    -   **OR**
    -   [https://the_hostname_you_have_dojo_deployed:your_server_port/complete/azuread-tenant-oauth2/](https://the_hostname_you_have_dojo_deployed:your_server_port/complete/azuread-tenant-oauth2/)

4.  Now, edit the dojo/`dojo/settings/settings.dist.py` file and edit/replace the following
    information:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY=(str, 'YOUR_APPLICATION_ID_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET=(str, 'YOUR_CLIENT_SECRET_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID=(str, 'YOUR_DIRECTORY_ID_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_ENABLED = True
    {{< /highlight >}}

5.  Restart your Dojo, and you should now see a **Login with Azure AD**
    button on the login page which should *magically* work

## Gitlab

In a similar fashion to that of Google and OKTA, using Gitlab as a
OAuth2 provider carries the same attributes and a similar procedure.
Follow along below.

1.  Navigate to your Gitlab settings page and got to the Applications
    section

    -   <https://gitlab.com/profile/applications>
    -   **OR**
    -   [https://the_hostname_you_have_gitlab_deployed:your_gitlab_port/profile/applications](https://the_hostname_you_have_gitlab_deployed:your_gitlab_port/profile/applications)

2.  Choose a name for your application
3.  For the Redirect URI, enter the DefectDojo URL with the following
    format

    -   [https://the_hostname_you_have_dojo_deployed:your_server_port/complete/gitlab/](https://the_hostname_you_have_dojo_deployed:your_server_port/complete/gitlab/)

4.  Now, edit the dojo/`dojo/settings/settings.dist.py` file and edit/replace the following
    information:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GITLAB_KEY=(str, 'YOUR_APPLICATION_ID_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_GITLAB_SECRET=(str, 'YOUR_SECRET_FROM_STEP_ABOVE'),
    DD_SOCIAL_AUTH_GITLAB_API_URL=(str, 'https://gitlab.com'),
    DD_SOCIAL_AUTH_GITLAB_OAUTH2_ENABLED = True
    {{< /highlight >}}

    Additionally, if you want to import your Gitlab projects as DefectDojo
    products, add the following line, still in dojo/`dojo/settings/settings.dist.py`:

    {{< highlight python >}}
    DD_SOCIAL_AUTH_GITLAB_PROJECT_AUTO_IMPORT = True
    {{< /highlight >}}

5.  Restart DefectDojo, and you should now see a **Login with Gitlab**
    button on the login page.

## SAML 2.0

{{% alert title="Warning" color="warning" %}}
The SAML integration below is based on [https://github.com/fangli/django-saml2-auth](django-saml2-auth) which is no longer maintained, see #3890
{{% /alert %}}

In a similar direction to OAuth, this SAML addition provides a more secure
perogative to SSO. For definitions of terms used and more information,
see the plugin [plugin
homepage](https://github.com/fangli/django-saml2-auth)

1.  Navigate to your SAML IdP and find your metadata
2.  Edit the dojo/`dojo/settings/settings.dist.py` file:

    {{< highlight python >}}
    DD_SAML2_ENABLED=(bool, **True**),
    # If the metadata can be accessed from a url, try the
    DD_SAML2_METADATA_AUTO_CONF_URL
    DD_SAML2_METADATA_AUTO_CONF_URL=(str, '<https://your_IdP.com/metadata.xml>'),
    # Otherwise, downlaod a copy of the metadata into an xml file, and
    # list the path in DD_SAML2_METADATA_LOCAL_FILE_PATH
    DD_SAML2_METADATA_LOCAL_FILE_PATH=(str, '/path/to/your/metadata.xml'),
    # Fill in DD_SAML2_ASSERTION_URL and DD_SAML2_ENTITY_ID to
    # match the specs of you IdP.
    # Configure the remaining optional fields to your desire.
    {{< /highlight >}}

4.  In the "Authentication" section of the `dojo/settings/settings.dist.py`, do the
    following

    - Find the "SAML_2_AUTH" dictionary
    - Comment out the metadata collection method that was not used.
    - For example, if METADATA_AUTO_CONF_URL was used, comment the
      METADATA_LOCAL_FILE_PATH line.

5.  Restart DefectDojo, and you should now see a **Login with SAML**
    button on the login page.

NOTE: In the case when IDP is configured to use self signed certificate,
than CA needs to be specified by define environments variable
REQUESTS_CA_BUNDLE that points to the path of public CA certificate.

## User Permissions

When a new user is created via the social-auth, only the default permissions are active. This means that the newly created user does not have access to add, edit, nor delete anything within DefectDojo. To circumvent that, a custom pipeline was added (dojo/pipline.py/modify_permissions) to elevate new users to staff. This can be disabled by setting 'is_staff' equal to False. Similarly, for an admin account, simply add the following to the modify_permissions pipeline:

{{< highlight python >}}
is_superuser = True
{{< /highlight >}}

Exception for Gitlab OAuth2: with
DD_SOCIAL_AUTH_GITLAB_PROJECT_AUTO_IMPORT set to True in
`dojo/settings/settings.dist.py`, where a new user is created via the Gitlab
social-auth, he has one permission: add_engagement. It allows him to
create further engagements on his products via the API.

## Other Providers

In an effort to accommodate as much generality as possible, it was
decided to implement OAuth2 with the
[social-auth](https://github.com/python-social-auth/social-core/tree/master/social_core/backends)
ecosystem as it has a library of compatible providers with documentation
of implementation. Conveniently, each provider has an identical
procedure of managing the authenticated responses and authorizing access
within a given application. The only difficulty is creating a new
authentication client with a given OAuth2 provider.
