---
title: "Okta"
description: "Configure Okta SSO in DefectDojo Pro"
weight: 15
audience: pro
---

DefectDojo Pro supports login via Okta. Open-Source users should refer to the [Open-Source Okta guide](/admin/sso/os__okta/).

## Prerequisites

Complete the following steps in Okta before configuring DefectDojo:

1. Sign in or create an account at [Okta](https://www.okta.com/developer/signup/).

2. Go to **Applications** and click **Add Application**.

   ![image](images/okta_1.png)

3. Select **Web Applications**.

   ![image](images/okta_2.png)

4. Under **Login Redirect URLs**, add your DefectDojo callback URL. Also check the **Implicit** box.

   ![image](images/okta_3.png)

5. Click **Done**.

6. From the **Dashboard**, note the **Org-URL**.

   ![image](images/okta_4.png)

7. Open the newly created application and note the **Client ID** and **Client Secret**.

   ![image](images/okta_5.png)

## Configuration

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **Okta**, and fill in the form:

- **Okta OAuth Key** — enter your **Client ID**
- **Okta OAuth Secret** — enter your **Client Secret**
- **Okta Tenant ID** — enter your Org-URL in the format `https://your-org-url/oauth2`

Check **Enable Okta OAuth** and submit the form. A **Login With Okta** button will appear on the login page.
