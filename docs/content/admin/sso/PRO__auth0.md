---
title: "Auth0"
description: "Configure Auth0 SSO in DefectDojo Pro"
weight: 3
audience: pro
---

DefectDojo Pro supports login via Auth0. Open-Source users should refer to the [Open-Source Auth0 guide](../OS__auth0/).

## Prerequisites

Complete the following steps in your Auth0 dashboard before configuring DefectDojo:

1. Create a new application: **Applications > Create Application > Single Page Web Application**.

2. Configure the application:
   - **Name:** `DefectDojo`
   - **Allowed Callback URLs:** `https://your-instance.cloud.defectdojo.com/complete/auth0/`

3. Note the following values — you will need them in DefectDojo:
   - **Domain**
   - **Client ID**
   - **Client Secret**

## Configuration

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **Auth0**, and fill in the form:

- **Auth0 OAuth Key** — enter your **Client ID**
- **Auth0 OAuth Secret** — enter your **Client Secret**
- **Auth0 Domain** — enter your **Domain**

Check **Enable Auth0 OAuth** to add a **Login With Auth0** button to the DefectDojo login page.
