---
title: Okta
description: Configurez l'authentification unique (SSO) Okta dans DefectDojo Pro
weight: 15
audience: pro
---

DefectDojo Pro prend en charge la connexion via Okta. La version open source de DefectDojo n'inclut pas l'authentification unique (SSO) — consultez [Utilisateurs autorisés](/admin/user_management/os__authorized_users/) pour le contrôle d'accès en open source.

## Prérequis

Effectuez les étapes suivantes dans Okta avant de configurer DefectDojo :

1. Connectez-vous ou créez un compte sur [Okta](https://www.okta.com/developer/signup/).

2. Accédez à **Applications** et cliquez sur **Add Application**.

   ![image](images/okta_1.png)

3. Sélectionnez **Web Applications**.

   ![image](images/okta_2.png)

4. Sous **Login Redirect URLs**, ajoutez l'URL de rappel (callback) de votre instance DefectDojo. Cochez également la case **Implicit**.

   ![image](images/okta_3.png)

5. Cliquez sur **Done**.

6. Depuis le **Dashboard**, notez l'**Org-URL**.

   ![image](images/okta_4.png)

7. Ouvrez l'application nouvellement créée et notez le **Client ID** et le **Client Secret**.

   ![image](images/okta_5.png)

## Configuration

Dans DefectDojo, accédez à **Enterprise Settings > OAuth Settings**, sélectionnez **Okta**, puis remplissez le formulaire :

- **Okta OAuth Key** — saisissez votre **Client ID**
- **Okta OAuth Secret** — saisissez votre **Client Secret**
- **Okta Tenant ID** — saisissez votre Org-URL au format `https://your-org-url/oauth2`

Cochez **Enable Okta OAuth** et envoyez le formulaire. Un bouton **Login With Okta** apparaîtra sur la page de connexion.
