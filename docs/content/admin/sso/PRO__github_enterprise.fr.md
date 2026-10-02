---
title: GitHub Enterprise
description: Configurer le SSO GitHub Enterprise dans DefectDojo Pro
weight: 7
audience: pro
---

DefectDojo Pro prend en charge la connexion via GitHub Enterprise. DefectDojo open source n'inclut pas le SSO — voir [Utilisateurs autorisés](/admin/user_management/os__authorized_users/) pour le contrôle d'accès en open source.

## Prérequis

Effectuez les étapes suivantes dans GitHub Enterprise avant de configurer DefectDojo :

1. [Créez une nouvelle application OAuth](https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app) dans votre GitHub Enterprise Server.

2. Choisissez un nom pour l'application, par exemple `DefectDojo`.

3. Définissez l'**URI de redirection** :
   `https://your-instance.cloud.defectdojo.com/complete/github-enterprise/`

4. Notez le **Client ID** et le **Client Secret** de l'application.

## Configuration

Dans DefectDojo, accédez à **Enterprise Settings > OAuth Settings**, sélectionnez **GitHub Enterprise**, et remplissez le formulaire :

- **GitHub Enterprise OAuth Key** — saisissez votre **Client ID**
- **GitHub Enterprise OAuth Secret** — saisissez votre **Client Secret**
- **GitHub Enterprise URL** — saisissez l'URL GitHub de votre organisation, par exemple `https://github.yourcompany.com/`
- **GitHub Enterprise API URL** — saisissez l'URL de l'API GitHub de votre organisation, par exemple `https://github.yourcompany.com/api/v3/`

Cochez **Enable GitHub Enterprise OAuth** et validez le formulaire. Un bouton **Login With GitHub** apparaîtra sur la page de connexion.
