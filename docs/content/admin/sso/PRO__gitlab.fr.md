---
title: GitLab
description: Configurer le SSO GitLab dans DefectDojo Pro
weight: 9
audience: pro
---

DefectDojo Pro prend en charge la connexion via GitLab. DefectDojo open source n'inclut pas le SSO — voir [Utilisateurs autorisés](/admin/user_management/os__authorized_users/) pour le contrôle d'accès en open source.

## Prérequis

Effectuez les étapes suivantes dans GitLab avant de configurer DefectDojo :

1. Accédez à la page Applications de votre profil GitLab :
   - GitLab.com : `https://gitlab.com/profile/applications`
   - Auto-hébergé : `https://your-gitlab-host/profile/applications`

2. Créez une nouvelle application :
   - **Name:** `DefectDojo`
   - **Redirect URI:** `https://your-dojo-instance.cloud.defectdojo.com/complete/gitlab/`

3. Notez l'**Application ID** et le **Secret** de l'application.

## Configuration

Dans DefectDojo, accédez à **Enterprise Settings > OAuth Settings**, sélectionnez **GitLab**, et remplissez le formulaire :

- **GitLab OAuth Key** — saisissez votre **Application ID**
- **GitLab OAuth Secret** — saisissez votre **Secret**
- **GitLab API URL** — saisissez l'URL de base de votre instance GitLab, par exemple `https://gitlab.com`

Cochez **Enable GitLab OAuth** et validez le formulaire. Un bouton **Login With GitLab** apparaîtra sur la page de connexion.
