---
title: Auth0
description: Configurer le SSO Auth0 dans DefectDojo Pro
weight: 3
audience: pro
---

DefectDojo Pro prend en charge la connexion via Auth0. DefectDojo open source n'inclut pas le SSO — voir [Utilisateurs autorisés](/admin/user_management/os__authorized_users/) pour le contrôle d'accès en open source.

## Prérequis

Effectuez les étapes suivantes dans votre tableau de bord Auth0 avant de configurer DefectDojo :

1. Créez une nouvelle application : **Applications > Create Application > Single Page Web Application**.

2. Configurez l'application :
   - **Name:** `DefectDojo`
   - **Allowed Callback URLs:** `https://your-instance.cloud.defectdojo.com/complete/auth0/`

3. Notez les valeurs suivantes — vous en aurez besoin dans DefectDojo :
   - **Domain**
   - **Client ID**
   - **Client Secret**

## Configuration

Dans DefectDojo, accédez à **Enterprise Settings > OAuth Settings**, sélectionnez **Auth0**, et remplissez le formulaire :

- **Auth0 OAuth Key** — saisissez votre **Client ID**
- **Auth0 OAuth Secret** — saisissez votre **Client Secret**
- **Auth0 Domain** — saisissez votre **Domain**

Cochez **Enable Auth0 OAuth** pour ajouter un bouton **Login With Auth0** à la page de connexion de DefectDojo.
