---
title: Authentification Google
description: Configurer OAuth Google dans DefectDojo Pro
weight: 11
audience: pro
---

DefectDojo Pro prend en charge la connexion via des comptes Google. Les nouveaux utilisateurs sont créés automatiquement lors de leur première connexion s'ils n'existent pas déjà. Les utilisateurs DefectDojo existants sont associés à des comptes Google par nom d'utilisateur (la partie avant le `@` dans leur adresse e-mail Google). DefectDojo open source n'inclut pas le SSO — voir [Utilisateurs autorisés](/admin/user_management/os__authorized_users/) pour le contrôle d'accès en open source.

## Prérequis

Effectuez les étapes suivantes dans la Google Cloud Console avant de configurer DefectDojo :

1. Connectez-vous à la [Google Developers Console](https://console.developers.google.com).

2. Accédez à **Credentials > Create Credentials > OAuth Client ID**.

   ![image](images/google_1.png)

3. Sélectionnez **Web Application** et donnez-lui un nom descriptif (par exemple `DefectDojo`).

4. Sous **Authorized Redirect URIs**, ajoutez :
   `https://your-instance.cloud.defectdojo.com/complete/google-oauth2/`

5. Notez le **Client ID** et la **Client Secret Key**.

## Configuration

Dans DefectDojo, accédez à **Enterprise Settings > OAuth Settings**, sélectionnez **Google**, et remplissez le formulaire :

- **Google OAuth Key** — saisissez votre **Client ID**
- **Google OAuth Secret** — saisissez votre **Client Secret Key**
- **Whitelisted Domains** — saisissez le domaine de votre organisation (par exemple `yourcompany.com`) pour permettre à tout utilisateur de ce domaine de se connecter
- **Whitelisted Email Addresses** — vous pouvez aussi saisir des adresses e-mail spécifiques à autoriser (par exemple `user1@yourcompany.com, user2@yourcompany.com`)

Vous devez définir au moins un domaine ou une adresse e-mail autorisé, sinon aucun utilisateur ne pourra se connecter via Google.

Cochez **Enable Google OAuth** et validez le formulaire. Un bouton **Login With Google** apparaîtra sur la page de connexion.
