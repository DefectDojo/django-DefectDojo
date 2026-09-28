---
title: KeyCloak
description: Configurer le SSO KeyCloak dans DefectDojo Pro
weight: 13
audience: pro
---

DefectDojo Pro prend en charge la connexion via KeyCloak. DefectDojo open source n'inclut pas le SSO — voir [Utilisateurs autorisés](/admin/user_management/os__authorized_users/) pour le contrôle d'accès en open source.

Ce guide suppose que vous disposez déjà d'un Realm KeyCloak configuré. Si ce n'est pas le cas, consultez la [documentation KeyCloak](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_admin/topics/realms/create.html).

## Prérequis

Effectuez les étapes suivantes dans votre realm KeyCloak avant de configurer DefectDojo :

1. Ajoutez un nouveau client de type `openid-connect`. Notez l'ID du client.

2. Dans les paramètres du client :
   - Définissez **Access Type** sur `confidential`
   - Sous **Valid Redirect URIs**, ajoutez votre URL DefectDojo, par exemple `https://yourorganization.cloud.defectdojo.com` ou `https://your-dojo-host/*`
   - Sous **Web Origins**, ajoutez la même URL (ou `+`)
   - Sous **Fine Grained OpenID Connect Configuration** :
     - Définissez **User Info Signed Response Algorithm** sur `RS256`
     - Définissez **Request Object Signature Algorithm** sur `RS256`
   - Enregistrez les paramètres.

3. Sous **Scope**, définissez **Full Scope Allowed** sur `off`.

4. Sous **Mappers**, ajoutez un mapper personnalisé :
   - **Name:** `aud`
   - **Mapper Type:** `audience`
   - **Included Audience:** sélectionnez l'ID de votre client
   - **Add ID to Token:** `off`
   - **Add Access to Token:** `on`

5. Sous **Credentials**, copiez le **Secret**.

6. Dans **Realm Settings > Keys**, copiez la **Public Key** (clé de signature).

7. Dans **Realm Settings > General > Endpoints**, ouvrez la configuration du point de terminaison OpenID et copiez les URL des points de terminaison **Authorization** et **Token**.

## Configuration

Dans DefectDojo, accédez à **Enterprise Settings > OAuth Settings**, sélectionnez **KeyCloak**, et remplissez le formulaire :

- **KeyCloak OAuth Key** — saisissez le nom de votre client (issu de l'étape 1)
- **KeyCloak OAuth Secret** — saisissez le secret des identifiants de votre client (issu de l'étape 5)
- **KeyCloak Public Key** — saisissez la Public Key de vos paramètres de realm (issue de l'étape 6)
- **KeyCloak Resource** — saisissez l'URL du point de terminaison Authorization (issue de l'étape 7)
- **KeyCloak Group Limiter** — saisissez l'URL du point de terminaison Token (issue de l'étape 7)
- **KeyCloak OAuth Login Button Text** — choisissez le texte du bouton de connexion DefectDojo

Cochez **Enable KeyCloak OAuth** et validez le formulaire. Un bouton de connexion apparaîtra sur la page de connexion avec le texte que vous avez configuré.
