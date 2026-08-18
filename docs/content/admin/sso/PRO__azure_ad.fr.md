---
title: Azure Active Directory
description: Configurer le SSO Azure AD et le mappage de groupes dans DefectDojo Pro
weight: 5
audience: pro
---

DefectDojo Pro prend en charge la connexion via Azure Active Directory (Azure AD), y compris la synchronisation automatique des groupes d'utilisateurs. DefectDojo open source n'inclut pas le SSO — voir [Utilisateurs autorisés](/admin/user_management/os__authorized_users/) pour le contrôle d'accès en open source.

## Prerequisites

Effectuez les étapes suivantes dans le portail Azure avant de configurer DefectDojo :

1. [Enregistrez une nouvelle application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) dans Azure Active Directory.

2. Notez les valeurs suivantes depuis l'application enregistrée :
   - **Application (client) ID**
   - **Directory (tenant) ID**
   - Sous **Certificates & Secrets**, créez un nouveau **Client Secret** et notez sa valeur
   - **Application ID URI**

3. Sous **Authentication > Redirect URIs**, ajoutez un URI de type **Web** :
   `https://your-instance.cloud.defectdojo.com/complete/azuread-tenant-oauth2/`

## Configuration

Dans DefectDojo, accédez à **Enterprise Settings > OAuth Settings**, sélectionnez **Azure AD**, et remplissez le formulaire :

- **Azure AD OAuth Key** — saisissez votre **Application (client) ID**
- **Azure AD OAuth Secret** — saisissez votre **Client Secret**
- **Azure AD Resource** — la valeur par défaut est `https://graph.microsoft.com/`. Il s'agit de l'URI que DefectDojo utilise pour lire des informations supplémentaires (comme les noms de groupes) depuis la [Microsoft Graph Web API](https://docs.azure.cn/en-us/entra/identity-platform/security-best-practices-for-app-registration#application-id-uri). Ne modifiez ceci que si vos noms de groupes sont stockés sur une autre ressource API.
- **Azure AD Tenant ID** — saisissez votre **Directory (tenant) ID**
- **Azure AD Groups Filter** — saisissez éventuellement une expression régulière pour restreindre les groupes d'utilisateurs importés (voir [Group Mapping](#group-mapping) ci-dessous)

Cochez **Enable Azure AD OAuth** et validez le formulaire. Un bouton **Login With Azure AD** apparaîtra sur la page de connexion.

## Group Mapping

Le mappage de groupes permet à DefectDojo d'importer l'appartenance à un [groupe d'utilisateurs](../../user_management/create_user_group/) depuis Azure AD. Les groupes d'utilisateurs dans DefectDojo régissent l'accès aux produits et aux types de produits via [RBAC](../../user_management/set_user_permissions/).

Cochez **Enable Azure AD OAuth Grouping** pour activer cette fonctionnalité. Lors de la connexion, DefectDojo fera correspondre les groupes Azure AD de l'utilisateur aux groupes DefectDojo existants. Tout groupe introuvable dans DefectDojo sera créé automatiquement.

Pour n'importer qu'un sous-ensemble de groupes, saisissez une expression régulière dans le champ **Azure AD Groups Filter**. Par exemple :
- `^team-.*` — correspond à tout groupe commençant par `team-`
- `teamA|teamB|groupC` — correspond à des groupes nommés spécifiques

### Configuring Azure AD to send groups

Le jeton Azure AD doit être configuré pour inclure les identifiants de groupe. Sans cela, aucune information de groupe ne sera présente dans le jeton.

Pour configurer cela :
1. Ajoutez une [revendication de groupe](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims) dans la configuration du jeton Azure AD. En cas de doute sur le type de groupe à sélectionner, choisissez **All Groups**.
2. N'activez **pas** l'option **Emit groups as role claims**.
3. Mettez à jour les autorisations API de l'application pour inclure `GroupMember.Read.All` ou `Group.Read.All`. `GroupMember.Read.All` est recommandé car il accorde moins d'autorisations.

### Group Cleaning

Si **Enable Azure AD OAuth Group Cleaning** est activé, les groupes DefectDojo créés via la synchronisation Azure AD seront automatiquement supprimés lorsqu'ils n'ont plus aucun membre. Lorsqu'un utilisateur est retiré d'un groupe dans Azure AD, il est également retiré du groupe correspondant dans DefectDojo.
