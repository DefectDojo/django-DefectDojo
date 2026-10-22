---
title: Authentification unique
description: DefectDojo Pro prend en charge SAML et une gamme de fournisseurs OAuth
  pour l'authentification unique
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2026-04-30 00:00:00+00:00
draft: false
weight: 8
collapsed: true
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
pro-feature: true
aliases:
- /fr/admin/user_management/configure_sso/
- /fr/admin/sso/os__saml/
- /fr/admin/sso/os__auth0/
- /fr/admin/sso/os__azure_ad/
- /fr/admin/sso/os__github_enterprise/
- /fr/admin/sso/os__gitlab/
- /fr/admin/sso/os__google/
- /fr/admin/sso/os__keycloak/
- /fr/admin/sso/os__oidc/
- /fr/admin/sso/os__okta/
- /fr/admin/sso/os__remote_user/
---

L'authentification unique est une fonctionnalité de **DefectDojo Pro**. Depuis DefectDojo 3.0, l'ensemble du périmètre SSO — SAML, OIDC et les fournisseurs OAuth intégrés — n'est disponible que dans DefectDojo Pro. La version open source de DefectDojo utilise une connexion locale par nom d'utilisateur/mot de passe et le flux de réinitialisation de mot de passe.

Si vous utilisez la version open source de DefectDojo et souhaitez le SSO, vous devrez passer à [DefectDojo Pro](https://defectdojo.com) ; la migration est décrite dans les [notes de mise à niveau 3.0](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only). Les comptes utilisateur et les appartenances aux groupes existants sont préservés lors de la mise à niveau. Pour le contrôle d'accès sur la version open source de DefectDojo, consultez la page [Utilisateurs autorisés](/admin/user_management/os__authorized_users/).

## Voir ce qui est configuré

**[Authorization Connectors](/admin/sso/pro__authorization_connectors/)** répertorie tous les fournisseurs pris en charge sur une seule page — lesquels sont configurés, lesquels sont activés, et quel protocole chacun utilise — et vous mène directement au formulaire de paramètres de chacun d'eux. Commencez ici si vous voulez connaître l'état de cette instance plutôt que configurer un fournisseur spécifique.

## Fournisseurs SSO pris en charge (DefectDojo Pro)

DefectDojo Pro prend en charge SAML ainsi que les fournisseurs OAuth suivants. Chaque guide détaille la configuration côté fournisseur et la configuration correspondante dans l'interface **Enterprise Settings** de Pro.

* **[Auth0](/admin/sso/pro__auth0/)**
* **[Azure Active Directory](/admin/sso/pro__azure_ad/)**
* **[GitHub Enterprise](/admin/sso/pro__github_enterprise/)**
* **[GitLab](/admin/sso/pro__gitlab/)**
* **[Google](/admin/sso/pro__google/)**
* **[KeyCloak](/admin/sso/pro__keycloak/)**
* **[Okta](/admin/sso/pro__okta/)**
* **[OIDC (OpenID Connect)](/admin/sso/pro__oidc/)**
* **[SAML](/admin/sso/pro__saml/)**
* **[LDAP](/admin/sso/pro__ldap/)**

## Provisionnement des utilisateurs depuis votre annuaire (DefectDojo Pro)

Les fournisseurs ci-dessus déterminent qui peut se connecter. **[SCIM Provisioning](/admin/sso/pro__scim/)** maintient la liste des comptes elle-même synchronisée avec votre annuaire, de sorte que les utilisateurs sont créés à leur arrivée, mis à jour lorsque leurs informations changent, et désactivés (avec leurs jetons API) à leur départ.

La configuration du SSO dans DefectDojo Pro ne peut être effectuée que par un **Superuser**.

**Utilisateurs DefectDojo Pro :** Ajoutez les adresses IP de vos services SAML ou SSO à la liste blanche du pare-feu avant de configurer le SSO. Voir [Règles de pare-feu](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings) pour plus d'informations.

## Désactivation de la connexion par nom d'utilisateur / mot de passe

Une fois le SSO configuré dans DefectDojo Pro, vous voudrez peut-être désactiver le formulaire de connexion traditionnel par nom d'utilisateur/mot de passe. Décochez **Allow Login via Username and Password** sous **Enterprise Settings > Login Settings**.

![image](images/pro_login_settings.png)

### Solution de repli pour la connexion

Si votre intégration SSO cesse de fonctionner, vous pouvez toujours revenir au formulaire de connexion standard en ajoutant ce qui suit à l'URL de votre DefectDojo :

`/login?force_login_form`

Nous recommandons de conserver au moins un compte administrateur avec un nom d'utilisateur et un mot de passe configurés en secours.
