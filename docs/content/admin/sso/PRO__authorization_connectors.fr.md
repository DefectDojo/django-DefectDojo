---
title: Connecteurs d'autorisation
description: 'Visualisez tous les fournisseurs d''identité sur une seule page : lesquels
  sont configurés, lesquels sont activés, et quel protocole chacun utilise'
weight: 1
audience: pro
---

Authorization Connectors est une page unique répertoriant chaque fournisseur d'identité pris en charge par DefectDojo Pro, l'état de chacun et le protocole qu'il utilise. Avant son existence, chaque fournisseur vivait dans son propre formulaire de paramètres, et il n'y avait aucun moyen de répondre à la question « qu'est-ce qui est configuré sur cette instance ? » sans tous les ouvrir.

Authorization Connectors est une fonctionnalité de **DefectDojo Pro**. Vous la trouverez sous **Connect > Authorization**. Seul un **Superuser** peut consulter ou modifier la configuration des fournisseurs d'identité.

![Authorization Connectors](images/authorization_connectors.png)

## Comment la page est organisée

Les fournisseurs sont répartis en deux sections, chacune triée par ordre alphabétique avec un compteur à côté de son titre :

* **Configured Providers** — les fournisseurs qui ont été mis en place sur cette instance, qu'ils soient actuellement activés ou non.
* **Available Providers** — les fournisseurs pris en charge mais pas encore mis en place.

Cette répartition se fait délibérément selon *configuré*, et non *activé*. Un fournisseur qui a été configuré puis désactivé reste dans Configured Providers, car c'est là que la personne qui l'a mis en place ira le chercher. Son état est indiqué sur la vignette à la place.

Chaque vignette affiche :

| | |
| --- | --- |
| **Logo et nom** | Le fournisseur, nommé sans son protocole |
| **Étiquette de protocole** | `SAML 2.0`, `OAuth 2.0`, `OpenID Connect`, ou `LDAP` |
| **Étiquette de statut** | `Enabled`, `Disabled`, ou `Not configured` |
| **Étiquette `BETA`** | Présente sur les fournisseurs encore en bêta |
| **Action** | **Manage Configuration** pour un fournisseur configuré, **Configure** pour un fournisseur disponible |

Les deux sections disposent d'un champ de recherche qui filtre sur le nom du fournisseur et sur le protocole ; ainsi, rechercher `oauth` limite la page aux fournisseurs OAuth.

![Available providers](images/authorization_available.png)

## Une seule configuration par fournisseur

Les paramètres d'un fournisseur d'identité forment un ensemble unique de valeurs par fournisseur et par instance — une seule application Okta, un seul fournisseur d'identité SAML, un seul annuaire LDAP. Les vignettes l'indiquent, et il n'y a pas d'option « en ajouter un autre » : pour modifier la façon dont un fournisseur est configuré, vous modifiez la configuration déjà existante.

C'est ce qui distingue Authorization Connectors des [galeries de connecteurs](/connectors/upstream/about/), où un même outil peut avoir plusieurs configurations côte à côte.

## Les trois états, et ce qu'ils signifient

| Statut | Signification | Que faire ensuite |
| --- | --- | --- |
| **Enabled** | Configuré et accepte les connexions | Rien |
| **Disabled** | Configuré, mais désactivé — son bouton n'apparaîtra pas sur la page de connexion | Réactivez-le depuis sa configuration quand vous le souhaitez |
| **Not configured** | Pris en charge, rien n'est encore renseigné | **Configure** pour le mettre en place |

Sélectionner un fournisseur ouvre directement le formulaire de paramètres propre à ce fournisseur. Il n'y a pas de sélecteur de fournisseur intermédiaire.

## Fournisseurs pris en charge

| Provider | Protocol | Setup guide |
| --- | --- | --- |
| Auth0 | OAuth 2.0 | [Auth0](/admin/sso/pro__auth0/) |
| GitHub Enterprise | OAuth 2.0 | [GitHub Enterprise](/admin/sso/pro__github_enterprise/) |
| GitLab | OAuth 2.0 | [GitLab](/admin/sso/pro__gitlab/) |
| Google | OAuth 2.0 | [Google](/admin/sso/pro__google/) |
| Keycloak | OAuth 2.0 | [KeyCloak](/admin/sso/pro__keycloak/) |
| LDAP | LDAP | [LDAP](/admin/sso/pro__ldap/) |
| Microsoft Entra ID | OAuth 2.0 | [Azure Active Directory](/admin/sso/pro__azure_ad/) |
| Okta | OAuth 2.0 | [Okta](/admin/sso/pro__okta/) |
| OpenID Connect | OpenID Connect | [OIDC](/admin/sso/pro__oidc/) |
| SAML | SAML 2.0 | [SAML](/admin/sso/pro__saml/) |

La page indique quel est l'état de configuration d'un fournisseur. Elle ne renvoie jamais les secrets de la configuration — les secrets clients, les mots de passe de liaison et les certificats ne font pas partie des données derrière cette page, et ne peuvent pas en être extraits.

## Quand un fournisseur ne se connecte pas

Authorization Connectors indique ce qui est configuré ; la page ne montre pas les échecs de connexion. Ceux-ci sont enregistrés dans [Diagnostics](/admin/diagnostics/pro__diagnostics/), où le SSO, le SAML et le LDAP consignent chacun leurs propres tentatives avec la raison du rejet — une signature d'assertion invalide, une liaison rejetée, un attribut incohérent. Ces lignes sont propres à l'instance et donc réservées aux superutilisateurs.

Conservez au moins un compte superutilisateur avec un nom d'utilisateur et un mot de passe en secours, et rappelez-vous que `/login?force_login_form` renvoie le formulaire de connexion standard si un fournisseur d'identité cesse de fonctionner. Voir [Single Sign-On](/admin/sso/) pour les deux.

## Voir aussi

* [Single Sign-On](/admin/sso/) — les guides de configuration par fournisseur et les paramètres de connexion
* [Diagnostics](/admin/diagnostics/pro__diagnostics/) — pourquoi une tentative de connexion a échoué
* [Connectors](/connectors/upstream/about/) — la galerie amont sur laquelle cette page est modelée
