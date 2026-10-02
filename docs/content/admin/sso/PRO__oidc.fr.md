---
title: OIDC
description: Configurez l'authentification unique (SSO) OpenID Connect (OIDC) dans
  DefectDojo Pro
weight: 17
audience: pro
---

DefectDojo Pro prend en charge la connexion via un fournisseur OpenID Connect (OIDC) générique. La version open source de DefectDojo n'inclut pas l'authentification unique (SSO) — consultez [Utilisateurs autorisés](/admin/user_management/os__authorized_users/) pour le contrôle d'accès en open source.

## Configuration

Dans DefectDojo, accédez à **Enterprise Settings > OIDC Settings**.

![image](images/oidc_pro.png)

Remplissez le formulaire :

1. **Endpoint** — l'URL de base de votre fournisseur OIDC. N'incluez pas `/.well-known/openid-configuration`.
2. **Client ID** — l'ID client de votre fournisseur OIDC.
3. **Client Secret** — le secret client de votre fournisseur OIDC.
4. Configurez éventuellement **Claim Mapping** et **Group Mapping** — voir ci-dessous.
5. Cochez **Enable OIDC**.

Envoyez le formulaire. Un bouton **Log In With OIDC** apparaîtra sur la page de connexion de DefectDojo.

Utilisez **Validate Config** à tout moment pour vérifier les paramètres sans les enregistrer. Cette fonction récupère le document de découverte, vérifie les clés de signature et l'émetteur, affiche l'URI de redirection exacte à enregistrer chez votre fournisseur, et vérifie vos mappages de revendications et de groupes par rapport aux revendications annoncées par le fournisseur.

## Claim Mapping

Chaque ligne associe une **OIDC Claim** au **DefectDojo Field** qu'elle doit renseigner. Utilisez **Add Claim Mapping** pour ajouter des lignes supplémentaires et l'icône de corbeille pour en supprimer une.

![image](images/sso_oidc_claim_mapping.png)

Un champ sans ligne associée conserve sa revendication standard ; cette section n'est donc nécessaire que si votre fournisseur nomme les choses différemment. Les revendications standard sont les suivantes :

| DefectDojo Field | Revendication standard |
| --- | --- |
| Username | `preferred_username` |
| Email | `email` |
| First Name | `given_name` |
| Last Name | `family_name` |

Notes :

- Une instance non configurée s'ouvre avec ces quatre lignes déjà renseignées, afin que vous puissiez voir ce que fait OIDC avant de modifier quoi que ce soit.
- Une même revendication peut alimenter plusieurs champs. Chaque champ DefectDojo ne peut être associé qu'à une seule revendication.
- Les revendications sont lues à la fois dans le jeton d'ID et dans la réponse userinfo ; une revendication que votre fournisseur ne renvoie que dans l'un des deux fonctionne donc quand même.
- Si une revendication associée est absente ou vide pour un utilisateur donné, le champ conserve sa valeur standard au lieu d'être vidé.

## Group Mapping

DefectDojo peut reproduire les groupes signalés par votre fournisseur sous forme de groupes DefectDojo à chaque connexion. Cochez **Enable Group Mapping** pour afficher les paramètres.

![image](images/sso_oidc_group_mapping.png)

- **Group Claim Name** — la revendication contenant les groupes de l'utilisateur. **La plupart des fournisseurs n'en émettent pas par défaut** et nécessitent la configuration explicite d'un mapper ; dans Keycloak, par exemple, ajoutez un mapper *Group Membership* au client. Notez qu'un mapper *User Realm Role* envoie des **rôles** de realm, et non des groupes.
- **Group Limiter Regex Expression** — seuls les groupes correspondant à cette expression sont reproduits. Utilisez `.*` pour tous les autoriser.
- **Remove Stale Group Memberships** — lorsque cette option est activée, les appartenances aux groupes provisionnés par OIDC que le fournisseur ne signale plus sont supprimées à la connexion suivante. Seuls les groupes créés par OIDC sont concernés ; les groupes que vous avez attribués manuellement, ainsi que les groupes provisionnés par un autre fournisseur tel que SAML, ne sont jamais modifiés.

Les groupes sont créés lors de leur première utilisation et nommés exactement comme le fournisseur les signale. Si votre fournisseur envoie des chemins de groupe complets (c'est le cas du mapper *Group Membership* de Keycloak lorsque **Full group path** est activé), le groupe DefectDojo est nommé `/Group A` plutôt que `Group A`. Désactivez cette option si vous voulez que les noms correspondent aux groupes provenant d'un autre fournisseur, sinon vous vous retrouverez avec deux groupes DefectDojo pour un même groupe logique.

Si le mappage des groupes semble ne rien faire, exécutez **Validate Config** : il indique si la revendication que vous avez indiquée fait partie de celles annoncées par le fournisseur.
