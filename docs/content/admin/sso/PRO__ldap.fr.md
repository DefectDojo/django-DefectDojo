---
title: Authentification LDAP
description: Configurer l'authentification LDAP dans DefectDojo Pro
weight: 20
audience: pro
aliases:
- /fr/en/open_source/ldap-authentication
---

DefectDojo Pro prend en charge l'authentification LDAP depuis l'interface **Enterprise Settings** — aucune image Docker personnalisée
ni fichier de configuration n'est nécessaire.

Contrairement aux autres fournisseurs de cette page, LDAP ne fonctionne pas par redirection. Les utilisateurs se connectent
avec le formulaire standard de nom d'utilisateur et de mot de passe de DefectDojo, et leurs identifiants sont vérifiés
auprès de votre annuaire. Il n'y a pas de bouton de connexion supplémentaire.

## Configuration

Ouvrez **Enterprise Settings > LDAP Settings**.

![image](images/sso_ldap_settings.png)

1. **Server URI** — l'annuaire auquel se connecter, par exemple `ldaps://ldap.example.com:636`.
   Privilégiez `ldaps://`. Si vous devez utiliser `ldap://` en clair, activez **Use StartTLS** ci-dessous afin que la
   connexion soit mise à niveau avant l'envoi des identifiants.
2. **Bind DN** — le nom distinctif du compte de service utilisé pour rechercher les utilisateurs.
   Laissez vide pour une liaison anonyme.
3. **Bind Password** — le mot de passe de ce compte de service. La valeur enregistrée n'est jamais
   renvoyée au navigateur ; laissez le champ vide pour conserver le mot de passe déjà enregistré.
4. **User Search Base** — le DN sous lequel rechercher les entrées utilisateur, par exemple
   `ou=people,dc=example,dc=com`.
5. **User Search Filter** — le filtre utilisé pour localiser l'utilisateur. Il **doit** contenir le
   paramètre littéral `%(user)s`, qui est remplacé par le nom d'utilisateur saisi. Les valeurs
   courantes sont `(uid=%(user)s)` pour OpenLDAP et `(sAMAccountName=%(user)s)` pour Active
   Directory.
6. **User Attribute Mapping** — voir ci-dessous.
7. Cochez **Enable LDAP** pour l'activer.

Utilisez **Validate Config** pour vérifier les paramètres sans les enregistrer. Cela indique si les paramètres sont
complets, si le serveur est accessible, si la liaison réussit, si les bases de recherche se résolvent, et si le
mappage des attributs semble utilisable.

## User Attribute Mapping

Chaque ligne associe un **LDAP Attribute** au **DefectDojo Field** qu'il doit renseigner. Utilisez
**Add Attribute Mapping** pour ajouter des lignes supplémentaires et l'icône de corbeille pour en supprimer une.

![image](images/sso_ldap_attribute_mapping.png)

- **LDAP Attribute** est un champ de texte libre qui doit correspondre à l'attribut réellement
  renvoyé par votre annuaire — par exemple `uid`, `givenName`, `sn`, `mail` sur OpenLDAP, ou `sAMAccountName`,
  `givenName`, `sn`, `mail` sur Active Directory.
- **DefectDojo Field** se choisit dans une liste : **Username**, **First Name**, **Last Name** et
  **Email**.
- Il est fortement recommandé de mapper un attribut vers **Email** : DefectDojo utilise l'adresse e-mail
  pour les notifications.
- Un même attribut peut alimenter plusieurs champs. Chaque champ DefectDojo ne peut être mappé
  qu'à partir d'un seul attribut.
- Sans aucun mappage, les comptes sont créés sans nom ni adresse e-mail.

**Always Update User** détermine quand le mappage est appliqué. Lorsqu'il est activé (par défaut), les
attributs mappés sont actualisés depuis l'annuaire à chaque connexion, si bien qu'un changement de nom ou d'e-mail
dans LDAP se répercute dans DefectDojo. Lorsqu'il est désactivé, ils ne sont appliqués qu'à la création du
compte.

## Group Mapping

DefectDojo peut refléter les groupes LDAP d'un utilisateur dans les groupes DefectDojo à la connexion. Cochez **Enable
Group Mapping** pour afficher les paramètres.

![image](images/sso_ldap_group_mapping.png)

- **Group Search Base** — le DN sous lequel rechercher les entrées de groupe, par exemple
  `ou=groups,dc=example,dc=com`. Requis lorsque le mappage de groupes est activé.
- **Group Type** — la façon dont votre annuaire modélise l'appartenance. Choisissez **groupOfNames** pour
  OpenLDAP et Active Directory, **groupOfUniqueNames**, ou **posixGroup**.
- **Group Limiter Regex Expression** — seuls les groupes dont le nom correspond à cette expression sont
  reflétés. Utilisez `.*` pour tous les autoriser, ou un préfixe tel que `^dd-` pour ne refléter que les groupes
  que vous souhaitez voir gérés par DefectDojo.

Les groupes sont créés à la première utilisation s'ils n'existent pas déjà. Un groupe nouvellement créé n'a aucune
permission tant qu'un superutilisateur ne les configure pas — voir
[Groupes d'utilisateurs](../../user_management/create_user_group/).

## Options supplémentaires

* **Use StartTLS** — met à niveau vers TLS une connexion `ldap://` en clair avant la liaison. Non nécessaire
  lorsque l'URI est déjà `ldaps://`.
* **Always Update User** — actualise les attributs mappés depuis l'annuaire à chaque connexion.

## Dépannage

Exécutez d'abord **Validate Config** — cela identifie généralement le problème directement. Au-delà de cela :

**Toutes les connexions échouent, mais l'annuaire est accessible.** Vérifiez que le **User Search Filter**
contient `%(user)s` et que l'attribut qu'il contient correspond à ce que les utilisateurs saisissent réellement. Un filtre
du type `(uid=%(user)s)` ne correspondra jamais si vos utilisateurs se connectent avec un
`sAMAccountName` Active Directory.

**Les connexions réussissent mais les comptes n'ont ni nom ni e-mail.** Le **User Attribute Mapping** est
vide, ou les noms d'attributs LDAP à gauche ne correspondent pas à ce que renvoie votre annuaire.

**Un nom a changé dans LDAP mais pas dans DefectDojo.** **Always Update User** est désactivé, si bien que le
mappage ne s'est appliqué qu'à la création du compte.

**Les tentatives de connexion se bloquent ou sont lentes.** Les connexions et les recherches sont limitées par un
délai d'expiration, de sorte qu'un annuaire inaccessible échoue au lieu de bloquer indéfiniment. Vérifiez **Server Reachability**
dans **Validate Config** et confirmez que le port est ouvert depuis l'hôte DefectDojo.
