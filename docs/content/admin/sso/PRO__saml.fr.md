---
title: Configuration SAML
description: Configurez SAML dans DefectDojo Pro
weight: 1
audience: pro
---

DefectDojo Pro prend en charge l'authentification SAML via l'interface **Enterprise Settings**. La version open source de DefectDojo n'inclut pas l'authentification unique (SSO) — consultez [Utilisateurs autorisés](/admin/user_management/os__authorized_users/) pour le contrôle d'accès en open source.

## URL ACS (Assertion Consumer Service)

Votre fournisseur d'identité doit savoir où envoyer (POST) la réponse SAML après l'authentification d'un utilisateur. L'URL ACS de DefectDojo est :

```
https://<your-instance>.cloud.defectdojo.com/saml2/acs/
```

Quelques points à connaître sur ce point de terminaison :

- **Ce point de terminaison n'accepte que les requêtes `POST`.** Ouvrir l'URL ACS directement dans un navigateur émet une requête GET et renverra une erreur **HTTP 405 Method Not Allowed**. Il s'agit d'un comportement attendu — cela ne signifie pas que SAML est cassé ou mal configuré. Ce point de terminaison est conçu pour être appelé par votre IdP dans le cadre du flux de redirection SAML, et non en saisissant l'URL dans un navigateur.
- **L'URL ACS est disponible en permanence sur votre instance DefectDojo Cloud** — vous n'avez pas besoin d'activer SAML dans DefectDojo avant de la renseigner dans votre IdP. Vous pouvez configurer le côté IdP et le côté DefectDojo dans l'ordre de votre choix.

## Configuration

1. Ouvrez **Enterprise Settings > SAML Settings**.

   ![image](images/sso_betaui_1.png)

2. Définissez un **Entity ID** — une étiquette ou une URL que votre fournisseur d'identité SAML utilise pour identifier DefectDojo. Ce champ est obligatoire.

3. Définissez éventuellement **Login Button Text** — le texte affiché sur le bouton sur lequel les utilisateurs cliquent pour démarrer la connexion SAML.

4. Définissez éventuellement une **Logout URL** vers laquelle rediriger les utilisateurs après leur déconnexion de DefectDojo.

5. Choisissez un **Name ID Format** :
   - **Persistent** — les utilisateurs sont identifiés de manière cohérente par SAML d'une session à l'autre.
   - **Transient** — les utilisateurs reçoivent un ID SAML différent à chaque connexion.
   - **Entity** — tous les utilisateurs partagent un seul NameID SAML.
   - **Encrypted** — le NameID de chaque utilisateur est chiffré.

6. **Required Attributes** — indiquez les attributs que DefectDojo exige dans la réponse SAML.

7. **Attribute Mapping** — associez les attributs envoyés par votre IdP aux champs utilisateur DefectDojo qu'ils doivent renseigner. Chaque ligne associe un **SAML Attribute** à un **DefectDojo Field** ; utilisez **Add Attribute Mapping** pour ajouter des lignes supplémentaires et l'icône de corbeille pour en supprimer une.

   ![image](images/sso_saml_attribute_mapping.png)

   - **SAML Attribute** est un champ libre qui doit correspondre exactement au nom d'attribut réellement émis par votre IdP. Certains IdP (par exemple Entra ID / Azure AD) envoient des URI de revendication complètes telles que `http://schemas.microsoft.com/identity/claims/emailaddress` plutôt que des noms conviviaux. Si vous ne savez pas ce que votre IdP envoie, activez **Enable SAML Debugging** (voir [Dépannage](#troubleshooting)) et examinez l'assertion dans les journaux.
   - **DefectDojo Field** est choisi dans une liste : **Username**, **First Name**, **Last Name** et **Email**.
   - Au minimum, associez l'attribut correspondant à **Username**. DefectDojo recherche les utilisateurs par nom d'utilisateur pour faire correspondre les connexions SAML aux comptes existants.
   - Il est fortement recommandé d'associer un attribut à **Email** : DefectDojo utilise l'adresse e-mail pour les notifications, et pour faire correspondre une connexion entrante à un compte existant par e-mail.
   - Un même attribut peut alimenter plusieurs champs — par exemple une revendication d'e-mail utilisée à la fois pour **Email** et **Username**. L'inverse n'est pas autorisé : chaque champ DefectDojo ne peut être associé qu'à un seul attribut.
   - Une ligne dont une seule moitié est renseignée est rejetée à l'enregistrement, et la cellule en cause est mise en évidence. Les lignes que vous ajoutez sans jamais les remplir sont ignorées plutôt que traitées comme des erreurs.

8. **Remote SAML Metadata** — l'URL où sont hébergées les métadonnées de votre fournisseur d'identité SAML.

9. Cochez **Enable SAML** en bas du formulaire pour activer la connexion SAML. Un bouton **Login With SAML** apparaîtra sur la page de connexion de DefectDojo.

   ![image](images/sso_saml_login.png).

## Options supplémentaires

* **Create Unknown User** — crée automatiquement un nouvel utilisateur DefectDojo s'il n'est pas trouvé dans la réponse SAML.
* **Allow Unknown Attributes** — autorise la connexion des utilisateurs disposant d'attributs non répertoriés dans l'Attribute Mapping.
* **Sign Assertions/Responses** — exige que toutes les réponses SAML entrantes soient signées.
* **Sign Logout Requests** — signe toutes les demandes de déconnexion envoyées par DefectDojo.
* **Force Authentication** — exige que les utilisateurs s'authentifient auprès du fournisseur d'identité à chaque connexion, indépendamment des sessions existantes.
* **Enable SAML Debugging** — journalise une sortie SAML détaillée à des fins de dépannage. Voir [Dépannage → Sortie de débogage SAML](#saml-debugging-output) pour savoir où apparaît cette sortie.

## Mappage des groupes SAML

DefectDojo peut utiliser l'assertion SAML pour attribuer automatiquement des utilisateurs à des [Groupes d'utilisateurs](../../user_management/create_user_group/). Les groupes dans DefectDojo attribuent des permissions à tous leurs membres ; le Group Mapping permet donc de gérer les permissions en masse. C'est le seul moyen de définir des permissions via SAML.

**Le mappage des groupes est facultatif.** Bien que les champs **Group Name Attribute** et **Group Limiter Regex Expression** apparaissent avec un astérisque de champ obligatoire (`*`) dans l'interface, le formulaire SAML s'enregistre sans eux, et la connexion SAML fonctionne sans mappage de groupes. Vous n'avez pas besoin de préconstruire des groupes ou des rôles dans votre IdP (par exemple les rôles d'application Azure AD) avant d'activer SAML — vous ne devez configurer ces champs que si vous voulez réellement que DefectDojo lise l'appartenance aux groupes à partir de l'assertion. Si vous ne configurez pas le mappage des groupes, les nouveaux utilisateurs SSO créés n'auront aucune permission par défaut ; voir [Accès par défaut pour les utilisateurs provisionnés par SSO](#default-access-for-sso-provisioned-users) ci-dessous.

Le champ **Group Name Attribute** indique quel attribut de l'assertion SAML contient les appartenances aux groupes de l'utilisateur. Lorsqu'un utilisateur se connecte, DefectDojo lit cet attribut et affecte l'utilisateur aux groupes correspondants. Pour limiter les groupes de l'assertion pris en compte, utilisez le champ **Group Limiter Regex Expression** — il s'agit d'une expression régulière appliquée aux noms de groupes de l'assertion, utilisée pour filtrer ceux sur lesquels DefectDojo doit agir.

La valeur doit correspondre exactement au nom d'attribut émis par votre fournisseur d'identité dans l'assertion, y compris tout préfixe d'espace de noms. Un nom court et convivial comme `groups` ne fonctionnera que si votre IdP est configuré pour émettre ce nom d'attribut littéral — de nombreux IdP utilisent à la place une URI de revendication complète.

### Attribut Group Name Attribute par fournisseur d'identité

| Fournisseur d'identité | Nom d'attribut par défaut à utiliser |
|---|---|
| **Entra ID / Azure AD** | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |
| **Okta** | `groups` (le nom d'attribut que vous avez configuré dans le Group Attribute Statement de l'application SAML) |
| **Keycloak** | `groups` (ou la valeur que vous avez définie comme « SAML Attribute Name » sur le mapper Group List) |
| **PingFederate / générique** | La valeur que vous avez configurée côté IdP — vérifiez l'assertion de votre IdP avant de supposer `groups` |

Si le mappage des groupes semble ne rien faire — les utilisateurs se connectent avec succès mais aucun groupe n'est créé ni attribué — voir [Dépannage → Le mappage des groupes SAML ne fait rien](#saml-group-mapping-does-nothing--users-log-in-but-no-groups-are-assigned) ci-dessous.

Si aucun groupe portant un nom correspondant n'existe, DefectDojo en crée un automatiquement et attribue à ses membres le rôle **Reader**. Notez que ce rôle Reader régit l'accès du membre *au groupe lui-même* — il n'accorde aucun accès aux Produits, Types de produits ou autres ressources organisationnelles sous-jacents. Ces permissions sont configurées séparément, et un groupe nouvellement créé automatiquement n'en possède aucune tant qu'un Superuser ne lui a pas attribué un rôle sur les Produits ou Types de produits concernés.

Pour activer le mappage des groupes, cochez la case **Enable Group Mapping** en bas du formulaire.

## Accès par défaut pour les utilisateurs provisionnés par SSO

Lorsqu'un nouvel utilisateur est créé via SAML (ou tout autre fournisseur social-auth) et n'est ajouté à aucun groupe via le SAML Group Mapping, il se retrouve sur une instance DefectDojo **sans aucune permission**. Il ne verra aucun Type de produit, aucun Produit et aucun Engagement lors de sa connexion — le tableau de bord apparaîtra vide.

Pour donner à chaque nouvel utilisateur SSO provisionné une base raisonnable, configurez un **Default group** + **Default group role** sur la page System Settings :

1. Ouvrez **⚙️ Configuration → System Settings** (réservé aux Superusers).
2. Définissez **Default group** sur le [Groupe d'utilisateurs](../../user_management/create_user_group/) que les nouveaux utilisateurs créés doivent rejoindre.
3. Définissez **Default group role** sur le rôle qu'ils doivent détenir dans ce groupe (par exemple **Reader**).
4. Définissez éventuellement **Default group email pattern** avec une expression régulière (par exemple `.*@yourcompany\.com$`) afin que le groupe par défaut ne s'applique qu'aux utilisateurs dont l'e-mail correspond.
5. Enregistrez.

**Default group** et **Default group role** doivent tous deux être définis — si l'un des deux est vide, le groupe par défaut n'est pas appliqué.

Ce paramètre s'applique à **chaque nouvel utilisateur créé**, y compris les utilisateurs créés via SAML, OAuth et d'autres fournisseurs social-auth, car il s'exécute sur le signal de création d'utilisateur de Django plutôt qu'à l'intérieur d'un backend d'authentification spécifique.

> **Les utilisateurs existants ne sont pas concernés.** Le groupe par défaut n'est appliqué que lors de la création initiale d'un utilisateur. Les utilisateurs DefectDojo existants conserveront leurs appartenances aux groupes actuelles même si vous modifiez ce paramètre ultérieurement.

## Différences entre Cloud et On-Premise

DefectDojo Cloud n'offre pas le même niveau de personnalisation SAML que DefectDojo On-Prem. Les seules variables modifiables le sont via l'interface utilisateur. Voici quelques-unes des différences clés :

| Fonctionnalité | Cloud | On-Premise |
|---|---|---|
| **Correspondance des noms d'utilisateur** | NameID uniquement | NameID uniquement (la variable d'environnement `SAML_USE_NAME_ID_AS_USERNAME` s'applique uniquement à l'Open Source, pas à Pro) |
| **Chiffrement des assertions SAML** | Non pris en charge actuellement | Non pris en charge actuellement |
| **Journaux de connexion SAML** | Non disponibles dans l'interface. Contactez le support pour demander les journaux. | Disponibles via les journaux du conteneur applicatif (`docker logs dojo`) |
| **Méthode de configuration** | Interface Enterprise Settings uniquement | Interface Enterprise Settings, Django Admin, ou Django Shell |
| **Variables d'environnement** | Ne peuvent pas être définies directement par les clients. Contactez le support pour toute modification. | Peuvent être définies via `dojo-compose-cli environment add` |

Si vous devez faire correspondre les utilisateurs sur un attribut autre que NameID (comme `uid` ou `email`), configurez votre fournisseur d'identité pour qu'il envoie la valeur souhaitée en tant que NameID plutôt que d'ajuster les paramètres de DefectDojo.

## Dépannage

### Sortie de débogage SAML

Lorsque **Enable SAML Debugging** (dans [Options supplémentaires](#additional-options)) est coché, DefectDojo écrit une sortie détaillée du traitement SAML — y compris les attributs bruts reçus de l'IdP — dans les journaux de l'application, au niveau `DEBUG`, sous le logger `saml2`.

| Où vous exécutez DefectDojo | Où lire la sortie de débogage |
|---|---|
| **DefectDojo Cloud** | Le journal de débogage SAML n'est pas exposé dans l'interface. Contactez le support DefectDojo pour demander les journaux d'une période donnée. |
| **On-Premise (conteneur unique)** | `docker logs dojo` (ou votre agrégation de journaux Helm/K8s) |
| **On-Premise (Helm/K8s)** | `kubectl logs deployment/defectdojo-django -c uwsgi` (ou l'agrégateur de journaux de votre cluster) |

Désactivez cette option une fois le dépannage terminé — les journaux de débogage SAML sont verbeux et peuvent contenir des valeurs d'attributs sensibles provenant de votre IdP.

### Les utilisateurs reçoivent une erreur « User not found » ou « Permission denied » après une connexion IdP réussie

Si l'assertion SAML est analysée avec succès (aucune erreur XML ou de signature) mais que DefectDojo refuse la connexion, la cause la plus fréquente est une **incohérence de nom d'utilisateur** entre l'IdP et DefectDojo.

DefectDojo recherche l'utilisateur **par nom d'utilisateur** pour faire correspondre une connexion SAML à un compte existant. Si la valeur envoyée par votre IdP dans l'attribut `username` ne correspond au nom d'utilisateur d'aucun utilisateur DefectDojo existant, la recherche échoue — même si le reste de l'assertion est valide.

Deux solutions possibles, choisissez celle qui convient à votre environnement :

- **Supprimez `username` de l'Attribute Mapping** et laissez DefectDojo utiliser par défaut le `NameID` SAML comme nom d'utilisateur. Cela convient si vos noms d'utilisateur DefectDojo correspondent déjà au format de NameID émis par votre IdP.
- **Alignez les noms d'utilisateur.** Assurez-vous que les noms d'utilisateur dans DefectDojo correspondent exactement à ce que votre IdP envoie dans la revendication `username`. Pour la plupart des organisations, la convention la plus simple consiste à faire correspondre les noms d'utilisateur DefectDojo à l'adresse e-mail de l'utilisateur, et à faire envoyer l'e-mail par l'IdP dans la revendication `username`.

Si vous ne savez pas exactement ce que l'IdP envoie, activez **Enable SAML Debugging** (ci-dessus) et examinez les attributs analysés dans les journaux.

### Le mappage des groupes SAML ne fait rien — les utilisateurs se connectent mais aucun groupe n'est attribué

La cause la plus fréquente est une incohérence entre le champ **Group Name Attribute** et le nom d'attribut réellement envoyé par votre IdP. Consultez le tableau [Attribut Group Name Attribute par fournisseur d'identité](#group-name-attribute-by-identity-provider) ci-dessus, et activez **Enable SAML Debugging** pour voir les attributs bruts renvoyés par l'IdP.
