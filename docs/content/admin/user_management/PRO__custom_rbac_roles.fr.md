---
title: Rôles RBAC personnalisés
description: Créez vos propres rôles en choisissant des autorisations individuelles,
  en utilisant les cinq rôles intégrés comme points de départ clonables
weight: 5
audience: pro
---

> **Fonctionnalité DefectDojo Pro.** Le système RBAC Membres / Groupes / Rôles globaux décrit sur cette page fait partie de DefectDojo Pro. La version open source de DefectDojo utilise le modèle [Utilisateurs autorisés](../os__authorized_users/). Consultez cette page pour le contrôle d'accès en open source, ainsi que les [notes de mise à niveau 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) si vous passez d'une édition à l'autre.

DefectDojo Pro est livré avec cinq rôles : **Reader**, **Writer**, **Maintainer**, **Owner**, et **API Importer**. Si aucun d'entre eux ne convient, vous pouvez désormais créer votre propre rôle en choisissant exactement les autorisations qu'il accorde.

Un rôle personnalisé fonctionne partout où un rôle intégré fonctionne : en tant que Rôle global, en tant que rôle d'un Groupe, en tant que rôle de groupe par défaut, et en tant que rôle de membre sur une Organisation ou un Actif individuel.

Les cinq rôles intégrés deviennent des **préréglages verrouillés et clonables**. Leurs autorisations restent inchangées (consultez les [tableaux des autorisations par action](../user_permission_chart/) pour savoir ce que chacun accorde), ils ne peuvent être ni modifiés ni supprimés, et les cloner est la méthode recommandée pour créer un nouveau rôle.

## Avant de commencer

La gestion des rôles personnalisés est désactivée par défaut. Un **superutilisateur** l'active depuis **Settings > Feature Flags**, en activant **Custom Roles**. Consultez [Indicateurs de fonctionnalités](/admin/feature_flags/pro__feature_flags/) pour savoir comment fonctionne cette page.

Tant que la fonctionnalité est désactivée, la page Rôles reste consultable : vous pouvez voir les rôles intégrés et leurs autorisations, mais vous ne pouvez rien créer, modifier, cloner ou supprimer.

La gestion des rôles nécessite le statut de **superutilisateur** ou le Rôle global **Owner** intégré. Ceci est volontaire et ne peut être délégué à un rôle personnalisé : consultez [Ce que débloque un Rôle global personnalisé](#what-a-custom-global-role-unlocks).

## Ouvrir la page Rôles

Accédez à **👤 Users > Roles** dans la barre latérale gauche. Cette entrée de menu est visible par les superutilisateurs et les détenteurs du Rôle global Owner intégré.

![La page Rôles listant les rôles intégrés et personnalisés](images/pro_roles_list.png)

Le tableau répertorie tous les rôles de votre instance :

| Colonne | Ce qu'elle affiche |
| --- | --- |
| **ID** | L'identifiant numérique du rôle. Utile pour filtrer le tableau des Utilisateurs ou pour les appels à l'API. |
| **Nom** | Le nom du rôle. |
| **Description** | Votre propre note décrivant l'objet du rôle. Facultatif, et vide à moins que quelqu'un ne le renseigne. Les rôles intégrés n'en ont pas par défaut. |
| **Autorisations** | Un décompte des autorisations accordées. Cliquez dessus pour ouvrir une vue en lecture seule de la grille complète. |
| **Utilisateurs** | Le nombre d'utilisateurs détenant ce rôle en tant que Rôle global. Cliquez pour les voir dans le tableau des Utilisateurs. |
| **Type** | **Built-in** pour les cinq préréglages, **Custom** pour les rôles que vous avez créés. |

Chaque colonne est triable et filtrable, et la recherche par mot-clé porte sur le nom et la description.

## Créer un rôle

### Cloner un rôle intégré (recommandé)

Le clonage vous permet de partir d'un ensemble d'autorisations déjà éprouvé plutôt que d'une grille vide, ce qui réduit considérablement le risque d'oublier accidentellement une autorisation dont un rôle a besoin.

1. Recherchez le rôle le plus proche de ce que vous souhaitez.
2. Ouvrez son menu **⋮** et choisissez **Clone Role**.
3. Une copie est créée immédiatement, nommée `<original> (copy)`, avec les mêmes autorisations et la même description que le rôle d'origine.
4. Ouvrez le menu **⋮** de la copie, choisissez **Edit Role**, puis renommez-la et ajustez ses autorisations.

Les rôles intégrés peuvent être clonés même s'ils ne peuvent pas être modifiés. Le clone conserve la trace du rôle dont il provient.

### Partir de zéro

1. Cliquez sur **New Role**.
2. Donnez-lui un **Name** (obligatoire) et, éventuellement, une **Description**.
3. Choisissez ses autorisations dans la grille ci-dessous (voir la section suivante).
4. Cliquez sur **Save Role**.

Les noms de rôle doivent être uniques, et la vérification ignore la casse : si `Triage Lead` existe, `triage lead` est rejeté.

## Choisir les autorisations

![La grille des autorisations dans le formulaire de rôle](images/pro_role_permission_grid.png)

Les autorisations sont regroupées en trois tableaux, plus une liste de contrôle.

**Les autorisations sur les objets** s'appliquent aux Organisations et aux Actifs auxquels le rôle est attribué, ainsi qu'à tout ce qui leur est imbriqué.

| Ligne | Voir | Ajouter | Modifier | Supprimer |
| --- | --- | --- | --- | --- |
| Organisation | ☑️ | ☑️ | ☑️ | ☑️ |
| Actif | ☑️ | ☑️ ¹ | ☑️ | ☑️ |
| Engagement | ☑️ | ☑️ | ☑️ | ☑️ |
| Test | ☑️ | ☑️ | ☑️ | ☑️ |
| Constatation | ☑️ | ☑️ | ☑️ | ☑️ |
| Groupe de constatations | ☑️ | ☑️ | ☑️ | ☑️ |
| Acceptation du risque | ☑️ | ☑️ | ☑️ | ☑️ |
| Emplacement | ☑️ | ☑️ | ☑️ | ☑️ |
| Composant | ☑️ | | | |
| Note | ² | ☑️ | ☑️ | ☑️ |
| Benchmark | ² | | ☑️ | ☑️ |
| Langue | ☑️ | ☑️ | ☑️ | ☑️ |
| Technologie | ☑️ | ☑️ | ☑️ | ☑️ |
| Configuration de l'analyse API de l'Actif | ☑️ | ☑️ | ☑️ | ☑️ |
| Fichiers de suivi de l'Actif | ☑️ | ☑️ | ☑️ | ☑️ |
| Groupe | ☑️ | | ☑️ | ☑️ |

1. **Actif > Ajouter** signifie créer un nouvel Actif au sein d'une Organisation à laquelle le rôle est attribué.
2. La visualisation des Notes et des Benchmarks est héritée : un rôle pouvant consulter l'Engagement, le Test, la Constatation ou l'Actif parent peut consulter ses Notes et ses Benchmarks. Ces cellules affichent une icône **?** au lieu d'une case à cocher.

**Les autorisations de Groupe et de Membre** contrôlent qui peut gérer l'appartenance. Les colonnes ici sont Voir, Gérer, Ajouter, Ajouter un Owner, Modifier et Supprimer.

| Ligne | Actions disponibles |
| --- | --- |
| Groupe d'Organisation, Groupe d'Actif | Voir, Ajouter, Ajouter un Owner, Modifier, Supprimer |
| Membre d'Organisation, Membre d'Actif, Membre de Groupe | Gérer, Ajouter un Owner, Supprimer |

**Les autorisations de fonctionnalités globales** conditionnent l'accès à des fonctionnalités Pro à l'échelle de l'instance plutôt qu'à des Organisations ou des Actifs individuels, **elles ne prennent donc effet que lorsque le rôle est détenu en tant que Rôle global**. Les accorder sur un rôle utilisé uniquement comme appartenance à un Actif n'a aucun effet.

| Ligne | Actions disponibles |
| --- | --- |
| Modèle de rapport | Voir, Ajouter, Modifier, Supprimer |
| Rapport généré | Voir, Ajouter, Supprimer |
| Connector, Sensei, Hiérarchie des Actifs, Version Manager, Tuner, Universal Parser, Règle, Intégration | Voir, Modifier |
| Politique de mitigation | Modifier |
| Journal d'audit, Metering | Voir |

**Les autorisations supplémentaires** forment une liste de contrôle de capacités qui ne correspondent pas au schéma Voir/Ajouter/Modifier/Supprimer :

* **Configurer les notifications de l'Actif** : choisir quelles notifications un Actif envoie, et où.
* **Importer un résultat d'analyse** : importer et réimporter des résultats d'analyse, en créant et en mettant à jour des Constatations.
* **Partager la disposition du tableau de bord** : publier une disposition de Tableau de bord pour d'autres utilisateurs. Rôle global uniquement.
* **Partager les préférences de tableau** : publier une vue de tableau enregistrée (colonnes, filtres, ordre de tri). Rôle global uniquement.
* **Voir l'historique des notes** : voir qui a modifié une note et quand.

### Comment lire la grille

![La vue en lecture seule des autorisations d'un rôle](images/pro_role_permissions_modal.png)

| Ce que vous voyez | Ce que cela signifie |
| --- | --- |
| Une case à cocher vide | L'autorisation existe et n'est pas accordée. Cliquez pour l'accorder. |
| Une case à cocher cochée | Accordée. |
| Une cellule vide et grisée | L'autorisation n'existe pas pour cette ligne et cette action. Non sélectionnable. |
| Une icône **?** | La visualisation est héritée d'un objet parent, il n'y a donc rien à accorder ici. |
| Une coche verte ✔ (vue en lecture seule) | Accordée. |
| Une croix rouge ✘ (vue en lecture seule) | Non accordée. |

Dans chaque ligne, l'autorisation la plus à gauche (**Voir**, ou **Gérer** sur les lignes de membres) conditionne le reste de la ligne. Vous devez l'accorder avant que les autres cellules de cette ligne ne deviennent disponibles, car un rôle ne peut pas réellement modifier ou supprimer ce qu'il ne peut pas voir. Décocher cette condition efface également le reste de la ligne.

## Modifier, cloner et supprimer

Le menu **⋮** de chaque ligne propose **Edit Role**, **Clone Role**, **Delete Role**, et **Role History**.

Les rôles intégrés ne proposent que **Clone Role**. Ils ne peuvent être ni modifiés ni supprimés, par personne, y compris les superutilisateurs. Cela permet de conserver une base de référence connue et de garder les mises à niveau prévisibles.

La suppression d'un rôle encore attribué à quelqu'un échouera. Réattribuez ou supprimez d'abord ces attributions, puis supprimez le rôle. Les attributions prises en compte à cet effet sont les appartenances à une Organisation et à un Actif (utilisateur comme groupe), les Rôles globaux, les appartenances à un Groupe, et le rôle de groupe par défaut dans les Paramètres système.

L'API peut effectuer cette réattribution pour vous en un seul appel. Consultez [Gérer les rôles via l'API](#managing-roles-through-the-api).

## Attribuer un rôle personnalisé

Les rôles personnalisés apparaissent dans chaque liste déroulante de rôles, aux côtés des rôles intégrés :

| Où | Comment |
| --- | --- |
| **Rôle global sur un utilisateur** | Le champ **Global Role** du formulaire de l'utilisateur. Superutilisateurs uniquement. Consultez [Définir les autorisations d'un utilisateur](../set_user_permissions/). |
| **Rôle global sur un groupe** | Le champ **Global Role** du formulaire du groupe. Consultez [Partager les autorisations : Groupes d'utilisateurs](../create_user_group/). |
| **Appartenance à une Organisation ou à un Actif** | La boîte de dialogue Autorisations sur l'Organisation ou l'Actif, pour les utilisateurs comme pour les groupes. Consultez [Définir les autorisations dans Pro](../pro_permissions_overhaul/). |
| **Rôle de groupe par défaut** | **Default group role** dans les Paramètres système, appliqué aux utilisateurs nouvellement créés. Consultez [Gérer les autorisations par défaut](../about_perms_and_roles/#manage-default-permissions). |
| **Rôle au sein d'un groupe** | La liste déroulante de rôles dans la liste des membres d'un groupe. Cette liste ne propose que les rôles accordant au moins une autorisation de Groupe ; un rôle sans autorisation de Groupe n'y apparaîtra donc pas. |

Deux contraintes sont à connaître :

* **Le niveau Owner est réservé.** Un rôle personnalisé ne peut jamais être un rôle de niveau Owner. Seul le rôle intégré Owner l'est, et lui seul détient donc le pouvoir implicite de gérer d'autres Owners.
* **Accorder le rôle Owner à quelqu'un d'autre nécessite toujours l'autorisation Add Owner correspondante**, que vous le fassiez sur une Organisation, un Actif ou un Groupe.

## Ce que débloque un Rôle global personnalisé

Certaines parties de l'interface sont conditionnées à un Rôle global minimum plutôt qu'à une autorisation individuelle. Pour que les rôles personnalisés fonctionnent avec ces conditions, DefectDojo classe un Rôle global personnalisé par rapport aux niveaux intégrés : un rôle personnalisé obtient le niveau le plus élevé dont il couvre **complètement** les autorisations.

* Un rôle personnalisé qui couvre tout ce qu'accorde Maintainer est traité comme Maintainer pour ces conditions.
* Couvrez tout ce qu'accorde Writer, et il est traité comme Writer. Idem pour Reader.
* Ne couvrez complètement aucun d'entre eux, et il n'obtient aucun niveau. Ses autorisations individuelles fonctionnent malgré tout exactement comme accordées ; seules les conditions d'interface basées sur le niveau restent fermées.
* **Le niveau Owner ne peut jamais être obtenu de cette façon.** La gestion des rôles, et tout ce qui est conditionné au Rôle global Owner, reste réservée aux superutilisateurs et au rôle intégré Owner.

La couverture doit être complète, ce qui surprend parfois. Un rôle cloné à partir de Maintainer obtient le niveau Maintainer. Reconstruisez les autorisations de Maintainer à la main, oubliez-en une, et le rôle se retrouve au niveau Writer à la place. Si un Rôle global personnalisé n'affiche pas l'interface que vous attendiez, comparez-le au niveau intégré correspondant dans les [tableaux des autorisations par action](../user_permission_chart/).

## Historique des rôles

Les rôles personnalisés conservent une piste d'audit. Ouvrez **Role History** depuis le menu **⋮** d'un rôle pour voir quelles autorisations ont été accordées ou révoquées, par qui, et quand, ainsi que les changements concernant qui détient le rôle.

Deux choses que cet historique ne montre pas : les modifications du nom et de la description du rôle lui-même, et les autorisations des rôles intégrés (celles-ci sont préconfigurées, jamais modifiées, et ne génèrent donc jamais d'historique).

L'historique des rôles est une simple lecture, il est donc disponible que la fonctionnalité Custom Roles soit activée ou non.

## Gérer les rôles via l'API

Les rôles sont disponibles à l'adresse `/api/v2/roles/`. Les lectures sont ouvertes à tout utilisateur authentifié, car les clients ont besoin de la liste des rôles pour peupler les listes déroulantes. Les écritures nécessitent le statut de superutilisateur ou le Rôle global Owner intégré, ainsi que l'indicateur de fonctionnalité Custom Roles.

| Opération | Requête |
| --- | --- |
| Lister les rôles | `GET /api/v2/roles/` |
| Récupérer un rôle | `GET /api/v2/roles/{id}/` |
| Lister toutes les autorisations attribuables | `GET /api/v2/roles/permissions_catalog/` |
| Créer un rôle | `POST /api/v2/roles/` avec `name`, `description` en option, et une liste `permissions` |
| Remplacer les autorisations d'un rôle | `PATCH /api/v2/roles/{id}/` avec une liste `permissions` |
| Cloner un rôle | `POST /api/v2/roles/{id}/clone/` avec un `name` et une `description` en option |
| Supprimer un rôle | `DELETE /api/v2/roles/{id}/` |
| Supprimer un rôle et déplacer ses attributions | `DELETE /api/v2/roles/{id}/?reassign_to={other_role_id}` |
| Lire l'historique d'un rôle | `GET /api/v2/roles/{id}/history/` |

Remarques :

* `permissions` **remplace** la liste des autorisations accordées au rôle plutôt que de s'y ajouter. Envoyez l'ensemble complet que vous souhaitez voir le rôle obtenir au final.
* `?reassign_to=` déplace toutes les attributions du rôle supprimé vers le rôle que vous indiquez, en une seule transaction. C'est le seul moyen de réattribuer en masse : l'interface ne le propose pas.
* Toute tentative de modification ou de suppression d'un rôle intégré renvoie `403`. Modifier une valeur d'autorisation inconnue, réutiliser un nom de rôle existant, ou supprimer un rôle en cours d'utilisation sans `reassign_to` renvoie `400` accompagné d'une explication.
* `is_owner` ne peut pas être défini via l'API. L'envoyer est accepté mais ignoré.

## À savoir

* **Plusieurs rôles sur le même objet accordent l'union de leurs autorisations.** Si un utilisateur détient un rôle directement sur un Actif et en hérite un autre via un groupe, il obtient tout ce que l'un ou l'autre rôle accorde. Les rôles ne font qu'ajouter des autorisations, jamais en retirer.
* **Les modifications d'autorisations sont prises en compte au prochain chargement de page**, pas instantanément dans la vue actuelle. Les tâches en arrière-plan peuvent prendre jusqu'à 30 secondes, et les données d'autorisation mises en cache jusqu'à 5 minutes, avant de refléter une modification.
* **Les listes déroulantes de rôles affichent jusqu'à 250 rôles.** Au-delà, certains rôles n'apparaîtront plus dans les listes déroulantes, bien qu'ils continuent de fonctionner.
* **Maintainer et Owner peuvent ajouter des Organisations, mais la grille ne l'indique pas.** Pour ces deux rôles, cette autorisation est stockée comme une autorisation de portée globale, et la grille ne lit que les autorisations de portée objet ; leur cellule **Organisation > Ajouter** apparaît donc comme non accordée. Cloner l'un ou l'autre rôle préserve cette autorisation.
* **La terminologie suit votre instance.** Cette documentation utilise Organisation et Actif, les libellés par défaut. Si votre instance a désactivé le renommage Organisation / Actif, les mêmes lignes affichent Type de produit et Produit à la place.
* **La page Rôles est en lecture seule pour tous les autres.** Un utilisateur qui accède directement à `/settings/roles` peut voir les rôles et leurs autorisations mais ne peut rien modifier. Les données d'autorisation ne sont pas sensibles, et le serveur applique la véritable limite à chaque écriture.
