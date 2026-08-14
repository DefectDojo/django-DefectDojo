---
title: Tableaux des autorisations d'action
description: Toutes les autorisations utilisateur de DefectDojo Pro en détail
weight: 4
audience: pro
aliases:
- /fr/en/customize_dojo/user_management/user_permission_chart
---

> **Fonctionnalité DefectDojo Pro.** Le système RBAC Membres / Groupes / Rôles globaux décrit sur cette page fait partie de DefectDojo Pro. La version open source de DefectDojo utilise le modèle [Utilisateurs autorisés](../os__authorized_users/) — consultez cette page pour le contrôle d'accès en version open source, ainsi que les [notes de mise à niveau 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) si vous passez d'une édition à l'autre.

## Tableau des autorisations par rôle

Ce tableau vise à répertorier toutes les autorisations liées à un Produit ou à un Type de produit, ainsi que les autorisations disponibles pour chaque rôle.

Les cinq rôles ci-dessous sont les **rôles intégrés** de DefectDojo Pro. Ce sont des préréglages verrouillés : leurs autorisations sont identiques sur chaque instance et ne peuvent pas être modifiées. Si vous avez créé vos propres rôles, ce tableau décrit les rôles intégrés dont ils ont été clonés, plutôt que les rôles eux-mêmes. Pour le catalogue complet des autorisations qu'un rôle peut recevoir, voir [Rôles RBAC personnalisés](../pro__custom_rbac_roles/#choosing-permissions).

| **Section** | **Autorisation** | Lecteur | Rédacteur | Mainteneur | Propriétaire | Importateur API |
| --- | --- | --- | --- | --- | --- | --- |
| **Accès au Produit / Type de produit** | Consulter le Produit ou le Type de produit assigné ¹ | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Consulter les Produits, Engagements, Tests, Constatations, Points de terminaison imbriqués | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Ajouter de nouveaux Produits (au sein du Type de produit assigné) ² |  |  | ☑️ | ☑️ |  |
|  | Supprimer les Produits ou Types de produit assignés |  |  |  | ☑️ |  |
| **Adhésion au Produit / Type de produit** | Ajouter des Utilisateurs en tant que Membres (à l'exclusion du Rôle Propriétaire) |  |  | ☑️ | ☑️ |  |
|  | Modifier les Rôles des membres (à l'exclusion du Rôle Propriétaire) |  |  | ☑️ | ☑️ |  |
|  | Modifier les Rôles des membres (y compris le Rôle Propriétaire) |  |  |  | ☑️ |  |
|  | Se retirer soi-même de l'adhésion au Produit / Type de produit | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | Attribuer un Rôle Propriétaire à un autre Utilisateur |  |  |  | ☑️ |  |
|  | Modifier une adhésion Produit/Type de produit associée au sein d'un Groupe³ |  |  |  | ☑️ |  |
|  | Supprimer une adhésion Produit/Type de produit associée au sein d'un Groupe³ |  |  |  |  |  |
| **Engagements** (Au sein d'un Produit) | Ajouter, Modifier des Engagements |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Consulter les Acceptations du risque ⁴ |  | ☑️ | ☑️ | ☑️ |  |
|  | Ajouter, Modifier des Acceptations du risque |  | ☑️ | ☑️ | ☑️ |  |
|  | Supprimer des Engagements |  |  | ☑️ | ☑️ |  |
| **Tests** (Au sein d'un Produit) | Ajouter des Tests |  | ☑️ | ☑️ | ☑️ |  |
|  | Modifier des Tests |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Supprimer des Tests |  |  | ☑️ | ☑️ |  |
| **Constatations**  (Au sein d'un Produit) | Ajouter des Constatations |  | ☑️ | ☑️ | ☑️ |  |
|  | Modifier des Constatations |  | ☑️ | ☑️ | ☑️ |  |
|  | Importer, Réimporter des Résultats de scan |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Supprimer des Constatations |  |  | ☑️ | ☑️ |  |
|  | Ajouter, Modifier, Supprimer des Groupes de constatations |  | ☑️ | ☑️ | ☑️ |  |
| **Autres données**  (Au sein d'un Produit) | Ajouter, Modifier des Points de terminaison |  | ☑️ | ☑️ | ☑️ |  |
|  | Supprimer des Points de terminaison |  |  | ☑️ | ☑️ |  |
|  | Modifier des Référentiels |  | ☑️ | ☑️ | ☑️ |  |
|  | Supprimer des Référentiels |  |  | ☑️ | ☑️ |  |
|  | Consulter l'historique des notes | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | Ajouter, Modifier, Supprimer ses propres Notes | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Modifier les Notes d'autres utilisateurs |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Supprimer les Notes d'autres utilisateurs |  |  | ☑️ | ☑️ |  |

1. Un utilisateur qui se voit attribuer des autorisations uniquement au niveau du Produit ne peut pas consulter le Type de produit dans lequel il est contenu.
2. Lorsqu'un nouveau Produit est ajouté sous un Type de produit, tous les Utilisateurs au niveau du Type de produit seront ajoutés en tant que Membres du nouveau Produit avec leur Rôle au niveau du Type de produit.
3. L'utilisateur qui souhaite apporter des modifications à un Groupe doit également disposer des **Autorisations de configuration** **Modifier le Groupe**, ainsi que d'un **Rôle de configuration de Groupe** **Mainteneur ou Propriétaire** dans le Groupe qu'il souhaite modifier.
4. La visibilité des Acceptations du risque est conditionnée par une autorisation minimale distincte de celle des Constatations — un Lecteur sur le Produit peut consulter les Constatations sous-jacentes mais **ne peut pas** consulter les Acceptations du risque auxquelles ces Constatations appartiennent.  Pour plus de détails sur les autorisations liées aux Acceptations du risque, le comportement de la date d'expiration et les processus de réinstatement, voir [Acceptations du risque (Pro)](/triage_findings/findings_workflows/pro__risk_acceptance/#risk-acceptance-permissions-and-visibility).

## Tableau des Autorisations de configuration

Chaque Autorisation de configuration se rapporte à une fonction particulière du logiciel, et dispose d'un ensemble d'actions associées qu'un utilisateur peut effectuer en lien avec cette fonction.

La majorité des Autorisations de configuration donnent aux utilisateurs l'accès à certaines pages de l'interface.

| **Autorisation de configuration** | **Consulter ☑️** | **Ajouter ☑️** | **Modifier ☑️** | **Supprimer ☑️** |
| --- | --- | --- | --- | --- |
| Gestionnaire d'identifiants | Accéder à la page **⚙️Configuration \> Gestionnaire d'identifiants** | Ajouter de nouvelles entrées au Gestionnaire d'identifiants | Modifier les entrées du Gestionnaire d'identifiants | Supprimer les entrées du Gestionnaire d'identifiants |
| Environnements de développement | n/a | Ajouter de nouveaux Environnements de développement à la liste 🗓️**Engagements \> Environnements** | Modifier les Environnements de développement dans la liste 🗓️**Engagements \> Environnements** | Supprimer des Environnements de développement de la liste **🗓️Engagements \> Environnements** |
| Modèles de constatation¹ | Accéder à la page **Constatations \> Modèles de constatation** | Ajouter un Modèle de constatation | Modifier un Modèle de constatation | Supprimer un Modèle de constatation |
| Groupes | Accéder à la page **👤Utilisateurs \> Groupes** | Ajouter un nouveau Groupe d'utilisateurs | Superutilisateur uniquement | Superutilisateur uniquement |
| Instances Jira | Accéder à la page **⚙️Configuration \> JIRA** | Ajouter une nouvelle Configuration JIRA | Modifier une Configuration JIRA existante | Supprimer une Configuration JIRA |
| Types de langage |  |  |  |  |
| Bannière de connexion | n/a | n/a | Modifier la bannière de connexion, située sous **⚙️Configuration \> Bannière de connexion** | n/a |
| Annonces | n/a | n/a | Configurer les Annonces, situées sous  **⚙️Configuration \> Annonces** | n/a |
| Types de note | Accéder à la page ⚙️Configuration \> Types de note | Ajouter un Type de note | Modifier un Type de note | Supprimer un Type de note |
| Moteurs de priorisation | Accéder à la page de configuration du Moteur de priorisation | Ajouter un nouveau Moteur de priorisation | Modifier un Moteur de priorisation existant | Supprimer un Moteur de priorisation |
| Types de produit | n/a | Ajouter un nouveau Type de produit (sous Produits \> Type de produit) | n/a | n/a |
| Questionnaires | Accéder à la page **Questionnaires \> Tous les questionnaires** | Ajouter un nouveau Questionnaire | Modifier un Questionnaire existant | Supprimer un Questionnaire |
| Questions | Accéder à la page **Questionnaires \> Questions** | Ajouter une nouvelle Question | Modifier une Question existante | n/a |
| Réglementations | n/a | Ajouter une Réglementation à la page **⚙️Configuration \> Réglementations** | Modifier une Réglementation existante | Supprimer une Réglementation |
| Planification du service de planification | Accéder à la page **Planification** | Superutilisateur uniquement | Modifier une Planification existante (changer le déclencheur, activer/désactiver) | Supprimer une Planification |
| Configuration SLA | Accéder à la page **⚙️Configuration \> Configuration SLA** | Ajouter une nouvelle Configuration SLA | Modifier une Configuration SLA existante | Supprimer une Configuration SLA |
| Types de test | n/a | Ajouter un nouveau Type de test (sous **Engagements \> Types de test**) | Modifier un Type de test existant | n/a |
| Configuration des outils | Accéder à la page **⚙️Configuration \> Configuration des outils** | Ajouter une nouvelle Configuration d'outil | Modifier une Configuration d'outil existante | Supprimer une Configuration d'outil |
| Types d'outils | Accéder à la page **⚙️Configuration \> Types d'outils** | Ajouter un nouveau Type d'outil | Modifier un Type d'outil existant | Supprimer un Type d'outil |
| Utilisateurs | Accéder à la page **👤Utilisateurs \> Utilisateurs** | Ajouter un nouvel Utilisateur à DefectDojo | Modifier un Utilisateur existant | Supprimer un Utilisateur |

1. L'accès à la page Modèles de constatation nécessite également le Rôle global **Rédacteur, Mainteneur** ou **Propriétaire** pour cet utilisateur.

## Autorisations de configuration de Groupe

| Configuration Permission | **Lecteur** | **Mainteneur** | **Propriétaire** |
| --- | --- | --- | --- |
| Consulter le Groupe | ☑️ | ☑️ | ☑️ |
| Se retirer soi-même du Groupe | ☑️ | ☑️ | ☑️ |
| Modifier le rôle d'un Membre dans un Groupe |  | ☑️ | ☑️ |
| Modifier ou Supprimer une adhésion à un Produit ou à un Type de produit depuis un Groupe¹ |  | ☑️ | ☑️ |
| Changer le rôle d'un Membre du Groupe en Propriétaire |  |  | ☑️ |
| Supprimer le Groupe |  |  | ☑️ |

1. Cela nécessite également que l'Utilisateur dispose au moins d'un Rôle Mainteneur sur le Produit ou le Type de produit qu'il souhaite modifier.
