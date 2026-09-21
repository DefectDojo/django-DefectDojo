---
title: "GitLab"
description: "Configuration des Connecteurs Upstream et Downstream pour GitLab"
weight: 65
audience: pro
---
## Connecteur Upstream

Le connecteur GitLab est un **connecteur d'actifs (Asset Connector)** : il énumère chaque projet (dépôt) auquel votre jeton a accès et crée un actif DefectDojo pour chacun, regroupés en organisations par espace de noms (namespace) GitLab (groupe ou utilisateur). Aucune constatation n'est importée.

#### Prérequis

Vous aurez besoin d'un jeton d'accès personnel (Personal Access Token) avec le scope **read_api**. Nous recommandons de créer le jeton depuis un compte de service dédié ; le connecteur liste les projets dont ce compte est membre.

#### Mappages du connecteur

1. Saisissez votre URL GitLab dans le champ **Location** : `https://gitlab.com`, ou l'URL de base de votre instance auto-hébergée.
2. Saisissez le Personal Access Token dans le champ **Secret**.

Chaque projet devient un enregistrement nommé d'après le projet, regroupé par son **namespace**. Les projets en attente de suppression dans GitLab (supprimés par un utilisateur, mais pas encore purgés par la tâche de fond de GitLab) sont exclus automatiquement ; la suppression d'un projet marque donc son enregistrement comme `MISSING` lors de la prochaine synchronisation, au lieu de laisser un actif fantôme renommé.

## Connecteur Downstream

L'intégration GitLab vous permet d'ajouter des tickets à un [projet GitLab](https://docs.gitlab.com/ee/user/project/).

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur le lien de votre serveur GitLab, par exemple `https://gitlab.com/`.
- **Token** doit être défini sur un jeton d'accès personnel GitLab. Le jeton doit disposer des portées API. Consultez le [guide GitLab pour créer un jeton d'accès personnel](https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token).

### Mappage du suivi des tickets

- **Project Name** : le nom du projet dans GitLab vers lequel vous souhaitez envoyer les tickets.

### Détails du mappage de la sévérité

Ceci correspond au champ Priority de GitLab.
- **Severity Field Name** : `Priority`
- **Info Mapping** : `1`
- **Low Mapping** : `2`
- **Medium Mapping** : `3`
- **High Mapping** : `4`
- **Critical Mapping** : `5`

### Détails du mappage du statut

Par défaut, GitLab dispose des statuts « opened » et « closed ».  Des étiquettes de statut supplémentaires peuvent être ajoutées si vous souhaitez suivre les statuts Faux positif ou Risque accepté.  Consultez la [documentation GitLab](https://docs.gitlab.com/user/work_items/status/) pour plus de détails.

- **Status Field Name** : `Status`
- **Active Mapping** : `opened`
- **Closed Mapping** : `closed`
- **False Positive Mapping** : `closed`
- **Risk Accepted Mapping** : `closed`
