---
title: "Bitbucket"
description: "Configuration des Connecteurs Upstream et Downstream pour Bitbucket"
weight: 25
audience: pro
---
## Connecteur Upstream

Le connecteur Bitbucket est un **Connecteur d'actifs** : il énumère les dépôts des espaces de travail (workspaces) Bitbucket Cloud que vous indiquez et crée un Actif DefectDojo pour chaque dépôt, regroupé en Organisations par projet Bitbucket. Aucune constatation n'est importée.

#### Prérequis

Bitbucket Cloud nécessite un jeton API Atlassian **à portée définie (scoped)** — les jetons API Atlassian classiques (sans portée) sont rejetés par Bitbucket avec une erreur « API Token provided has no Bitbucket scopes ».

1. Rendez-vous sur [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) et choisissez **Create API token with scopes**.
2. Sélectionnez l'application **Bitbucket**, puis accordez les portées en lecture : `read:account:bitbucket`, `read:workspace:bitbucket`, `read:repository:bitbucket` et `read:project:bitbucket`.

Seul Bitbucket Cloud (bitbucket.org) est pris en charge. Bitbucket Server a atteint sa fin de vie en 2024, et Bitbucket Data Center n'est pas pris en charge.

#### Mappages du Connecteur

1. Saisissez `https://bitbucket.org` dans le champ **Location**.
2. Saisissez l'e-mail du compte Atlassian auquel appartient le jeton dans le champ **Email**.
3. Saisissez le jeton API à portée définie dans le champ **Secret**.
4. Saisissez un ou plusieurs slugs d'espace de travail (séparés par des virgules) dans le champ **Workspace Slugs**. Ce champ est obligatoire : les jetons API à portée définie de Bitbucket ne peuvent pas lister automatiquement les espaces de travail, DefectDojo doit donc être informé des espaces de travail à lire.

Chaque dépôt devient un Enregistrement portant le nom du dépôt, regroupé par **projet** Bitbucket.

## Connecteur Downstream

L'intégration Bitbucket vous permet de transmettre des tickets vers le [suivi des tickets](https://support.atlassian.com/bitbucket-cloud/docs/enable-an-issue-tracker/) d'un dépôt Bitbucket Cloud.

Le suivi des tickets est optionnel dans Bitbucket et doit être activé sur le dépôt avant que DefectDojo puisse y créer des tickets. Pour l'activer, ouvrez le dépôt dans Bitbucket, sélectionnez **Repository settings**, puis activez le suivi des tickets sous **Features**.

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur `https://bitbucket.org`.
- **Email** doit être l'adresse e-mail du compte Atlassian auquel appartient le jeton API.
- **API Token** doit être défini sur un jeton API Atlassian à portée limitée.

Les mots de passe d'application Bitbucket sont dépréciés par Atlassian et ne fonctionneront pas avec cette intégration. Pour créer un jeton API :

1. Ouvrez les [paramètres du compte Atlassian](https://id.atlassian.com/manage-profile/security/api-tokens) et choisissez **Security**, puis **Create and manage API tokens**.
2. Choisissez **Create API token with scopes**, nommez le jeton et définissez une date d'expiration.
3. Sélectionnez **Bitbucket** comme application.
4. Accordez au jeton l'autorisation de lire les dépôts, ainsi que de lire et écrire des tickets.

### Mappage du suivi des tickets

- **Workspace** doit correspondre au slug de l'espace de travail contenant le dépôt, tel qu'il apparaît dans les URL de bitbucket.org.
- **Repository Slug** doit correspondre au slug du dépôt dans lequel vous souhaitez créer des tickets.

### Détails du mappage de la sévérité

Ceci correspond au champ Priority des tickets Bitbucket. Les attributs du formulaire sont fournis par défaut, et chaque valeur doit être l'une des priorités de Bitbucket : `trivial`, `minor`, `major`, `critical` ou `blocker`.

- **Severity Field Name** : `priority`
- **Info Mapping** : `trivial`
- **Low Mapping** : `minor`
- **Medium Mapping** : `major`
- **High Mapping** : `critical`
- **Critical Mapping** : `blocker`

### Détails du mappage du statut

Ceci correspond au champ State des tickets Bitbucket. Chaque valeur doit être l'un des états de ticket de Bitbucket : `new`, `open`, `resolved`, `on hold`, `invalid`, `duplicate`, `wontfix` ou `closed`.

- **Status Field Name** : `state`
- **Active Mapping** : `new`
- **Closed Mapping** : `resolved`
- **False Positive Mapping** : `invalid`
- **Risk Accepted Mapping** : `wontfix`
