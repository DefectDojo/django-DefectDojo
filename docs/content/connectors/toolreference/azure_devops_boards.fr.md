---
title: "Azure DevOps Boards"
description: "Comment configurer le Connecteur Downstream Azure DevOps Boards pour DefectDojo"
weight: 21
audience: pro
---
### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur votre URL Azure - par exemple `https://dev.azure.com/{your organization}`
- **Token** doit être défini sur un jeton d'accès personnel Azure.

L'authentification avec Azure DevOps nécessite un [jeton d'accès personnel](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)
dont les autorisations sont définies sur « Read, Write and Manage » pour les « Work Items » du projet Azure avec lequel vous souhaitez travailler.

### Mappage du suivi des tickets

Ces informations déterminent la façon dont DefectDojo associe les attributs d'une Constatation ou d'un Groupe de constatations à un projet donné dans Azure DevOps :

#### Détails du mappage du suivi des tickets

Le champ `Project ID` correspond au nom ou à l'ID du projet dans Azure.

#### Détails du mappage de la sévérité

Les attributs du formulaire sont fournis par défaut et sont les suivants :

- **Severity Field Name** : `/fields/Microsoft.VSTS.Common.Priority`
- **Info Mapping** : `4`
- **Low Mapping** : `4`
- **Medium Mapping** : `3`
- **High Mapping** : `2`
- **Critical Mapping** : `1`

#### Détails du mappage du statut

Les attributs du formulaire sont fournis par défaut et sont les suivants :

- **Status Field Name** : `/fields/System.State`
- **Active Mapping** : `To Do`
- **Closed Mapping** : `Done`
- **False Positive Mapping** : `Done`
- **Risk Accepted Mapping** : `Done`
