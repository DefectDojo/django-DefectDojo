---
title: "GitHub"
description: "Configuration des Connecteurs Upstream et Downstream pour GitHub"
weight: 63
audience: pro
---
## Connecteur Upstream

Le connecteur GitHub est un **connecteur d'actifs (Asset Connector)** : il énumère les dépôts auxquels votre jeton a accès et crée un actif DefectDojo pour chacun, regroupés en organisations par propriétaire GitHub (organisation ou utilisateur). Aucune constatation n'est importée.

**Remarque :** ce connecteur importe uniquement l'**inventaire** de vos dépôts. Pour importer les alertes de sécurité GitHub — code scanning, Dependabot et secret scanning — sous forme de constatations, utilisez le connecteur **GitHub Advanced Security** distinct décrit plus bas. Les deux sont indépendants et peuvent être exécutés ensemble.

#### Prérequis

Le connecteur s'authentifie avec un **jeton d'accès personnel** GitHub et ne lit que les **métadonnées** du dépôt (nom, description, URL et propriétaire) — il n'accède ni à votre code, ni à vos issues, ni à vos alertes de sécurité. Il importe chaque dépôt dont le compte du jeton est propriétaire, collaborateur, ou membre de l'organisation propriétaire ; vérifiez donc que le compte du jeton peut voir les dépôts que vous souhaitez refléter. Nous recommandons un compte de service dédié.

Le jeton n'a besoin que d'un accès en lecture seule aux métadonnées du dépôt :

- Un jeton *fine-grained* nécessite **Repository permissions → Metadata: Read-only**, accordé aux dépôts (ou à l'ensemble de l'organisation) que vous souhaitez importer.
- Un jeton *classic* nécessite le scope **`repo`** pour inclure les dépôts privés (utilisez **`public_repo`** si vous n'avez besoin que des dépôts publics), ainsi que **`read:org`** pour que les dépôts appartenant à une organisation soient résolus.

Seul GitHub.com (y compris GitHub Enterprise Cloud) est pris en charge. GitHub Enterprise **Server** n'est pas pris en charge par ce connecteur pour le moment.

#### Mappages du connecteur

1. Saisissez `https://api.github.com` dans le champ **Location**.
2. Saisissez le jeton d'accès personnel dans le champ **Secret**.

Aucune liste d'organisations ou de dépôts n'est à saisir — DefectDojo importe tous les dépôts que le jeton peut voir. Chaque dépôt devient un enregistrement nommé d'après le dépôt, regroupé par **owner** GitHub (organisation ou utilisateur). Si un dépôt est supprimé par la suite, ou si le jeton perd l'accès à celui-ci, son enregistrement associé est marqué `MISSING` lors de la prochaine synchronisation plutôt que supprimé — DefectDojo ne supprime jamais silencieusement un Produit.

## Connecteur Downstream

L'intégration GitHub vous permet d'ajouter des tickets à un [GitHub Project](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/about-projects), ce qui ouvre également des tickets dans un dépôt (Repo) associé. Ces dépôts/projets peuvent être associés soit à une organisation GitHub, soit à un compte GitHub personnel.

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur l'URL de votre utilisateur ou organisation GitHub, selon l'endroit où vous souhaitez créer des tickets, par exemple `https://github.com/{your-organization}`
- **Token** doit être défini sur un jeton d'accès personnel GitHub.

Les jetons d'accès personnels pour GitHub peuvent être créés à l'adresse https://github.com/settings/tokens.  Le jeton doit disposer des portées Repo et Project.

### Mappage du suivi des tickets

- **Issue Tracker Mapping Label** doit être défini pour identifier le projet ou le dépôt dans lequel vous souhaitez créer des tickets.
- **Project Number** doit correspondre à l'ID du projet GitHub vers lequel vous souhaitez envoyer les éléments.  Vous pouvez l'obtenir depuis l'URL affichée lorsque vous consultez un projet, par exemple `https://github.com/orgs/{your-org}/projects/{project number}`.
- **Repository Name** doit correspondre au nom d'un dépôt associé à votre organisation (ou utilisateur) vers lequel vous souhaitez transmettre des tickets.


### Détails du mappage de la sévérité

**Pour configurer l'intégration, le projet DOIT disposer d'un champ personnalisé créé pour représenter la priorité des tickets ; sinon, la sévérité ne sera pas correctement mappée et les tickets ne seront pas transmis à GitHub.**

Suivez ce guide pour créer un [champ personnalisé](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/quickstart-for-projects#creating-a-field-to-track-priority).
Chaque sévérité doit disposer d'une option à sélection unique correspondante.  Par exemple, par défaut, DefectDojo propose P0, P1, P2, P3, P4 comme valeurs possibles de priorité, et chacune d'elles doit être ajoutée au champ personnalisé Priority.

- **Severity Field Name** : `Priority`
- **Info Mapping** : `P0`
- **Low Mapping** : `P1`
- **Medium Mapping** : `P2`
- **High Mapping** : `P3`
- **Critical Mapping** : `P4`

### Détails du mappage du statut

Par défaut, les nouveaux projets GitHub disposent des statuts « In Progress » et « Done » pour les tickets.  Des statuts supplémentaires peuvent être ajoutés au projet pour suivre les statuts Faux positif ou Risque accepté si vous le souhaitez.  L'une des façons d'y parvenir consiste à ajouter une nouvelle colonne de statut au tableau du projet.

- **Status Field Name** : `Status`
- **Active Mapping** : `In Progress`
- **Closed Mapping** : `Done`
- **False Positive Mapping** : `Done`
- **Risk Accepted Mapping** : `Done`
